/**
 * PhishNet Content Script
 * Extracts email content, attachments, and links from Gmail/Outlook; coordinates scanning and threat modals
 */

(function () {
  'use strict';

  const root = typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this);
  const PhishNet = root.PhishNet || {};

  const logger = PhishNet.logger || {
    debug: () => {},
    info: () => {},
    warn: (...args) => console.warn('[PhishNet]', ...args),
    error: (...args) => console.error('[PhishNet]', ...args)
  };

  const getSelectorsForCurrentSite = PhishNet.getSelectorsForCurrentSite || (() => null);
  const UTILITY_SELECTORS = PhishNet.UTILITY_SELECTORS || { skipElements: [] };
  const heuristicDetect = PhishNet.heuristicDetect || (() => ({ label: 'uncertain', confidence: 0.5, reasons: [] }));
  const safeQuery = PhishNet.safeQuery || ((el, sel) => el ? el.querySelector(Array.isArray(sel) ? sel[0] : sel) : null);
  const safeText = PhishNet.safeText || ((el, max = 3000) => (el?.textContent || '').trim().slice(0, max));
  const safeAttr = PhishNet.safeAttr || ((el, attr, fb = '') => el?.getAttribute(attr) || fb);

  // State
  let currentSelectors = null;
  let observer = null;
  // The close function of the currently open modal, so a reopen can remove the
  // previous one's keydown listener instead of leaking it.
  let activeModalClose = null;
  let messageListenerRegistered = false;
  let scanDebounceTimer = null;
  // When the currently pending scan was first requested. A mutation after
  // MAX_DEBOUNCE_WAIT_MS fires the scan instead of restarting the window.
  let scanDebounceStartedAt = 0;
  let lastUrl = typeof location !== 'undefined' ? location.href : '';
  const activeScans = new Set();
  const scannedEmailIds = new Set();
  // Elements already handled. Ids are evicted from the LRU set above, so the
  // set alone cannot answer "has this exact DOM node been scanned?".
  const scannedElements = new WeakSet();
  // Last verdict per element, so a settings change can re-render without
  // re-running inference.
  const renderedResults = new Map();
  let activeSettings = { highlightLinks: true, sensitivityThreshold: 0.7 };
  const MAX_TRACKED_IDS = 50;
  // Long enough that a signature or footer does not push the real content past
  // the cut. The model still truncates to its own token budget.
  const BODY_TEXT_LIMIT = 12000;
  // Keep the content-to-worker payload within background.js validation limits.
  // Preserve the complete subject in emailContent for local heuristics.
  const MAX_SCAN_SUBJECT = 1024;
  const MAX_EXTRACTED_ATTACHMENTS = 50;
  const MAX_EXTRACTED_LINKS = 100;
  // Labels that mean "this is an attack". The threshold applies to all of
  // them; a label outside this set is never downgraded.
  const PHISHING_LABELS = new Set(['phishing_email', 'phishing_url']);
  const SCAN_DEBOUNCE_MS = 400;
  // Longest a scan may be deferred on a page that never stops mutating.
  const MAX_DEBOUNCE_WAIT_MS = 2000;

  /**
   * Initialize content script
   */
  function init() {
    currentSelectors = getSelectorsForCurrentSite();

    if (!currentSelectors) {
      logger.debug('Not on a supported email provider');
      return;
    }

    logger.debug(`Initialized for ${currentSelectors.provider} (${currentSelectors.variant})`);

    // Start consolidated observer
    startEmailObserver();

    // Listen for messages from background/popup
    if (!messageListenerRegistered) {
      chrome.runtime.onMessage.addListener(handleMessage);
      messageListenerRegistered = true;
    }

    // A hidden-then-restored tab needs its own sweep; the observer only sees
    // mutations, not a tab that was in the background.
    document.addEventListener('visibilitychange', onVisibilityChange);

    // Notify background that content script is ready
    chrome.runtime.sendMessage({ type: 'CONTENT_READY', provider: currentSelectors.provider }).catch(() => {});
  }

  /**
   * Consolidated MutationObserver to detect both email opens and SPA navigation
   */
  function startEmailObserver() {
    if (observer) {
      observer.disconnect();
    }

    observer = new MutationObserver(() => {
      const currentUrl = location.href;
      if (currentUrl !== lastUrl) {
        lastUrl = currentUrl;
        scannedEmailIds.clear();
        debouncedCheckForNewEmails(800);
        return;
      }

      debouncedCheckForNewEmails(SCAN_DEBOUNCE_MS);
    });

    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true
    });

    // Initial check
    checkForNewEmails();
  }

  /**
   * Debounced check for new emails
   */
  function debouncedCheckForNewEmails(delay = SCAN_DEBOUNCE_MS) {
    const now = Date.now();

    // No scan is pending: open a fresh wait window.
    if (scanDebounceTimer === null) scanDebounceStartedAt = now;

    // The window is spent. Run now rather than push the scan further out.
    if (now - scanDebounceStartedAt >= MAX_DEBOUNCE_WAIT_MS) {
      clearTimeout(scanDebounceTimer);
      scanDebounceTimer = null;
      scanDebounceStartedAt = 0;
      checkForNewEmails();
      return;
    }

    clearTimeout(scanDebounceTimer);
    scanDebounceTimer = setTimeout(() => {
      scanDebounceTimer = null;
      scanDebounceStartedAt = 0;
      checkForNewEmails();
    }, delay);
  }

  /**
   * Check for newly opened emails in the DOM
   */
  function checkForNewEmails() {
    if (!currentSelectors || !currentSelectors.selectors) return;
    const selectors = currentSelectors.selectors;
    const messageElements = document.querySelectorAll(selectors.messages);

    if (messageElements.length === 0) return;

    // Collect this pass's work before touching the tracking set.
    //
    // Evicting while iterating was a loop: with more than MAX_TRACKED_IDS
    // elements, the id dropped was usually the next one to be visited, so it
    // was re-added and scanned in the same pass. The badge injection then
    // mutated the DOM, which retriggered the observer and scheduled another
    // pass — endless inference and badge churn on long threads.
    const discovered = [];
    const discoveredIds = new Set();
    messageElements.forEach((element) => {
      // An element already handled is skipped even if its id was evicted from
      // the LRU set, so a long-lived DOM node is never scanned twice.
      if (scannedElements.has(element)) return;

      const emailId = getEmailId(element);
      if (!emailId) return;

      // A scan that is in progress can still be deferred (e.g. auto-scan is
      // disabled). Do not permanently mark another copy of that message as
      // handled before the first scan has actually completed.
      if (activeScans.has(emailId) || discoveredIds.has(emailId)) return;
      if (scannedEmailIds.has(emailId)) {
        scannedElements.add(element);
        return;
      }
      discoveredIds.add(emailId);
      discovered.push({ element, emailId });
    });

    if (discovered.length === 0) return;

    // Claim every id for this pass, then trim. The order matters: trimming
    // first would evict an id that a later element in this same pass needs.
    for (const { emailId } of discovered) scannedEmailIds.add(emailId);
    while (scannedEmailIds.size > MAX_TRACKED_IDS) {
      scannedEmailIds.delete(scannedEmailIds.values().next().value);
    }

    for (const { element, emailId } of discovered) {
      scannedElements.add(element);
      scanEmail(element, emailId);
    }
  }

  /**
   * Get unique email identifier
   */
  /**
   * A stable identifier for a message element.
   *
   * Provider ids are preferred. `[role=listitem]` in Outlook often has no
   * `data-convid`, and falling back to a sender+subject hash means two
   * legitimate messages with the same subject collide — one is marked scanned
   * without ever being looked at. When no id attribute exists, a content hash
   * is used instead, so distinct messages stay distinct.
   */
  function getEmailId(element) {
    if (!element) return null;

    const ATTRIBUTE_IDS = [
      'messageId', 'message-id', 'convid', 'conversationId', 'conversation-id',
      'itemId', 'item-id', 'dataMessageId', 'dataConversatonId'
    ];
    for (const key of ATTRIBUTE_IDS) {
      const value = element.dataset?.[key] || element.getAttribute?.(key);
      if (typeof value === 'string' && value.trim()) return value.trim();
    }

    const selectors = currentSelectors?.selectors;
    if (selectors) {
      const senderEl = element.querySelector(selectors.sender) || element.querySelector(selectors.senderEmail);
      const subjectEl = element.querySelector(selectors.subject) || element.querySelector(selectors.subjectAlt);

      if (senderEl || subjectEl) {
        // Include the entire message, not just the first 24 decoded bytes
        // of sender/subject. Otherwise similarly titled emails collapse to
        // one ID and the second message may never be scanned.
        const signature = [
          senderEl?.textContent || '',
          subjectEl?.textContent || '',
          element.textContent || ''
        ].join('\0');
        const bytes = new TextEncoder().encode(signature);
        // Synchronous 64-bit FNV-1a: stable across reloads and Unicode-safe.
        // This is a deduplication key, not a cryptographic identity.
        let hash = 0xcbf29ce484222325n;
        for (const byte of bytes) {
          hash ^= BigInt(byte);
          hash = BigInt.asUintN(64, hash * 0x100000001b3n);
        }
        return 'fallback-' + hash.toString(16).padStart(16, '0');
      }
    }

    return null;
  }

  /**
   * Extract and scan email content
   */
  async function scanEmail(element, emailId) {
    if (!element) return null;
    if (emailId && activeScans.has(emailId)) return null;

    let completedScan = false;
    if (emailId) {
      activeScans.add(emailId);
    }

    try {
      const emailContent = extractEmailContent(element);

      // Get non-sensitive preferences; whitelist decisions remain in the extension background.
      let settings = { autoScan: true, sensitivityThreshold: 0.7, highlightLinks: true, showTooltip: true };
      try {
        const response = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' });
        if (response) settings = Object.assign(settings, response);
      } catch (e) {
        logger.debug('Using default settings for scan');
      }

      const senderEmail = emailContent.sender?.email?.toLowerCase() || '';
      const senderDomain = emailContent.sender?.domain?.toLowerCase() || '';
      let isWhitelisted = false;
      try {
        const trust = await chrome.runtime.sendMessage({
          type: 'CHECK_TRUSTED_SENDER', email: senderEmail, domain: senderDomain
        });
        isWhitelisted = trust?.trusted === true;
      } catch (error) {
        logger.debug('Trusted sender lookup unavailable; scanning normally');
      }

      if (isWhitelisted) {
        const trustedResult = {
          label: 'trusted',
          confidence: 1.0,
          reasons: ['Sender is on your Trusted Senders whitelist'],
          processingTime: 0,
          links: emailContent.links,
          attachments: emailContent.attachments,
          emailContent
        };
        injectBadge(element, trustedResult);
        logScanRecord(emailContent, trustedResult);
        completedScan = true;
        return trustedResult;
      }

      if (!settings.autoScan && !emailId?.startsWith('manual-')) {
        return null;
      }

      // Phishing messages can be one word, an image-only link, or even an
      // empty body with a dangerous attachment. Sender and link heuristics
      // must still run; only a truly empty, unidentified message is deferred.
      const hasText = !!emailContent.text?.trim();
      const hasSignals = hasText || !!emailContent.sender?.email ||
        !!emailContent.sender?.domain || emailContent.links.length > 0 ||
        emailContent.attachments.length > 0 || emailContent.hasFormElements;
      if (!hasSignals) {
        logger.debug('Email has no content or metadata to scan yet');
        return null;
      }

      // Run ML classification via background worker
      let mlResult = null;
      // An empty string cannot be meaningfully classified by the text model.
      // Still run heuristic detection below when sender/link signals exist.
      if (hasText) {
        try {
          const response = await chrome.runtime.sendMessage({
            type: 'SCAN_EMAIL',
            payload: {
              ...emailContent,
              subject: emailContent.subject.slice(0, MAX_SCAN_SUBJECT),
              url: window.location.href,
              emailId
            }
          });

          if (response && response.success && response.result) {
            mlResult = response.result;
          }
        } catch (mlError) {
          logger.debug('ML inference unavailable, applying heuristic detection');
        }
      }

      // Fallback to advanced heuristic detector.
      // heuristicDetect reads links and attachments off emailContent; passing
      // them again as positional args made it concatenate each array onto
      // itself, so every link and attachment was counted twice.
      const heuristicRes = heuristicDetect(emailContent);
      const result = mlResult ? Object.assign({}, heuristicRes, mlResult, {
        links: heuristicRes.links,
        attachments: heuristicRes.attachments,
        signals: heuristicRes.signals
      }) : heuristicRes;

      result.emailContent = emailContent;

      if (emailContent.attachmentsTruncated) {
        result.reasons = Array.isArray(result.reasons) ? result.reasons : [];
        result.reasons.push('Only the first 50 attachments were examined; this message contains more attachments.');
      }
      if (emailContent.linksTruncated) {
        result.reasons = Array.isArray(result.reasons) ? result.reasons : [];
        result.reasons.push('Only the first 100 links were examined; this message contains more links.');
      }

      activeSettings = settings;

      // Apply sensitivity threshold
      // Every phishing verdict is subject to the user's threshold, not just
      // phishing_email. A phishing_url verdict used to bypass it entirely, so a
      // user who set a high threshold still saw link verdicts they had asked to
      // be treated as uncertain.
      const finalResult = applyThreshold(result, settings.sensitivityThreshold);

      // Inject UI indicators
      renderPresentation(element, finalResult, settings);
      renderedResults.set(element, result);

      // Log locally for popup stats
      logScanRecord(emailContent, result);

      completedScan = true;
      return result;
    } catch (error) {
      logger.error('Email scan error:', error);
      return null;
    } finally {
      if (emailId) {
        activeScans.delete(emailId);
        // A deferred scan is not a scan. Reconsider it when its DOM changes,
        // or when auto-scan is enabled, instead of caching an absent verdict.
        if (!completedScan) {
          scannedEmailIds.delete(emailId);
          scannedElements.delete(element);
        }
      }
    }
  }

  /**
   * Apply the user's sensitivity threshold to a verdict.
   *
   * Every phishing verdict is subject to it, not just phishing_email: a
   * phishing_url verdict used to bypass it entirely.
   */
  function applyThreshold(result, threshold) {
    if (!result || !PHISHING_LABELS.has(result.label)) return result;
    if (result.confidence >= threshold) return result;
    const downgraded = { ...result, label: 'uncertain', reasons: [...(result.reasons || [])] };
    downgraded.reasons.unshift(
      `Confidence (${Math.round(result.confidence * 100)}%) is below sensitivity threshold (${Math.round(threshold * 100)}%)`
    );
    return downgraded;
  }

  /**
   * Draw the badge and link highlights for a verdict.
   *
   * Existing marks are cleared first so a re-render after a settings change
   * replaces them rather than stacking.
   */
  function renderPresentation(element, result, settings) {
    try {
      element.querySelectorAll?.('.phishnet-badge, .phishnet-link-warning')
        .forEach((node) => node.remove());
    } catch (e) {}

    injectBadge(element, result);
    if (settings?.highlightLinks) {
      highlightLinks(element, result);
    }
  }

  /**
   * Re-render every visible verdict against the current settings.
   *
   * A SETTINGS_UPDATE used to be ignored, so badges and link highlights stayed
   * as they were until the page reloaded.
   */
  function rerenderAll() {
    for (const [element, result] of renderedResults) {
      if (!element?.isConnected) {
        renderedResults.delete(element);
        continue;
      }
      renderPresentation(element, applyThreshold(result, activeSettings.sensitivityThreshold), activeSettings);
    }
  }

  /**
   * Log scan result to chrome.storage.local for dashboard
   */
  function logScanRecord(emailContent, result) {
    if (!chrome.storage?.local) return;

    try {
      chrome.storage.local.get(['scanHistory', 'scanStats'], (data) => {
        const history = data.scanHistory || [];
        const stats = data.scanStats || { total: 0, phishing: 0, safe: 0, uncertain: 0, trusted: 0 };

        stats.total++;
        if (result.label === 'phishing_email') stats.phishing++;
        else if (result.label === 'legitimate_email') stats.safe++;
        else if (result.label === 'trusted') stats.trusted++;
        else stats.uncertain++;

        const newRecord = {
          id: Date.now(),
          subject: (emailContent.subject || 'No Subject').slice(0, 80),
          sender: emailContent.sender?.email || emailContent.sender?.domain || 'Unknown',
          label: result.label,
          confidence: Math.round((result.confidence || 0) * 100),
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        };

        const updatedHistory = [newRecord, ...history.slice(0, 19)]; // Keep latest 20
        chrome.storage.local.set({ scanHistory: updatedHistory, scanStats: stats }).catch(() => {});
      });
    } catch (e) {}
  }

  /**
   * Regions that hold metadata rather than message content.
   *
   * When the body container is the whole message element, its textContent
   * includes the sender, subject and date lines, and quoted-reply attribution.
   * Those tokens would otherwise be scanned as body text.
   */
  function headerSelectorList() {
    const selectors = currentSelectors?.selectors || {};
    return [
      selectors.subject,
      selectors.subjectAlt,
      selectors.subjectFallback,
      selectors.sender,
      selectors.senderName,
      selectors.senderEmail,
      selectors.senderFallback,
      '.gmail_attr',
      '.mail-message-header',
      '[role="heading"]'
    ].filter(Boolean);
  }

  /**
   * Clone `source` with non-content regions removed.
   */
  function cloneBody(source, { stripHeaders }) {
    const clone = source.cloneNode(true);
    const skipList = (UTILITY_SELECTORS.skipElements || []).concat([
      'script', 'style', 'noscript', '.phishnet-badge', '.phishnet-link-warning'
    ]);
    if (stripHeaders) skipList.push(...headerSelectorList());
    skipList.forEach((sel) => {
      try {
        clone.querySelectorAll(sel).forEach(el => el.remove());
      } catch (e) {}
    });
    return clone;
  }

  /** Accept only complete email addresses, never addresses embedded in tooltips. */
  function parseSenderEmail(raw) {
    if (typeof raw !== 'string') return '';
    let value = raw.trim();
    if (value.startsWith('<') && value.endsWith('>')) value = value.slice(1, -1).trim();
    if (value.length > 320) return '';
    const at = value.indexOf('@');
    if (at <= 0 || at !== value.lastIndexOf('@')) return '';
    const local = value.slice(0, at);
    const domain = value.slice(at + 1);
    if (local.length > 64 || local.startsWith('.') || local.endsWith('.') || local.includes('..')) {
      return '';
    }
    if (!/^[a-z0-9!#$%&'*+/=?^_\x60{|}~.-]+$/i.test(local)) return '';
    const domainLabel = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
    const labels = domain.split('.');
    return domain.length <= 253 && labels.length >= 2 &&
      labels.every(label => domainLabel.test(label)) ? value : '';
  }

  /**
   * Extract email content and attachments from DOM element
   */
  function extractEmailContent(element) {
    const selectors = currentSelectors?.selectors || {};

    // Extract subject. The search is scoped to the message's own container:
    // falling back to `document` let a page-level heading become the subject.
    const subjectRoot = element.closest('[data-thread-id]') || element.closest('[data-convid]') || element;
    const subjectSelectors = [
      selectors.subject,
      selectors.subjectAlt,
      selectors.subjectFallback,
      'h2[data-thread-id]',
      'h2', 'h3', '[role="heading"]',
      '[data-thread-id] h2'
    ].filter(Boolean);
    const subjectEl = safeQuery(subjectRoot, subjectSelectors, 'Subject');
    const subject = safeText(subjectEl);

    // Extract sender
    let senderName = '', senderEmail = '', senderDomain = '';
    const senderSelectors = [
      selectors.sender,
      selectors.senderName,
      selectors.senderEmail,
      selectors.senderFallback,
      '[email]', '[data-email]', '.sender', '.from', '[data-testid="message-header-sender-name"]'
    ].filter(Boolean);
    const senderEl = safeQuery(element, senderSelectors, 'Sender');
    // Outlook renders display names and addresses in separate sibling nodes.
    // Resolve the address independently, even when the name selector matches.
    const senderEmailEl = selectors.senderEmail
      ? safeQuery(element, selectors.senderEmail, 'Sender email')
      : null;

    if (senderEl) {
      senderName = safeText(senderEl);
      senderEmail = parseSenderEmail(safeAttr(senderEl, 'email')) ||
        parseSenderEmail(safeAttr(senderEl, 'data-email')) ||
        parseSenderEmail(safeAttr(senderEl, 'title')) ||
        parseSenderEmail(senderName);
      if (senderEmail) {
        senderDomain = senderEmail.split('@')[1].toLowerCase();
      }
    }
    if (senderEmailEl) {
      const address = parseSenderEmail(safeAttr(senderEmailEl, 'email')) ||
        parseSenderEmail(safeAttr(senderEmailEl, 'data-email')) ||
        parseSenderEmail(safeAttr(senderEmailEl, 'title')) ||
        parseSenderEmail(safeText(senderEmailEl));
      if (address) {
        senderEmail = address;
        senderDomain = senderEmail.split('@')[1].toLowerCase();
      }
    }

    // Extract body text.
    //
    // When no body selector matches, the container is the whole message
    // element, so its metadata regions are stripped before the text is read.
    // Otherwise the sender, subject and date lines are scanned as body text.
    const bodySelectors = [
      selectors.messageBody,
      selectors.messageBodyAlt,
      selectors.messageBodyFallback,
      '[data-message-id] .ii.gt',
      '[data-message-id] .a3s',
      '[data-testid="message-body-content"]',
      '[data-testid="message-body"]',
      '.elementToProof',
      '.allowTextSelection',
      '.message-body',
      '.email-body',
      '[role="main"]',
      'article'
    ].filter(Boolean);

    const matchedBody = safeQuery(element, bodySelectors, 'Body');
    const bodyEl = matchedBody || element;
    let bodyText = '';

    if (bodyEl) {
      try {
        bodyText = safeText(cloneBody(bodyEl, { stripHeaders: !matchedBody }), BODY_TEXT_LIMIT);
      } catch (e) {
        bodyText = safeText(bodyEl, BODY_TEXT_LIMIT);
      }
    }

    // Extract links from the message body only.
    //
    // Reading `element` picked up quoted replies and signature links, so an old
    // phishing link in a forwarded thread could flag an otherwise safe email.
    const { links, truncated: linksTruncated } = extractLinks(bodyEl);

    // Extract attachments
    const attachments = extractAttachments(element);

    // Interactive form elements are a phishing signal, but the detector only
    // receives textContent, where tags never appear. Count them here and pass
    // a boolean rather than testing the text for '<form'.
    let hasFormElements = false;
    try {
      hasFormElements = !!bodyEl.querySelector?.('form, input, select, textarea');
    } catch (e) {
      hasFormElements = false;
    }

    const fullText = `${subject}\n\n${bodyText}`.trim();

    return {
      text: fullText,
      subject,
      body: bodyText,
      links,
      linksTruncated,
      attachments: attachments.items,
      attachmentsTruncated: attachments.truncated,
      hasFormElements,
      sender: {
        name: senderName,
        email: senderEmail,
        domain: senderDomain
      }
    };
  }

  /**
   * Extract links from email
   */
  function extractLinks(element) {
    const selectors = currentSelectors?.selectors || {};
    const linkQuery = selectors.links || 'a[href]';
    const links = [];

    const linkElements = element.querySelectorAll(linkQuery);

    for (let i = 0; i < Math.min(linkElements.length, MAX_EXTRACTED_LINKS); i++) {
      const linkEl = linkElements[i];
      const rawHref = linkEl.getAttribute('href');
      if (!rawHref) continue;

      // Resolve relative and scheme-relative links as the browser would;
      // keep the raw attribute for residual HTML-entity-encoded values.
      const hasEntity = /&amp;/i.test(rawHref);
      let href = hasEntity ? rawHref.replace(/&amp;/gi, '&') : (linkEl.href || rawHref);
      if (!/^(?:https?:|mailto:)/i.test(href)) {
        try {
          href = new URL(href, document.baseURI).href;
        } catch (e) {
          continue;
        }
      }
      if (!/^(?:https?:|mailto:)/i.test(href)) continue;

      let text = (linkEl.textContent || '').trim();
      // An image-only link has no text content. Without a fallback the
      // display-text mismatch check is skipped, which is exactly the shape of
      // an "image as link" phish.
      if (!text) {
        const img = linkEl.querySelector?.('img');
        text = (
          safeAttr(linkEl, 'aria-label') ||
          safeAttr(linkEl, 'title') ||
          safeAttr(img, 'alt') ||
          safeAttr(img, 'title') ||
          ''
        ).trim();
      }
      if (!text && linkEl.querySelector?.('img')) text = '[image link]';
      if (text.length > 120) text = text.slice(0, 120) + '...';

      const isSuspicious = PhishNet.isUrlSuspicious ? PhishNet.isUrlSuspicious(href) : false;

      links.push({ href, text, suspicious: isSuspicious });
    }

    return { links, truncated: linkElements.length > MAX_EXTRACTED_LINKS };
  }

  /**
   * Extract attachment filenames from email
   */
  function extractAttachments(element) {
    const selectors = currentSelectors?.selectors || {};
    const attachments = [];
    const seenAttachments = new Set();
    let truncated = false;
    const attSelectors = [
      selectors.attachmentNames,
      selectors.attachments,
      '[data-testid*="attachment"]',
      '[download_url]',
      '.aZo'
    ].filter(Boolean);

    for (const sel of attSelectors) {
      if (truncated) break;
      try {
        for (const el of element.querySelectorAll(sel)) {
          // Broad attachment selectors also match size labels and wrappers.
          // Count only file-name nodes when a wrapper contains one.
          const testId = el.getAttribute?.('data-testid') || '';
          if (/attachment[-_]?(?:size|filesize)/i.test(testId)) continue;
          if (selectors.attachmentSizes && el.matches?.(selectors.attachmentSizes)) continue;
          if (selectors.attachmentNames && el.querySelector?.(selectors.attachmentNames)) continue;
          if (attachments.length >= MAX_EXTRACTED_ATTACHMENTS) {
            truncated = true;
            break;
          }
          const name = el.getAttribute('title') || el.getAttribute('download') || el.textContent || '';
          // Normalize invisible/directional formatting and filesystem trailing
          // punctuation before the filename reaches attachment heuristics.
          const clean = name.replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]/g, '')
            .trim().replace(/[. ]+$/, '');
          // Keep the suffix (including a dangerous extension) for oversized
          // names while bounding the payload passed to the detector.
          const boundedName = clean.length > 255 ? `…${clean.slice(-254)}` : clean;
          // A message can contain different files with the same filename.
          // Dedupe overlapping DOM selectors by identity, not name alone.
          const container = el.closest?.('[data-testid*="attachment"], .aZo') || el;
          const attr = (node, keys) => keys.map(key => node.getAttribute?.(key)).find(Boolean) || '';
          const size = (attr(el, ['data-size', 'data-file-size']) ||
            attr(container, ['data-size', 'data-file-size']) ||
            (selectors.attachmentSizes && container.querySelector?.(selectors.attachmentSizes)?.textContent) || '').trim();
          const type = (attr(el, ['data-mime-type', 'data-type', 'type']) ||
            attr(container, ['data-mime-type', 'data-type', 'type'])).trim().toLowerCase();
          const identity = JSON.stringify([boundedName, size, type]);
          if (boundedName && !seenAttachments.has(identity)) {
            seenAttachments.add(identity);
            attachments.push(boundedName);
          }
        }
      } catch (e) {}
    }

    return { items: attachments, truncated };
  }

  /**
   * Inject classification badge into email header
   */
  function injectBadge(element, result) {
    if (!element || !result) return;

    const existing = element.querySelector('.phishnet-badge');
    if (existing) existing.remove();

    const selectors = currentSelectors?.selectors || {};

    const insertPoint = element.querySelector(selectors.sender) ||
                        element.querySelector(selectors.senderEmail) ||
                        element.querySelector(selectors.subject) ||
                        element.querySelector(selectors.subjectAlt) ||
                        element.querySelector('h2, h3, [role="heading"]');

    if (!insertPoint || !insertPoint.parentNode) return;

    const badgeConfig = {
      'phishing_email': { icon: '⚠️', label: 'Phishing', class: 'phishnet-badge--phishing' },
      'phishing_url': { icon: '🔗', label: 'Phishing Link', class: 'phishnet-badge--phishing' },
      'legitimate_email': { icon: '🛡️', label: 'Safe', class: 'phishnet-badge--safe' },
      'legitimate_url': { icon: '🔗', label: 'Safe Link', class: 'phishnet-badge--safe' },
      'trusted': { icon: '⭐', label: 'Trusted Sender', class: 'phishnet-badge--trusted' },
      'uncertain': { icon: '❓', label: 'Uncertain', class: 'phishnet-badge--uncertain' }
    };

    const config = badgeConfig[result.label] || badgeConfig.uncertain;
    const confidencePct = Math.round((result.confidence || 0) * 100);

    const badge = document.createElement('span');
    badge.className = `phishnet-badge ${config.class} phishnet-tooltip-trigger`;
    badge.setAttribute('role', 'button');
    badge.setAttribute('tabindex', '0');
    badge.setAttribute('aria-label', `${config.label} (${confidencePct}%) - Click or press Enter for threat details`);
    badge.setAttribute('data-confidence', String(result.confidence || 0));
    badge.setAttribute('data-tooltip', `${config.label} (${confidencePct}%) • Click for Threat Details`);
    badge.textContent = `${config.icon} ${config.label} (${confidencePct}%)`;

    // Click or keyboard trigger to open detailed threat breakdown modal
    badge.addEventListener('click', (e) => {
      e.stopPropagation();
      e.preventDefault();
      openThreatModal(result);
    });
    badge.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.stopPropagation();
        e.preventDefault();
        openThreatModal(result);
      }
    });

    insertPoint.parentNode.insertBefore(badge, insertPoint.nextSibling);
    ensureTooltipStyles();
  }

  /**
   * Interactive Threat Breakdown Modal
   */
  function openThreatModal(result) {
    // Tear the previous modal down properly. Removing its DOM node alone left
    // its document-level keydown handler attached, so every reopen leaked one
    // and ESC ran a stale close handler.
    if (activeModalClose) {
      activeModalClose();
      activeModalClose = null;
    }

    const backdrop = document.createElement('div');
    backdrop.id = 'phishnet-modal-root';
    backdrop.className = 'phishnet-modal-backdrop';

    const card = document.createElement('div');
    card.className = 'phishnet-modal-card';
    card.setAttribute('role', 'dialog');
    card.setAttribute('aria-modal', 'true');
    card.setAttribute('aria-labelledby', 'phishnet-modal-title-id');

    const header = document.createElement('div');
    header.className = 'phishnet-modal-header';

    const headerLeft = document.createElement('div');
    headerLeft.className = 'phishnet-modal-header-left';

    const logoSpan = document.createElement('span');
    logoSpan.className = 'phishnet-modal-logo';
    logoSpan.setAttribute('aria-hidden', 'true');
    logoSpan.textContent = '🎣';

    const titleSpan = document.createElement('span');
    titleSpan.className = 'phishnet-modal-title';
    titleSpan.id = 'phishnet-modal-title-id';
    titleSpan.textContent = 'PhishNet Threat Inspector';

    headerLeft.appendChild(logoSpan);
    headerLeft.appendChild(titleSpan);

    const headerCloseBtn = document.createElement('button');
    headerCloseBtn.className = 'phishnet-modal-close';
    headerCloseBtn.id = 'phishnetModalCloseBtn';
    headerCloseBtn.setAttribute('aria-label', 'Close threat details dialog');
    headerCloseBtn.textContent = '✕';

    header.appendChild(headerLeft);
    header.appendChild(headerCloseBtn);


    const body = document.createElement('div');
    body.className = 'phishnet-modal-body';

    const confidencePct = Math.round((result.confidence || 0) * 100);
    const verdictClass = result.label.includes('phishing') ? 'phishing' : (result.label.includes('legitimate') || result.label === 'trusted' ? 'safe' : 'uncertain');
    const verdictTitle = result.label === 'trusted' ? 'Trusted Sender' : (result.label.includes('phishing') ? 'Phishing Threat Detected' : (result.label.includes('legitimate') ? 'Legitimate Email' : 'Suspicious / Uncertain'));
    const verdictIcon = result.label === 'trusted' ? '⭐' : (result.label.includes('phishing') ? '⚠️' : (result.label.includes('legitimate') ? '🛡️' : '❓'));

    // Verdict Banner
    const verdictBanner = document.createElement('div');
    verdictBanner.className = `phishnet-verdict-banner ${verdictClass}`;

    const verdictLabel = document.createElement('div');
    verdictLabel.className = 'phishnet-verdict-label';

    const iconSpan = document.createElement('span');
    iconSpan.textContent = verdictIcon;

    const titleSpan2 = document.createElement('span');
    titleSpan2.textContent = verdictTitle;

    verdictLabel.appendChild(iconSpan);
    verdictLabel.appendChild(titleSpan2);

    const scoreDiv = document.createElement('div');
    scoreDiv.className = 'phishnet-verdict-score';
    scoreDiv.textContent = confidencePct + '%';

    verdictBanner.appendChild(verdictLabel);
    verdictBanner.appendChild(scoreDiv);

    body.appendChild(verdictBanner);

    // Reasons Card
    if (result.reasons && result.reasons.length > 0) {
      const reasonsCard = document.createElement('div');
      reasonsCard.className = 'phishnet-reasons-card';

      const reasonsTitle = document.createElement('div');
      reasonsTitle.className = 'phishnet-reasons-title';
      reasonsTitle.textContent = 'Detected Indicators:';
      reasonsCard.appendChild(reasonsTitle);

      result.reasons.forEach(r => {
        const item = document.createElement('div');
        item.className = 'phishnet-reason-item';
        item.textContent = r;
        reasonsCard.appendChild(item);
      });
      body.appendChild(reasonsCard);
    }

    // Signals Card
    if (result.signals) {
      const signalsGrid = document.createElement('div');
      signalsGrid.className = 'phishnet-signals-grid';

      const signals = [
        { title: 'Urgency Panic Score', value: `${result.signals.urgencyScore}/40`, color: result.signals.urgencyScore > 20 ? '#f43f5e' : '#10b981' },
        { title: 'Domain Trust Risk', value: `${result.signals.senderTrustScore}/45`, color: result.signals.senderTrustScore > 20 ? '#f43f5e' : '#10b981' },
        { title: 'Link Threat Level', value: `${result.signals.linkRiskScore}/45`, color: result.signals.linkRiskScore > 0 ? '#f43f5e' : '#10b981' },
        { title: 'Attachment Safety', value: result.signals.attachmentRiskScore > 0 ? 'Threat Detected' : 'Clean', color: result.signals.attachmentRiskScore > 0 ? '#f43f5e' : '#10b981' }
      ];

      signals.forEach(sig => {
        const sigCard = document.createElement('div');
        sigCard.className = 'phishnet-signal-card';

        const sigTitle = document.createElement('span');
        sigTitle.className = 'phishnet-signal-title';
        sigTitle.textContent = sig.title;

        const sigValue = document.createElement('span');
        sigValue.className = 'phishnet-signal-value';
        sigValue.style.color = sig.color;
        sigValue.textContent = sig.value;

        sigCard.appendChild(sigTitle);
        sigCard.appendChild(sigValue);
        signalsGrid.appendChild(sigCard);
      });

      body.appendChild(signalsGrid);
    }

    // Link Inspector
    if (result.links && result.links.length > 0) {
      const linkSection = document.createElement('div');
      linkSection.className = 'phishnet-reasons-card';

      const linkSectionTitle = document.createElement('div');
      linkSectionTitle.className = 'phishnet-reasons-title';
      linkSectionTitle.textContent = `Links in Email (${result.links.length}):`;
      linkSection.appendChild(linkSectionTitle);

      const linkList = document.createElement('div');
      linkList.className = 'phishnet-link-list';

      result.links.slice(0, 6).forEach(link => {
        const item = document.createElement('div');
        item.className = `phishnet-link-item ${link.suspicious ? 'suspicious' : ''}`;

        // Security: Avoid innerHTML with unescaped link.href to prevent DOM XSS
        const urlSpan = document.createElement('span');
        urlSpan.className = 'phishnet-link-url';
        urlSpan.title = link.href;
        urlSpan.textContent = link.href;

        const badgeSpan = document.createElement('span');
        badgeSpan.style.fontSize = '10px';
        badgeSpan.style.fontWeight = '700';
        badgeSpan.style.color = link.suspicious ? '#f43f5e' : '#10b981';
        badgeSpan.textContent = link.suspicious ? '⚠️ Suspicious' : '✓ Safe';

        item.appendChild(urlSpan);
        item.appendChild(badgeSpan);
        linkList.appendChild(item);
      });
      linkSection.appendChild(linkList);
      body.appendChild(linkSection);
    }

    // Footer
    const footer = document.createElement('div');
    footer.className = 'phishnet-modal-footer';

    const senderEmail = result.emailContent?.sender?.email || '';
    const whitelistBtn = document.createElement('button');
    whitelistBtn.className = 'phishnet-btn phishnet-btn--secondary';
    whitelistBtn.textContent = '⭐ Whitelist Sender';
    whitelistBtn.addEventListener('click', async () => {
      if (!senderEmail) return;
      chrome.runtime.sendMessage({
        type: 'ADD_WHITELIST',
        entry: senderEmail
      }).then(() => {
        whitelistBtn.textContent = '✓ Whitelisted!';
        whitelistBtn.disabled = true;
      });
    });

    const closeBtn = document.createElement('button');
    closeBtn.className = 'phishnet-btn phishnet-btn--primary';
    closeBtn.textContent = 'Close';
    closeBtn.addEventListener('click', closeModal);

    footer.appendChild(whitelistBtn);
    footer.appendChild(closeBtn);

    card.appendChild(header);
    card.appendChild(body);
    card.appendChild(footer);
    backdrop.appendChild(card);

    backdrop.addEventListener('click', (e) => {
      if (e.target === backdrop) closeModal();
    });

    // The dialog is announced as modal, so focus moves into it on open and
    // returns to whatever opened it on close. Without this a keyboard user
    // keeps tabbing through the page behind the overlay.
    const previouslyFocused = document.activeElement;

    const focusableSelector = [
      'button:not([disabled])',
      'a[href]',
      'input:not([disabled])',
      'select:not([disabled])',
      'textarea:not([disabled])',
      '[tabindex]:not([tabindex="-1"])'
    ].join(',');

    function focusableNodes() {
      try {
        return [...card.querySelectorAll(focusableSelector)].filter(
          (node) => node.offsetParent !== null || node === document.activeElement
        );
      } catch (e) {
        return [];
      }
    }

    function onKeyEscape(e) {
      if (e.key === 'Escape') {
        e.stopPropagation();
        closeModal();
        return;
      }
      // Keep Tab inside the dialog.
      if (e.key !== 'Tab') return;
      const nodes = focusableNodes();
      if (nodes.length === 0) return;
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      if (e.shiftKey && (document.activeElement === first || !card.contains(document.activeElement))) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && (document.activeElement === last || !card.contains(document.activeElement))) {
        e.preventDefault();
        first.focus();
      }
    }

    function closeModal() {
      document.removeEventListener('keydown', onKeyEscape);
      backdrop.remove();
      if (activeModalClose === closeModal) activeModalClose = null;
      // Restore focus to the badge that opened the dialog.
      if (previouslyFocused && typeof previouslyFocused.focus === 'function' && previouslyFocused.isConnected) {
        try { previouslyFocused.focus(); } catch (e) {}
      }
    }

    document.addEventListener('keydown', onKeyEscape);
    activeModalClose = closeModal;

    (document.body || document.documentElement).appendChild(backdrop);

    const closeButton = document.getElementById('phishnetModalCloseBtn') || closeBtn;
    closeButton?.addEventListener('click', closeModal);
    try { closeButton?.focus(); } catch (e) {}
  }

  /**
   * Highlight suspicious links
   */
  function highlightLinks(element, result) {
    if (!element) return;
    const selectors = currentSelectors?.selectors || {};
    const linkQuery = selectors.links || 'a[href]';
    const links = element.querySelectorAll(linkQuery);

    links.forEach((linkEl) => {
      const href = linkEl.getAttribute('href');
      if (!href) return;

      const flaggedInResult = result?.links?.some(l => l.href === href && l.suspicious);
      const isSuspicious = flaggedInResult || (PhishNet.isUrlSuspicious ? PhishNet.isUrlSuspicious(href) : false);

      if (isSuspicious) {
        linkEl.classList.add('phishnet-link--suspicious');
        linkEl.classList.add('phishnet-tooltip-trigger');

        const tooltipMsg = `Suspicious link: ${href.slice(0, 80)}`;
        linkEl.setAttribute('data-phishnet-tooltip', tooltipMsg);
        linkEl.setAttribute('data-tooltip', tooltipMsg);

        if (!linkEl.querySelector('.phishnet-link-warning')) {
          const warning = document.createElement('span');
          warning.className = 'phishnet-link-warning';
          warning.textContent = '⚠️';
          linkEl.appendChild(warning);
        }
      }
    });
  }

  /**
   * Ensure tooltip CSS is injected
   */
  function ensureTooltipStyles() {
    if (document.getElementById('phishnet-tooltip-styles')) return;

    const style = document.createElement('style');
    style.id = 'phishnet-tooltip-styles';
    style.textContent = `.phishnet-tooltip-trigger { position: relative; }`;
    (document.head || document.documentElement).appendChild(style);
  }

  /**
   * Handle incoming runtime messages
   */
  function handleMessage(message, sender, sendResponse) {
    if (!message || !message.type) return;

    switch (message.type) {
      case 'SCAN_CURRENT_EMAIL': {
        const selectors = currentSelectors?.selectors || {};
        const messageElements = document.querySelectorAll(selectors.messages || '[data-message-id]');
        if (messageElements.length > 0) {
          const latestEmail = messageElements[messageElements.length - 1];
          const emailId = 'manual-' + Date.now();
          scanEmail(latestEmail, emailId).then((result) => {
            if (result) {
              sendResponse({ success: true, result });
            } else {
              sendResponse({ success: false, error: 'Could not extract email content' });
            }
          }).catch((err) => {
            sendResponse({ success: false, error: err.message });
          });
        } else {
          sendResponse({ success: false, error: 'No opened email found on page' });
        }
        return true;
      }

      case 'SETTINGS_UPDATE':
        // Re-render badges against the new settings; the stored verdicts are
        // enough, so no inference is repeated.
        if (message.payload && typeof message.payload === 'object') {
          activeSettings = { ...activeSettings, ...message.payload };
        }
        rerenderAll();
        if (message.payload?.autoScan === true) {
          debouncedCheckForNewEmails(0);
        }
        break;

      case 'MODEL_STATUS':
        break;
    }
  }

  // Cleanup on unload
  /**
   * Tear down everything this script attached.
   *
   * Centralised so nothing is missed: the observer, the debounce timer, the
   * modal's document-level keydown handler, the runtime message listener and
   * the visibility listener all outlive this scope on an SPA navigation.
   */
  function teardown() {
    if (observer) {
      observer.disconnect();
      observer = null;
    }
    clearTimeout(scanDebounceTimer);
    scanDebounceTimer = null;
    scanDebounceStartedAt = 0;

    // The keydown listener lives on `document`, which outlives this script's
    // scope, so it must be removed explicitly.
    if (activeModalClose) {
      activeModalClose();
      activeModalClose = null;
    }

    if (messageListenerRegistered) {
      chrome.runtime.onMessage.removeListener(handleMessage);
      messageListenerRegistered = false;
    }

    document.removeEventListener('visibilitychange', onVisibilityChange);

    // A scan still in flight when the document goes away cannot report back.
    activeScans.clear();
    renderedResults.clear();
  }

  /**
   * Scan again when the tab becomes visible.
   *
   * The content script initialises at `document_idle`, which can be before a
   * single-page app has rendered its message list; the mutation observer
   * covers later inserts, but a tab that was simply hidden and restored needs
   * a sweep of its own.
   */
  function onVisibilityChange() {
    if (document.visibilityState !== 'visible') return;
    if (!currentSelectors) return;
    debouncedCheckForNewEmails();
  }

  window.addEventListener('beforeunload', teardown);

  // A sweep after init catches content that rendered between document_idle and
  // the first observer callback.
  window.addEventListener('load', () => {
    if (currentSelectors) checkForNewEmails();
  }, { once: true });

  // Initialize
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
