/**
 * PhishNet Background Service Worker
 * Handles model loading, message routing, inference coordination, and whitelist management
 */

import logger from './utils/logger.js';
import { isSupportedMailTabSender, isSupportedMailTabUrl } from './utils/mail-urls.mjs';
import { DEFAULT_SETTINGS, normalizeStoredSettings, validateSettingsPatch } from './utils/settings-validation.mjs';
import { MAX_WHITELIST_ENTRIES, normalizeWhitelistEntry } from './utils/whitelist-entry.mjs';
import { checkSender } from './utils/message-auth.mjs';
import { broadcastToMailTabs } from './utils/mail-tab-broadcast.mjs';

// State
let offscreenDocumentCreated = false;
let modelStatus = 'loading'; // 'loading' | 'ready' | 'error'
let modelLoadProgress = 0;
let settings = normalizeStoredSettings(DEFAULT_SETTINGS);

function tabSettings() {
  const { whitelist, ...visible } = settings;
  return visible;
}

/**
 * The subset of settings the offscreen document actually reads.
 *
 * `runInference` used to forward the whole settings object, copying the
 * trusted-sender whitelist into the offscreen context on every scan even
 * though only the threshold is consulted there.
 */
function offscreenSettings() {
  return { sensitivityThreshold: settings.sensitivityThreshold };
}

function settingsForSender(sender) {
  return sender?.tab ? tabSettings() : settings;
}

function isTrustedSender(email, domain) {
  if (typeof email !== 'string' || typeof domain !== 'string' ||
      email.length > 320 || domain.length > 255) return false;
  const normalizedEmail = email.trim().toLowerCase();
  const normalizedDomain = domain.trim().toLowerCase();
  return settings.whitelist.some(entry => {
    if (typeof entry !== 'string') return false;
    const item = entry.toLowerCase().trim();
    return item && (item === normalizedEmail || item === normalizedDomain ||
      normalizedEmail.endsWith('@' + item));
  });
}

const pendingInferenceCallbacks = new Map();

// Reject oversized scan messages before copying them to the offscreen document.
// The model only needs `text`; the remaining fields are checked because content
// scripts legitimately include them in SCAN_EMAIL messages.
const MAX_SCAN_TEXT = 32768;
const MAX_SCAN_SUBJECT = 1024;
const MAX_SCAN_LINKS = 128;
const MAX_SCAN_ATTACHMENTS = 64;
const MAX_SCAN_LINK_FIELD = 4096;
const MAX_SCAN_ATTACHMENT_FIELD = 1024;

function validScanPayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return false;
  const fitsText = (value, limit) => value === undefined ||
    (typeof value === 'string' && value.length <= limit);
  if (typeof payload.text !== 'string' || payload.text.length > MAX_SCAN_TEXT ||
      !fitsText(payload.subject, MAX_SCAN_SUBJECT) ||
      !fitsText(payload.body, MAX_SCAN_TEXT)) return false;
  if (payload.hasFormElements !== undefined && typeof payload.hasFormElements !== 'boolean') return false;

  if (payload.links !== undefined) {
    if (!Array.isArray(payload.links) || payload.links.length > MAX_SCAN_LINKS) return false;
    if (!payload.links.every(link => link && typeof link === 'object' &&
      fitsText(link.href, MAX_SCAN_LINK_FIELD) &&
      fitsText(link.text, MAX_SCAN_LINK_FIELD))) return false;
  }
  if (payload.attachments !== undefined) {
    if (!Array.isArray(payload.attachments) || payload.attachments.length > MAX_SCAN_ATTACHMENTS) return false;
    if (!payload.attachments.every(att => typeof att === 'string'
      ? att.length <= MAX_SCAN_ATTACHMENT_FIELD
      : att && typeof att === 'object' &&
        fitsText(att.name, MAX_SCAN_ATTACHMENT_FIELD) &&
        fitsText(att.size, MAX_SCAN_ATTACHMENT_FIELD) &&
        fitsText(att.type, MAX_SCAN_ATTACHMENT_FIELD))) return false;
  }
  if (payload.sender !== undefined && (payload.sender === null ||
      typeof payload.sender !== 'object' || Array.isArray(payload.sender) ||
      !['name', 'email', 'domain'].every(key => fitsText(payload.sender[key], MAX_SCAN_SUBJECT)))) {
    return false;
  }
  return true;
}

/**
 * Initialize background service worker
 */
async function init() {
  logger.debug('Background service worker starting');

  // Load settings from storage
  await loadSettings();

  // Create offscreen document for model inference
  await createOffscreenDocument();

  // Notify tabs of model status
  broadcastModelStatus();
}

/**
 * Load non-sensitive preferences from sync and trusted senders from local.
 * Migrate and remove whitelists saved by earlier versions in sync storage.
 */
async function loadSettings() {
  return new Promise((resolve) => {
    chrome.storage.sync.get([
      'autoScan',
      'sensitivityThreshold',
      'highlightLinks',
      'showTooltip',
      'theme',
      'whitelist' // Read only to migrate and delete legacy synced data.
    ], (synced) => {
      chrome.storage.local.get('whitelist', (local) => {
        // Prefer the local-only list (including a malformed one) over stale
        // synced data, then validate all preferences before exposing them.
        const hasLocalWhitelist = local?.whitelist !== undefined;
        settings = normalizeStoredSettings({
          ...synced,
          ...(hasLocalWhitelist ? { whitelist: local.whitelist } : {})
        });

        if (Object.hasOwn(synced ?? {}, 'whitelist')) {
          // Local data takes precedence. Delete the old synced copy only
          // after the chosen whitelist has been written locally.
          chrome.storage.local.set({ whitelist: settings.whitelist }, () => {
            chrome.storage.sync.remove('whitelist', () => resolve(settings));
          });
        } else {
          resolve(settings);
        }
      });
    });
  });
}

/**
 * Persist the trusted-sender whitelist locally, never in synced settings.
 *
 * Every callback checks `chrome.runtime.lastError`: the promise used to resolve
 * with the in-memory settings regardless, so a failed write left the caller
 * believing a setting was saved when it would revert on the next load.
 */
async function saveSettings(newSettings) {
  settings = { ...settings, ...newSettings };
  const { whitelist, ...syncedSettings } = settings;
  return new Promise((resolve, reject) => {
    chrome.storage.local.set({ whitelist }, () => {
      const localError = chrome.runtime.lastError;
      if (localError) {
        reject(new Error(`Could not save the whitelist: ${localError.message}`));
        return;
      }
      chrome.storage.sync.set(syncedSettings, () => {
        const syncError = chrome.runtime.lastError;
        if (syncError) {
          reject(new Error(`Could not save settings: ${syncError.message}`));
          return;
        }
        // Also clean up any whitelist synced by an older extension version.
        chrome.storage.sync.remove('whitelist', () => {
          // A leftover synced whitelist is a migration nuisance, not a failed
          // save: the settings themselves are already durable.
          if (chrome.runtime.lastError) {
            logger.debug('Could not remove legacy synced whitelist:',
              chrome.runtime.lastError.message);
          }
          resolve(settings);
        });
      });
    });
  });
}

/**
 * Create offscreen document for model inference
 */
async function createOffscreenDocument() {
  try {
    if (chrome.offscreen && typeof chrome.offscreen.hasDocument === 'function') {
      const hasDoc = await chrome.offscreen.hasDocument();
      if (hasDoc) {
        offscreenDocumentCreated = true;
        logger.debug('Offscreen document already exists (hasDocument)');
        return;
      }
    } else if (self.clients && typeof self.clients.matchAll === 'function') {
      const clients = await self.clients.matchAll();
      const existing = clients.find(c => c.url.includes('offscreen.html'));
      if (existing) {
        offscreenDocumentCreated = true;
        logger.debug('Offscreen document already exists (clients.matchAll)');
        return;
      }
    }

    if (offscreenDocumentCreated) return;

    await chrome.offscreen.createDocument({
      url: chrome.runtime.getURL('public/offscreen.html'),
      reasons: ['LOCAL_STORAGE', 'WORKERS'],
      justification: 'Run Transformers.js model inference in isolated context'
    });

    offscreenDocumentCreated = true;
    logger.debug('Offscreen document created');

  } catch (error) {
    if (error.message && error.message.includes('Only a single offscreen document may be created')) {
      offscreenDocumentCreated = true;
      return;
    }
    logger.error('Failed to create offscreen document:', error);
    modelStatus = 'error';
    broadcastModelStatus({ error: error.message });
  }
}

/**
 * Single unified message dispatcher.
 *
 * `chrome.runtime.sendMessage` reaches every extension context at once, so the
 * sender is checked before the message is routed. Rules live in
 * `message-auth.mjs`; see there for why each group is separated.
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || !message.type) return false;

  const allowed = checkSender(message.type, sender, chrome.runtime?.id, isSupportedMailTabSender);
  if (!allowed.ok) {
    logger.debug(`Rejected ${message.type}: ${allowed.error}`);
    sendResponse({ success: false, error: allowed.error });
    return false;
  }

  handleIncomingMessage(message, sender)
    .then((result) => {
      sendResponse(result);
    })
    .catch((err) => {
      sendResponse({ success: false, error: err.message });
    });

  return true; // Keep channel open for async response
});

/**
 * Route incoming message to appropriate handler
 */
async function handleIncomingMessage(message, sender) {
  switch (message.type) {
    // Content script / tab messages
    case 'CONTENT_READY':
      return { modelStatus, settings: settingsForSender(sender) };

    case 'SCAN_EMAIL':
      if (!validScanPayload(message.payload)) {
        return { success: false, error: 'Scan payload is invalid or too large' };
      }
      if (modelStatus !== 'ready') {
        logger.debug('Model not ready, returning useHeuristic signal');
        return { success: false, error: 'Model not ready', useHeuristic: true };
      }

      try {
        // Forward the sender, links and form signal the model's reason generation needs, but
        // nothing else: the body, subject, attachments, and any other field
        // stay out of the offscreen document. Both are already bounded by
        // validScanPayload above.
        const payload = { text: message.payload.text };
        if (message.payload.sender !== undefined) payload.sender = message.payload.sender;
        if (message.payload.links !== undefined) payload.links = message.payload.links;
        if (message.payload.hasFormElements === true) payload.hasFormElements = true;
        const result = await runInference(payload);
        return { success: true, result };
      } catch (error) {
        logger.error('Inference error:', error);
        return { success: false, error: error.message, useHeuristic: true };
      }

    case 'GET_SETTINGS':
      return settingsForSender(sender);

    case 'CHECK_TRUSTED_SENDER':
      return { trusted: isTrustedSender(message.email, message.domain) };

    case 'GET_MODEL_STATUS':
      return { status: modelStatus, progress: modelLoadProgress };

    // Popup messages
    case 'GET_STATUS':
      return { modelStatus, progress: modelLoadProgress, settings: settingsForSender(sender) };

    case 'UPDATE_SETTINGS':
      {
        const error = validateSettingsPatch(message.settings);
        if (error) return { success: false, error };
      }
      await saveSettings(message.settings);
      broadcastSettingsUpdate();
      return { success: true, settings: settingsForSender(sender) };

    case 'ADD_WHITELIST': {
      const entry = normalizeWhitelistEntry(message.entry);
      if (!entry.ok) return { success: false, error: entry.error };
      if (settings.whitelist.length >= MAX_WHITELIST_ENTRIES &&
          !settings.whitelist.includes(entry.value)) {
        return { success: false, error: `Whitelist cannot exceed ${MAX_WHITELIST_ENTRIES} entries` };
      }
      if (!settings.whitelist.includes(entry.value)) {
        settings.whitelist.push(entry.value);
        await saveSettings({ whitelist: settings.whitelist });
        broadcastSettingsUpdate();
      }
      return sender?.tab ? { success: true } : { success: true, whitelist: settings.whitelist };
    }

    case 'REMOVE_WHITELIST': {
      const entry = normalizeWhitelistEntry(message.entry);
      // An entry that is no longer valid cannot be in a validated list, but it
      // may still be in storage from an older version; drop it by its raw form.
      const raw = typeof message.entry === 'string' ? message.entry.trim().toLowerCase() : '';
      if (!entry.ok && !raw) return { success: false, error: entry.error };
      settings.whitelist = settings.whitelist.filter(w => w !== (entry.ok ? entry.value : raw));
      await saveSettings({ whitelist: settings.whitelist });
      broadcastSettingsUpdate();
      return sender?.tab ? { success: true } : { success: true, whitelist: settings.whitelist };
    }

    case 'CLEAR_HISTORY': {
      if (chrome.storage?.local) {
        // Clear all locally cached scan data (including future cache keys),
        // but preserve the local-only trusted-sender preference.
        const localData = await chrome.storage.local.get(null);
        const historyKeys = Object.keys(localData).filter(key => key !== 'whitelist');
        if (historyKeys.length) await chrome.storage.local.remove(historyKeys);
      }
      return { success: true };
    }

    case 'SCAN_CURRENT_TAB': {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs.length > 0 && tabs[0].id) {
        if (!isSupportedMailTabUrl(tabs[0].url)) {
          return { success: false, error: 'Open Gmail or Outlook to scan an email.' };
        }
        return new Promise((resolve) => {
          chrome.tabs.sendMessage(tabs[0].id, { type: 'SCAN_CURRENT_EMAIL' }, (response) => {
            if (chrome.runtime.lastError) {
              resolve({ success: false, error: 'Cannot connect to email tab. Refresh the page.' });
            } else {
              resolve(response || { success: false, error: 'No response from page' });
            }
          });
        });
      }
      return { success: false, error: 'No active tab found' };
    }

    case 'RELOAD_MODEL': {
      modelStatus = 'loading';
      modelLoadProgress = 0;
      broadcastModelStatus();
      // Close the existing offscreen document so a fresh one re-runs init().
      // On Chrome 109-149, hasDocument() may still report true immediately after
      // closeDocument() because teardown is async. Wait for the document to be
      // fully gone before creating a new one; otherwise createOffscreenDocument()
      // bails early thinking one still exists and the reload is a no-op.
      try {
        if (chrome.offscreen?.closeDocument && await chrome.offscreen.hasDocument()) {
          await chrome.offscreen.closeDocument();
          for (let i = 0; i < 50; i++) {
            if (!(await chrome.offscreen.hasDocument())) break;
            await new Promise((r) => setTimeout(r, 100));
          }
        }
      } catch (e) {
        logger.debug('closeDocument during reload:', e?.message);
      }
      offscreenDocumentCreated = false;
      await createOffscreenDocument();
      return { success: true, status: modelStatus };
    }

    // Offscreen document lifecycle messages
    case 'OFFSCREEN_READY':
      modelStatus = 'ready';
      modelLoadProgress = 100;
      broadcastModelStatus();
      return { success: true };

    case 'OFFSCREEN_ERROR':
      modelStatus = 'error';
      broadcastModelStatus({ error: message.error });
      return { success: true };

    case 'MODEL_LOAD_PROGRESS':
      modelLoadProgress = message.progress || 0;
      broadcastModelStatus({ progress: modelLoadProgress, message: message.message });
      return { success: true };

    case 'INFERENCE_RESULT':
      if (pendingInferenceCallbacks.has(message.requestId)) {
        const { resolve } = pendingInferenceCallbacks.get(message.requestId);
        pendingInferenceCallbacks.delete(message.requestId);
        resolve(message.result);
      }
      return { success: true };

    case 'INFERENCE_ERROR':
      if (pendingInferenceCallbacks.has(message.requestId)) {
        const { reject } = pendingInferenceCallbacks.get(message.requestId);
        pendingInferenceCallbacks.delete(message.requestId);
        reject(new Error(message.error));
      }
      return { success: true };

    default:
      return { success: false, error: `Unknown message type: ${message.type}` };
  }
}

/**
 * Run inference via offscreen document with timeout handling
 */
function runInference(emailData) {
  return new Promise((resolve, reject) => {
    const requestId = crypto.randomUUID();

    const timer = setTimeout(() => {
      if (pendingInferenceCallbacks.has(requestId)) {
        pendingInferenceCallbacks.delete(requestId);
        reject(new Error('Inference timeout (15s limit exceeded)'));
      }
    }, 15000);

    pendingInferenceCallbacks.set(requestId, {
      resolve: (val) => {
        clearTimeout(timer);
        resolve(val);
      },
      reject: (err) => {
        clearTimeout(timer);
        reject(err);
      }
    });

    // Send payload to offscreen document.
    //
    // Wrapped in a promise chain rather than calling `.catch` on the result:
    // sendMessage can throw synchronously when the context is invalidated or
    // the API is absent, and the executor would throw before any .catch was
    // attached, leaving the pending entry and its 15s timer to expire on their
    // own and report a misleading timeout.
    Promise.resolve()
      .then(() => chrome.runtime.sendMessage({
        type: 'RUN_INFERENCE',
        requestId,
        payload: emailData,
        // Only the fields reason generation reads. The trusted-sender
        // whitelist is never used offscreen and must not cross contexts.
        settings: offscreenSettings()
      }))
      .catch((err) => {
        clearTimeout(timer);
        pendingInferenceCallbacks.delete(requestId);
        reject(err);
      });
  });
}

/**
 * Broadcast settings update to all tabs
 */
/**
 * Broadcast settings to the tabs that have the content script.
 *
 * Only mail tabs are targeted: a message to every tab is dropped everywhere
 * else, and the tab list grows with the user's browsing.
 */
function broadcastSettingsUpdate() {
  broadcastToMailTabs(
    {
      query: (q) => chrome.tabs.query(q),
      send: (tabId, msg) => chrome.tabs.sendMessage(tabId, msg)
    },
    { type: 'SETTINGS_UPDATE', payload: tabSettings() }
  ).catch((err) => logger.debug('Settings broadcast failed:', err?.message));
}

/**
 * Broadcast model status to all tabs
 */
function broadcastModelStatus(extra = {}) {
  broadcastToMailTabs(
    {
      query: (q) => chrome.tabs.query(q),
      send: (tabId, msg) => chrome.tabs.sendMessage(tabId, msg)
    },
    { type: 'MODEL_STATUS', payload: { status: modelStatus, progress: modelLoadProgress, ...extra } }
  ).catch((err) => logger.debug('Status broadcast failed:', err?.message));
}

// Lifecycle events
chrome.runtime.onInstalled.addListener(async (details) => {
  logger.debug('Extension installed/updated:', details.reason);
  if (details.reason === 'install') {
    await saveSettings(settings);
  }
  initOnce();
});

chrome.runtime.onStartup.addListener(() => {
  logger.debug('Browser startup');
  initOnce();
});

// Guard against double-init (top-level + onInstalled/onStartup firing together)
let initPromise = null;
function initOnce() {
  if (!initPromise) {
    initPromise = init().catch((e) => {
      logger.error('Background init failed:', e);
      initPromise = null; // Allow retry on next wake
    });
  }
  return initPromise;
}

// Initialize on background start
initOnce();
