/**
 * CSS Selectors for Gmail and Outlook email extraction
 * Adapted from inbox-triage-extension with PhishNet-specific additions
 */

(function () {
  'use strict';

  const root = typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this);

  const EMAIL_SELECTORS = {
    gmail: {
      // Individual email messages within thread
      messages: '[data-message-id]',

      // Email content areas
      messageBody: '[data-message-id] .ii.gt div',
      messageBodyAlt: '[data-message-id] .a3s.aiL',
      messageBodyFallback: '[data-message-id] .gs',

      // Subject line
      subject: 'h2[data-thread-id] span',
      subjectAlt: '[data-legacy-thread-id] h2 span',
      subjectFallback: 'h2.hP',

      // Sender information
      sender: '[data-message-id] .go span[email]',
      senderName: '[data-message-id] .go .qu span[title]',
      senderFallback: '[data-message-id] .gD[email]',

      // Attachment selectors
      attachments: '[data-message-id] .aZo, [data-message-id] span[download_url]',
      attachmentNames: '[data-message-id] .aV3, [data-message-id] .aZo span[title]',
      attachmentSizes: '[data-message-id] .SaRA, [data-message-id] .aZo .SaRBLe',

      // Link selectors for phishing detection
      links: '[data-message-id] a[href]'    },

    outlook: {
      // Individual messages
      messages: '[data-convid] [role="listitem"]',

      // Message content
      messageBody: '[data-testid="message-body-content"]',
      messageBodyAlt: '.rps_1679 .elementToProof',
      messageBodyFallback: '[data-testid="message-body"] .allowTextSelection',

      // Subject
      subject: '[data-testid="conversation-subject"]',
      subjectAlt: 'h1[id*="subject"]',
      subjectFallback: '[data-testid="subject"]',

      // Sender information
      sender: '[data-testid="message-header-sender-name"]',
      senderEmail: '[data-testid="message-header-sender-email"]',
      senderFallback: '[data-testid="from"]',

      // Attachment selectors
      attachments: '[data-testid*="attachment"]',
      attachmentNames: '[data-testid="attachment-name"]',
      attachmentSizes: '[data-testid="attachment-size"]',

      // Link selectors for phishing detection
      links: '[data-convid] a[href]'    },

    // Outlook.com specific selectors (personal Outlook)
    outlookCom: {
      messages: '[data-convid] [role="listitem"]',
      messageBody: '[data-testid="message-body-content"]',
      messageBodyAlt: '[data-testid="message-body"] .allowTextSelection',
      messageBodyFallback: '.allowTextSelection',
      subject: '[data-testid="conversation-subject"]',
      subjectAlt: 'h1[data-testid="subject"]',
      sender: '[data-testid="message-header-sender-name"]',
      senderEmail: '[data-testid="message-header-sender-email"]',
      attachments: '[data-testid*="attachment"]',
      attachmentNames: '[data-testid="attachment-name"]',
      attachmentSizes: '[data-testid="attachment-size"]',
      links: '[data-convid] a[href]',
    },

    // Outlook Office 365 specific selectors (business/enterprise Outlook)
    outlookOffice365: {
      messages: '[data-convid] [role="listitem"]',
      messageBody: '[data-testid="message-body-content"]',
      messageBodyAlt: '[aria-label*="Message body"] .allowTextSelection',
      messageBodyFallback: '.allowTextSelection',
      subject: '[data-testid="conversation-subject"]',
      subjectAlt: '[id*="subject"]',
      sender: '[data-testid="message-header-sender-name"]',
      senderEmail: '[data-testid="message-header-sender-email"]',
      attachments: '[data-testid*="attachment"]',
      attachmentNames: '[data-testid="attachment-name"]',
      attachmentSizes: '[data-testid="attachment-size"]',
      links: '[data-convid] a[href]',
    }
  };

  /**
   * Get the appropriate selectors for the current email provider
   * Enhanced to detect Outlook version variations
   */
  function getSelectorsForCurrentSite(currentLocation = (typeof window !== 'undefined' ? window.location : null)) {
    if (!currentLocation) {
      return null;
    }
    const hostname = currentLocation.hostname || '';
    const url = currentLocation.href || '';

    if (hostname.includes('mail.google.com')) {
      return { provider: 'gmail', variant: 'standard', selectors: EMAIL_SELECTORS.gmail };
    } else if (hostname.includes('outlook.') || hostname.includes('office.com') || hostname.includes('office365.com')) {
      // Check personal Outlook first
      if (hostname.includes('outlook.live.com') || hostname.includes('outlook.com')) {
        return { provider: 'outlook', variant: 'com', selectors: EMAIL_SELECTORS.outlookCom };
      } else if (hostname.includes('outlook.office.com') ||
                 hostname.includes('outlook.office365.com') ||
                 url.includes('/owa/')) {
        return { provider: 'outlook', variant: 'office365', selectors: EMAIL_SELECTORS.outlookOffice365 };
      } else {
        return { provider: 'outlook', variant: 'default', selectors: EMAIL_SELECTORS.outlook };
      }
    }

    return null;
  }

  /**
   * Additional utility selectors
   */
  const UTILITY_SELECTORS = {
    // Common patterns for avoiding extraction of certain elements
    skipElements: [
      '[data-is-draft="true"]',
      '.compose',
      '.reply-box',
      '[data-testid*="compose"]',
      '.gmail_signature',
      '.signature',
      '[data-smartmail="signature"]',
      '.yj6qo', // Gmail signature class
      '.adn.ads' // Gmail ads
    ],

    // Phishing indicator keywords (for reason generation)
    phishingKeywords: [
      'urgent', 'immediate', 'verify', 'account', 'suspend', 'locked',
      'click here', 'confirm', 'update', 'security', 'unauthorized',
      'limited time', 'act now', 'expire', 'password', 'credential',
      'bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google',
      'invoice', 'receipt', 'order', 'shipment', 'delivery',
      'refund', 'tax', 'irs', 'government', 'legal', 'court'
    ],

    // Suspicious TLDs and URL shorteners come from src/utils/threat-lists.js,
    // which loads first. They used to be duplicated here and had drifted from
    // the detector's copy.
    ...(root.PhishNet?.THREAT_LISTS || {})
  };

  // Expose globally for use in content script
  root.PhishNet = root.PhishNet || {};
  root.PhishNet.getSelectorsForCurrentSite = getSelectorsForCurrentSite;
  root.PhishNet.EMAIL_SELECTORS = EMAIL_SELECTORS;
  root.PhishNet.UTILITY_SELECTORS = UTILITY_SELECTORS;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { getSelectorsForCurrentSite, EMAIL_SELECTORS, UTILITY_SELECTORS };
  }
})();
