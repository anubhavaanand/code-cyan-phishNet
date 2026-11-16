const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

/**
 * The content script downgrades a phishing verdict to `uncertain` when its
 * confidence is below the user's threshold. The bug was that the guard tested
 * `label === 'phishing_email'`, so a `phishing_url` verdict bypassed it.
 *
 * These tests drive the real scan path with a stubbed classifier so the label
 * and confidence are controlled directly.
 */
function harness({ label, confidence, threshold = 0.7, messageText = 'Please verify your account immediately by clicking the link below now.' }) {
  const callbacks = {};
  const scans = [];

  class MutationObserverMock {
    observe() {}
    disconnect() {}
  }

  const insertParent = {
    children: [],
    insertBefore(node) { this.children.push(node); node.parentNode = this; return node; }
  };
  const insertPoint = { parentNode: insertParent, nextSibling: null };

  const message = {
    dataset: { messageId: 'msg-0' },
    textContent: messageText,
    querySelector(selector) {
      if (selector === '.phishnet-badge' || selector === 'form, input, select, textarea') return null;
      return insertPoint;
    },
    querySelectorAll: () => [],
    closest: () => null,
    getAttribute: () => null,
    cloneNode() { return this; }
  };

  const documentMock = {
    readyState: 'loading',
    body: { appendChild() {} },
    documentElement: { appendChild() {} },
    head: { appendChild() {} },
    querySelector: () => null,
    querySelectorAll: (selector) => (selector === '[data-message-id]' ? [message] : []),
    getElementById: () => null,
    createElement: () => ({
      style: {},
      dataset: {},
      children: [],
      setAttribute() {},
      appendChild(child) { this.children.push(child); return child; },
      addEventListener() {},
      remove() {}
    }),
    addEventListener: (event, handler) => { callbacks[`document:${event}`] = handler; },
    removeEventListener() {}
  };

  const context = {
    globalThis: {
      PhishNet: {
        getSelectorsForCurrentSite: () => ({
          provider: 'gmail',
          variant: 'default',
          selectors: { messages: '[data-message-id]', sender: '.sender' }
        }),
        // The classifier's verdict. Content.js overlays this onto the heuristic.
        heuristicDetect: () => ({
          label: 'legitimate_email', confidence: 0.99, reasons: [], links: [], attachments: []
        }),
        isUrlSuspicious: () => ({ suspicious: false, reason: '' }),
        safeText: (el, max = 3000) => String(el?.textContent || '').trim().slice(0, max),
        safeAttr: () => '',
        safeQuery: () => null,
        logger: { debug() {}, log() {}, warn() {}, error() {} }
      }
    },
    window: {
      location: { href: 'https://mail.google.com/mail/u/0/', hostname: 'mail.google.com' },
      addEventListener: (event, handler) => { callbacks[`window:${event}`] = handler; }
    },
    document: documentMock,
    location: { href: 'https://mail.google.com/mail/u/0/' },
    MutationObserver: MutationObserverMock,
    chrome: {
      runtime: {
        onMessage: { addListener() {}, removeListener() {} },
        sendMessage: async (message) => {
          if (message?.type === 'GET_SETTINGS') {
            return {
              autoScan: true,
              sensitivityThreshold: threshold,
              highlightLinks: false,
              showTooltip: true
            };
          }
          if (message?.type === 'SCAN_EMAIL') {
            scans.push(message.payload?.emailId);
            // The background worker's answer: the model's verdict.
            return { success: true, result: { label, confidence, reasons: [], allScores: {} } };
          }
          return null;
        }
      },
      storage: {
        local: {
          get: (_k, cb) => (cb ? cb({}) : Promise.resolve({})),
          set: (_v, cb) => (cb ? cb() : Promise.resolve())
        }
      }
    },
    setTimeout,
    clearTimeout,
    Date,
    console: { log() {}, debug() {}, warn() {}, error() {} }
  };

  const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
  runInNewContext(source, context);

  return {
    scans,
    callbacks,
    /** Boot and return the verdict the scan produced. */
    async scan() {
      callbacks['document:DOMContentLoaded']?.();
      await new Promise((r) => setTimeout(r, 400));
      const badge = insertParent.children.find((c) => String(c.className).includes('phishnet-badge'));
      // The badge carries the final label; data attributes are not enough to
      // tell phishing_email from phishing_url, so read the class list.
      return {
        badge,
        className: badge ? String(badge.className) : null,
        label: badge ? badge.getAttribute?.('data-verdict') : null
      };
    }
  };
}

/** The verdict recorded by the scan, recovered from the injected badge class. */
function verdictClass(result) {
  return /phishnet-badge--(phishing|safe|trusted|uncertain)/.exec(result.className || '')?.[1] || null;
}

test('a phishing_email verdict below the threshold becomes uncertain', async () => {
  const h = harness({ label: 'phishing_email', confidence: 0.5 });
  const result = await h.scan();
  assert.equal(verdictClass(result), 'uncertain');
});

test('a phishing_url verdict below the threshold also becomes uncertain', async () => {
  // The bug: only phishing_email was downgraded, so phishing_url bypassed the
  // user's threshold entirely.
  const h = harness({ label: 'phishing_url', confidence: 0.5 });
  const result = await h.scan();
  assert.equal(verdictClass(result), 'uncertain');
});

test('a phishing verdict at or above the threshold is kept', async () => {
  for (const label of ['phishing_email', 'phishing_url']) {
    const h = harness({ label, confidence: 0.9 });
    const result = await h.scan();
    assert.equal(verdictClass(result), 'phishing', `${label} at 90% must survive a 70% threshold`);
  }
});

test('a non-phishing verdict is never downgraded', async () => {
  for (const label of ['legitimate_email', 'legitimate_url']) {
    const h = harness({ label, confidence: 0.1 });
    const result = await h.scan();
    assert.equal(verdictClass(result), 'safe', `${label} must not be relabelled`);
  }
});

test('the threshold is inclusive at the boundary', async () => {
  // confidence === threshold must not be downgraded: the comparison is `<`.
  const h = harness({ label: 'phishing_url', confidence: 0.7, threshold: 0.7 });
  const result = await h.scan();
  assert.equal(verdictClass(result), 'phishing');
});

test('a short phishing message still reaches inference', async () => {
  const h = harness({ label: 'phishing_email', confidence: 0.95, messageText: 'Verify now' });
  const result = await h.scan();
  assert.deepEqual(h.scans, ['msg-0']);
  assert.equal(verdictClass(result), 'phishing');
});

test('an empty message with no subject, sender, link or attachment is skipped', async () => {
  const h = harness({ label: 'phishing_email', confidence: 0.95, messageText: '' });
  await h.scan();
  assert.equal(h.scans.length, 0);
});
