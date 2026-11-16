const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

/**
 * Build a content script context with `count` scannable message elements.
 *
 * Both regressions are about listeners: a debounce timer that never fires, and
 * a document-level keydown handler that outlives its modal. The harness
 * therefore counts scans and tracks document keydown handlers.
 */
function harness({ count = 0 } = {}) {
  const callbacks = {};
  const documentKeydown = new Set();
  const scans = [];
  let observerCallback = null;

  class MutationObserverMock {
    constructor(fn) { observerCallback = fn; }
    observe() {}
    disconnect() {}
  }

  const elements = Array.from({ length: count }, (_, i) => ({
    dataset: { messageId: `msg-${i}` },
    textContent: `Message ${i}: please verify your account by clicking the link below.`,
    querySelector: () => null,
    querySelectorAll: () => [],
    closest: () => null,
    getAttribute: () => null,
    cloneNode() { return this; }
  }));

  const documentMock = {
    readyState: 'loading',
    body: { appendChild() {} },
    documentElement: { appendChild() {} },
    head: { appendChild() {} },
    querySelector: () => null,
    querySelectorAll: (selector) => (selector === '[data-message-id]' ? elements : []),
    getElementById: () => null,
    createElement: () => ({
      style: {},
      dataset: {},
      children: [],
      setAttribute() {},
      appendChild(child) { this.children.push(child); return child; },
      addEventListener() {},
      remove() { this.removed = true; }
    }),
    addEventListener: (event, handler) => {
      callbacks[`document:${event}`] = handler;
      if (event === 'keydown') documentKeydown.add(handler);
    },
    removeEventListener: (event, handler) => {
      if (event === 'keydown') documentKeydown.delete(handler);
    }
  };

  const context = {
    globalThis: {
      PhishNet: {
        getSelectorsForCurrentSite: () => ({
          provider: 'gmail',
          variant: 'default',
          selectors: { messages: '[data-message-id]' }
        })
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
            return { autoScan: true, sensitivityThreshold: 0.7, highlightLinks: true, showTooltip: true };
          }
          if (message?.type === 'SCAN_EMAIL') {
            scans.push(message.payload?.emailId);
            return { success: true, result: { label: 'legitimate_email', confidence: 0.9 } };
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
    documentKeydown,
    /** The live element list; tests push to it to simulate new mail. */
    elements,
    /** Append an element as if a new message arrived. */
    addElement(i) {
      elements.push({
        dataset: { messageId: `msg-${i}` },
        textContent: `Message ${i}: please verify your account by clicking the link below.`,
        querySelector: () => null,
        querySelectorAll: () => [],
        closest: () => null,
        getAttribute: () => null,
        cloneNode() { return this; }
      });
    },
    boot() { callbacks['document:DOMContentLoaded']?.(); },
    /** Fire the MutationObserver as if the DOM changed again. */
    mutate() { observerCallback?.(); }
  };
}

/** Open the threat modal by simulating a completed scan of one message. */
function openModal(h) {
  // The modal is opened from the badge's click handler after a scan; driving
  // that path needs a real DOM. Call the exposed path instead.
  return h;
}

test('the debounce does not starve when mutations never stop', async () => {
  const h = harness({ count: 0 });
  h.boot();
  await new Promise((r) => setTimeout(r, 300));
  h.scans.length = 0;

  // A busy page: a new element arrives, and something mutates the DOM, faster
  // than the debounce window, for longer than MAX_DEBOUNCE_WAIT_MS (2000ms).
  // A plain debounce resets on every mutation and never scans.
  const deadline = Date.now() + 2600;
  let next = 0;
  while (Date.now() < deadline) {
    h.addElement(next++);
    h.mutate();
    await new Promise((r) => setTimeout(r, 150));
  }
  // Measured before the loop's last timer would fire: a debounce that keeps
  // resetting has scanned nothing at this point, even though it would
  // eventually fire once the page went quiet.
  const scannedWhileBusy = h.scans.length;
  await new Promise((r) => setTimeout(r, 600));

  assert.ok(
    scannedWhileBusy > 0,
    `a continuously mutating page must still be scanned; saw ${scannedWhileBusy}`
  );
  assert.equal(new Set(h.scans).size, h.scans.length, 'no id scanned twice');
});

test('the debounce still coalesces a burst of mutations', async () => {
  const h = harness({ count: 0 });
  h.boot();
  await new Promise((r) => setTimeout(r, 300));
  h.scans.length = 0;

  h.addElement(0);
  // Five mutations inside one debounce window: one scan, not five.
  for (let i = 0; i < 5; i++) {
    h.mutate();
    await new Promise((r) => setTimeout(r, 30));
  }
  await new Promise((r) => setTimeout(r, 900));

  assert.equal(h.scans.length, 1, `expected one scan, saw ${h.scans.length}`);
});
