const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

/**
 * Build a content script context whose DOM is `count` message elements, each
 * with its own id. Returns the scan requests the script issued.
 */
function harness({ count, ids } = {}) {
  const scans = [];
  const callbacks = {};
  const listeners = new Set();

  // The loop needs the observer to fire again, exactly as a badge injection or
  // any other DOM write would retrigger it.
  let observerCallback = null;
  class MutationObserverMock {
    constructor(fn) { observerCallback = fn; }
    observe() {}
    disconnect() {}
  }

  // Each element carries enough text to pass the "too short to scan" gate.
  const elements = Array.from({ length: count }, (_, i) => {
    const id = ids ? ids[i] : `msg-${i}`;
    return {
      dataset: { messageId: id },
      // Long enough that scanEmail does not skip the message as too short.
      textContent: `Message ${id}: please verify your account by clicking the link below.`,
      querySelector: () => null,
      querySelectorAll: () => [],
      closest: () => null,
      getAttribute: () => null,
      cloneNode() { return this; }
    };
  });

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
      // getSelectorsForCurrentSite() defaults to window.location.
      location: { href: 'https://mail.google.com/mail/u/0/', hostname: 'mail.google.com' },
      addEventListener: (event, handler) => { callbacks[event] = handler; }
    },
    document: {
      readyState: 'loading',
      body: {},
      addEventListener: (event, handler) => { callbacks[event] = handler; },
      querySelector: () => null,
      querySelectorAll: (selector) => (selector === '[data-message-id]' ? elements : []),
      createElement: () => ({
        style: {},
        setAttribute() {},
        appendChild() {},
        addEventListener() {},
        remove() {}
      }),
      head: { appendChild() {} }
    },
    location: { href: 'https://mail.google.com/mail/u/0/' },
    MutationObserver: MutationObserverMock,
    chrome: {
      runtime: {
        onMessage: {
          addListener: (fn) => { listeners.add(fn); },
          removeListener: (fn) => listeners.delete(fn)
        },
        // The content script asks for settings before scanning; hand back the
        // defaults so a scan proceeds.
        sendMessage: async (message) => {
          if (message?.type === 'GET_SETTINGS') {
            return { autoScan: true, sensitivityThreshold: 0.7, highlightLinks: true, showTooltip: true };
          }
          if (message?.type === 'SCAN_EMAIL') {
            scans.push(message.payload?.emailId ?? null);
            return { success: true, result: { label: 'legitimate_email', confidence: 0.9 } };
          }
          return null;
        }
      },
      storage: {
        local: {
          get: (_keys, cb) => (cb ? cb({}) : Promise.resolve({})),
          set: (_values, cb) => (cb ? cb() : Promise.resolve())
        }
      }
    },
    setTimeout,
    clearTimeout,
    console
  };

  const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
  runInNewContext(source, context);

  return {
    scans,
    callbacks,
    elements,
    start() {
      callbacks.DOMContentLoaded();
    },
    /** Fire the MutationObserver as if the DOM changed again. */
    mutate() {
      if (observerCallback) observerCallback();
    }
  };
}

test('a short thread is scanned exactly once', async () => {
  const h = harness({ count: 5 });
  h.start();
  // Let the debounced observer pass and the async scan settle.
  await new Promise((r) => setTimeout(r, 1200));

  assert.equal(h.scans.length, 5, `expected 5 scans, saw ${h.scans.length}`);
  assert.equal(new Set(h.scans).size, 5, 'each message id scanned once');
});

test('a thread longer than the tracking cap settles instead of rescanning', async () => {
  // 51 elements against a cap of 50. Evicting during iteration dropped the id
  // that was about to be visited, so it was re-added and scanned in the same
  // pass; the badge injection then retriggered the observer and started the
  // cycle again.
  const h = harness({ count: 51 });
  h.start();
  await new Promise((r) => setTimeout(r, 800));

  // Badge injection mutates the DOM, which retriggers the observer. Each pass
  // used to find the evicted ids "new" again and rescan them.
  for (let pass = 0; pass < 3; pass++) {
    h.mutate();
    await new Promise((r) => setTimeout(r, 600));
  }

  // The exact number is not the point: the pass must terminate and no id may
  // be scanned twice. A loop would keep finding "new" ids and exceed this.
  const counts = new Map();
  for (const id of h.scans) counts.set(id, (counts.get(id) || 0) + 1);

  const duplicates = [...counts.entries()].filter(([, n]) => n > 1);
  assert.deepEqual(duplicates, [], `ids scanned more than once: ${JSON.stringify(duplicates)}`);
  assert.equal(h.scans.length, 51, `expected exactly 51 scans across 4 passes, saw ${h.scans.length}`);
});

test('an element whose id was evicted is not scanned again', async () => {
  // Two elements sharing one id: the second must be skipped rather than
  // re-queued, because the DOM node itself was already handled.
  const h = harness({ count: 2, ids: ['same-id', 'same-id'] });
  h.start();

  await new Promise((r) => setTimeout(r, 1200));

  assert.equal(h.scans.length, 1, `expected a single scan, saw ${h.scans.length}`);
});