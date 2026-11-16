const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

/**
 * Content script harness that can complete a scan and open the threat modal.
 *
 * The leak under test is a document-level keydown listener that survives its
 * modal, so the harness counts those and can click the injected badge.
 */
function harness() {
  const callbacks = {};
  const documentKeydown = new Set();
  const created = [];

  /** A node the modal builder can append children to. */
  function makeNode(tag) {
    return {
      tag,
      style: {},
      dataset: {},
      children: [],
      parentNode: null,
      _handlers: {},
      setAttribute() {},
      getAttribute: () => null,
      appendChild(child) { this.children.push(child); child.parentNode = this; return child; },
      insertBefore(node) { this.children.push(node); node.parentNode = this; return node; },
      addEventListener(type, handler) { (this._handlers[type] ||= []).push(handler); },
      removeEventListener(type, handler) {
        const list = this._handlers[type] || [];
        const i = list.indexOf(handler);
        if (i >= 0) list.splice(i, 1);
      },
      remove() { this.removed = true; },
      fire(type, event = {}) { for (const fn of this._handlers[type] || []) fn(event); }
    };
  }

  // The badge needs an insertion point with a parent.
  const insertParent = makeNode('div');
  const insertPoint = makeNode('div');
  insertPoint.parentNode = insertParent;

  const message = {
    dataset: { messageId: 'msg-0' },
    textContent: 'Please verify your account immediately by clicking the link below now.',
    querySelector(selector) {
      if (selector === '.phishnet-badge') return null;
      return insertPoint;
    },
    querySelectorAll: () => [],
    closest: () => null,
    getAttribute: () => null,
    nextSibling: null,
    cloneNode() { return this; }
  };

  const documentMock = {
    readyState: 'loading',
    body: makeNode('body'),
    documentElement: makeNode('html'),
    head: makeNode('head'),
    querySelector: () => null,
    querySelectorAll: (selector) => (selector === '[data-message-id]' ? [message] : []),
    getElementById: (id) => created.find((n) => n.id === id) || null,
    createElement: (tag) => {
      const node = makeNode(tag);
      created.push(node);
      return node;
    },
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
          selectors: {
            messages: '[data-message-id]',
            sender: '.sender',
            senderEmail: '[email]',
            subject: 'h2'
          }
        }),
        // The real implementations come from utils/heuristic-detector.js, which
        // is a side-effect import in the source. This harness runs the script
        // as plain text, so supply the few members the scan path touches.
        heuristicDetect: () => ({
          label: 'phishing_email',
          confidence: 0.98,
          reasons: ['test'],
          links: [],
          attachments: []
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
    MutationObserver: class { observe() {} disconnect() {} },
    chrome: {
      runtime: {
        onMessage: { addListener() {}, removeListener() {} },
        sendMessage: async (message) => {
          if (message?.type === 'GET_SETTINGS') {
            return { autoScan: true, sensitivityThreshold: 0.7, highlightLinks: true, showTooltip: true };
          }
          if (message?.type === 'SCAN_EMAIL') {
            return { success: true, result: { label: 'phishing_email', confidence: 0.98, reasons: ['test'] } };
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

  const h = {
    callbacks,
    documentKeydown,
    /** Boot and wait for the initial scan to inject a badge. */
    async boot() {
      callbacks['document:DOMContentLoaded']?.();
      await new Promise((r) => setTimeout(r, 400));
      return h;
    },
    /** The badge node that was inserted into the message. */
    badge() {
      return insertParent.children.find((c) => String(c.className).includes('phishnet-badge'));
    }
  };
  return h;
}

test('reopening the modal does not accumulate keydown listeners', async () => {
  const h = await harness().boot();

  const badge = h.badge();
  assert.ok(badge, 'the scan must inject a badge');

  badge.fire('click', { stopPropagation() {}, preventDefault() {} });
  assert.equal(h.documentKeydown.size, 1, 'the first modal installs one ESC handler');

  // A second threat, opened while the first modal is still up. The old code
  // removed the DOM node without calling closeModal, so the handler stayed.
  h.badge()?.fire('click', { stopPropagation() {}, preventDefault() {} });
  assert.equal(h.documentKeydown.size, 1, 'the second modal must not add another handler');

  // And a third, to be sure it is not just a one-off.
  h.badge()?.fire('click', { stopPropagation() {}, preventDefault() {} });
  assert.equal(h.documentKeydown.size, 1, 'repeated opens must not grow the listener set');
});

test('closing the modal removes its keydown listener', async () => {
  const h = await harness().boot();

  const badge = h.badge();
  badge.fire('click', { stopPropagation() {}, preventDefault() {} });
  assert.equal(h.documentKeydown.size, 1);

  // ESC runs the document-level handler, which calls closeModal.
  const esc = h.callbacks['document:keydown'];
  assert.ok(esc, 'a keydown handler must be registered');
  esc({ key: 'Escape' });

  assert.equal(h.documentKeydown.size, 0, 'closing the modal must remove the handler');
});