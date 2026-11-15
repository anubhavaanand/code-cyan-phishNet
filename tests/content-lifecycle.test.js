const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

test('content script unregisters its runtime listener when a mail tab unloads', () => {
  const callbacks = {};
  const listeners = new Set();
  let addCalls = 0;
  let observerDisconnected = false;

  class MutationObserverMock {
    observe() {}
    disconnect() { observerDisconnected = true; }
  }

  const context = {
    globalThis: {
      PhishNet: {
        getSelectorsForCurrentSite: () => ({ provider: 'gmail', variant: 'default', selectors: { messages: '[data-message-id]' } })
      }
    },
    window: {
      addEventListener: (event, handler) => { callbacks[event] = handler; }
    },
    document: {
      readyState: 'loading',
      body: {},
      addEventListener: (event, handler) => { callbacks[event] = handler; },
      querySelectorAll: () => []
    },
    location: { href: 'https://mail.google.com/mail/u/0/' },
    MutationObserver: MutationObserverMock,
    chrome: { runtime: {
      onMessage: {
        addListener: (fn) => { addCalls++; listeners.add(fn); },
        removeListener: (fn) => listeners.delete(fn)
      },
      sendMessage: () => Promise.resolve()
    } },
    setTimeout,
    clearTimeout,
    console
  };

  const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
  runInNewContext(source, context);
  assert.equal(listeners.size, 0, 'listener should not register before DOMContentLoaded');

  callbacks.DOMContentLoaded();
  assert.equal(listeners.size, 1);
  callbacks.DOMContentLoaded();
  assert.equal(addCalls, 1, 'reinitialization must not register duplicate listeners');
  observerDisconnected = false;
  callbacks.beforeunload();
  assert.equal(listeners.size, 0);
  assert.equal(observerDisconnected, true);
});

test('content script passes each link and attachment to heuristic detection once', async () => {
  const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
  const marker = '  // Cleanup on unload';
  const extract = '      const emailContent = extractEmailContent(element);';
  assert.ok(source.includes(marker));
  assert.ok(source.includes(extract));

  // Expose the scanner and supply extracted data without building a browser DOM.
  const instrumented = source
    .replace(marker, '  root.PhishNet.scanEmailForTest = scanEmail;\n' + marker)
    .replace(extract, '      const emailContent = element.testEmailContent || extractEmailContent(element);');

  const calls = [];
  const emailContent = {
    text: 'Verify your account immediately.',
    subject: 'Verify now',
    sender: { email: 'sender@example.com', domain: 'example.com' },
    links: [{ href: 'http://suspicious.example/verify' }],
    attachments: ['invoice.zip']
  };
  const phishNet = {
    heuristicDetect: (...args) => {
      calls.push(args);
      return { label: 'uncertain', confidence: 0.5, links: emailContent.links,
        attachments: emailContent.attachments, reasons: [] };
    }
  };

  runInNewContext(instrumented, {
    globalThis: { PhishNet: phishNet },
    window: { location: { href: 'https://mail.google.com/' }, addEventListener() {} },
    location: { href: 'https://mail.google.com/' },
    document: { readyState: 'loading', addEventListener() {} },
    chrome: { runtime: {
      sendMessage: async ({ type }) => type === 'GET_SETTINGS' ? { highlightLinks: false } : null
    } },
    console: { warn() {}, error() {} }
  });

  await phishNet.scanEmailForTest({ testEmailContent: emailContent }, 'manual-dedupe');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].length, 1, 'links and attachments must not be passed a second time');
  assert.equal(calls[0][0], emailContent);
});
