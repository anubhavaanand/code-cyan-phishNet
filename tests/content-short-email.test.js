const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
const detector = require('../src/utils/heuristic-detector.js');

function harness({ body = '', subject = '', sender = '', links = [], autoScan = true, trusted = false } = {}) {
  const state = { body, subject, sender, links, autoScan, trusted };
  const messages = [];
  const heuristicInputs = [];
  const listeners = {};
  const parent = { insertBefore(node) { node.parentNode = this; } };
  const senderNode = {
    textContent: 'Sender',
    parentNode: parent,
    nextSibling: null,
    getAttribute: (name) => name === 'email' ? state.sender : null
  };
  const subjectNode = { get textContent() { return state.subject; } };
  const bodyNode = {
    get textContent() { return state.body; },
    cloneNode() { return this; },
    querySelector: () => null,
    querySelectorAll(selector) {
      if (selector !== 'a[href]') return [];
      return state.links.map((href) => ({
        textContent: '',
        getAttribute: (name) => name === 'href' ? href : null,
        querySelector: () => null
      }));
    }
  };
  const element = {
    dataset: { messageId: 'short-message' },
    get textContent() { return state.body; },
    closest: () => null,
    getAttribute: () => null,
    querySelector(selector) {
      if (selector === '.sender') return state.sender ? senderNode : null;
      if (selector === '.subject') return state.subject ? subjectNode : null;
      if (selector === '.body') return bodyNode;
      return null;
    },
    querySelectorAll: () => [],
    cloneNode() { return this; },
    isConnected: true
  };
  class Observer {
    observe() {}
    disconnect() {}
  }
  const chrome = {
    runtime: {
      onMessage: {
        addListener: (fn) => { listeners.message = fn; },
        removeListener: () => {}
      },
      async sendMessage(message) {
        messages.push(message);
        if (message.type === 'GET_SETTINGS') {
          return { autoScan: state.autoScan, highlightLinks: false, sensitivityThreshold: 0.7 };
        }
        if (message.type === 'CHECK_TRUSTED_SENDER') return { trusted: state.trusted };
        if (message.type === 'SCAN_EMAIL') return { success: false, useHeuristic: true };
        return null;
      }
    },
    storage: {
      local: {
        get(_keys, callback) { callback({}); },
        set() { return Promise.resolve(); }
      }
    }
  };
  const document = {
    readyState: 'loading',
    body: {},
    head: { appendChild() {} },
    addEventListener: (event, fn) => { listeners[`document:${event}`] = fn; },
    removeEventListener() {},
    querySelectorAll: (selector) => selector === '[data-message-id]' ? [element] : [],
    getElementById: () => null,
    createElement: () => ({
      style: {},
      setAttribute() {},
      addEventListener() {},
      appendChild() {}
    })
  };
  const context = {
    globalThis: {
      PhishNet: {
        getSelectorsForCurrentSite: () => ({
          provider: 'gmail', variant: 'default',
          selectors: { messages: '[data-message-id]', sender: '.sender', subject: '.subject', messageBody: '.body' }
        }),
        heuristicDetect(content) {
          heuristicInputs.push(content);
          return detector.heuristicDetect(content);
        },
        isUrlSuspicious: detector.isUrlSuspicious,
        logger: { debug() {}, error() {} }
      }
    },
    document,
    window: {
      location: { href: 'https://mail.google.com/mail/u/0/' },
      addEventListener: (event, fn) => { listeners[`window:${event}`] = fn; }
    },
    location: { href: 'https://mail.google.com/mail/u/0/' },
    MutationObserver: Observer,
    chrome,
    setTimeout,
    clearTimeout,
    console
  };
  runInNewContext(source, context);

  const settle = () => new Promise((resolve) => setTimeout(resolve, 15));
  return {
    state, messages, heuristicInputs,
    async start() { listeners['document:DOMContentLoaded'](); await settle(); },
    async resweep() { listeners['window:load'](); await settle(); },
    async enableAutoScan() {
      state.autoScan = true;
      listeners.message({ type: 'SETTINGS_UPDATE', payload: { autoScan: true } });
      await settle();
    },
    scans: () => messages.filter(({ type }) => type === 'SCAN_EMAIL')
  };
}

test('a short phishing message is sent to ML and heuristics', async () => {
  const h = harness({ body: 'Verify now' });
  await h.start();
  assert.equal(h.scans().length, 1);
  assert.equal(h.scans()[0].payload.text, 'Verify now');
  assert.equal(h.heuristicInputs.length, 1);
});

test('long subjects are bounded for ML without dropping local phishing analysis', async () => {
  const subject = 'Urgent account verification '.repeat(55).trim();
  const h = harness({ body: 'Verify your account now', subject });
  await h.start();
  assert.equal(h.scans().length, 1);
  assert.equal(h.scans()[0].payload.subject, subject.slice(0, 1024));
  assert.equal(h.scans()[0].payload.text.startsWith(subject), true);
  assert.equal(h.heuristicInputs[0].subject, subject);
});

test('an empty body with a phishing link still receives heuristic analysis', async () => {
  const h = harness({ links: ['https://8.8.8.8/login'] });
  await h.start();
  assert.equal(h.scans().length, 0, 'empty text should not run the text classifier');
  assert.equal(h.heuristicInputs.length, 1);
  assert.equal(detector.heuristicDetect(h.heuristicInputs[0]).links[0].suspicious, true);
});

test('an empty body with a sender still reaches sender heuristics', async () => {
  const h = harness({ sender: 'sender@paypa1.example' });
  await h.start();
  assert.equal(h.scans().length, 0);
  assert.equal(h.heuristicInputs.length, 1);
  assert.equal(h.heuristicInputs[0].sender.email, 'sender@paypa1.example');
});

test('explicitly trusted short messages do not run inference', async () => {
  const h = harness({ body: 'Hi', sender: 'alice@example.com', trusted: true });
  await h.start();
  assert.equal(h.scans().length, 0);
  assert.equal(h.heuristicInputs.length, 0);
});

test('a message deferred before its body arrives is scanned when it gains content', async () => {
  const h = harness();
  await h.start();
  assert.equal(h.scans().length, 0);
  h.state.body = 'Verify now';
  await h.resweep();
  assert.equal(h.scans().length, 1);
  await h.resweep();
  assert.equal(h.scans().length, 1, 'a completed scan must not be repeated');
});

test('enabling auto-scan retries a previously deferred message exactly once', async () => {
  const h = harness({ body: 'Verify now', autoScan: false });
  await h.start();
  assert.equal(h.scans().length, 0);
  await h.enableAutoScan();
  assert.equal(h.scans().length, 1);
  await h.resweep();
  assert.equal(h.scans().length, 1);
});
