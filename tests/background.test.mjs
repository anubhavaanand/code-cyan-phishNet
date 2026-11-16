/**
 * Service-worker message router tests.
 *
 * src/background.js is an ES module that registers its listener for
 * side effects, so this suite installs the chrome mock on globalThis, imports
 * the worker once, and then drives it through the same onMessage contract the
 * popup and content scripts use.
 */
import { test, describe, before, it } from 'node:test';
import assert from 'node:assert/strict';

import chromeMockModule from './helpers/chrome-mock.js';

const { createChromeMock } = chromeMockModule;

const mock = createChromeMock();
globalThis.chrome = mock.chrome;

// Importing registers the runtime.onMessage listener and kicks off init().
await import('../src/background.js');
await mock.flush();
await mock.flush();

const send = (message, sender) => mock.send(message, sender);

/**
 * A content script's sender.
 *
 * `chrome.runtime.sendMessage` reaches every extension context, so the worker
 * checks that a message claiming to come from a tab really came from a mail tab
 * the content script may run in.
 */
const tabSender = { id: 'phishnet-test', tab: { id: 91, url: 'https://mail.google.com/mail/u/0/' } };

describe('service worker bootstrap', () => {
  it('registers a message listener', () => {
    assert.ok(mock.messageListeners.length > 0, 'worker must register onMessage');
  });

  it('creates the offscreen document once', async () => {
    const res = await send({ type: 'GET_STATUS' });
    assert.equal(mock.offscreenState.created, 1);
    assert.ok(res);
  });
});

describe('GET_STATUS / GET_SETTINGS', () => {
  it('reports a status payload with settings', async () => {
    const res = await send({ type: 'GET_STATUS' });
    assert.ok(res);
    assert.ok('modelStatus' in res, 'status payload must include modelStatus');
    assert.ok('progress' in res);
    assert.ok(res.settings, 'status payload must include settings');
  });

  it('returns the documented default settings', async () => {
    const res = await send({ type: 'GET_SETTINGS' });
    assert.equal(res.autoScan, true);
    assert.equal(res.highlightLinks, true);
    assert.equal(res.showTooltip, true);
    assert.equal(res.sensitivityThreshold, 0.7);
    assert.equal(res.theme, 'auto');
    assert.ok(Array.isArray(res.whitelist));
    assert.ok(res.whitelist.includes('github.com'));
  });
});

describe('UPDATE_SETTINGS', () => {
  it('rejects malformed whitelist updates without corrupting settings or storage', async () => {
    const before = (await send({ type: 'GET_SETTINGS' })).whitelist;
    const storedBefore = mock.localStore.whitelist;
    for (const invalid of ['github.com', { 0: 'github.com' }, [42, 'github.com'], null]) {
      const res = await send({ type: 'UPDATE_SETTINGS', settings: { whitelist: invalid } });
      assert.equal(res.success, false, `rejected ${JSON.stringify(invalid)}`);
      assert.deepEqual((await send({ type: 'GET_SETTINGS' })).whitelist, before);
      assert.deepEqual(mock.localStore.whitelist, storedBefore);
    }
  });

  it('rejects invalid scalar settings and unexpected keys without persisting them', async () => {
    const before = await send({ type: 'GET_SETTINGS' });
    const storedBefore = { ...mock.syncStore };
    for (const invalid of [
      { sensitivityThreshold: NaN },
      { sensitivityThreshold: -0.1 },
      { sensitivityThreshold: 1.1 },
      { autoScan: 'false' },
      { showTooltip: null },
      { theme: 'unknown' },
      { whitelist: ['valid.example', 42] },
      { whitelist: ['  '] },
      { extraneous: true },
    ]) {
      const res = await send({ type: 'UPDATE_SETTINGS', settings: invalid });
      assert.equal(res.success, false, JSON.stringify(invalid));
      assert.deepEqual(await send({ type: 'GET_SETTINGS' }), before);
      assert.deepEqual(mock.syncStore, storedBefore);
    }
  });

  it('persists the change to storage.sync', async () => {
    const res = await send({ type: 'UPDATE_SETTINGS', settings: { autoScan: false, theme: 'dark' } });
    assert.equal(res.success, true);
    assert.equal(res.settings.autoScan, false);
    assert.equal(res.settings.theme, 'dark');
    assert.equal(mock.syncStore.autoScan, false, 'must be written through to storage');
    assert.equal(mock.syncStore.theme, 'dark');
  });

  it('is reflected by a subsequent GET_SETTINGS', async () => {
    const res = await send({ type: 'GET_SETTINGS' });
    assert.equal(res.autoScan, false);
    assert.equal(res.theme, 'dark');
  });

  it('preserves unrelated keys', async () => {
    await send({ type: 'UPDATE_SETTINGS', settings: { showTooltip: false } });
    const res = await send({ type: 'GET_SETTINGS' });
    assert.equal(res.showTooltip, false);
    assert.equal(res.autoScan, false, 'autoScan must survive an unrelated update');
  });
});

describe('whitelist management', () => {
  it('adds a trimmed, lowercased entry exactly once', async () => {
    const first = await send({ type: 'ADD_WHITELIST', entry: '  Example.COM  ' });
    assert.equal(first.success, true);
    assert.ok(first.whitelist.includes('example.com'));

    const second = await send({ type: 'ADD_WHITELIST', entry: 'example.com' });
    assert.equal(second.whitelist.filter((w) => w === 'example.com').length, 1, 'no duplicates');
  });

  it('rejects an empty entry instead of silently ignoring it', async () => {
    const before = (await send({ type: 'GET_SETTINGS' })).whitelist.length;
    const res = await send({ type: 'ADD_WHITELIST', entry: '   ' });
    // A blank entry is a caller bug, not a no-op: reporting success for a
    // change that was not made hides it.
    assert.equal(res.success, false);
    assert.match(res.error, /empty/i);
    const after = (await send({ type: 'GET_SETTINGS' })).whitelist.length;
    assert.equal(after, before, 'blank entries must not be stored');
  });

  it('removes an entry', async () => {
    const res = await send({ type: 'REMOVE_WHITELIST', entry: 'example.com' });
    assert.equal(res.success, true);
    assert.equal(res.whitelist.includes('example.com'), false);
  });

  it('persists trusted senders only in local storage', async () => {
    assert.ok(Array.isArray(mock.localStore.whitelist));
    assert.equal(mock.localStore.whitelist.includes('example.com'), false);
    assert.equal(Object.hasOwn(mock.syncStore, 'whitelist'), false);
  });

  it('never syncs the whitelist when unrelated preferences change', async () => {
    await send({ type: 'ADD_WHITELIST', entry: 'private.sender@example.com' });
    await send({ type: 'UPDATE_SETTINGS', settings: { theme: 'light' } });
    assert.ok(mock.localStore.whitelist.includes('private.sender@example.com'));
    assert.equal(Object.hasOwn(mock.syncStore, 'whitelist'), false);
    assert.equal(mock.syncStore.theme, 'light');
  });
});

describe('CLEAR_HISTORY', () => {
  it('clears all extension-local scan data without erasing synced settings', async () => {
    mock.localStore.scanHistory = [{ id: 1 }];
    mock.localStore.scanStats = { total: 5 };
    mock.localStore.futureThreatCache = { private: 'sensitive scan data' };
    const previousTheme = mock.syncStore.theme;
    const previousWhitelist = [...mock.localStore.whitelist];

    const res = await send({ type: 'CLEAR_HISTORY' });
    assert.equal(res.success, true);
    assert.deepEqual(mock.localStore, { whitelist: previousWhitelist });
    assert.equal(mock.syncStore.theme, previousTheme);
  });
});

describe('SCAN_EMAIL gating', () => {
  it('rejects oversized scan fields before forwarding to the model', async () => {
    for (const payload of [
      { text: 'x'.repeat(32769) },
      { text: 'ok', subject: 's'.repeat(1025) },
      { text: 'ok', body: 'b'.repeat(32769) },
      { text: 'ok', links: Array(129).fill({ href: 'https://example.com' }) },
      { text: 'ok', links: [{ href: 'h'.repeat(4097) }] },
      { text: 'ok', attachments: Array(65).fill('hello.txt') },
      { text: 'ok', attachments: [{ name: 'n'.repeat(1025) }] },
      { text: 'ok', sender: { email: 'e'.repeat(1025) } },
      { text: 'ok', links: 'not an array' },
    ]) {
      const sentBefore = mock.sentMessages.filter(m => m.type === 'RUN_INFERENCE').length;
      const res = await send({ type: 'SCAN_EMAIL', payload }, tabSender);
      assert.equal(res.success, false, JSON.stringify(Object.keys(payload)));
      assert.match(res.error, /payload.*(invalid|large)/i);
      assert.equal(mock.sentMessages.filter(m => m.type === 'RUN_INFERENCE').length, sentBefore);
    }
  });

  it('reports useHeuristic while the model is not ready', async () => {
    // The worker boots in the 'loading' state until the offscreen document
    // reports OFFSCREEN_READY.
    const res = await send({
      type: 'SCAN_EMAIL',
      payload: { text: 'hello', subject: 'hi' },
    }, tabSender);
    assert.equal(res.success, false);
    assert.equal(res.useHeuristic, true);
  });

  it('returns the inference result once the model reports ready', async () => {
    mock.deliver({ type: 'OFFSCREEN_READY' });
    await mock.flush();

    const res = await send({
      type: 'SCAN_EMAIL',
      payload: { text: 'hello', subject: 'hi' },
    }, tabSender);
    assert.equal(res.success, true, JSON.stringify(res));
    assert.ok(res.result, 'expected an inference result');
    assert.equal(typeof res.result.label, 'string');
  });

  it('forwards bounded text, sender, and links while accepting fields at their limits', async () => {
    const payload = {
      text: 'x'.repeat(32768), subject: 's'.repeat(1024),
      body: 'b'.repeat(32768),
      links: Array(128).fill({ href: 'https://example.com' }),
      attachments: Array(64).fill({ name: 'document.pdf' }),
      sender: { email: 'sender@example.com' },
      unexpectedNestedField: { unused: true }
    };
    const res = await send({ type: 'SCAN_EMAIL', payload }, tabSender);
    assert.equal(res.success, true);
    const forwarded = mock.sentMessages.filter(m => m.type === 'RUN_INFERENCE').at(-1);
    // The model needs the sender and the real hrefs to explain a verdict; the
    // body, subject, attachments, and unknown fields stay behind.
    assert.deepEqual(forwarded.payload, {
      text: payload.text,
      sender: payload.sender,
      links: payload.links
    });
    assert.equal('attachments' in forwarded.payload, false);
    assert.equal('unexpectedNestedField' in forwarded.payload, false);
  });

  it('omits an absent sender and link list rather than sending empty values', async () => {
    const res = await send({ type: 'SCAN_EMAIL', payload: { text: 'plain body' } }, tabSender);
    assert.equal(res.success, true);
    const forwarded = mock.sentMessages.filter(m => m.type === 'RUN_INFERENCE').at(-1);
    assert.deepEqual(forwarded.payload, { text: 'plain body' });
  });
});

describe('unknown messages', () => {
  it('returns a structured error rather than throwing', async () => {
    const res = await send({ type: 'TOTALLY_UNKNOWN' });
    assert.equal(res.success, false);
    assert.match(res.error, /Unknown message type/);
  });

  it('ignores messages without a type', async () => {
    const res = await send({ noType: true });
    assert.equal(res, undefined);
  });
});

describe('SCAN_CURRENT_TAB', () => {
  it('reports a clear error when there is no active tab', async () => {
    const res = await send({ type: 'SCAN_CURRENT_TAB' });
    assert.equal(res.success, false);
    assert.match(res.error, /No active tab/i);
  });
});


describe('content-script whitelist privacy', () => {

  it('withholds the whitelist from all content-script settings responses', async () => {
    const full = await send({ type: 'GET_SETTINGS' });
    assert.ok(full.whitelist.includes('github.com'), 'popup retains its settings');

    for (const [message, getSettings] of [
      [{ type: 'CONTENT_READY' }, response => response.settings],
      [{ type: 'GET_SETTINGS' }, response => response],
    ]) {
      const response = await mock.send(message, tabSender);
      assert.ok(getSettings(response).autoScan !== undefined);
      assert.equal(Object.hasOwn(getSettings(response), 'whitelist'), false);
    }
  });

  it('refuses privileged messages from a tab outright', async () => {
    // GET_STATUS carries the settings payload, and ADD_WHITELIST changes
    // protection state. Neither is a content script's to ask for, so the worker
    // rejects them before the handler runs rather than filtering the reply.
    for (const message of [
      { type: 'GET_STATUS' },
      { type: 'ADD_WHITELIST', entry: 'private.invalid' },
      { type: 'REMOVE_WHITELIST', entry: 'github.com' },
      { type: 'UPDATE_SETTINGS', settings: { autoScan: false } },
      { type: 'CLEAR_HISTORY' },
    ]) {
      const response = await mock.send(message, tabSender);
      assert.equal(response.success, false, `${message.type} must be rejected from a tab`);
      assert.equal(Object.hasOwn(response, 'settings'), false);
    }
  });

  it('checks sender trust in the background without disclosing the list', async () => {
    const known = await mock.send({
      type: 'CHECK_TRUSTED_SENDER', email: 'alice@github.com', domain: 'github.com',
    }, tabSender);
    assert.deepEqual(known, { trusted: true });
    const unknown = await mock.send({
      type: 'CHECK_TRUSTED_SENDER', email: 'alice@example.invalid', domain: 'example.invalid',
    }, tabSender);
    assert.deepEqual(unknown, { trusted: false });

    // The popup page adds the entry; a tab may never do so. An extension page
    // gets the updated list back, since it renders the list it just changed.
    const added = await send({ type: 'ADD_WHITELIST', entry: 'private.invalid' });
    assert.equal(added.success, true);
    assert.ok(added.whitelist.includes('private.invalid'));
    assert.ok((await send({ type: 'GET_SETTINGS' })).whitelist.includes('private.invalid'));
    await send({ type: 'REMOVE_WHITELIST', entry: 'private.invalid' });
  });

  it('does not broadcast to tabs without the content script', async () => {
    // chrome.tabs.query({}) returns every tab; sending to all of them is wasted
    // work, since only mail tabs have the content script listening.
    mock.tabsVisible.push(
      { id: 91, url: 'https://mail.google.com/mail/u/0/' },
      { id: 92, url: 'https://example.com/' },
      { id: 93, url: 'https://mail.google.com.evil.example/' },
      { id: 94, url: 'about:blank' }
    );
    try {
      await send({ type: 'UPDATE_SETTINGS', settings: { showTooltip: true } });
      const recipients = new Set(
        mock.tabMessages.filter(m => m.message.type === 'SETTINGS_UPDATE').map(m => m.tabId)
      );
      assert.deepEqual([...recipients], [91]);
    } finally {
      mock.tabsVisible.length = 0;
    }
  });

  it('broadcasts only non-sensitive preferences to tabs', async () => {
    mock.tabsVisible.push({ id: 91, url: 'https://mail.google.com/mail/u/0/' });
    try {
      await send({ type: 'UPDATE_SETTINGS', settings: { showTooltip: true } });
      const broadcast = mock.tabMessages.findLast(
        m => m.tabId === 91 && m.message.type === 'SETTINGS_UPDATE'
      );
      assert.ok(broadcast, 'tab should receive preferences update');
      assert.equal(Object.hasOwn(broadcast.message.payload, 'whitelist'), false);
      assert.equal(broadcast.message.payload.showTooltip, true);
    } finally {
      mock.tabsVisible.length = 0;
    }
  });
});
