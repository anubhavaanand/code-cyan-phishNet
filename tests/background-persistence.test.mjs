/**
 * Background persistence and message-safety regressions.
 *
 * These cover three low-severity audit findings that share `src/background.js`:
 * a storage failure reported as success, a synchronous sendMessage throwing
 * past its cleanup, and the trusted-sender whitelist crossing into the offscreen
 * document on every scan.
 */
import { test, describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

import chromeMockModule from './helpers/chrome-mock.js';

const WORKER = new URL('../src/background.js', import.meta.url);

let mock;
let send;

before(async () => {
  mock = chromeMockModule.createChromeMock();
  globalThis.chrome = mock.chrome;
  await import(WORKER.href);
  await mock.flush();
  await mock.flush();
  send = (message, sender) => mock.send(message, sender);
});

describe('saveSettings failure reporting', () => {
  it('reports a failed local write instead of success', async () => {
    const originalSet = mock.chrome.storage.local.set;
    mock.chrome.storage.local.set = (_values, cb) => {
      // How MV3 reports a rejected write.
      mock.chrome.runtime.lastError = { message: 'QUOTA_BYTES quota exceeded' };
      cb();
      mock.chrome.runtime.lastError = undefined;
    };
    try {
      const result = await send({ type: 'UPDATE_SETTINGS', settings: { showTooltip: false } });
      assert.equal(result.success, false);
      assert.match(result.error, /could not save the whitelist/i);
      assert.match(result.error, /QUOTA_BYTES/);
    } finally {
      mock.chrome.storage.local.set = originalSet;
    }
  });

  it('reports a failed synced write instead of success', async () => {
    const originalSet = mock.chrome.storage.sync.set;
    mock.chrome.storage.sync.set = (_values, cb) => {
      mock.chrome.runtime.lastError = { message: 'Sync storage is unavailable' };
      cb();
      mock.chrome.runtime.lastError = undefined;
    };
    try {
      const result = await send({ type: 'UPDATE_SETTINGS', settings: { showTooltip: true } });
      assert.equal(result.success, false);
      assert.match(result.error, /could not save settings/i);
      assert.match(result.error, /Sync storage is unavailable/);
    } finally {
      mock.chrome.storage.sync.set = originalSet;
    }
  });

  it('still reports success when both writes succeed', async () => {
    const result = await send({ type: 'UPDATE_SETTINGS', settings: { showTooltip: true } });
    assert.equal(result.success, true);
  });
});

describe('offscreen settings minimization', () => {
  it('forwards only the threshold, never the whitelist', async () => {
    await mock.deliver({ type: 'OFFSCREEN_READY' });
    await mock.flush();

    const before = mock.sentMessages.filter(m => m.type === 'RUN_INFERENCE').length;
    const tabSender = { id: 'phishnet-test', tab: { id: 91, url: 'https://mail.google.com/mail/u/0/' } };
    const result = await send({ type: 'SCAN_EMAIL', payload: { text: 'hello there, please review this' } }, tabSender);
    assert.equal(result.success, true);

    const forwarded = mock.sentMessages.filter(m => m.type === 'RUN_INFERENCE');
    assert.equal(forwarded.length, before + 1);
    const sent = forwarded.at(-1);
    assert.deepEqual(sent.settings, { sensitivityThreshold: 0.7 });
    assert.equal(Object.hasOwn(sent.settings, 'whitelist'), false);
  });
});

describe('runInference cleanup on a synchronous sendMessage failure', () => {
  it('clears the pending timer when sendMessage throws synchronously', async () => {
    const original = mock.chrome.runtime.sendMessage;
    // The timer the worker arms for the 15s timeout. The old code left it and
    // the pending map entry behind, because the executor threw before any
    // .catch was attached.
    const originalClearTimeout = globalThis.clearTimeout;
    let cleared = 0;
    globalThis.clearTimeout = (...args) => {
      cleared += 1;
      return originalClearTimeout(...args);
    };
    mock.chrome.runtime.sendMessage = () => {
      // MV3 throws synchronously once the extension context is invalidated.
      throw new Error('Extension context invalidated.');
    };
    try {
      const tabSender = { id: 'phishnet-test', tab: { id: 91, url: 'https://mail.google.com/mail/u/0/' } };
      const started = Date.now();
      const result = await send({ type: 'SCAN_EMAIL', payload: { text: 'hello there, please review' } }, tabSender);
      const elapsed = Date.now() - started;

      // The old code let the throw escape the executor before any cleanup, so
      // the caller waited out the 15s timeout instead.
      assert.ok(elapsed < 5000, `must fail fast, took ${elapsed}ms`);
      assert.equal(result.success, false);
      assert.match(result.error, /context invalidated/i);
      assert.ok(cleared > 0, 'the timeout timer must be cleared on the failure path');
    } finally {
      mock.chrome.runtime.sendMessage = original;
      globalThis.clearTimeout = originalClearTimeout;
    }
  });
});