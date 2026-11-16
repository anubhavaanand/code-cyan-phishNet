/**
 * Firefox worker parity tests.
 *
 * Two regressions live here:
 *  - F-078: the Firefox worker carried a reduced isUrlSuspicious copy, missing
 *    the homograph, lookalike-brand, open-redirect and keyword checks.
 *  - F-079: runInference awaited the pipeline with no timeout, so a hung model
 *    left the popup waiting forever.
 *
 * The worker is a classic script in Firefox, loaded from
 * `background.scripts`. These tests import it as a module, which is how it
 * behaves under Node, and stand in for the vendored model bundle.
 */
import { test, describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

const DETECTOR = new URL('../src/utils/heuristic-detector.js', import.meta.url);
const WORKER = new URL('../src/background-firefox.js', import.meta.url);
const STUB = new URL('./fixtures/transformers-stub.mjs', import.meta.url);

const EXTENSION_ID = 'phishnet-test';

/**
 * Install the mock `browser` global and load the worker.
 *
 * Returns the message handler plus the state the worker wrote to.
 */
let bootCount = 0;

async function bootWorker({ modelReady = true } = {}) {
  // Each boot gets a fresh module instance, so listeners are registered again.
  const workerUrl = `${WORKER.href}?boot=${++bootCount}`;
  const listeners = [];
  const syncStore = {};
  const writes = [];

  globalThis.browser = {
    runtime: {
      id: EXTENSION_ID,
      getURL: (path) => {
        // Route the vendored model bundle to the stub; everything else is real.
        if (String(path).endsWith('transformers.min.js')) return STUB.href;
        return new URL(`../${path}`, import.meta.url).href;
      },
      onMessage: { addListener: (fn) => listeners.push(fn) }
    },
    storage: {
      sync: {
        get: async () => ({ ...syncStore }),
        set: async (next) => {
          writes.push(structuredClone(next));
          Object.assign(syncStore, next);
        }
      },
      local: { clear: async () => {} }
    },
    tabs: { query: async () => [], sendMessage: async () => {} }
  };

  // The background page loads the shared detection engine as a classic script
  // before the worker, which installs globalThis.PhishNet.
  await import(DETECTOR.href);
  assert.ok(globalThis.PhishNet, 'the shared detection engine must install itself');

  await import(workerUrl);

  if (modelReady) {
    // The worker loads the model eagerly on boot; wait for it to finish.
    for (let i = 0; i < 100; i++) {
      const status = await listeners[0]({ type: 'GET_STATUS' }, { id: EXTENSION_ID });
      if (status?.modelStatus === 'ready') break;
      await new Promise((r) => setTimeout(r, 20));
    }
  }

  return { handler: listeners[0], writes, store: syncStore };
}

describe('Firefox detection parity', () => {
  let phishnet;

  before(async () => {
    await import(DETECTOR.href);
    phishnet = globalThis.PhishNet;
  });

  it('installs the shared detection engine', () => {
    assert.equal(typeof phishnet?.isUrlSuspicious, 'function');
  });

  it('detects a homograph the reduced copy missed', () => {
    // Cyrillic 'а' in "раypal" folds onto "paypal".
    assert.equal(phishnet.isUrlSuspicious('https://раypal.com/'), true);
  });

  it('detects a lookalike brand the reduced copy missed', () => {
    assert.equal(phishnet.isUrlSuspicious('https://paypa1.com/'), true);
    assert.equal(phishnet.isUrlSuspicious('https://payapl.com/'), true);
  });

  it('detects an open redirect the reduced copy missed', () => {
    assert.equal(
      phishnet.isUrlSuspicious('https://example.com/redirect?url=https://evil.example/'),
      true
    );
  });

  it('detects an invisible character the reduced copy missed', () => {
    assert.equal(phishnet.isUrlSuspicious('https://paypa\u200bl.com/'), true);
  });

  it('still accepts an ordinary URL', () => {
    assert.equal(phishnet.isUrlSuspicious('https://github.com/settings'), false);
    assert.equal(phishnet.isUrlSuspicious('https://www.paypal.com/account'), false);
  });

  it('keeps the keyword rule the reduced copy had', () => {
    assert.equal(phishnet.isUrlSuspicious('https://secure-login.example.com/'), true);
  });
});

describe('Firefox inference timeout', () => {
  it('rejects a model call that never returns', async () => {
    const { handler } = await bootWorker();

    const started = Date.now();
    const result = await handler(
      { type: 'SCAN_EMAIL', payload: { text: 'please verify your account now' } },
      { id: EXTENSION_ID }
    );
    const elapsed = Date.now() - started;

    assert.equal(result.success, false, 'a hung model must not report success');
    assert.match(result.error, /Inference timeout after \d+ms/, `unexpected error: ${result.error}`);
    assert.equal(result.useHeuristic, true, 'the caller must be told to fall back');
    assert.ok(elapsed < 30000, `the caller must not wait indefinitely; waited ${elapsed}ms`);
  });

});