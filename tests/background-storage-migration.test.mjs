/**
 * Regression tests for one-time migration of previously synced sender addresses.
 * Each import uses a distinct module URL to start a fresh service worker.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import chromeMockModule from './helpers/chrome-mock.js';

const { createChromeMock } = chromeMockModule;

const cases = [
  {
    name: 'moves legacy synced addresses to local storage before deleting sync',
    sync: { whitelist: ['legacy.sender@example.com'], theme: 'dark' },
    local: {},
    expected: ['legacy.sender@example.com']
  },
  {
    name: 'prefers existing local addresses and removes stale synced data',
    sync: { whitelist: ['stale.sender@example.com'] },
    local: { whitelist: ['local.sender@example.com'] },
    expected: ['local.sender@example.com']
  },
  {
    name: 'retains a local-only whitelist with no legacy sync copy',
    sync: { autoScan: false },
    local: { whitelist: ['local.sender@example.com'] },
    expected: ['local.sender@example.com']
  }
];

for (const [index, scenario] of cases.entries()) {
  test(scenario.name, async () => {
    const mock = createChromeMock({ sync: scenario.sync, local: scenario.local });
    globalThis.chrome = mock.chrome;
    await import(`../src/background.js?storage-migration=${index}`);
    await mock.flush();
    await mock.flush();

    assert.deepEqual(mock.localStore.whitelist, scenario.expected);
    assert.equal(Object.hasOwn(mock.syncStore, 'whitelist'), false);
    assert.deepEqual((await mock.send({ type: 'GET_SETTINGS' })).whitelist, scenario.expected);

    await mock.send({ type: 'UPDATE_SETTINGS', settings: { theme: 'light' } });
    assert.deepEqual(mock.localStore.whitelist, scenario.expected);
    assert.equal(Object.hasOwn(mock.syncStore, 'whitelist'), false);
    assert.equal(mock.syncStore.theme, 'light');
  });
}
