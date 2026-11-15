import { test } from 'node:test';
import assert from 'node:assert/strict';

test('Firefox rejects malformed and hostile settings without persisting them', async () => {
  const syncStore = {
    autoScan: 'yes', sensitivityThreshold: 3, highlightLinks: true,
    theme: 'unexpected',
    whitelist: [42, ' Trusted.Example ', 'bad domain', 'trusted.example'],
  };
  let handler;
  const writes = [];
  globalThis.browser = {
    runtime: {
      getURL: (path) => new URL('../' + path, import.meta.url).href,
      onMessage: { addListener: (fn) => { handler = fn; } },
    },
    storage: {
      sync: {
        get: async () => ({ ...syncStore }),
        set: async (next) => { writes.push(structuredClone(next)); Object.assign(syncStore, next); },
      },
      local: { clear: async () => {} },
    },
    tabs: { query: async () => [], sendMessage: async () => {} },
  };
  await import('../src/background-firefox.js');
  for (let i = 0; i < 10 && !handler; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(typeof handler, 'function');
  // The boot step loads the shared validator before applying stored preferences.
  let restored;
  for (let i = 0; i < 20; i++) {
    restored = await handler({ type: 'GET_SETTINGS' });
    if (restored.whitelist.length === 1) break;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.equal(restored.autoScan, true);
  assert.equal(restored.sensitivityThreshold, 0.7);
  assert.equal(restored.theme, 'aloe');
  assert.deepEqual(restored.whitelist, ['trusted.example']);

  for (const invalid of [
    null, [], { autoScan: 'false' }, { sensitivityThreshold: -1 },
    { theme: 'unknown' }, { theme: 'light' }, { whitelist: [42] },
    { whitelist: ['ok.example', 'bad domain'] }, { whitelist: ['x.example', 'x.example'] },
    { extraPermission: true },
  ]) {
    const before = writes.length;
    const result = await handler({ type: 'UPDATE_SETTINGS', settings: invalid });
    assert.equal(result.success, false, JSON.stringify(invalid));
    assert.equal(writes.length, before, 'rejected update must not persist');
  }

  const good = await handler({
    type: 'UPDATE_SETTINGS',
    settings: { autoScan: false, sensitivityThreshold: 0.35, theme: 'graphite' },
  });
  assert.equal(good.success, true);
  assert.equal(syncStore.sensitivityThreshold, 0.35);
  assert.equal(syncStore.theme, 'graphite');

  for (const invalid of [42, {}, 'not a domain', 'x'.repeat(255)]) {
    const before = writes.length;
    const result = await handler({ type: 'ADD_WHITELIST', entry: invalid });
    assert.equal(result.success, false);
    assert.equal(writes.length, before);
  }

  const added = await handler({ type: 'ADD_WHITELIST', entry: '  ALICE@Trusted.Example ' });
  assert.equal(added.success, true);
  assert.ok(added.whitelist.includes('alice@trusted.example'));
  assert.equal((await handler({ type: 'REMOVE_WHITELIST', entry: null })).success, false);
  assert.equal((await handler({ type: 'REMOVE_WHITELIST', entry: 'alice@trusted.example' })).success, true);
});
