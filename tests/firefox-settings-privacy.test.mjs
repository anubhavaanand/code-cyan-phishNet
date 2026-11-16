import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

test('Firefox background only supplies whitelist decisions to content scripts', async () => {
  const source = readFileSync(new URL('../src/background-firefox.js', import.meta.url), 'utf8');
  const messages = [];
  let listener;
  const browser = {
    runtime: { onMessage: { addListener: (fn) => { listener = fn; } } },
    tabs: {
      query: async () => [{ id: 1 }],
      sendMessage: async (id, message) => { messages.push({ id, message }); },
    },
    storage: {
      sync: { get: async () => ({}), set: async () => {} },
      local: { clear: async () => {} },
    },
  };
  const context = vm.createContext({ browser, console, URL });
  // Avoid invoking model-download startup in an offline message-contract test.
  new vm.Script(source.split('// ---- boot ----')[0]).runInContext(context);
  const tabSender = { tab: { id: 1 } };
  const settings = await listener({ type: 'GET_SETTINGS' }, tabSender);
  assert.equal(Object.hasOwn(settings, 'whitelist'), false);
  assert.ok((await listener({ type: 'GET_SETTINGS' }, {})).whitelist.includes('github.com'));
  assert.equal((await listener({
    type: 'CHECK_TRUSTED_SENDER', email: 'alice@github.com', domain: 'github.com',
  }, tabSender)).trusted, true);
  const added = await listener({ type: 'ADD_WHITELIST', entry: 'private.invalid' }, tabSender);
  assert.equal(Object.hasOwn(added, 'whitelist'), false);
  assert.ok((await listener({ type: 'GET_SETTINGS' }, {})).whitelist.includes('private.invalid'));
  assert.equal(Object.hasOwn((await listener({ type: 'CONTENT_READY' }, tabSender)).settings, 'whitelist'), false);
  assert.equal(Object.hasOwn((await listener({ type: 'GET_STATUS' }, tabSender)).settings, 'whitelist'), false);
  await Promise.resolve();
  assert.ok(messages.some(m => m.message.type === 'SETTINGS_UPDATE'));
  assert.ok(messages.filter(m => m.message.type === 'SETTINGS_UPDATE').every(
    m => !Object.hasOwn(m.message.payload, 'whitelist')
  ));
});
