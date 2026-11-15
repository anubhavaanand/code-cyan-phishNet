import test from 'node:test';
import assert from 'node:assert/strict';
import { canSend, createNotifier } from '../src/utils/background-notify.mjs';

test('a delivered message resolves true', async () => {
  const sent = [];
  const notify = createNotifier((m) => {
    sent.push(m);
    return Promise.resolve();
  });
  assert.equal(await notify({ type: 'OFFSCREEN_READY' }), true);
  assert.deepEqual(sent, [{ type: 'OFFSCREEN_READY' }]);
});

test('a rejected send is swallowed, not left unhandled', async () => {
  const failures = [];
  const notify = createNotifier(
    () => Promise.reject(new Error('Receiving end does not exist')),
    (message, error) => failures.push([message, error])
  );

  // The point of the fix: this must not reject.
  await assert.doesNotReject(() => notify({ type: 'OFFSCREEN_READY' }));
  assert.equal(await notify({ type: 'OFFSCREEN_READY' }), false);
  assert.equal(failures.length, 2);
  assert.equal(failures[0][0].type, 'OFFSCREEN_READY');
  assert.match(failures[0][1].message, /Receiving end does not exist/);
});

test('a synchronous throw from sendMessage is contained too', async () => {
  const failures = [];
  const notify = createNotifier(
    () => {
      throw new Error('Extension context invalidated');
    },
    (message, error) => failures.push(error)
  );

  await assert.doesNotReject(() => notify({ type: 'OFFSCREEN_ERROR' }));
  assert.equal(await notify({ type: 'OFFSCREEN_ERROR' }), false);
  assert.match(failures[0].message, /Extension context invalidated/);
});

test('an absent send function is a no-op, not a crash', async () => {
  const notify = createNotifier(undefined);
  assert.equal(await notify({ type: 'OFFSCREEN_READY' }), false);
});

test('a callback-style send with no promise is treated as delivered', async () => {
  const notify = createNotifier(() => undefined);
  assert.equal(await notify({ type: 'MODEL_LOAD_PROGRESS' }), true);
});

test('canSend reflects the extension context being alive', () => {
  assert.equal(canSend({ id: 'abc' }), true);
  assert.equal(canSend({}), false);
  assert.equal(canSend(undefined), false);
  assert.equal(canSend(null), false);
});

test('a failing progress report does not disturb the caller', async () => {
  // Progress is fire-and-forget: runInference must not be affected by it.
  const notify = createNotifier(() => Promise.reject(new Error('worker asleep')));
  const results = await Promise.all([
    notify({ type: 'MODEL_LOAD_PROGRESS', progress: 15 }),
    Promise.resolve('model ready')
  ]);
  assert.deepEqual(results, [false, 'model ready']);
});