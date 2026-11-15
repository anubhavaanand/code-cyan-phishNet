import test from 'node:test';
import assert from 'node:assert/strict';
import { warmupKey, isWarmed, markWarmed, WARMUP_KEY } from '../src/utils/warmup-cache.mjs';

/** A minimal in-memory stand-in for chrome.storage.session. */
function fakeStore(initial = {}) {
  const data = { ...initial };
  return {
    data,
    get: async (key) => ({ [key]: data[key] }),
    set: async (items) => { Object.assign(data, items); }
  };
}

test('the warm-up key pins the model build, revision, and dtype', () => {
  assert.equal(
    warmupKey('org/model', 'abc123', 'q8'),
    'org/model@abc123:q8'
  );
});

test('a model that was never warmed up is not reported as warmed', async () => {
  const store = fakeStore();
  assert.equal(await isWarmed(store, warmupKey('m', 'r', 'q8')), false);
});

test('marking a build warmed makes isWarmed true for that build only', async () => {
  const store = fakeStore();
  const key = warmupKey('m', 'r', 'q8');

  assert.equal(await markWarmed(store, key), true);
  assert.equal(await isWarmed(store, key), true);
  assert.equal(await isWarmed(store, warmupKey('other', 'r', 'q8')), false);
});

test('a different revision is not covered by an earlier warm-up', async () => {
  const store = fakeStore();
  await markWarmed(store, warmupKey('m', 'rev1', 'q8'));

  assert.equal(await isWarmed(store, warmupKey('m', 'rev1', 'q8')), true);
  assert.equal(await isWarmed(store, warmupKey('m', 'rev2', 'q8')), false);
});

test('a different dtype is not covered by an earlier warm-up', async () => {
  const store = fakeStore();
  await markWarmed(store, warmupKey('m', 'r', 'q8'));
  assert.equal(await isWarmed(store, warmupKey('m', 'r', 'fp32')), false);
});

test('the record survives a fresh store object reading the same data', async () => {
  const store = fakeStore();
  await markWarmed(store, warmupKey('m', 'r', 'q8'));

  const reopened = fakeStore({ ...store.data });
  assert.equal(await isWarmed(reopened, warmupKey('m', 'r', 'q8')), true);
});

test('the record is written under the expected key', async () => {
  const store = fakeStore();
  await markWarmed(store, warmupKey('m', 'r', 'q8'));
  assert.ok(store.data[WARMUP_KEY], 'expected the record under WARMUP_KEY');
  assert.ok(store.data[WARMUP_KEY][warmupKey('m', 'r', 'q8')]);
});

test('an unavailable store fails open rather than throwing', async () => {
  const broken = {
    get: async () => { throw new Error('storage unavailable'); },
    set: async () => { throw new Error('storage unavailable'); }
  };

  assert.equal(await isWarmed(broken, 'k'), false);
  assert.equal(await markWarmed(broken, 'k'), false);
});

test('a malformed stored record is treated as empty', async () => {
  for (const bad of [null, 'nope', 42, ['a']]) {
    const store = fakeStore({ [WARMUP_KEY]: bad });
    assert.equal(await isWarmed(store, 'k'), false, JSON.stringify(bad));
  }
});

test('the record is pruned to its bound', async () => {
  const store = fakeStore();
  for (let i = 0; i < 12; i++) {
    await markWarmed(store, warmupKey('m', `rev${i}`, 'q8'));
  }
  const entries = Object.keys(store.data[WARMUP_KEY]);
  assert.ok(entries.length <= 8, `expected <=8 entries, got ${entries.length}`);
});

test('the newest build is the one retained when pruning', async () => {
  const store = fakeStore();
  for (let i = 0; i < 12; i++) {
    await markWarmed(store, warmupKey('m', `rev${i}`, 'q8'));
  }
  const entries = store.data[WARMUP_KEY];
  assert.ok(entries[warmupKey('m', 'rev11', 'q8')], 'newest build must survive');
  assert.equal(entries[warmupKey('m', 'rev0', 'q8')], undefined, 'oldest build should be pruned');
});