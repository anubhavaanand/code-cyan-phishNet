import test from 'node:test';
import assert from 'node:assert/strict';
import { createInferenceGuard, INFERENCE_TIMEOUT_MS } from '../src/utils/inference-guard.mjs';

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));

test('the default timeout matches the 15s budget the UI quotes', () => {
  assert.equal(INFERENCE_TIMEOUT_MS, 15000);
});

test('a run that finishes in time resolves', async () => {
  const guard = createInferenceGuard(50);
  const run = guard.begin('r1');
  await assert.doesNotReject(() => guard.run(Promise.resolve('ok'), run));
  assert.equal(await guard.run(Promise.resolve('ok'), run), 'ok');
});

test('a slow run rejects and marks itself timed out', async () => {
  const guard = createInferenceGuard(20);
  const run = guard.begin('r1');
  const work = tick(200).then(() => 'late');
  await assert.rejects(() => guard.run(work, run), /Inference timeout after 20ms/);
  assert.equal(run.timedOut, true);
});

test('a superseded run is no longer current', () => {
  const guard = createInferenceGuard(1000);
  const first = guard.begin('r1');
  assert.equal(guard.isCurrent(first), true);

  const second = guard.begin('r2');
  assert.equal(guard.isCurrent(second), true);
  assert.equal(guard.isCurrent(first), false);
});

test('the first run notices it was superseded before it can finish', async () => {
  const guard = createInferenceGuard(1000);
  const first = guard.begin('r1');
  let firstFinished = false;

  const firstWork = (async () => {
    await tick(20);
    // What runInference does after the model returns.
    if (!guard.isCurrent(first)) throw new Error('superseded');
    firstFinished = true;
    return 'first';
  })();

  const firstPromise = guard.run(firstWork, first);
  guard.begin('r2'); // a newer scan arrives while the first is running

  await assert.rejects(() => firstPromise, /superseded/);
  assert.equal(firstFinished, false, 'superseded run must not produce a result');
});

test('only the request that owns the current run may reply', () => {
  const guard = createInferenceGuard(1000);
  const first = guard.begin('r1');
  guard.begin('r2');

  assert.equal(guard.owns('r1'), false);
  assert.equal(guard.owns('r2'), true);
  assert.equal(guard.owns(undefined), false);
  assert.equal(guard.owns(null), false);
});

test('a run id is only owned while its run is current', () => {
  const guard = createInferenceGuard(1000);
  guard.begin('r1');
  assert.equal(guard.owns('r1'), true);
  guard.reset();
  assert.equal(guard.owns('r1'), false);
  assert.equal(guard.isCurrent(null), false);
});

test('the timeout timer is cleared when the run wins the race', async () => {
  const guard = createInferenceGuard(10);
  const run = guard.begin('r1');
  await guard.run(Promise.resolve('fast'), run);
  // If the timer survived the race it would fire later and mark the run.
  await tick(30);
  assert.equal(run.timedOut, false);
});

test('a rejected run still clears its timer', async () => {
  const guard = createInferenceGuard(10);
  const run = guard.begin('r1');
  await assert.rejects(() => guard.run(Promise.reject(new Error('model died')), run), /model died/);
  await tick(30);
  assert.equal(run.timedOut, false);
});