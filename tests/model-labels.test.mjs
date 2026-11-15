import test from 'node:test';
import assert from 'node:assert/strict';
import {
  CANONICAL_LABELS,
  normalizePredictions,
  labelSpaceSize,
  resolveLabelName
} from '../src/utils/model-labels.mjs';

test('the pinned model\'s four class names resolve to themselves', () => {
  for (const name of CANONICAL_LABELS) {
    assert.equal(resolveLabelName(name, 0), name);
  }
});

test('a renamed checkpoint is resolved by its label semantics, not its position', () => {
  // `POSITIVE` is the phishing class here, but it sits at index 0, where the
  // old `LABEL_0 -> legitimate_email` table would have called it legitimate.
  assert.equal(resolveLabelName('POSITIVE', 0), 'phishing_email');
  assert.equal(resolveLabelName('NEGATIVE', 1), 'legitimate_email');
  assert.equal(resolveLabelName('NEGATIVE', 3), 'legitimate_email');
});

test('class order alone no longer decides the verdict', () => {
  const results = [
    { label: 'phishing_url', score: 0.97 },
    { label: 'legitimate_url', score: 0.02 },
    { label: 'phishing_email', score: 0.007 },
    { label: 'legitimate_email', score: 0.003 }
  ];
  const [top] = normalizePredictions(results);
  assert.equal(top.label, 'phishing_url');
  assert.equal(top.score, 0.97);
});

test('URL and email classes stay apart when names are descriptive', () => {
  assert.equal(resolveLabelName('safe_link', 0), 'legitimate_url');
  assert.equal(resolveLabelName('malicious_message', 1), 'phishing_email');
  assert.equal(resolveLabelName('suspicious_mail', 1), 'phishing_email');
  assert.equal(resolveLabelName('unsafe_url', 3), 'phishing_url');
  assert.equal(resolveLabelName('benign_body', 0), 'legitimate_email');
});

test('a polarity word alone is never given a modality by its slot', () => {
  // Slot 3 holds the phishing URL class, but `phishing` alone does not say it
  // judges URLs, so guessing would put a URL verdict on an email.
  assert.equal(resolveLabelName('phishing', 1), null);
  assert.equal(resolveLabelName('phishing', 3), null);
  assert.equal(resolveLabelName('safe', 0), null);
  assert.equal(resolveLabelName('totally-unknown', 0), null);
});

test('an opaque LABEL_n id is only mapped by position', () => {
  assert.equal(resolveLabelName('LABEL_2', 2), 'legitimate_url');
  assert.equal(resolveLabelName('label_1', 1), 'phishing_email');
  // A binary model has no four-class layout, so positional guessing stops.
  assert.equal(resolveLabelName('LABEL_1', 5), null);
  assert.equal(resolveLabelName('LABEL_9', 1), null);
});

test('an unrecognisable label is dropped rather than guessed', () => {
  assert.equal(resolveLabelName('class-weird', 0), null);
  assert.equal(resolveLabelName('', 0), null);
  assert.equal(resolveLabelName(undefined, 0), null);
  assert.equal(resolveLabelName(null, 1), null);
});

test('normalizePredictions sorts best-first and keeps the raw label', () => {
  const predictions = normalizePredictions([
    { label: 'legitimate_email', score: 0.1 },
    { label: 'phishing_email', score: 0.9 }
  ]);
  assert.deepEqual(predictions.map(p => p.label), ['phishing_email', 'legitimate_email']);
  assert.equal(predictions[0].rawLabel, 'phishing_email');
});

test('normalizePredictions tolerates a single object and missing scores', () => {
  const single = normalizePredictions({ label: 'phishing_email', score: 0.5 });
  assert.equal(single.length, 1);
  assert.equal(single[0].label, 'phishing_email');

  const noScore = normalizePredictions([{ label: 'phishing_email' }]);
  assert.equal(noScore[0].score, 0);

  const badScore = normalizePredictions([{ label: 'phishing_email', score: 'nope' }]);
  assert.equal(badScore[0].score, 0);
});

test('all four classes survive normalization when all four are returned', () => {
  const predictions = normalizePredictions([
    { label: 'phishing_email', score: 0.4 },
    { label: 'legitimate_email', score: 0.3 },
    { label: 'phishing_url', score: 0.2 },
    { label: 'legitimate_url', score: 0.1 }
  ]);
  assert.equal(predictions.length, 4);
  assert.equal(new Set(predictions.map(p => p.label)).size, 4);
});

test('labelSpaceSize asks for every class the checkpoint declares', () => {
  assert.equal(labelSpaceSize({ model: { config: { id2label: { 0: 'a', 1: 'b' } } } }), 4);
  assert.equal(labelSpaceSize({ model: { config: { id2label: { 0: 'a', 1: 'b', 2: 'c' } } } }), 4);
  assert.equal(
    labelSpaceSize({ model: { config: { id2label: { 0: 'a', 1: 'b', 2: 'c', 3: 'd', 4: 'e' } } } }),
    5
  );
});

test('labelSpaceSize falls back to four when the pipeline exposes no config', () => {
  assert.equal(labelSpaceSize(null), 4);
  assert.equal(labelSpaceSize({}), 4);
  assert.equal(labelSpaceSize({ model: {} }), 4);
  assert.equal(labelSpaceSize({ model: { config: {} } }), 4);
});