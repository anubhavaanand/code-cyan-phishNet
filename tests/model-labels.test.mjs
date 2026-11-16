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
    assert.equal(resolveLabelName(name), name);
  }
});

test('a renamed checkpoint is resolved by its label semantics, not its position', () => {
  // `POSITIVE` is the phishing class here, but it sits at index 0, where the
  // old `LABEL_0 -> legitimate_email` table would have called it legitimate.
  assert.equal(resolveLabelName('POSITIVE'), 'phishing_email');
  assert.equal(resolveLabelName('NEGATIVE'), 'legitimate_email');
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
  assert.equal(resolveLabelName('safe_link'), 'legitimate_url');
  assert.equal(resolveLabelName('malicious_message'), 'phishing_email');
  assert.equal(resolveLabelName('suspicious_mail'), 'phishing_email');
  assert.equal(resolveLabelName('unsafe_url'), 'phishing_url');
  assert.equal(resolveLabelName('benign_body'), 'legitimate_email');
});

test('a polarity word alone is never given a modality by its slot', () => {
  // `phishing` alone does not say it judges URLs, so guessing would put a URL
  // verdict on an email.
  assert.equal(resolveLabelName('phishing'), null);
  assert.equal(resolveLabelName('safe'), null);
  assert.equal(resolveLabelName('totally-unknown'), null);
});

test('an opaque LABEL_n id is mapped by class id, never by rank', () => {
  assert.equal(resolveLabelName('LABEL_2'), 'legitimate_url');
  assert.equal(resolveLabelName('label_1'), 'phishing_email');
  assert.equal(resolveLabelName('LABEL_0'), 'legitimate_email');
  assert.equal(resolveLabelName('LABEL_3'), 'phishing_url');
  // A class id outside the four-class layout is unmappable.
  assert.equal(resolveLabelName('LABEL_9'), null);
});

test('a score-sorted topk result keeps the winning class as the verdict', () => {
  // ONNX TopK returns results sorted by score descending, so LABEL_1 lands at
  // array index 0. Reading the index as a class slot dropped LABEL_0/LABEL_1
  // and reported a 3% loser as the verdict.
  const topk = [
    { label: 'LABEL_1', score: 0.88 },
    { label: 'LABEL_0', score: 0.07 },
    { label: 'LABEL_2', score: 0.03 },
    { label: 'LABEL_3', score: 0.02 }
  ];
  const predictions = normalizePredictions(topk);
  assert.equal(predictions.length, 4);
  assert.equal(predictions[0].label, 'phishing_email');
  assert.equal(predictions[0].score, 0.88);
  assert.deepEqual(
    predictions.map(p => p.label),
    ['phishing_email', 'legitimate_email', 'legitimate_url', 'phishing_url']
  );
});

test('the checkpoint id2label table outranks the number in the label', () => {
  // A checkpoint that reordered its classes emits LABEL_2 for what PhishNet
  // calls `phishing_email`. The table is authoritative.
  const id2label = { 0: 'LABEL_0', 1: 'LABEL_2', 2: 'LABEL_3', 3: 'LABEL_1' };
  assert.equal(resolveLabelName('LABEL_2', id2label), 'phishing_email');
  assert.equal(resolveLabelName('LABEL_0', id2label), 'legitimate_email');
  assert.equal(resolveLabelName('LABEL_3', id2label), 'legitimate_url');
  assert.equal(resolveLabelName('LABEL_1', id2label), 'phishing_url');
});

test('a label the id2label table does not declare is dropped', () => {
  const id2label = { 0: 'LABEL_0', 1: 'LABEL_1' };
  assert.equal(resolveLabelName('LABEL_2', id2label), null);
});

test('normalizePredictions passes the id2label table through', () => {
  const id2label = { 0: 'LABEL_0', 1: 'LABEL_2', 2: 'LABEL_3', 3: 'LABEL_1' };
  const predictions = normalizePredictions(
    [{ label: 'LABEL_2', score: 0.9 }, { label: 'LABEL_0', score: 0.1 }],
    id2label
  );
  assert.equal(predictions[0].label, 'phishing_email');
  assert.equal(predictions[1].label, 'legitimate_email');
});

test('an unrecognisable label is dropped rather than guessed', () => {
  assert.equal(resolveLabelName('class-weird'), null);
  assert.equal(resolveLabelName(''), null);
  assert.equal(resolveLabelName(undefined), null);
  assert.equal(resolveLabelName(null), null);
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