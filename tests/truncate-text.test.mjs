import test from 'node:test';
import assert from 'node:assert/strict';
import { truncateText } from '../src/utils/truncate-text.mjs';

test('retains ordinary text up to its approximate token budget', () => {
  assert.equal(truncateText('123456789', 2), '12345678');
  assert.equal(truncateText('12345678', 2), '12345678');
  assert.equal(truncateText('', 2), '');
});

test('does not split a surrogate pair at the boundary', () => {
  assert.equal(truncateText('1234567💌rest', 2), '1234567');
  assert.equal(truncateText('123456💌rest', 2), '123456💌');
  assert.equal(truncateText('1234567🔐rest', 2), '1234567');
});

test('preserves non-surrogate Unicode at the boundary', () => {
  assert.equal(truncateText('日本語安全e-mail', 1), '日本語安');
});

test('cuts on a word boundary instead of mid-word', () => {
  // 8 chars is the budget at 2 tokens; a raw slice gives "verify y".
  assert.equal(truncateText('verify your account now', 2), 'verify');
  assert.equal(truncateText('hello world this is long', 2), 'hello');
});

test('prefers the last boundary that keeps most of the budget', () => {
  // The last space inside "hello world this..." sits at 11, past the 8-char
  // budget. Backing off to it would throw away a third of the allowed text,
  // so the earlier boundary at 5 is the better cut.
  assert.equal(truncateText('hello world this is a long email body', 2), 'hello');
});

test('keeps as much text as it can when one early space dominates', () => {
  // The only space in range is at index 1, well below the 60% floor, so the
  // text is cut hard rather than reduced to a single character.
  assert.equal(truncateText('a bbbbbbbbbbbbbbbbbbbbbbbbbb', 2), 'a bbbbbb');
});

test('falls back to a hard cut when the budget holds no whitespace', () => {
  assert.equal(truncateText('abcdefghijklmnop', 2), 'abcdefgh');
  assert.equal(truncateText('日本語安全無事です', 1), '日本語安');
});

test('a non-positive or non-finite budget yields empty text', () => {
  assert.equal(truncateText('some text', 0), '');
  assert.equal(truncateText('some text', -1), '');
  assert.equal(truncateText('some text', NaN), '');
  assert.equal(truncateText('some text', undefined), '');
});

test('falsy input yields an empty string', () => {
  assert.equal(truncateText('', 4), '');
  assert.equal(truncateText(null, 4), '');
  assert.equal(truncateText(undefined, 4), '');
});

test('text shorter than the budget is returned unchanged', () => {
  const short = 'short body';
  assert.equal(truncateText(short, 512), short);
});