import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import {
  buildReasons,
  collectUrls,
  collectSenderDomain,
  cleanUrl
} from '../src/utils/reason-builder.mjs';

const require = createRequire(import.meta.url);
const detector = require('../src/utils/heuristic-detector.js');

const build = (params) => buildReasons({ ...params, detector });

const PREDICTIONS = [
  { label: 'phishing_email', score: 0.94 },
  { label: 'phishing_url', score: 0.03 },
  { label: 'legitimate_url', score: 0.02 },
  { label: 'legitimate_email', score: 0.01 }
];

test('the verdict label produces its reason', () => {
  const reasons = build({ predictions: PREDICTIONS });
  assert.equal(reasons[0], 'Content matches phishing patterns');
});

test('a link hidden behind anchor text is still checked', () => {
  // The body has no literal URL, only the words "click here".
  const text = 'Dear customer, click here to restore your account.';
  const links = [{ href: 'https://secure-verify-login.tk', text: 'click here' }];

  const withoutLinks = build({ predictions: PREDICTIONS, text });
  assert.ok(!withoutLinks.some((r) => r.includes('suspicious link')),
    'text alone cannot see the anchor href');

  const withLinks = build({ predictions: PREDICTIONS, text, links });
  assert.ok(withLinks.some((r) => r.includes('suspicious link')),
    'a structured href must be checked');
});

test('the structured sender domain is used instead of scanning prose', () => {
  const text = 'Your account is locked. Contact support.';
  const sender = { name: 'Account Security', email: 'security@paypa1-verify.tk' };

  const withSender = build({ predictions: PREDICTIONS, text, sender });
  assert.ok(
    withSender.some((r) => r.includes('paypa1-verify.tk')),
    'the From header domain must be reported'
  );
});

test('sender.domain is preferred over the email form', () => {
  const sender = { email: 'someone@github.com', domain: 'paypa1-secure.tk' };
  const reasons = build({ predictions: PREDICTIONS, text: '', sender });
  assert.ok(reasons.some((r) => r.includes('paypa1-secure.tk')));
});

test('a sender domain that is only in prose is still found', () => {
  // No structured sender: the text fallback must keep working.
  const reasons = build({
    predictions: PREDICTIONS,
    text: 'write to billing@paypa1-secure.tk for help'
  });
  assert.ok(reasons.some((r) => r.includes('paypa1-secure.tk')));
});

test('a trusted sender domain produces no sender reason', () => {
  const reasons = build({
    predictions: PREDICTIONS,
    text: '',
    sender: { email: 'notifications@github.com' }
  });
  assert.ok(!reasons.some((r) => r.includes('sender domain')));
  assert.ok(!reasons.some((r) => r.includes('mimics')));
});

test('sentence punctuation does not corrupt a URL host', () => {
  assert.equal(cleanUrl('https://example.com.'), 'https://example.com');
  assert.equal(cleanUrl('https://bit.ly/3xYz,'), 'https://bit.ly/3xYz');
  assert.equal(cleanUrl('https://example.com/path).'), 'https://example.com/path');
  assert.equal(cleanUrl('https://example.com'), 'https://example.com');
});

test('a trailing-period phishing link is still counted as suspicious', () => {
  const text = 'Visit https://paypa1-secure.tk. now.';
  const reasons = build({ predictions: PREDICTIONS, text });
  assert.ok(reasons.some((r) => r.includes('suspicious link')));
});

test('structured links win over the text scan', () => {
  const links = [{ href: 'https://paypa1-secure.tk' }];
  const text = 'see https://github.com for the real thing';
  const urls = collectUrls({ links, text });
  assert.deepEqual(urls, ['https://paypa1-secure.tk']);
});

test('the text scan is used when no links are supplied', () => {
  assert.deepEqual(
    collectUrls({ text: 'a https://github.com and https://paypa1-secure.tk.' }),
    ['https://github.com', 'https://paypa1-secure.tk']
  );
});

test('a plain string link is accepted alongside link objects', () => {
  assert.deepEqual(
    collectUrls({ links: ['https://a.example', { href: 'https://b.example' }] }),
    ['https://a.example', 'https://b.example']
  );
});

test('an empty or malformed link list falls back to the text', () => {
  assert.deepEqual(collectUrls({ links: [], text: 'https://a.example' }), ['https://a.example']);
  assert.deepEqual(collectUrls({ links: null, text: 'https://a.example' }), ['https://a.example']);
  assert.deepEqual(collectUrls({ links: [null, 42, {}], text: 'x https://a.example' }), ['https://a.example']);
});

test('sender domain is lower-cased and trimmed', () => {
  assert.equal(collectSenderDomain({ sender: { domain: '  PayPa1-Secure.TK ' } }), 'paypa1-secure.tk');
  assert.equal(collectSenderDomain({ sender: { email: 'A@PayPa1-Secure.TK' } }), 'paypa1-secure.tk');
  assert.equal(collectSenderDomain({ text: 'x@y.example.' }), 'y.example');
});

test('no sender information yields null rather than a guess', () => {
  assert.equal(collectSenderDomain({}), null);
  assert.equal(collectSenderDomain({ sender: {} }), null);
  assert.equal(collectSenderDomain({ sender: { email: 'not-an-email' } }), null);
});

test('low confidence is reported against the configured threshold', () => {
  const borderline = [{ label: 'phishing_email', score: 0.72 }];
  const reasons = build({ predictions: borderline, settings: { sensitivityThreshold: 0.8 } });
  assert.ok(reasons.includes('Low confidence - manual review recommended'));
});

test('a confident prediction is not marked low confidence', () => {
  const reasons = build({ predictions: PREDICTIONS, settings: { sensitivityThreshold: 0.7 } });
  assert.ok(!reasons.includes('Low confidence - manual review recommended'));
});

test('urgency keywords are reported from the text', () => {
  const reasons = build({ predictions: PREDICTIONS, text: 'URGENT: verify your account now' });
  assert.ok(reasons.some((r) => r.includes('urgency keywords')));
});

test('structured HTML form signal is reported alongside ML reasons', () => {
  const withForm = build({ predictions: PREDICTIONS, text: 'Hello', hasFormElements: true });
  const withoutForm = build({ predictions: PREDICTIONS, text: 'Hello', hasFormElements: false });
  assert.ok(withForm.includes('Interactive form elements inside email'));
  assert.ok(!withoutForm.includes('Interactive form elements inside email'));
});

test('reasons are capped at five and de-duplicated', () => {
  const reasons = build({
    predictions: PREDICTIONS,
    text: 'urgent verify account suspended click here https://a.tk https://b.tk',
    sender: { email: 'x@paypa1-secure.tk' },
    links: [{ href: 'https://c.tk' }, { href: 'https://d.tk' }]
  });
  assert.ok(reasons.length <= 5, `expected <=5, got ${reasons.length}`);
  assert.equal(new Set(reasons).size, reasons.length);
});

test('an empty prediction set does not throw', () => {
  assert.deepEqual(build({ predictions: [] }), []);
});

test('a missing detector does not throw', () => {
  const reasons = buildReasons({ predictions: PREDICTIONS, text: 'verify your account' });
  assert.ok(Array.isArray(reasons));
  assert.ok(reasons.length > 0);
});
