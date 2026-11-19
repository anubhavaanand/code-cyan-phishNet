const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

// Run the actual content-script extractor with a minimal Outlook DOM fixture.
// The function is private to its IIFE, so isolate its source without executing
// the observer, service-worker messages, or presentation code.
const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
// The extractor delegates to two helpers and a length constant, all defined
// earlier in the same IIFE, so slice from the first of them.
const start = source.indexOf('  /**\n   * Regions that hold metadata rather than message content.');
const end = source.indexOf('\n  /**\n   * Extract links from email', start);
assert.ok(start !== -1 && end > start, 'production extraction function should be present');
const extracted = source.slice(start, end);

const node = (text, attrs = {}) => ({
  textContent: text,
  getAttribute: (name) => attrs[name] ?? null,
  querySelectorAll: () => [],
  cloneNode() { return this; }
});

function extractSender({ name, address, nameEmail, nameTitle, emailAttr, addressTitle } = {}) {
  const elements = {
    '[data-testid="message-header-sender-name"]': name ? node(name, { ...(nameEmail ? { email: nameEmail } : {}), ...(nameTitle ? { title: nameTitle } : {}) }) : null,
    '[data-testid="message-header-sender-email"]': address ? node(address, { ...(emailAttr ? { email: emailAttr } : {}), ...(addressTitle ? { title: addressTitle } : {}) }) : null,
    '[data-testid="message-body-content"]': node('Please review the attached message body.')
  };
  const element = {
    querySelector: (selector) => elements[selector] ?? null,
    closest: () => null
  };
  const selectors = {
    sender: '[data-testid="message-header-sender-name"]',
    senderEmail: '[data-testid="message-header-sender-email"]',
    messageBody: '[data-testid="message-body-content"]'
  };
  const query = (base, candidates) => {
    if (!base) return null;
    return (Array.isArray(candidates) ? candidates : [candidates])
      .map((selector) => base.querySelector(selector)).find(Boolean) ?? null;
  };
  const context = {
    currentSelectors: { provider: 'outlook', selectors },
    safeQuery: query,
    safeText: (el) => (el?.textContent ?? '').trim(),
    safeAttr: (el, attr) => el?.getAttribute(attr) ?? '',
    UTILITY_SELECTORS: { skipElements: [] },
    BODY_TEXT_LIMIT: 12000,
    document: { querySelector: () => null },
    extractLinks: () => [],
    extractAttachments: () => []
  };
  const extract = runInNewContext(extracted + '\nextractEmailContent', context);
  return extract(element).sender;
}

test('Outlook reads a separate sender address even when the display name matches first', () => {
  const sender = extractSender({ name: 'Microsoft Support', address: 'attacker@micros0ft.example' });
  assert.equal(sender.name, 'Microsoft Support');
  assert.equal(sender.email, 'attacker@micros0ft.example');
  assert.equal(sender.domain, 'micros0ft.example');
});

test('dedicated Outlook email attribute takes priority over the display-name field', () => {
  const sender = extractSender({
    name: 'Trusted Support', nameEmail: 'support@example.com',
    address: 'Sender contact', emailAttr: 'phish@lookalike.example'
  });
  assert.equal(sender.name, 'Trusted Support');
  assert.equal(sender.email, 'phish@lookalike.example');
  assert.equal(sender.domain, 'lookalike.example');
});

test('falls back to sender attributes when the dedicated address node is absent', () => {
  const sender = extractSender({ name: 'Legitimate sender', nameEmail: 'user@example.org' });
  assert.equal(sender.email, 'user@example.org');
  assert.equal(sender.domain, 'example.org');
});

test('a tooltip with an embedded email cannot supply a false trusted sender', () => {
  const sender = extractSender({
    name: 'Security Desk',
    nameTitle: 'Trusted Support <support@trusted.example>',
    address: 'Display name',
    addressTitle: 'Forwarded by attacker@evil.example',
  });
  assert.equal(sender.email, '');
  assert.equal(sender.domain, '');
});

test('email attributes take precedence over a misleading tooltip', () => {
  const sender = extractSender({
    name: 'Trusted Support',
    nameEmail: 'phish@lookalike.example',
    nameTitle: 'trusted@example.org',
  });
  assert.equal(sender.email, 'phish@lookalike.example');
  assert.equal(sender.domain, 'lookalike.example');
});

test('malformed email fields cannot smuggle in an embedded address', () => {
  const sender = extractSender({
    name: 'Account Support',
    nameEmail: 'attacker@evil.example via trusted.example',
    address: 'Not an email',
    addressTitle: 'help@trusted.example (unverified)',
  });
  assert.equal(sender.email, '');
  assert.equal(sender.domain, '');
});
