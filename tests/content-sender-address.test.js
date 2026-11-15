const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

// Run the actual content-script extractor with a minimal Outlook DOM fixture.
// The function is private to its IIFE, so isolate its source without executing
// the observer, service-worker messages, or presentation code.
const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
const start = source.indexOf('  function extractEmailContent(element) {');
const end = source.indexOf('\n  /**\n   * Extract links from email', start);
assert.ok(start !== -1 && end > start, 'production extraction function should be present');
const extracted = source.slice(start, end);

const node = (text, attrs = {}) => ({
  textContent: text,
  getAttribute: (name) => attrs[name] ?? null,
  querySelectorAll: () => [],
  cloneNode() { return this; }
});

function extractSender({ name, address, nameEmail, emailAttr } = {}) {
  const elements = {
    '[data-testid="message-header-sender-name"]': name ? node(name, nameEmail ? { email: nameEmail } : {}) : null,
    '[data-testid="message-header-sender-email"]': address ? node(address, emailAttr ? { email: emailAttr } : {}) : null,
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
