const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

test('Outlook attachment size labels and wrappers are not counted as files', () => {
  const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
  const marker = '  // Cleanup on unload';
  assert.ok(source.includes(marker));
  const instrumented = source.replace(marker, `
  currentSelectors = { provider: 'outlook', selectors: {
    attachmentNames: '[data-testid="attachment-name"]',
    attachmentSizes: '[data-testid="attachment-size"]',
    attachments: '[data-testid*="attachment"]'
  } };
  root.PhishNet.extractAttachmentsForTest = extractAttachments;
` + marker);
  const root = { PhishNet: {} };
  runInNewContext(instrumented, {
    globalThis: root,
    window: { addEventListener() {} },
    document: { readyState: 'loading', addEventListener() {} },
    location: { href: 'https://outlook.com/mail/' },
    console
  });

  const name = {
    textContent: 'invoice.pdf',
    getAttribute: (attr) => ({ 'data-testid': 'attachment-name', title: 'invoice.pdf' })[attr] || null,
    querySelector: () => null,
    matches: () => false,
    closest() { return this; }
  };
  const size = {
    textContent: '1.2 MB',
    getAttribute: (attr) => ({ 'data-testid': 'attachment-size', title: '1.2 MB' })[attr] || null,
    querySelector: () => null,
    matches: (selector) => selector === '[data-testid="attachment-size"]',
    closest() { return this; }
  };
  const wrapper = {
    textContent: 'invoice.pdf 1.2 MB',
    getAttribute: (attr) => attr === 'data-testid' ? 'attachment-row' : null,
    querySelector: (selector) => selector === '[data-testid="attachment-name"]' ? name : null,
    matches: () => false,
    closest() { return this; }
  };
  const email = {
    querySelectorAll(selector) {
      if (selector === '[data-testid="attachment-name"]') return [name];
      if (selector === '[data-testid*="attachment"]') return [wrapper, name, size];
      return [];
    }
  };

  const result = root.PhishNet.extractAttachmentsForTest(email);
  assert.deepEqual(Array.from(result.items), ['invoice.pdf']);
  assert.equal(result.truncated, false);
});
