const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

test('attachment extraction bounds payload and reports unexamined entries', () => {
  const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
  const marker = '  // Cleanup on unload';
  assert.ok(source.includes(marker));
  const instrumented = source.replace(marker, '  root.PhishNet.extractAttachmentsForTest = extractAttachments;\n' + marker);
  const root = { PhishNet: {} };
  runInNewContext(instrumented, {
    globalThis: root,
    window: { addEventListener() {} },
    document: { readyState: 'loading', addEventListener() {} },
    location: { href: 'https://mail.google.com/' },
    console
  });

  let examined = 0;
  const rows = Array.from({ length: 75 }, (_, i) => ({
    textContent: `report-${i}.pdf`,
    getAttribute(key) {
      if (key === 'title') examined++;
      return key === 'title' ? `report-${i}.pdf` : null;
    },
    closest() { return this; }
  }));
  const element = {
    querySelectorAll(selector) { return selector === '[data-testid*="attachment"]' ? rows : []; }
  };
  const result = root.PhishNet.extractAttachmentsForTest(element);
  assert.equal(result.items.length, 50);
  assert.equal(result.items[49], 'report-49.pdf');
  assert.equal(result.truncated, true);
  assert.equal(examined, 50, 'entries past the limit must not be processed');

  const small = root.PhishNet.extractAttachmentsForTest({
    querySelectorAll: (selector) => selector === '[data-testid*="attachment"]' ? rows.slice(0, 2) : []
  });
  assert.equal(small.items.length, 2);
  assert.equal(small.truncated, false);
});
