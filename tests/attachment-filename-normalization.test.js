const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

test('attachment extraction retains extensionless and disguised dangerous filenames', () => {
  const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
  const marker = '  // Cleanup on unload';
  assert.ok(source.includes(marker));
  const instrumented = source.replace(marker,
    '  root.PhishNet.extractAttachmentsForTest = extractAttachments;\n' + marker);
  const root = { PhishNet: {} };
  runInNewContext(instrumented, {
    globalThis: root,
    window: { addEventListener() {} },
    document: { readyState: 'loading', addEventListener() {} },
    location: { href: 'https://mail.google.com/' },
    console
  });

  const names = [
    'README',
    'invoice.exe.  ',
    'install\u202Egnp.exe',
    'pay\u200Bload.scr',
    'a'.repeat(305) + '.exe',
    '   .   '
  ];
  const rows = names.map((name) => ({
    textContent: name,
    getAttribute: (attribute) => attribute === 'title' ? name : null,
    closest() { return this; }
  }));
  const email = {
    querySelectorAll: (selector) => selector === '[data-testid*="attachment"]' ? rows : []
  };

  const result = root.PhishNet.extractAttachmentsForTest(email);
  const actual = Array.from(result.items);
  assert.deepEqual(actual.slice(0, 4), ['README', 'invoice.exe', 'installgnp.exe', 'payload.scr']);
  assert.equal(actual.length, 5, 'an empty name must not count as an attachment');
  assert.ok(actual[4].endsWith('.exe'), 'long filenames must retain the dangerous extension');
  assert.ok(actual[4].length <= 255, 'huge DOM names must be bounded');
});
