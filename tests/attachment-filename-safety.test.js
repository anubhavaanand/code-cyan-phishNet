const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

test('attachment extraction normalizes deceptive names without dropping extensionless files', () => {
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

  const filenames = [
    'payload.exe.  ',
    'pay\u200bload.js',
    '\u202ereport.cmd\u202c',
    'README',
    'a'.repeat(130) + '.exe',
    '...   ',
    '   '
  ];
  const rows = filenames.map(name => ({
    textContent: name,
    getAttribute(key) { return key === 'title' ? name : null; },
    closest() { return this; }
  }));
  const element = {
    querySelectorAll(selector) { return selector === '[data-testid*="attachment"]' ? rows : []; }
  };
  const result = root.PhishNet.extractAttachmentsForTest(element);
  assert.deepEqual(Array.from(result.items), [
    'payload.exe', 'payload.js', 'report.cmd', 'README', 'a'.repeat(96) + '.exe'
  ]);
  assert.equal(result.truncated, false);
});
