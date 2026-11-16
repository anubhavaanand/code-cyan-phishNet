const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

test('email link extraction bounds work and reports omitted anchors', () => {
  const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
  const marker = '  // Cleanup on unload';
  assert.ok(source.includes(marker));
  const instrumented = source.replace(marker, '  root.PhishNet.extractLinksForTest = extractLinks;\n' + marker);
  const root = { PhishNet: {} };
  runInNewContext(instrumented, {
    globalThis: root,
    window: { addEventListener() {} },
    document: { readyState: 'loading', addEventListener() {} },
    location: { href: 'https://mail.google.com/' },
    console
  });

  let inspected = 0;
  const anchors = Array.from({ length: 125 }, (_, i) => ({
    getAttribute(name) {
      if (name === 'href') { inspected++; return `https://example.org/${i}`; }
      return null;
    },
    textContent: `Link ${i}`
  }));
  const element = { querySelectorAll: () => anchors };
  const result = root.PhishNet.extractLinksForTest(element);
  assert.equal(result.links.length, 100);
  assert.equal(result.links[0].href, 'https://example.org/0');
  assert.equal(result.links[99].href, 'https://example.org/99');
  assert.equal(result.truncated, true);
  assert.equal(inspected, 100, 'later links must not undergo per-link processing');

  const short = root.PhishNet.extractLinksForTest({ querySelectorAll: () => anchors.slice(0, 2) });
  assert.equal(short.links.length, 2);
  assert.equal(short.truncated, false);
});
