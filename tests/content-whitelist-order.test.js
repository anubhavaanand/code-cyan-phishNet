const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');

test('sender trust is checked before scanning, without a short-message cutoff', () => {
  const content = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
  const whitelist = content.indexOf('if (isWhitelisted) {');
  const hasSignals = content.indexOf('const hasSignals =');
  const modelScan = content.indexOf("type: 'SCAN_EMAIL'");

  assert.ok(whitelist !== -1 && hasSignals !== -1 && modelScan !== -1);
  assert.ok(whitelist < hasSignals, 'explicit sender trust must take precedence over scanning');
  assert.ok(hasSignals < modelScan, 'only messages without any usable signals should be deferred');
  assert.ok(!content.includes('emailContent.text.length < 15'), 'short phishing messages must be scanned');
});
