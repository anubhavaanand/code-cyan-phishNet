const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const path = require('node:path');

test('sender trust is checked before an entirely empty email is skipped', () => {
  const content = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
  const whitelist = content.indexOf('if (isWhitelisted) {');
  const emptyEmail = content.indexOf('if (!hasEmailSignals) {');
  const modelScan = content.indexOf("type: 'SCAN_EMAIL'");

  assert.ok(whitelist !== -1 && emptyEmail !== -1 && modelScan !== -1);
  assert.ok(whitelist < emptyEmail, 'trusted senders should be checked before empty-content handling');
  assert.ok(emptyEmail < modelScan, 'messages with no signals need no model scan');
  assert.doesNotMatch(content, /emailContent\.text\.length\s*<\s*15/, 'short messages must be scanned');
});
