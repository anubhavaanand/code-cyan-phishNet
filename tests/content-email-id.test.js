const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const { TextEncoder } = require('node:util');
const path = require('node:path');

function loadGetEmailId() {
  const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
  const anchor = '  /**\n   * Extract and scan email content';
  assert.ok(source.includes(anchor), 'content-script test hook insertion point');
  // Expose the private helper only inside this test VM; no production API.
  const withHook = source.replace(anchor, `
  currentSelectors = { selectors: {
    sender: '.sender', senderEmail: '.sender',
    subject: '.subject', subjectAlt: '.subject'
  } };
  root.__testGetEmailId = getEmailId;
${anchor}`);
  const root = { PhishNet: {} };
  runInNewContext(withHook, {
    globalThis: root,
    window: { addEventListener() {} },
    document: { readyState: 'loading', addEventListener() {} },
    location: { href: 'https://mail.google.com/' },
    TextEncoder,
    console
  });
  return root.__testGetEmailId;
}

function message({ sender = 'someone@example.com', subject = 'Monthly receipt',
  body = 'This message contains the receipt details', id } = {}) {
  return {
    dataset: id ? { messageId: id } : {},
    getAttribute: () => null,
    textContent: `${sender} ${subject} ${body}`,
    querySelector(selector) {
      if (selector === '.sender') return { textContent: sender };
      if (selector === '.subject') return { textContent: subject };
      return null;
    }
  };
}

test('provider-supplied message IDs take precedence over fallback hashing', () => {
  const getEmailId = loadGetEmailId();
  assert.equal(getEmailId(message({ id: 'provider-id-123' })), 'provider-id-123');
});

test('different messages with the same sender and subject get distinct scan IDs', () => {
  const getEmailId = loadGetEmailId();
  const first = message({ body: 'First receipt: number 1001' });
  const second = message({ body: 'Second receipt: number 1002' });
  assert.notEqual(getEmailId(first), getEmailId(second));
  assert.equal(getEmailId(first), getEmailId(first));
});

test('UTF-8 content and late differences are included in scan IDs', () => {
  const getEmailId = loadGetEmailId();
  const first = message({ subject: '配送状況', body: 'A'.repeat(128) + '注文一' });
  const second = message({ subject: '配送状況', body: 'A'.repeat(128) + '注文二' });
  assert.match(getEmailId(first), /^fallback-[0-9a-f]{16}$/);
  assert.notEqual(getEmailId(first), getEmailId(second));
  assert.equal(getEmailId(first), getEmailId(message({ subject: '配送状況', body: 'A'.repeat(128) + '注文一' })));
  assert.ok(!getEmailId(first).includes('注文'));
});
