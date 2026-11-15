const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');
const { EMAIL_SELECTORS } = require('../src/selectors.js');

test('Outlook sender extraction preserves display name and reads sibling email address', () => {
  const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
  const marker = '\n})();';
  assert.ok(source.includes(marker), 'content script has expected wrapper');
  const instrumented = source.replace(marker, `
  globalThis.__extractForTest = (element, selectors) => {
    currentSelectors = { selectors };
    return extractEmailContent(element);
  };
})();`);
  const sandbox = {
    globalThis: { PhishNet: {} },
    window: { addEventListener() {} },
    document: { readyState: 'loading', addEventListener() {} },
    console
  };
  runInNewContext(instrumented, sandbox);
  const nameNode = { textContent: 'PayPal Billing', getAttribute: () => null };
  const emailNode = { textContent: 'billing@paypa1.example.org', getAttribute: () => null };

  for (const variant of ['outlook', 'outlookCom', 'outlookOffice365']) {
    const selectors = EMAIL_SELECTORS[variant];
    const message = {
      closest() { return this; },
      querySelector(selector) {
        if (selector === selectors.sender) return nameNode;
        if (selector === selectors.senderEmail) return emailNode;
        return null;
      },
      querySelectorAll() { return []; }
    };
    const sender = sandbox.globalThis.__extractForTest(message, selectors).sender;
    assert.equal(sender.name, 'PayPal Billing', variant);
    assert.equal(sender.email, 'billing@paypa1.example.org', variant);
    assert.equal(sender.domain, 'paypa1.example.org', variant);
  }
});
