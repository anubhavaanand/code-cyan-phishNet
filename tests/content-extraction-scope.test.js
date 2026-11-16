const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { runInNewContext } = require('node:vm');
const path = require('node:path');

/**
 * Extraction scope tests.
 *
 * The extractor must read the current message only: not the sender or subject
 * lines, not quoted replies, and not the page around it. Each case here drives
 * the real `extractEmailContent` with a small DOM fixture.
 */
const source = readFileSync(path.resolve(__dirname, '../src/content.js'), 'utf8');
const start = source.indexOf('  /**\n   * Regions that hold metadata rather than message content.');
// The links helper is part of the contract under test, so include it too.
const end = source.indexOf('\n  /**\n   * Extract attachment filenames from email', start);
assert.ok(start !== -1 && end > start, 'production extraction function should be present');
const extracted = source.slice(start, end);

/** A node with children, text and attribute lookup. */
function element(tag, { text = '', attrs = {}, children = [], className = '' } = {}) {
  const node = {
    tag,
    className,
    attributes: attrs,
    children: [],
    parent: null,
    __text: text,
    get textContent() {
      return [node.__text, ...node.children.map((c) => c.textContent)].join('');
    },
    getAttribute: (name) => attrs[name] ?? null,
    querySelector: (sel) => queryAll(node, sel)[0] ?? null,
    querySelectorAll: (sel) => queryAll(node, sel),
    closest: (sel) => {
      let current = node;
      while (current) {
        if (matches(current, sel)) return current;
        current = current.parent;
      }
      return null;
    },
    cloneNode() {
      return element(tag, {
        text,
        attrs: { ...attrs },
        className,
        children: children.map((c) => c.cloneNode())
      });
    },
    remove() {
      if (node.parent) node.parent.children = node.parent.children.filter((c) => c !== node);
    }
  };
  children.forEach((c) => { c.parent = node; node.children.push(c); });
  return node;
}

/** Very small selector support: tag, .class, #id, [attr], tag[attr], descendants. */
function matches(node, selector) {
  return selector.split(',').some((part) => {
    let sel = part.trim();
    if (!sel) return false;
    const last = sel.split(/\s+/).pop();
    if (last !== sel) return matches(node, last);

    const attr = /\[([\w-]+)(?:="([^"]*)")?\]/.exec(sel);
    if (attr) {
      const value = node.attributes[attr[1]];
      if (value === undefined) return false;
      if (attr[2] !== undefined && value !== attr[2]) return false;
      const tag = sel.slice(0, attr.index).trim();
      return tag === '' || node.tag === tag;
    }
    if (sel.startsWith('.')) return String(node.className).split(/\s+/).includes(sel.slice(1));
    if (sel.startsWith('#')) return node.attributes.id === sel.slice(1);
    return node.tag === sel;
  });
}

function descendants(node, out = []) {
  for (const child of node.children) {
    out.push(child);
    descendants(child, out);
  }
  return out;
}

function queryAll(root, selector) {
  return descendants(root).filter((n) => matches(n, selector));
}

/** Build an extraction context around a fixture root. */
function extractWith(rootElement, { selectors = {}, attachments = [] } = {}) {
  const context = {
    currentSelectors: { provider: 'gmail', selectors },
    safeQuery: (base, candidates) => {
      if (!base) return null;
      const list = Array.isArray(candidates) ? candidates : [candidates];
      for (const selector of list) {
        const hit = queryAll(base, selector)[0];
        if (hit) return hit;
      }
      return null;
    },
    safeText: (el, max = 3000) => {
      const raw = String(el?.textContent ?? '').trim();
      return raw.length > max ? raw.slice(0, max) : raw;
    },
    safeAttr: (el, attr) => el?.getAttribute?.(attr) ?? '',
    UTILITY_SELECTORS: { skipElements: [] },
    BODY_TEXT_LIMIT: 12000,
    MAX_EXTRACTED_LINKS: 100,
    document: { querySelector: () => null },
    extractAttachments: () => attachments,
    PhishNet: { isUrlSuspicious: () => false }
  };
  const extract = runInNewContext(extracted + '\nextractEmailContent', context);
  return extract(rootElement);
}

test('body text excludes the sender and subject lines when no body node matches', () => {
  const subject = element('h2', { text: 'Your account is suspended', className: 'subject' });
  const sender = element('span', { text: 'security@paypa1.com', className: 'sender' });
  const body = element('div', { text: 'Please confirm your password today.' });
  const root = element('div', { children: [subject, sender, body] });

  const result = extractWith(root, {
    selectors: { subject: '.subject', sender: '.sender' }
  });

  // `text` is subject + body by design; `body` is the scanned message content.
  assert.ok(result.body.includes('Please confirm your password today.'));
  assert.equal(result.body.includes('Your account is suspended'), false,
    'the subject line must not be scanned as body text');
  assert.equal(result.body.includes('security@paypa1.com'), false,
    'the sender line must not be scanned as body text');
});

test('body text keeps content when a dedicated body node matches', () => {
  const header = element('div', { text: 'Sender Name', className: 'sender' });
  const body = element('div', { text: 'Real message content here.', className: 'message-body' });
  const root = element('div', { children: [header, body] });

  const result = extractWith(root, {
    selectors: { sender: '.sender', messageBody: '.message-body' }
  });

  assert.ok(result.text.includes('Real message content here.'));
});

test('image-only links get display text from alt text', () => {
  const img = element('img', { attrs: { alt: 'Verify your account' } });
  const anchor = element('a', { attrs: { href: 'https://evil.example/' }, children: [img] });
  const root = element('div', { children: [anchor] });

  const result = extractWith(root, { selectors: {} });

  const link = result.links.find((l) => String(l.href) === 'https://evil.example/');
  assert.ok(link, 'the link must be extracted');
  assert.equal(link.text, 'Verify your account');
});

test('an image link with no alt text is still marked as an image link', () => {
  const img = element('img');
  const anchor = element('a', { attrs: { href: 'https://evil.example/x' }, children: [img] });
  const root = element('div', { children: [anchor] });

  const result = extractWith(root, { selectors: {} });
  const link = result.links.find((l) => String(l.href) === 'https://evil.example/x');
  assert.equal(link.text, '[image link]');
});

test('links come from the body, not from a quoted reply outside it', () => {
  const quote = element('blockquote', { children: [
    element('a', { attrs: { href: 'https://old-phish.example/' }, text: 'click' })
  ] });
  const body = element('div', { className: 'message-body', children: [
    element('a', { attrs: { href: 'https://current.example/' }, text: 'current' })
  ] });
  const root = element('div', { children: [quote, body] });

  const result = extractWith(root, {
    selectors: { messageBody: '.message-body' }
  });

  // Map to host-realm strings: values from the VM have a different prototype.
  const hrefs = [...result.links].map((l) => String(l.href));
  assert.deepEqual(hrefs, ['https://current.example/'],
    'only links inside the body container may be analyzed');
});

test('the body limit is high enough to keep late content', () => {
  const longText = 'x'.repeat(6000) + 'click here to verify';
  const body = element('div', { text: longText, className: 'message-body' });
  const root = element('div', { children: [body] });

  const result = extractWith(root, { selectors: { messageBody: '.message-body' } });
  assert.ok(result.body.includes('click here to verify'),
    'content past the old 4000-character cut must survive');
});