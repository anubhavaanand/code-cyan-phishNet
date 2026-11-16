/**
 * Trusted-sender whitelist entry validation.
 *
 * A whitelist entry disables scanning for everything it matches, so an
 * over-broad value is a protection bypass rather than a bad preference.
 */
import { test, describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  MAX_WHITELIST_ENTRIES,
  isDomain,
  isEmailAddress,
  normalizeWhitelist,
  normalizeWhitelistEntry
} from '../src/utils/whitelist-entry.mjs';

describe('domain validation', () => {
  it('accepts a fully-qualified domain', () => {
    assert.equal(isDomain('github.com'), true);
    assert.equal(isDomain('mail.example.co.uk'), true);
    assert.equal(isDomain('a-b.example.com'), true);
  });

  it('rejects a bare label', () => {
    // `com` as an entry would trust every .com domain.
    assert.equal(isDomain('com'), false);
    assert.equal(isDomain('localhost'), false);
    assert.equal(isDomain('intranet'), false);
  });

  it('rejects malformed domains', () => {
    assert.equal(isDomain(''), false);
    assert.equal(isDomain('example'), false);
    assert.equal(isDomain('-bad.com'), false);
    assert.equal(isDomain('bad-.com'), false);
    assert.equal(isDomain('exa mple.com'), false);
    assert.equal(isDomain('example..com'), false);
    assert.equal(isDomain('.example.com'), false);
  });
});

describe('email validation', () => {
  it('accepts a plain address', () => {
    assert.equal(isEmailAddress('alice@example.com'), true);
    assert.equal(isEmailAddress('a.b+c@mail.example.co.uk'), true);
  });

  it('rejects malformed addresses', () => {
    assert.equal(isEmailAddress(''), false);
    assert.equal(isEmailAddress('alice'), false);
    assert.equal(isEmailAddress('@example.com'), false);
    assert.equal(isEmailAddress('alice@'), false);
    assert.equal(isEmailAddress('a@b@c.com'), false);
    assert.equal(isEmailAddress('alice@localhost'), false);
  });
});

describe('normalizeWhitelistEntry', () => {
  it('trims and lowercases', () => {
    assert.deepEqual(normalizeWhitelistEntry('  Example.COM  '), { ok: true, value: 'example.com' });
    assert.deepEqual(normalizeWhitelistEntry('Alice@Example.com'), {
      ok: true,
      value: 'alice@example.com'
    });
  });

  it('rejects wildcards and patterns', () => {
    for (const entry of ['*', '*.com', 'example.*', 'a?c.com', '[abc].com']) {
      const result = normalizeWhitelistEntry(entry);
      assert.equal(result.ok, false, `${entry} must be rejected`);
      assert.match(result.error, /wildcard/i);
    }
  });

  it('rejects a bare `@` and whitespace', () => {
    assert.equal(normalizeWhitelistEntry('@').ok, false);
    assert.equal(normalizeWhitelistEntry('a @b.com').ok, false);
  });

  it('rejects a bare top-level domain', () => {
    const result = normalizeWhitelistEntry('com');
    assert.equal(result.ok, false);
    assert.match(result.error, /domain/i);
  });

  it('rejects non-strings and blanks', () => {
    for (const entry of [42, null, undefined, {}, [], '']) {
      assert.equal(normalizeWhitelistEntry(entry).ok, false, `${JSON.stringify(entry)} must be rejected`);
    }
  });
});

describe('normalizeWhitelist', () => {
  it('keeps valid entries and drops duplicates', () => {
    const result = normalizeWhitelist(['Example.com', 'example.com', 'ALICE@x.org']);
    assert.equal(result.ok, true);
    assert.deepEqual(result.value, ['example.com', 'alice@x.org']);
  });

  it('rejects a non-array', () => {
    assert.equal(normalizeWhitelist('github.com').ok, false);
    assert.equal(normalizeWhitelist(null).ok, false);
  });

  it('rejects a list that exceeds the cap', () => {
    const tooMany = Array.from({ length: MAX_WHITELIST_ENTRIES + 1 }, (_, i) => `h${i}.example.com`);
    const result = normalizeWhitelist(tooMany);
    assert.equal(result.ok, false);
    assert.match(result.error, /cannot exceed/);
  });

  it('accepts a list at the cap', () => {
    const atCap = Array.from({ length: MAX_WHITELIST_ENTRIES }, (_, i) => `h${i}.example.com`);
    assert.equal(normalizeWhitelist(atCap).ok, true);
  });

  it('reports the first bad entry rather than silently dropping it', () => {
    const result = normalizeWhitelist(['github.com', '*', 'example.org']);
    assert.equal(result.ok, false);
    assert.match(result.error, /wildcard/i);
  });
});