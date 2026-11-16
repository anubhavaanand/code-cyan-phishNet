/**
 * Threat-list parity.
 *
 * The heuristic detector and the content script's selector table both decide
 * what a risky TLD or shortener is. They used to hold separate copies that had
 * drifted — the detector knew `.icu` while selectors.js knew `tiny.cc` — so the
 * heuristic path and the ML path disagreed on the same URL.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import threatLists from '../src/utils/threat-lists.js';
import { UTILITY_SELECTORS } from '../src/selectors.js';
import detector from '../src/utils/heuristic-detector.js';

describe('threat-list parity', () => {
  test('both contexts read the same list object', () => {
    assert.equal(threatLists, globalThis.PhishNet.THREAT_LISTS);
    assert.deepEqual(UTILITY_SELECTORS.suspiciousTlds, threatLists.suspiciousTlds);
    assert.deepEqual(UTILITY_SELECTORS.urlShorteners, threatLists.urlShorteners);
  });

  test('a TLD known to one context is known to the other', () => {
    // The concrete drift this replaces.
    for (const tld of ['.icu', '.monster', '.rest', '.buzz']) {
      assert.ok(threatLists.suspiciousTlds.includes(tld), `${tld} must be in the shared list`);
    }
  });

  test('a shortener known to one context is known to the other', () => {
    for (const host of ['tiny.cc', 'rebrand.ly', 'shorturl.at', 's.id']) {
      assert.ok(
        threatLists.urlShorteners.includes(host),
        `${host} must be in the shared list`
      );
    }
  });

  test('the detector and selectors agree on a TLD verdict', () => {
    // Both paths classify the same host the same way.
    for (const tld of threatLists.suspiciousTlds) {
      const host = `phishnet-probe${tld.replace('.', '')}${tld}`;
      assert.equal(
        detector.isUrlSuspicious(`https://${host}/`),
        UTILITY_SELECTORS.suspiciousTlds.some((t) => host.endsWith(t)),
        `${host} must be judged consistently`
      );
    }
  });

  test('the lists contain no duplicates', () => {
    assert.equal(
      new Set(threatLists.suspiciousTlds).size,
      threatLists.suspiciousTlds.length
    );
    assert.equal(
      new Set(threatLists.urlShorteners).size,
      threatLists.urlShorteners.length
    );
  });

  test('entries are lowercased and TLDs are dot-prefixed', () => {
    for (const tld of threatLists.suspiciousTlds) {
      assert.ok(tld.startsWith('.'), `${tld} must start with a dot`);
      assert.equal(tld, tld.toLowerCase());
    }
    for (const host of threatLists.urlShorteners) {
      assert.equal(host, host.toLowerCase());
    }
  });
});