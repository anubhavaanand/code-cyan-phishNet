/**
 * The single source of truth for threat lists.
 *
 * The heuristic detector and the content script's selector table both need the
 * same risky-TLD and URL-shortener lists. They used to carry separate copies
 * that drifted: the detector knew `.icu` and `.monster`, selectors.js knew
 * `tiny.cc` and `rebrand.ly`, and neither knew the other's entries. That made
 * the heuristic path and the ML path disagree on the same URL.
 *
 * This file is a classic script so both the content script and the offscreen
 * document can load it before the detector, which reads `PhishNet.THREAT_LISTS`.
 */
(function () {
  'use strict';

  const root = typeof globalThis !== 'undefined'
    ? globalThis
    : (typeof window !== 'undefined' ? window : this);

  const THREAT_LISTS = Object.freeze({
    // TLDs disproportionately used for disposable phishing hosts.
    suspiciousTlds: Object.freeze([
      '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club',
      '.work', '.date', '.faith', '.loan', '.win', '.bid', '.review',
      '.country', '.stream', '.download', '.xin', '.racing', '.men',
      '.buzz', '.surf', '.icu', '.monster', '.rest'
    ]),

    // URL shorteners that hide the real destination.
    urlShorteners: Object.freeze([
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
      'buff.ly', 'adf.ly', 'bc.vc', 'shorte.st', 'clck.ru', 'cutt.ly',
      'rb.gy', 'tiny.cc', 'v.gd', 's.id', 'shorturl.at', 'rebrand.ly'
    ])
  });

  root.PhishNet = root.PhishNet || {};
  root.PhishNet.THREAT_LISTS = THREAT_LISTS;
  root.PhishNet.UTILITY_SELECTORS = Object.assign(
    {},
    root.PhishNet.UTILITY_SELECTORS,
    THREAT_LISTS
  );

  // Node and the CommonJS test suite load these files directly rather than
  // through the extension's script tags.
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = THREAT_LISTS;
  }
})();