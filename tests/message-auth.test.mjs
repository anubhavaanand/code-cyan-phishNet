/**
 * Sender authorisation for background messages.
 *
 * `chrome.runtime.sendMessage` reaches every extension context at once, so the
 * worker must decide who may send what before routing. These tests pin that
 * contract independently of the model-loading service worker.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  CONTENT_ONLY_MESSAGE_TYPES,
  KNOWN_MESSAGE_TYPES,
  OFFSCREEN_MESSAGE_TYPES,
  PRIVILEGED_MESSAGE_TYPES,
  SHARED_MESSAGE_TYPES,
  checkSender
} from '../src/utils/message-auth.mjs';
import { isSupportedMailTabUrl } from '../src/utils/mail-urls.mjs';

const EXT = 'phishnet-test';

/** A content script in a supported mail tab. */
const mailTab = { id: EXT, tab: { id: 1, url: 'https://mail.google.com/mail/u/0/' } };
/** A tab the content script does not run in. */
const otherTab = { id: EXT, tab: { id: 2, url: 'https://example.com/' } };
/** An extension page such as the popup or options page. */
const page = { id: EXT };
const offscreen = { id: EXT, url: 'chrome-extension://' + EXT + '/public/offscreen.html' };

// Use the extension's own URL predicate so the test cannot drift from what
// the worker actually accepts. A substring test would also accept
// https://mail.google.com.evil.example/.
const isMailTab = (sender) => isSupportedMailTabUrl(sender?.tab?.url);
const check = (type, sender) => checkSender(type, sender, EXT, isMailTab);

describe('sender identity', () => {
  it('rejects a message from another extension', () => {
    const result = checkSender('GET_SETTINGS', { id: 'other-extension' }, EXT, isMailTab);
    assert.equal(result.ok, false);
    assert.match(result.error, /not from this extension/);
  });

  it('rejects a message with no sender', () => {
    for (const sender of [null, undefined, 'nonsense', 42]) {
      const result = checkSender('GET_SETTINGS', sender, EXT, isMailTab);
      assert.equal(result.ok, false);
      assert.match(result.error, /no sender/);
    }
  });

  it('rejects everything when the extension context is gone', () => {
    const result = checkSender('GET_SETTINGS', page, undefined, isMailTab);
    assert.equal(result.ok, false);
    assert.match(result.error, /unavailable/);
  });
});

describe('tab senders', () => {
  it('allows content-script messages from a supported mail tab', () => {
    for (const type of CONTENT_ONLY_MESSAGE_TYPES) {
      assert.equal(check(type, mailTab).ok, true, `${type} must be allowed`);
    }
  });

  it('rejects content-script messages from an unsupported tab', () => {
    for (const type of CONTENT_ONLY_MESSAGE_TYPES) {
      const result = check(type, otherTab);
      assert.equal(result.ok, false, `${type} must be rejected`);
      assert.match(result.error, /not from a supported mail tab/);
    }
  });

  it('rejects a host that merely contains a mail hostname', () => {
    // A substring check would accept these; the URL parser must not.
    for (const url of [
      'https://mail.google.com.evil.example/',
      'https://evil.example/mail.google.com',
      'http://mail.google.com/'
    ]) {
      const sender = { id: EXT, tab: { id: 3, url } };
      const result = check(CONTENT_ONLY_MESSAGE_TYPES[0], sender);
      assert.equal(result.ok, false, `${url} must be rejected`);
      assert.match(result.error, /not from a supported mail tab/);
    }
  });

  it('allows shared lookups from both a mail tab and an extension page', () => {
    for (const type of SHARED_MESSAGE_TYPES) {
      assert.equal(check(type, mailTab).ok, true);
      assert.equal(check(type, page).ok, true);
    }
  });

  it('forbids a tab from privileged actions', () => {
    for (const type of PRIVILEGED_MESSAGE_TYPES) {
      const result = check(type, mailTab);
      assert.equal(result.ok, false, `${type} must be rejected from a tab`);
      assert.match(result.error, /not allowed from a tab/);
    }
  });

  it('forbids a tab from messages another context owns', () => {
    for (const type of ['GET_STATUS', 'ADD_WHITELIST', 'CLEAR_HISTORY', 'RELOAD_MODEL']) {
      assert.equal(check(type, otherTab).ok, false);
    }
  });
});

describe('extension page senders', () => {
  it('allows privileged actions from an extension page', () => {
    for (const type of PRIVILEGED_MESSAGE_TYPES) {
      assert.equal(check(type, page).ok, true, `${type} must be allowed`);
    }
  });

  it('forbids an extension page from content-script-only messages', () => {
    for (const type of CONTENT_ONLY_MESSAGE_TYPES) {
      const result = check(type, page);
      assert.equal(result.ok, false, `${type} must be rejected`);
      assert.match(result.error, /must come from a mail tab/);
    }
  });
});

describe('offscreen lifecycle', () => {
  it('accepts model events only from the offscreen inference document', () => {
    for (const type of OFFSCREEN_MESSAGE_TYPES) {
      assert.equal(check(type, offscreen).ok, true, type);
    }
  });

  it('rejects forged model events from mail tabs, extension pages, and other URLs', () => {
    const impostors = [
      mailTab,
      otherTab,
      page,
      { id: EXT, url: 'chrome-extension://' + EXT + '/dist/popup.html' },
      { ...offscreen, tab: { id: 4, url: 'https://mail.google.com/' } },
      { id: EXT, url: 'chrome-extension://' + EXT + '/public/offscreen.html?fake=1' },
    ];
    for (const type of OFFSCREEN_MESSAGE_TYPES) {
      for (const sender of impostors) {
        const result = check(type, sender);
        assert.equal(result.ok, false, type + ' from ' + JSON.stringify(sender));
        assert.match(result.error, /not from the offscreen document/);
      }
    }
  });
});

describe('unknown types', () => {
  it('rejects a type the worker does not route', () => {
    const result = check('TOTALLY_UNKNOWN', page);
    assert.equal(result.ok, false);
    assert.match(result.error, /Unknown message type/);
  });

  it('rejects an empty type', () => {
    assert.equal(check('', page).ok, false);
    assert.equal(check(undefined, page).ok, false);
  });
});

describe('the type groups are disjoint', () => {
  it('never lists a type in two groups', () => {
    const groups = [
      CONTENT_ONLY_MESSAGE_TYPES,
      SHARED_MESSAGE_TYPES,
      PRIVILEGED_MESSAGE_TYPES,
      OFFSCREEN_MESSAGE_TYPES
    ];
    const seen = new Set();
    for (const group of groups) {
      for (const type of group) {
        assert.equal(seen.has(type), false, `${type} appears in more than one group`);
        seen.add(type);
      }
    }
    assert.equal(seen.size, KNOWN_MESSAGE_TYPES.length);
  });
});