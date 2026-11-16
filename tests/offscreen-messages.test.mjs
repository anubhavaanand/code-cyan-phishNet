/**
 * Message-ownership tests for the offscreen document.
 *
 * chrome.runtime.sendMessage broadcasts to every extension context at once,
 * including the offscreen document. Chrome keeps the first sendResponse it
 * sees, so a listener that answers a message it does not own can preempt the
 * background worker. These tests pin the ownership contract.
 */
import { test, describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  OFFSCREEN_MESSAGE_TYPES,
  isExtensionContext,
  shouldHandle
} from '../src/utils/offscreen-messages.mjs';

const EXT_ID = 'phishnet-test';
const worker = { id: EXT_ID };
const tabSender = { id: EXT_ID, tab: { id: 7, url: 'https://mail.google.com/' } };

/** Message types the background worker owns and must not be answered here. */
const WORKER_TYPES = [
  'GET_SETTINGS', 'GET_STATUS', 'ADD_WHITELIST', 'REMOVE_WHITELIST',
  'UPDATE_SETTINGS', 'SCAN_EMAIL', 'SCAN_CURRENT_TAB', 'CHECK_TRUSTED_SENDER',
  'MODEL_STATUS', 'OFFSCREEN_READY', 'INFERENCE_RESULT', 'CLEAR_HISTORY',
  'RELOAD_MODEL', 'SETTINGS_UPDATE'
];

describe('offscreen message ownership', () => {
  it('owns exactly RUN_INFERENCE', () => {
    assert.deepEqual(OFFSCREEN_MESSAGE_TYPES, ['RUN_INFERENCE']);
  });

  it('claims RUN_INFERENCE from the background worker', () => {
    assert.equal(shouldHandle({ type: 'RUN_INFERENCE' }, worker, EXT_ID), true);
  });

  it('ignores every message type owned by the background worker', () => {
    for (const type of WORKER_TYPES) {
      assert.equal(
        shouldHandle({ type }, worker, EXT_ID),
        false,
        `${type} must not be claimed by the offscreen document`
      );
    }
  });

  it('ignores RUN_INFERENCE from a content script', () => {
    assert.equal(shouldHandle({ type: 'RUN_INFERENCE' }, tabSender, EXT_ID), false);
  });

  it('ignores RUN_INFERENCE from a foreign extension', () => {
    assert.equal(shouldHandle({ type: 'RUN_INFERENCE' }, { id: 'other' }, EXT_ID), false);
  });

  it('ignores messages with no type, no sender, or no id', () => {
    assert.equal(shouldHandle({}, worker, EXT_ID), false);
    assert.equal(shouldHandle(null, worker, EXT_ID), false);
    assert.equal(shouldHandle(undefined, worker, EXT_ID), false);
    assert.equal(shouldHandle('RUN_INFERENCE', worker, EXT_ID), false);
    assert.equal(shouldHandle({ type: 'RUN_INFERENCE' }, null, EXT_ID), false);
    assert.equal(shouldHandle({ type: 'RUN_INFERENCE' }, {}, EXT_ID), false);
  });

  it('treats a sender with no tab as an extension context', () => {
    assert.equal(isExtensionContext(worker, EXT_ID), true);
    assert.equal(isExtensionContext({}, EXT_ID), false, 'id must match');
  });

  it('does not confuse a missing tab with a tab sender', () => {
    assert.equal(isExtensionContext({ id: EXT_ID, tab: null }, EXT_ID), true);
    assert.equal(isExtensionContext({ id: EXT_ID, tab: undefined }, EXT_ID), true);
    assert.equal(isExtensionContext(tabSender, EXT_ID), false);
  });
});