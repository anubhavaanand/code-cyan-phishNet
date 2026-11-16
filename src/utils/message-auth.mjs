/**
 * Which extension context may send which message to the background worker.
 *
 * `chrome.runtime.sendMessage` reaches every extension context at once — the
 * popup, the options page, the offscreen document, and every content script
 * running in a tab. The worker cannot assume the sender is the context a message
 * belongs to: without this check any page that could reach the extension could
 * rewrite settings, add trusted senders, or clear history.
 *
 * Rules live here rather than inline in the worker so they can be tested without
 * importing the model-loading service worker.
 */

/** Messages only a mail tab's content script may send. */
export const CONTENT_ONLY_MESSAGE_TYPES = Object.freeze([
  'CONTENT_READY',
  'SCAN_EMAIL'
]);

/**
 * Messages both a mail tab and an extension page legitimately send.
 *
 * The popup and options page ask for these on open, and the content script asks
 * between scans, so neither sender can be excluded.
 */
export const SHARED_MESSAGE_TYPES = Object.freeze([
  'GET_SETTINGS',
  'CHECK_TRUSTED_SENDER'
]);

/**
 * Messages that only the extension's own pages send.
 *
 * These change protection state, run inference, or trigger a scan. A tab has no
 * business asking for any of them.
 */
export const PRIVILEGED_MESSAGE_TYPES = Object.freeze([
  'GET_STATUS',
  'UPDATE_SETTINGS',
  'ADD_WHITELIST',
  'REMOVE_WHITELIST',
  'CLEAR_HISTORY',
  'SCAN_CURRENT_TAB',
  'RELOAD_MODEL',
  'GET_MODEL_STATUS'
]);

/** Messages the offscreen document produces about its own lifecycle. */
export const OFFSCREEN_MESSAGE_TYPES = Object.freeze([
  'OFFSCREEN_READY',
  'OFFSCREEN_ERROR',
  'MODEL_LOAD_PROGRESS',
  'INFERENCE_RESULT',
  'INFERENCE_ERROR'
]);

const CONTENT_ONLY = new Set(CONTENT_ONLY_MESSAGE_TYPES);
const SHARED = new Set(SHARED_MESSAGE_TYPES);
const PRIVILEGED = new Set(PRIVILEGED_MESSAGE_TYPES);
const OFFSCREEN = new Set(OFFSCREEN_MESSAGE_TYPES);

/** Every type the worker knows how to route. */
export const KNOWN_MESSAGE_TYPES = Object.freeze([
  ...CONTENT_ONLY_MESSAGE_TYPES,
  ...SHARED_MESSAGE_TYPES,
  ...PRIVILEGED_MESSAGE_TYPES,
  ...OFFSCREEN_MESSAGE_TYPES
]);

/**
 * Whether a message with `sender.tab` set came from a supported mail tab.
 *
 * Injected rather than imported so this module stays free of the URL allowlist
 * and remains testable on its own.
 *
 * @param {(sender: unknown) => boolean} isMailTab predicate for a tab sender
 * @returns {(sender: unknown) => boolean}
 */
export function createTabCheck(isMailTab) {
  return (sender) => Boolean(sender) && typeof sender === 'object' &&
    sender.tab !== undefined && sender.tab !== null && isMailTab(sender);
}

/**
 * Whether `sender` may deliver a message of `type`.
 *
 * @param {string} type message type
 * @param {unknown} sender the `sender` argument Chrome passes to a listener
 * @param {string} extensionId this extension's id, from `chrome.runtime.id`
 * @param {(sender: unknown) => boolean} isMailTab predicate for a tab sender
 * @returns {{ok: true}|{ok: false, error: string}}
 */
export function checkSender(type, sender, extensionId, isMailTab) {
  // An absent id means the extension context is gone; nothing can be trusted.
  if (!extensionId) return { ok: false, error: 'Extension context is unavailable' };
  if (!sender || typeof sender !== 'object') return { ok: false, error: 'Message has no sender' };
  if (sender.id !== extensionId) return { ok: false, error: 'Message is not from this extension' };

  // Offscreen status is only ever produced by the offscreen document itself.
  if (OFFSCREEN.has(type)) return { ok: true };

  const fromTab = sender.tab !== undefined && sender.tab !== null;

  if (fromTab) {
    if (!CONTENT_ONLY.has(type) && !SHARED.has(type)) {
      return { ok: false, error: `Message type ${type} is not allowed from a tab` };
    }
    return isMailTab(sender)
      ? { ok: true }
      : { ok: false, error: 'Message is not from a supported mail tab' };
  }

  // Extension pages: privileged actions, plus the shared lookups the popup
  // needs on open. Content-script-only messages must come from a real tab.
  if (PRIVILEGED.has(type) || SHARED.has(type)) return { ok: true };
  if (CONTENT_ONLY.has(type)) return { ok: false, error: 'Message must come from a mail tab' };

  return { ok: false, error: `Unknown message type: ${type}` };
}