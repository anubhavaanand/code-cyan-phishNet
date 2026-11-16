/**
 * Which runtime messages an extension context is allowed to answer.
 *
 * `chrome.runtime.sendMessage` broadcasts to every extension context at once,
 * including the offscreen document. Chrome keeps the first `sendResponse` it
 * receives, so a listener that answers a message it does not own can win the
 * race against the context that actually handles it — and the caller is told
 * the wrong thing, or gets a synchronous error instead of an async result.
 *
 * The offscreen document exists to run model inference and owns exactly one
 * message type. Everything else belongs to the background worker.
 */

/** The only message type the offscreen document is allowed to answer. */
export const OFFSCREEN_MESSAGE_TYPES = Object.freeze(['RUN_INFERENCE']);

const OWNED = new Set(OFFSCREEN_MESSAGE_TYPES);

/**
 * Whether `sender` is one of this extension's own privileged contexts.
 *
 * A content script always carries the tab it ran in; the background worker and
 * other extension pages do not.
 *
 * @param {unknown} sender the `sender` argument Chrome passes to a listener
 * @param {string} extensionId this extension's id, from `chrome.runtime.id`
 * @returns {boolean}
 */
export function isExtensionContext(sender, extensionId) {
  if (!sender || typeof sender !== 'object') return false;
  if (sender.id !== extensionId) return false;
  return sender.tab === undefined || sender.tab === null;
}

/**
 * Whether the offscreen document should answer this message.
 *
 * Both conditions must hold: the type is one this document owns, and the
 * message came from a privileged extension context rather than a tab.
 *
 * @param {unknown} message the message Chrome delivered
 * @param {unknown} sender the `sender` argument Chrome passes to a listener
 * @param {string} extensionId this extension's id, from `chrome.runtime.id`
 * @returns {boolean}
 */
export function shouldHandle(message, sender, extensionId) {
  if (!message || typeof message !== 'object') return false;
  if (!OWNED.has(message.type)) return false;
  return isExtensionContext(sender, extensionId);
}