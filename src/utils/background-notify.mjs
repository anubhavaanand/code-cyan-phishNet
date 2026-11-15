/**
 * Tell the background worker something, tolerating there being nobody to tell.
 *
 * The offscreen document outlives its listener: the service worker can be
 * suspended between the moment a scan finishes and the moment the reply is
 * sent, and during shutdown `chrome.runtime.sendMessage` can throw outright
 * instead of returning a rejected promise. Both used to surface as an unhandled
 * rejection in the offscreen document's console, and the status the message
 * carried (`OFFSCREEN_READY`, `OFFSCREEN_ERROR`) was simply lost.
 *
 * Nothing here retries. A message that cannot be delivered is logged and
 * dropped, because the alternative — queueing model status in the offscreen
 * document — needs a reader on the other side, and the worker's own state
 * handling is a separate concern.
 */

/**
 * Whether this extension context can still send messages at all.
 *
 * `chrome.runtime.id` is cleared when the extension is reloaded or the context
 * is invalidated; after that every send fails.
 *
 * @param {object} runtime chrome.runtime
 * @returns {boolean}
 */
export function canSend(runtime) {
  return Boolean(runtime && runtime.id);
}

/**
 * Wrap a `chrome.runtime.sendMessage`-shaped function so it never rejects.
 *
 * @param {(message: object) => Promise<unknown>|undefined} send
 * @param {(message: object, error: unknown) => void} [onFailure] called when the
 *   message could not be delivered
 * @returns {(message: object) => Promise<boolean>} resolves true when delivered,
 *   false when it was dropped
 */
export function createNotifier(send, onFailure = () => {}) {
  if (typeof send !== 'function') {
    return () => Promise.resolve(false);
  }

  return function notify(message) {
    let pending;
    try {
      pending = send(message);
    } catch (error) {
      // A synchronous throw: the context is gone, or the API is absent.
      onFailure(message, error);
      return Promise.resolve(false);
    }

    if (!pending || typeof pending.catch !== 'function') {
      // Older callback-style API, or a stub that returned nothing.
      return Promise.resolve(true);
    }

    return pending.then(
      () => true,
      (error) => {
        onFailure(message, error);
        return false;
      }
    );
  };
}