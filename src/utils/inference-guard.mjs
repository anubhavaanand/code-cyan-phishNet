/**
 * Inference run guarding.
 *
 * `runInference` races the model call against a timeout, but the vendored
 * Transformers.js build takes no `AbortSignal`: the promise rejects while the
 * WASM work behind it keeps running to completion. Two things follow from that,
 * and both need to be handled explicitly:
 *
 *  - the abandoned run still consumes CPU, so it must not go on to do the
 *    post-processing (reason generation, score mapping) that nobody will read;
 *  - a newer request makes an older one stale. Superseding it means the older
 *    run's result is dropped instead of reported as if it were current, and its
 *    caller hears about it immediately rather than waiting out its own timeout.
 */

export const INFERENCE_TIMEOUT_MS = 15000;

/**
 * @param {number} [timeoutMs]
 */
export function createInferenceGuard(timeoutMs = INFERENCE_TIMEOUT_MS) {
  let active = null;
  let sequence = 0;

  return {
    /**
     * Register a new run and supersede whatever was in flight.
     * @param {string|null} requestId caller's id, for logs
     */
    begin(requestId = null) {
      const run = { requestId, sequence: ++sequence, timedOut: false };
      active = run;
      return run;
    },

    /**
     * Whether `run` is still the one the caller is waiting for.
     *
     * After `reset()` there is no current run, and `null` must not compare
     * equal to that absence.
     *
     * @param {{sequence: number}|null|undefined} run
     */
    isCurrent(run) {
      return run != null && active === run;
    },

    /**
     * Await `work`, rejecting if it outlives the timeout.
     *
     * On timeout the run is marked as timed out, so `work` can abandon its
     * remaining work the next time it checks `isCurrent`.
     *
     * @template T
     * @param {Promise<T>} work
     * @param {{timedOut: boolean}} run
     * @returns {Promise<T>}
     */
    async run(work, run) {
      // Reject immediately if this run was superseded by a newer begin()
      // before run() was called. Without this, a stale run still races its
      // work against the timeout, wasting CPU on post-processing nobody reads.
      if (!this.isCurrent(run)) {
        throw new Error('Inference superseded by a newer request');
      }

      let timerId;
      const timeout = new Promise((_, reject) => {
        timerId = setTimeout(() => {
          run.timedOut = true;
          reject(new Error(`Inference timeout after ${timeoutMs}ms`));
        }, timeoutMs);
      });

      try {
        return await Promise.race([work, timeout]);
      } finally {
        clearTimeout(timerId);
      }
    },

    /**
     * Whether `requestId` is still waiting on the current run.
     *
     * Used by the reply handler so a late result for a superseded request is
     * dropped instead of overwriting a newer scan's verdict.
     *
     * @param {string|null|undefined} requestId
     * @returns {boolean}
     */
    owns(requestId) {
      return requestId !== null && requestId !== undefined && active?.requestId === requestId;
    },

    /** Forget the current run, e.g. when the document is torn down. */
    reset() {
      active = null;
    }
  };
}