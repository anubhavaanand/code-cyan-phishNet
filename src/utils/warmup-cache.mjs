/**
 * Session-scoped record of which model builds have been warmed up.
 *
 * The offscreen document is recreated whenever the worker tears it down — on
 * `RELOAD_MODEL`, and when the browser reclaims the document under memory
 * pressure. Each recreation used to run the dummy warm-up inference again, even
 * though the same model build had already been exercised in this browser
 * session.
 *
 * `chrome.storage.session` is the right scope: it lives exactly as long as the
 * browser session and is not written to disk, so nothing about the model or the
 * user's mail is persisted. The key includes the model id, the pinned revision,
 * and the dtype, so a model change invalidates the record instead of silently
 * skipping the warm-up for a build that was never exercised.
 *
 * Every operation fails open. A missing or unavailable store simply means "not
 * warmed", which costs one inference rather than correctness.
 */

export const WARMUP_KEY = 'phishnet:model-warmup';

// Keep the record bounded. One entry per model build, and builds change rarely.
const MAX_ENTRIES = 8;

/**
 * The record key for one model build.
 *
 * @param {string} modelId
 * @param {string} revision
 * @param {string} dtype
 * @returns {string}
 */
export function warmupKey(modelId, revision, dtype) {
  return `${modelId}@${revision}:${dtype}`;
}

/**
 * Read the record, tolerating any storage failure or malformed contents.
 *
 * @param {{get: (key: string) => Promise<object>}} storage
 * @returns {Promise<Record<string, number>>}
 */
async function readRecord(storage) {
  try {
    const data = await storage.get(WARMUP_KEY);
    const record = data?.[WARMUP_KEY];
    if (!record || typeof record !== 'object' || Array.isArray(record)) return {};
    return record;
  } catch {
    return {};
  }
}

/**
 * Whether this model build was already warmed up in this browser session.
 *
 * @param {{get: (key: string) => Promise<object>}} storage
 * @param {string} key from {@link warmupKey}
 * @returns {Promise<boolean>}
 */
export async function isWarmed(storage, key) {
  const record = await readRecord(storage);
  return Boolean(record[key]);
}

/**
 * Record that this model build has been warmed up.
 *
 * @param {{get: (key: string) => Promise<object>, set: (items: object) => Promise<void>}} storage
 * @param {string} key from {@link warmupKey}
 * @returns {Promise<boolean>} whether the record was written
 */
export async function markWarmed(storage, key) {
  const record = await readRecord(storage);

  // Delete before re-adding so a re-marked build moves to the end of insertion
  // order rather than keeping its original position.
  delete record[key];
  record[key] = Date.now();

  // Prune by insertion order rather than by timestamp. Several builds marked in
  // the same millisecond would otherwise tie, and a stable sort would then drop
  // the newest instead of the oldest. Object key order is insertion order for
  // string keys, so the oldest entries are at the front and the newest are kept.
  const pruned = {};
  for (const entryKey of Object.keys(record).slice(-MAX_ENTRIES)) {
    pruned[entryKey] = record[entryKey];
  }

  try {
    await storage.set({ [WARMUP_KEY]: pruned });
    return true;
  } catch {
    return false;
  }
}