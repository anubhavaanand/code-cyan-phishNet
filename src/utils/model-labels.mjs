/**
 * Translate a text-classification checkpoint's own labels onto the four
 * canonical names the rest of the extension speaks.
 *
 * The ML path used to index a hard-coded `LABEL_0..LABEL_3` table. That is only
 * correct for one checkpoint, and a checkpoint that renames or reorders its
 * classes produces a confident wrong verdict — a phishing email reported as
 * `legitimate_email`. Transformers.js names labels from the checkpoint's
 * `id2label` (`{0:"LABEL_0"}`, `{0:"NEGATIVE",1:"POSITIVE"}`, or the dataset's
 * own names), so labels are resolved from what they say, and only the four-class
 * `LABEL_n` layout is inferred by position.
 */

// The pinned model's four classes and what each one means. This is both the
// semantic fallback and the only layout whose index order is meaningful.
export const KNOWN_LABELS = {
  legitimate_email: { kind: 'email', legitimate: true },
  phishing_email: { kind: 'email', legitimate: false },
  legitimate_url: { kind: 'url', legitimate: true },
  phishing_url: { kind: 'url', legitimate: false }
};

export const CANONICAL_LABELS = Object.keys(KNOWN_LABELS);

// Matching uses lookarounds rather than \b: labels are frequently snake_case
// (`phishing_email`), and `_` is a word character, so \b never splits it.
const PHISHING_NAME = /(?<![a-z0-9])(?:phish(?:ing)?|scam|fraud|malicious|attack|deceptive|spoof(?:ed)?|danger(?:ous)?|unsafe|untrusted|bogus|suspicious)(?![a-z0-9])/;
const LEGITIMATE_NAME = /(?<![a-z0-9])(?:legit(?:imate)?|safe|benign|ham|clean|genuine|trust(?:ed|worthy)?)(?![a-z0-9])/;
const NEGATED_LEGITIMATE = /(?<![a-z0-9])(?:illegit|not[-_ ]?legit|non[-_ ]?legit)/;
const EMAIL_NAME = /(?<![a-z0-9])(?:mail|email|msg|message|body|text|content|subject)(?![a-z0-9])/;
const URL_NAME = /(?<![a-z0-9])(?:url|urls|link|links|uri|href|domain|site|web)(?![a-z0-9])/;

/**
 * A binary checkpoint whose classes say nothing about the modality being judged
 * (`POSITIVE`/`NEGATIVE`). PhishNet scans email, so the email class is the only
 * defensible mapping, and `phishing_email` is the verdict callers act on.
 */
const BINARY_POSITIVE = new Set(['positive', 'spam']);
const BINARY_NEGATIVE = new Set(['negative', 'ham']);

/**
 * Resolve one raw model label to a canonical name.
 *
 * @param {unknown} rawLabel label as reported by the pipeline
 * @param {number} index position in the score array the label came from
 * @returns {string|null} canonical name, or null when the label is unmappable
 */
export function resolveLabelName(rawLabel, index) {
  const raw = typeof rawLabel === 'string' ? rawLabel.trim() : '';
  if (!raw) return null;

  const lower = raw.toLowerCase();
  if (KNOWN_LABELS[lower]) return lower;

  // Position is only ever a hint, and only a valid one when the caller passed a
  // real slot. Anything else must be treated as "no positional information".
  const hasPosition = Number.isInteger(index) && index >= 0 && index < CANONICAL_LABELS.length;
  const position = hasPosition ? index : -1;

  // 1. The label names both a polarity and a modality: trust it outright.
  const saysPhishing = PHISHING_NAME.test(lower) || NEGATED_LEGITIMATE.test(lower);
  const saysLegitimate = LEGITIMATE_NAME.test(lower) && !saysPhishing;
  if (saysPhishing !== saysLegitimate && EMAIL_NAME.test(lower) !== URL_NAME.test(lower)) {
    const polarity = saysPhishing ? 'phishing' : 'legitimate';
    const name = `${polarity}_${EMAIL_NAME.test(lower) ? 'email' : 'url'}`;
    if (KNOWN_LABELS[name]) return name;
  }

  // 2. A binary label with no modality at all.
  if (BINARY_POSITIVE.has(lower)) return 'phishing_email';
  if (BINARY_NEGATIVE.has(lower)) return 'legitimate_email';

  // 3. An opaque but explicitly numbered id (`LABEL_2`). Position is meaningful
  // only when the number agrees with the slot the model returned it in, which
  // is what a reordered checkpoint would violate.
  const numbered = lower.match(/^label_?(\d+)$/);
  if (!numbered) return null;
  if (Number(numbered[1]) !== position) return null;
  return CANONICAL_LABELS[position];
}

/**
 * Map a pipeline result onto canonical names, sorted best-first.
 *
 * The raw label is kept alongside the canonical one so `allScores` stays
 * traceable back to whatever the checkpoint called its classes.
 *
 * @param {object|object[]} results pipeline output (or a single object)
 * @returns {{label: string, score: number, rawLabel: unknown}[]}
 */
export function normalizePredictions(results) {
  const entries = Array.isArray(results) ? results : [results];
  return entries
    .map((entry, i) => {
      const score = Number(entry?.score);
      return {
        rawLabel: entry?.label,
        label: resolveLabelName(entry?.label, i),
        score: Number.isFinite(score) ? score : 0
      };
    })
    .filter(entry => entry.label)
    .sort((a, b) => b.score - a.score);
}

/**
 * Ask the pipeline for every class the checkpoint declares.
 *
 * A fixed `topk` silently drops classes: against a binary checkpoint a class
 * vanishes from `allScores` entirely, and against a wider checkpoint a class
 * that would have won is never scored. Falls back to the pinned model's four
 * classes when the pipeline does not expose its config.
 *
 * @param {object|null} classifier pipeline instance
 * @returns {number}
 */
export function labelSpaceSize(classifier) {
  const id2label = classifier?.model?.config?.id2label;
  const declared = id2label && typeof id2label === 'object'
    ? Object.keys(id2label).length
    : 0;
  return Math.max(declared, CANONICAL_LABELS.length, 1);
}