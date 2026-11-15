/**
 * Approximate token budget for models the extension does not have a tokenizer
 * for. English prose averages close to this; CJK and dense punctuation run
 * closer to one character per token, so the model's own tokenizer still gets
 * the final say (the pipeline truncates to `model_max_length`).
 */
const CHARS_PER_TOKEN = 4;

/**
 * Trim a trailing high surrogate, so a cut never sends half a character.
 */
function trimSurrogate(value) {
  return /[\uD800-\uDBFF]$/.test(value) ? value.slice(0, -1) : value;
}

/**
 * Truncate to an approximate token budget without cutting a word in half.
 *
 * A raw `slice(0, maxChars)` produced fragments like `...verify your acc`,
 * which the model scores as if the word were real. Backing off to the last
 * whitespace keeps the surviving text readable and matches what a human would
 * consider the start of the email. The back-off is bounded: it only applies
 * while it keeps most of the budget, so a single early space in a long
 * token cannot discard nearly the whole input.
 *
 * @param {string} text
 * @param {number} maxTokens approximate token budget
 * @returns {string}
 */
export function truncateText(text, maxTokens) {
  if (!text) return '';

  const budget = Number.isFinite(maxTokens) && maxTokens > 0 ? Math.floor(maxTokens) : 0;
  const maxChars = budget * CHARS_PER_TOKEN;
  if (maxChars <= 0) return '';
  if (text.length <= maxChars) return text;

  const clipped = text.slice(0, maxChars);

  // Only a boundary that preserves most of the budget is worth taking.
  const floor = Math.floor(maxChars * 0.6);
  for (let i = clipped.length - 1; i >= floor; i--) {
    if (/\s/.test(clipped[i])) return clipped.slice(0, i);
  }

  // No usable whitespace: a hard cut, minus any half character it produced.
  // JS slicing counts UTF-16 code units, not Unicode code points.
  return trimSurrogate(clipped);
}