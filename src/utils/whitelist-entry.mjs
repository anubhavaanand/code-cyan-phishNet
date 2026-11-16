/**
 * Validation for trusted-sender whitelist entries.
 *
 * A whitelist entry disables scanning for everything it matches, so an
 * over-broad value is a protection bypass rather than a bad preference: `*`
 * would trust every sender, and a bare `com` would trust every .com domain.
 *
 * Entries are matched three ways in `isTrustedSender`: the whole entry as an
 * email address, the whole entry as a domain, or the entry as a domain suffix
 * of the sender's address. Each form is validated here so a caller cannot
 * smuggle in a wildcard or a malformed value.
 */

/** Longest a domain may be, per RFC 1035. */
export const MAX_DOMAIN_LENGTH = 253;

/** Longest an email address may be, per RFC 5321. */
export const MAX_EMAIL_LENGTH = 320;

/** Most entries a single whitelist may hold. */
export const MAX_WHITELIST_ENTRIES = 100;

const LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/**
 * Whether `value` is a syntactically valid, fully-qualified domain.
 *
 * A bare label is rejected on purpose: `com` or `localhost` as a whitelist
 * entry would trust a whole top-level domain or every host on the machine.
 *
 * @param {string} value already lowercased and trimmed
 * @returns {boolean}
 */
export function isDomain(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_DOMAIN_LENGTH) {
    return false;
  }
  if (!value.includes('.')) return false;
  const labels = value.split('.');
  if (labels.length < 2) return false;
  return labels.every((label) => label.length >= 1 && label.length <= 63 && LABEL.test(label));
}

/**
 * Whether `value` is a syntactically valid email address.
 *
 * @param {string} value already lowercased and trimmed
 * @returns {boolean}
 */
export function isEmailAddress(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_EMAIL_LENGTH) {
    return false;
  }
  const at = value.indexOf('@');
  if (at <= 0 || at !== value.lastIndexOf('@')) return false;
  const local = value.slice(0, at);
  if (local.length === 0 || local.length > 64) return false;
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false;
  if (!/^[a-z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test(local)) return false;
  return isDomain(value.slice(at + 1));
}

/**
 * Normalise a whitelist entry, or report why it cannot be accepted.
 *
 * @param {unknown} raw candidate entry from a message or from storage
 * @returns {{ok: true, value: string}|{ok: false, error: string}}
 */
export function normalizeWhitelistEntry(raw) {
  if (typeof raw !== 'string') return { ok: false, error: 'Whitelist entries must be strings' };

  const value = raw.trim().toLowerCase();
  if (value.length === 0) return { ok: false, error: 'Whitelist entries cannot be empty' };

  // Reject anything that tries to express a pattern rather than a host.
  if (/[*?#[\]\\]/.test(value)) {
    return { ok: false, error: 'Whitelist entries cannot contain wildcards' };
  }
  if (/\s/.test(value)) return { ok: false, error: 'Whitelist entries cannot contain whitespace' };

  if (value.includes('@')) {
    return isEmailAddress(value)
      ? { ok: true, value }
      : { ok: false, error: 'Whitelist entry is not a valid email address' };
  }

  return isDomain(value)
    ? { ok: true, value }
    : { ok: false, error: 'Whitelist entry is not a valid domain' };
}

/**
 * Validate a whole whitelist, including its size.
 *
 * @param {unknown} raw candidate list
 * @returns {{ok: true, value: string[]}|{ok: false, error: string}}
 */
export function normalizeWhitelist(raw) {
  if (!Array.isArray(raw)) return { ok: false, error: 'Whitelist must be an array' };
  if (raw.length > MAX_WHITELIST_ENTRIES) {
    return { ok: false, error: `Whitelist cannot exceed ${MAX_WHITELIST_ENTRIES} entries` };
  }

  const entries = [];
  for (const item of raw) {
    const result = normalizeWhitelistEntry(item);
    if (!result.ok) return result;
    // Duplicates are dropped rather than rejected: the list is a set.
    if (!entries.includes(result.value)) entries.push(result.value);
  }
  return { ok: true, value: entries };
}