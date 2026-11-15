/**
 * Human-readable reasons for a verdict.
 *
 * The ML path used to run its email and URL regexes over `text` alone — the
 * subject and body. That misses the two strongest signals a mail provider hands
 * over as structure rather than prose: the sender address in the From header,
 * and each link's real `href`, which is routinely hidden behind anchor text
 * like "Click here". A mail whose body contains no literal URL and no literal
 * address therefore produced no link or sender reason at all, even when the DOM
 * carried a phishing link and a lookalike sender domain.
 *
 * Reasons now come from structure when it is supplied and from text when it is
 * not, so the text-only callers keep working unchanged.
 */

// Prose characters that end a sentence rather than belong to a URL. Without
// this, "https://example.com." yields the host "example.com." and
// "https://bit.ly/x," yields "bit.ly/x," — both wrong for any consumer that
// reads the host back out of the string.
const TRAILING_PUNCTUATION = /[.,;:!?)\]}'"`]+$/;

// A URL scan is capped so a pathological input cannot make reason generation
// quadratic in the size of the body.
const MAX_URLS_SCANNED = 200;

const EMAIL_IN_TEXT = /[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/;
const URL_IN_TEXT = /https?:\/\/[^\s"'<>]+/g;

/** Strip sentence-final punctuation from a URL found in prose. */
export function cleanUrl(url) {
  return String(url).replace(TRAILING_PUNCTUATION, '');
}

/**
 * Every URL worth checking, taken from structured links when present and from
 * the text otherwise.
 *
 * @param {{links?: {href?: string}[], text?: string}} input
 * @returns {string[]}
 */
export function collectUrls({ links, text } = {}) {
  if (Array.isArray(links) && links.length > 0) {
    const fromLinks = links
      .map((link) => (typeof link === 'string' ? link : link?.href))
      .filter((href) => typeof href === 'string' && href.length > 0)
      .map(cleanUrl);
    if (fromLinks.length > 0) return fromLinks.slice(0, MAX_URLS_SCANNED);
  }

  const fromText = String(text || '').match(URL_IN_TEXT) || [];
  return fromText.map(cleanUrl).slice(0, MAX_URLS_SCANNED);
}

/**
 * The sender domain, from the structured sender when present and from the text
 * otherwise.
 *
 * @param {{sender?: {email?: string, domain?: string}, text?: string}} input
 * @returns {string|null}
 */
export function collectSenderDomain({ sender, text } = {}) {
  if (sender && typeof sender === 'object') {
    const explicit = typeof sender.domain === 'string' && sender.domain.trim();
    if (explicit) return explicit.trim().toLowerCase().replace(TRAILING_PUNCTUATION, '');

    const email = typeof sender.email === 'string' ? sender.email : '';
    const at = email.lastIndexOf('@');
    if (at !== -1) {
      const domain = email.slice(at + 1).trim().toLowerCase().replace(TRAILING_PUNCTUATION, '');
      if (domain) return domain;
    }
  }

  // Text fallback: the first address that looks like a sender. The regex is
  // non-global on purpose — `match` with /g returns whole matches, not the
  // captured domain.
  const match = String(text || '').match(EMAIL_IN_TEXT);
  if (!match) return null;
  const domain = match[1].toLowerCase().replace(TRAILING_PUNCTUATION, '');
  return domain || null;
}

/**
 * Build the reason list for a prediction set.
 *
 * @param {object} params
 * @param {{label: string, score: number}[]} params.predictions sorted best-first
 * @param {string} [params.text]
 * @param {{domain?: string, email?: string}} [params.sender]
 * @param {{href?: string}[]} [params.links]
 * @param {object} [params.settings]
 * @param {object} params.detector the detection helpers (`isUrlSuspicious`,
 *   `isDomainSuspicious`, `checkLookalikeBrand`)
 * @returns {string[]} at most five reasons
 */
export function buildReasons({
  predictions = [],
  text = '',
  sender,
  links,
  settings = {},
  detector
}) {
  const { isUrlSuspicious, isDomainSuspicious, checkLookalikeBrand } = detector || {};
  const reasons = [];

  const top = predictions[0];

  // The verdict itself.
  const topReason = top && LABEL_REASONS[top.label];
  if (topReason) reasons.push(topReason);

  // Low confidence.
  const threshold = settings.sensitivityThreshold ?? 0.7;
  if (top && top.score < threshold) {
    reasons.push('Low confidence - manual review recommended');
  }

  // Urgency language.
  const lowerText = String(text || '').toLowerCase();
  const foundKeywords = PHISHING_KEYWORDS.filter((kw) => lowerText.includes(kw));
  if (foundKeywords.length > 0) {
    reasons.push(`Contains urgency keywords: ${foundKeywords.slice(0, 3).join(', ')}`);
  }

  // Links.
  if (typeof isUrlSuspicious === 'function') {
    const suspiciousLinks = collectUrls({ links, text })
      .filter((url) => isUrlSuspicious(url)).length;
    if (suspiciousLinks > 0) {
      reasons.push(`${suspiciousLinks} suspicious link(s) detected`);
    }
  }

  // Sender domain.
  const domain = collectSenderDomain({ sender, text });
  if (domain) {
    if (typeof isDomainSuspicious === 'function' && isDomainSuspicious(domain)) {
      reasons.push(`Suspicious sender domain: ${domain}`);
    } else if (typeof checkLookalikeBrand === 'function') {
      const lookalike = checkLookalikeBrand(domain);
      if (lookalike && lookalike.brand && lookalike.brand !== 'unknown') {
        reasons.push(`Domain mimics "${lookalike.brand}" (${domain})`);
      }
    }
  }

  // De-duplicate while preserving order, then cap.
  return [...new Set(reasons)].slice(0, 5);
}

export const PHISHING_KEYWORDS = [
  'urgent', 'immediate', 'verify', 'account', 'suspend', 'locked',
  'click here', 'confirm', 'update', 'security', 'unauthorized',
  'limited time', 'act now', 'expire', 'password', 'credential'
];

export const LABEL_REASONS = {
  'legitimate_email': 'Content appears legitimate',
  'phishing_email': 'Content matches phishing patterns',
  'legitimate_url': 'Links appear safe',
  'phishing_url': 'Suspicious links detected'
};