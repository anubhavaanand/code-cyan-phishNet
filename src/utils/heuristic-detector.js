/**
 * PhishNet Heuristic & Threat Detection Engine v1.1
 *
 * Research-grounded techniques:
 *  - UTS #39-style confusable skeletoning (homoglyph normalization)
 *  - Damerau-Levenshtein distance (transposition-aware typosquatting)
 *  - Display-name vs sender-domain brand impersonation cross-check
 *  - Open-redirect, dangerous-scheme, invisible-character URL inspection
 *  - Category-weighted scoring squashed through a logistic function
 */

(function () {
  'use strict';

  const root = typeof globalThis !== 'undefined' ? globalThis : (typeof window !== 'undefined' ? window : this);

  // The canonical lists live in src/utils/threat-lists.js, which every context
  // loads before this file. They used to be duplicated here, and the copy had
  // drifted from the selector table's: this detector knew .icu while
  // selectors.js knew tiny.cc, so the heuristic and ML paths disagreed on the
  // same URL. An inline copy remains only as a last resort for a context that
  // loaded this file on its own.
  // Fall back to requiring the shared module when this file is loaded on its
  // own (Node, tests), where no earlier script tag installed the lists.
  const sharedLists = root.PhishNet?.THREAT_LISTS ||
    root.PhishNet?.UTILITY_SELECTORS ||
    (typeof require === 'function' ? safeRequireThreatLists() : null);

  const UTILITY_SELECTORS = sharedLists || {
    suspiciousTlds: ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club'],
    urlShorteners: ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']
  };

  const HIGH_PROFILE_BRANDS = [
    'paypal','microsoft','google','amazon','apple','netflix','chase',
    'wellsfargo','bankofamerica','citibank','coinbase','binance','dhl',
    'fedex','usps','ups','facebook','instagram','twitter','linkedin',
    'github','dropbox','adobe','walmart','ebay'
  ];
  const BRAND_SET = new Set(HIGH_PROFILE_BRANDS);

  const DANGEROUS_EXTENSIONS = new Set([
    'exe','scr','bat','cmd','vbs','vbe','js','jse','wsf','wsh',
    'hta','iso','img','lnk','jar','msi','ps1','reg','pif'
  ]);

  // Scripts are common in legitimate mail — a developer sending a module, a
  // config file — so a bare .js is not treated as dangerous on its own. It is
  // still dangerous when it is disguised as a document (invoice.pdf.js), which
  // the double-extension check below handles.
  const SCRIPT_EXTENSIONS = new Set(['js', 'jse']);
  const EXECUTABLE_EXTENSIONS = new Set(
    [...DANGEROUS_EXTENSIONS].filter((e) => !SCRIPT_EXTENSIONS.has(e))
  );

  // Types that are safe to open, and therefore the ones worth disguising. Only
  // a document type in front of a dangerous one is a deception.
  const DOCUMENT_TYPES = new Set([
    'pdf','doc','docx','xls','xlsx','ppt','pptx','txt','rtf','csv',
    'jpg','jpeg','png','gif','bmp','webp','svg',
    'zip','rar','7z','tar','gz'
  ]);

  const CYRILLIC_REGEX = /\p{Script=Cyrillic}/u;
  const GREEK_REGEX   = /\p{Script=Greek}/u;
  const LATIN_REGEX   = /[a-zA-Z]/;
  const IP_HOSTNAME_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;
  const IPV6_HOSTNAME_REGEX = /^\[[0-9a-f:.]+\]$/i;

  // zero-width joiner/non-joiner, word-joiner, BOM, soft hyphen
  const INVISIBLE_CHARS = new Set([0x200B,0x200C,0x200D,0x2060,0xFEFF,0xAD].map(c => String.fromCharCode(c)));
  const hasInvisible = s => { for (const ch of s) if (INVISIBLE_CHARS.has(ch)) return true; return false; };
  const stripInvisible = s => { let o=''; for (const ch of s) if (!INVISIBLE_CHARS.has(ch)) o+=ch; return o; };

  const MULTI_PART_SUFFIXES = new Set([
    'co.uk','org.uk','ac.uk','gov.uk','co.jp','ne.jp','or.jp',
    'com.au','net.au','org.au','com.br','com.mx','com.ar',
    'co.in','net.in','org.in','com.cn','com.hk','co.nz',
    'com.sg','com.tr','co.za','com.my','co.kr'
  ]);

  const KNOWN_OFFICIAL_DOMAINS = new Set([
    'microsoftonline.com','live.com','office.com','outlook.com','msn.com',
    'windowsupdate.com','googlemail.com','youtube.com','gmail.com','youtu.be'
  ]);

  // memoization caches (bounded) — hot paths hit these per brand per link
  const REG_DOMAIN_CACHE = new Map();
  const SKELETON_CACHE = new Map();

  const SUSPICIOUS_TLD_SET = new Set(
    (UTILITY_SELECTORS.suspiciousTlds || []).map(t => t.replace(/^\./, ''))
  );
  const SHORTENER_SET = new Set(UTILITY_SELECTORS.urlShorteners || []);

  function getRegistrableDomain(host) {
    if (!host) return '';
    const cached = REG_DOMAIN_CACHE.get(host);
    if (cached !== undefined) return cached;
    const parts = String(host).toLowerCase().replace(/\.$/, '').split('.');
    for (const suffix of MULTI_PART_SUFFIXES) {
      const sl = suffix.split('.').length;
      if (parts.length > sl && parts.slice(-sl).join('.') === suffix) {
        return parts.slice(-(sl + 1)).join('.');
      }
    }
    const out = parts.slice(-2).join('.');
    if (REG_DOMAIN_CACHE.size < 2048) REG_DOMAIN_CACHE.set(host, out);
    return out;
  }

  function isOfficialBrandHost(hostname) {
    if (!hostname) return false;
    const host = String(hostname).toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split(':')[0];
    const registrable = getRegistrableDomain(host);
    if (KNOWN_OFFICIAL_DOMAINS.has(registrable)) return true;

    const regParts = registrable.split('.');
    const secondLevel = regParts.length >= 2 ? regParts[regParts.length - 2] : registrable;
    if (BRAND_SET.has(secondLevel)) return true;

    if (regParts.length === 3) {
      const maybeSuffix = regParts.slice(-2).join('.');
      if (MULTI_PART_SUFFIXES.has(maybeSuffix) && BRAND_SET.has(regParts[0])) return true;
    }
    return false;
  }

  /* ===================================================================
   * UTS #39-style confusable skeletoning.
   * Maps visually ambiguous code points to their Latin base and folds
   * common digit/letter substitutions, so homoglyph attacks collapse
   * into their ASCII target BEFORE string distances are computed.
   * ================================================================== */
  const CONFUSABLE_MAP = new Map();
  (function buildConfusables() {
    // Cyrillic/Greek homoglyphs -> Latin base (per-letter groups only;
    // never map one plain Latin letter onto another)
    const groups = {
      a: ['\u0430', '\u03B1'],
      c: ['\u0441', '\u03F2'],
      e: ['\u0435', '\u03B5'],
      h: ['\u04BB'],
      i: ['\u0456', '\u03AF'],
      j: ['\u0458'],
      o: ['\u043E', '\u03BF'],
      p: ['\u0440'],
      s: ['\u0455', '\u03C2'],
      x: ['\u0445'],
      y: ['\u0443']
    };
    for (const [latin, lookalikes] of Object.entries(groups)) {
      CONFUSABLE_MAP.set(latin, latin);
      for (const lk of lookalikes) CONFUSABLE_MAP.set(lk.toLowerCase(), latin);
    }
    // Common digit/symbol substitutions, used only during brand comparison.
    // Applied after letter groups so they cannot shadow them.
    const digitFolds = { '0':'o', '1':'l', '3':'e', '4':'a', '5':'s', '7':'t', '8':'b', '$':'s', '@':'a' };
    for (const [from, to] of Object.entries(digitFolds)) CONFUSABLE_MAP.set(from, to);
  })();

/**
 * Order reasons so the most actionable survive truncation.
 *
 * A weaponised attachment is the strongest signal the engine produces, but it
 * was appended last and could be cut by the display cap, hiding the one line a
 * user most needs to read.
 *
 * @param {string[]} reasons
 * @param {number} [limit]
 * @returns {string[]}
 */
function prioritiseReasons(reasons, limit = 6) {
  if (reasons.length <= limit) return reasons;
  const critical = (reason) => /attachment/i.test(reason) && !/only the first/i.test(reason);
  const important = reasons.filter(critical);
  const rest = reasons.filter((reason) => !critical(reason));
  return [...important, ...rest].slice(0, limit);
}

/**
 * Load the canonical threat lists, tolerating a bundler that has no `require`.
 */
function safeRequireThreatLists() {
  try {
    return require('./threat-lists.js');
  } catch {
    return null;
  }
}

/**
 * Whether an IPv4 literal is in a private, loopback or link-local range.
 *
 * These addresses only resolve inside the user's own network, so a link to one
 * is an intranet or local-dev target rather than a phishing host.
 *
 * @param {string} host hostname or IP literal
 * @returns {boolean}
 */
function isPrivateIpAddress(host) {
  const octets = String(host || '').split('.').map((part) => Number(part));
  if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return false;
  }
  const [a, b] = octets;
  if (a === 10) return true;                       // 10.0.0.0/8
  if (a === 127) return true;                      // loopback
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true;         // 192.168.0.0/16
  if (a === 169 && b === 254) return true;         // link-local
  if (a === 0) return true;                        // "this host"
  return false;
}

/**
 * Detect local IPv6 literal destinations without treating every intranet URL
 * as phishing. URL.hostname includes brackets for IPv6 in Chrome and Firefox.
 */
function isPrivateIpv6Address(host) {
  const address = String(host).toLowerCase().replace(/^\[|\]$/g, '');
  if (address === '::' || address === '::1') return true;

  const first = address.startsWith('::') ? 0 : parseInt(address.split(':')[0], 16);
  if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 (unique local)
  if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 (link-local)

  // Browsers canonicalize IPv4-mapped addresses into hex groups. Preserve the
  // same private/public distinction as direct IPv4 links, so wrapping an IPv4
  // address in ::ffff: cannot bypass the phishing check.
  const mapped = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(address);
  if (mapped) {
    const high = parseInt(mapped[1], 16), low = parseInt(mapped[2], 16);
    return isPrivateIpAddress(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
  }
  return false;
}

/**
 * skeleton(str): fold str into its unambiguous ASCII form.
   * 'p\u0430ypal' -> 'paypal', 'g00gle' -> 'google'
   */
  function skeleton(str) {
    const raw = String(str || '');
    const hit = SKELETON_CACHE.get(raw);
    if (hit !== undefined) return hit;
    let s0 = raw.toLowerCase().normalize('NFKC');
    s0 = stripInvisible(s0);
    let out = '';
    for (const ch of s0) out += CONFUSABLE_MAP.get(ch) || ch;
    if (SKELETON_CACHE.size < 1024) SKELETON_CACHE.set(raw, out);
    return out;
  }

  /**
   * Damerau-Levenshtein (OSA form) with three-row buffers:
   * counts adjacent transpositions ('payapl' <-> 'paypal' = 1)
   * without per-call map allocations.
   */
  function damerauLevenshtein(a, b) {
    if (a === b) return 0;
    const m = a.length, n = b.length;
    if (!m) return n;
    if (!n) return m;

    let prevPrev = new Array(n + 1);
    let prev = new Array(n + 1);
    let curr = new Array(n + 1);

    for (let j = 0; j <= n; j++) { prev[j] = j; prevPrev[j] = j; }

    for (let i = 1; i <= m; i++) {
      curr[0] = i;
      for (let j = 1; j <= n; j++) {
        const cost = a.charCodeAt(i - 1) === b.charCodeAt(j - 1) ? 0 : 1;
        let v = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          v = Math.min(v, prevPrev[j - 2] + 1); // the swap itself is the single edit
        }
        curr[j] = v;
      }
      // rotate THREE generations: curr recycles the oldest buffer
      // (recycling old-prev here aliases prevPrev two rows back)
      const oldest = prevPrev;
      prevPrev = prev;
      prev = curr;
      curr = oldest;
    }
    return prev[n];
  }

  // legacy alias retained for API compatibility
  function levenshteinDistance(a, b) { return damerauLevenshtein(a, b); }

  /**
   * Punycode (RFC 3492) decode, for a single label.
   * No punycode API is available in a content script — URL.domainToUnicode
   * exists in Chrome but not in Firefox, and not in Node for tests — so this
   * is the decoder. It only needs to handle real IDN labels; malformed input
   * returns null rather than throwing.
   */
  const punycodeToUnicode = (() => {
    const BASE = 36, TMIN = 1, TMAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

    const adapt = (delta, numPoints, firstTime) => {
      let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
      d += Math.floor(d / numPoints);
      let k = 0;
      while (d > ((BASE - TMIN) * TMAX) >> 1) {
        d = Math.floor(d / (BASE - TMIN));
        k += BASE;
      }
      return k + Math.floor(((BASE - TMIN + 1) * d) / (d + SKEW));
    };

    const digitValue = (code) => {
      if (code >= 48 && code <= 57) return code - 22;   // 0-9 -> 26-35
      if (code >= 65 && code <= 90) return code - 65;   // A-Z -> 0-25
      if (code >= 97 && code <= 122) return code - 97;  // a-z -> 0-25
      return -1;
    };

    const decodeLabel = (input) => {
      const basic = input.lastIndexOf('-');
      const output = [];
      for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));

      let n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
      let idx = basic > 0 ? basic + 1 : 0;

      while (idx < input.length) {
        const oldi = i;
        let w = 1;
        for (let k = BASE; ; k += BASE) {
          if (idx >= input.length) return null;
          const digit = digitValue(input.charCodeAt(idx++));
          if (digit < 0) return null;
          i += digit * w;
          const t = k <= bias ? TMIN : (k >= bias + TMAX ? TMAX : k - bias);
          if (digit < t) break;
          w *= BASE - t;
        }
        const outLen = output.length + 1;
        bias = adapt(i - oldi, outLen, oldi === 0);
        n += Math.floor(i / outLen);
        i %= outLen;
        output.splice(i, 0, n);
        i++;
      }
      try {
        return String.fromCodePoint(...output);
      } catch {
        return null;
      }
    };

    return (domain) => {
      const labels = String(domain || '').toLowerCase().split('.');
      let changed = false;
      const out = labels.map((label) => {
        if (!label.startsWith('xn--')) return label;
        const decoded = decodeLabel(label.slice(4));
        if (decoded === null) return label;
        changed = true;
        return decoded;
      });
      return changed ? out.join('.') : null;
    };
  })();

  /**
   * Punycode is not inherently suspicious. Most of it is ordinary IDN —
   * `xn--80ak6aa92e.com`, `xn--p1ai`, the Cyrillic TLD — and flagging every
   * occurrence marked legitimate internationalised domains as phishing.
   *
   * A punycode label is only a homograph when what it decodes to is
   * confusable with a brand, or when a brand sits in plain ASCII beside it
   * in the same domain. Both are checked on the decoded form.
   */
  function punycodeSpoofsBrand(cleanDomain) {
    if (!cleanDomain.includes('xn--')) return false;

    const decoded = punycodeToUnicode(cleanDomain);
    if (decoded === null) return true; // undecodable punycode is not something we can vouch for

    const skeleton = (s) => {
      let out = '';
      const folded = s.toLowerCase().normalize('NFKC');
      for (const ch of stripInvisible(folded)) out += CONFUSABLE_MAP.get(ch) || ch;
      return out;
    };

    const decodedLabels = decoded.split('.');
    const asciiLabels = cleanDomain.split('.').filter((l) => !l.startsWith('xn--'));

    for (const brand of BRAND_SET) {
      // decoded label folds onto a brand
      for (const label of decodedLabels) {
        if (label.startsWith('xn--')) continue;
        if (skeleton(label) === brand && label !== brand) return true;
      }
      // brand in plain ASCII alongside a punycode label
      if (asciiLabels.includes(brand) && decodedLabels.length > asciiLabels.length) return true;
    }
    return false;
  }

  /**
   * Mixed-script homograph detection (Latin + Cyrillic/Greek mixing,
   * punycode labels, or invisible characters).
   */
  function detectHomographAttack(str) {
    if (!str) return false;
    const s = String(str).toLowerCase();
    if (hasInvisible(s)) return true;
    const hasLatin = LATIN_REGEX.test(s);
    const mixedScript = (hasLatin && CYRILLIC_REGEX.test(s)) ||
                        (hasLatin && GREEK_REGEX.test(s) && s.length > 4);
    if (mixedScript) return true;
    return punycodeSpoofsBrand(s);
  }

  /**
   * Lookalike brand analysis with skeleton-normalized comparison.
   */
  // memoized wrapper — same domain strings recur across sender + every link
  const LOOKALIKE_CACHE = new Map();
  function checkLookalikeBrand(domain) {
    if (!domain) return null;
    if (LOOKALIKE_CACHE.has(domain)) return LOOKALIKE_CACHE.get(domain);
    const result = checkLookalikeBrandUncached(domain);
    if (LOOKALIKE_CACHE.size < 2048) LOOKALIKE_CACHE.set(domain, result);
    return result;
  }

  function checkLookalikeBrandUncached(domain) {
    const cleanDomain = domain.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '').split(':')[0];

    if (detectHomographAttack(cleanDomain)) {
      return { brand: 'unknown', type: 'homograph', reason: `Homograph / deceptive characters in domain (${cleanDomain})` };
    }

    if (isOfficialBrandHost(cleanDomain)) return null;

    const parts = cleanDomain.split('.');
    // Resolve the registrable label without assuming a one-part TLD (.com),
    // so confusable brands on .co.uk, .co.jp, etc. get the same analysis.
    const registrableParts = getRegistrableDomain(cleanDomain).split('.');
    const mainName = registrableParts[0];
    const skelMain = skeleton(mainName);
    // Only labels before the registrable domain are subdomains. The
    // registrable label itself is analyzed as a possible skeleton spoof.
    const subdomainLabels = parts.slice(0, -registrableParts.length);

    for (const brand of BRAND_SET) {
      // subdomain deception: a brand used as a whole label somewhere other than
      // the registrable name. Comparing labels rather than substrings is what
      // separates github.evil.com (deceptive) from mygithub.io and
      // notamazon.com (legitimate domains that merely contain the word).
      if (mainName !== brand && subdomainLabels.some((l) => l === brand || skeleton(l) === brand)) {
        return { brand, type: 'subdomain_deception', reason: `Brand '${brand}' deceptive use in subdomain or domain` };
      }
      // typosquatting on skeleton forms with Damerau distance.
      // dist 0 with a different raw label = perfect skeleton spoof (paypa1.com)
      if (mainName.length >= 4 && Math.abs(mainName.length - brand.length) <= 2) {
        const dist = damerauLevenshtein(skelMain, brand);
        if (dist === 0 && mainName !== brand) {
          return { brand, type: 'skeleton_spoof', reason: `Confusable characters spoofing '${brand}' (${mainName})` };
        }
        // A brand bolted onto the front or back of another word is a compound
        // (mygithub, githubtv, amazonian), not a typo of the brand. Those are
        // ordinary names, and flagging them is the false positive this issue
        // is about. Real typos — substitutions, transpositions, a single edit
        // in the middle — still land below.
        const compound = mainName.startsWith(brand) || mainName.endsWith(brand);
        if (dist === 1 || (dist === 2 && mainName.length >= 6 && !compound)) {
          return { brand, type: 'typosquatting', reason: `Typosquatted lookalike domain for '${brand}' (${mainName})` };
        }
      }
    }
    return null;
  }

  function analyzeAttachment(filename = '') {
    if (!filename) return { dangerous: false };
    // Normalize display-control obfuscation, NTFS alternate data streams, and
    // Windows' ignored trailing dots/spaces before inspecting the extension.
    const lowerName = filename.toLowerCase()
      .replace(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, '')
      .replace(/:([^:/\\]*:)?\$data$/i, '')
      .trim()
      .replace(/[. ]+$/g, '');
    const doubleExtMatch = lowerName.match(/\.([a-z0-9]+)\.([a-z0-9]+)$/i);
    // A deceptive double extension needs a document/media type in front of the
    // dangerous one (invoice.pdf.exe). A compound name like app.min.js is not
    // deception — `min` is not something anyone is tricked into opening — so it
    // falls through to the plain extension check below.
    if (doubleExtMatch &&
        DOCUMENT_TYPES.has(doubleExtMatch[1]) &&
        DANGEROUS_EXTENSIONS.has(doubleExtMatch[2])) {
      return { filename, dangerous: true, reason: `Deceptive double extension detected: .${doubleExtMatch[1]}.${doubleExtMatch[2]}` };
    }
    const extMatch = lowerName.match(/\.([a-z0-9]+)$/i);
    if (extMatch && EXECUTABLE_EXTENSIONS.has(extMatch[1])) {
      return { filename, dangerous: true, reason: `Executable or script attachment: .${extMatch[1]}` };
    }
    if (extMatch && SCRIPT_EXTENSIONS.has(extMatch[1])) {
      return { filename, dangerous: false, reason: `Script attachment: .${extMatch[1]}` };
    }
    return { filename, dangerous: false };
  }

  const OPEN_REDIRECT_REGEX = /[?&](url|redirect|redir|next|continue|dest|destination|return)=/i;
  const DANGEROUS_SCHEME_REGEX = /^\s*(data|javascript|vbscript|file):/i;

  function isUrlSuspicious(url) {
    if (!url) return false;
    const raw = String(url);

    // dangerous schemes
    if (DANGEROUS_SCHEME_REGEX.test(raw)) return true;
    // invisible-character obfuscation
    if (hasInvisible(raw)) return true;

    // An unparseable URL is malformed, not proven malicious. The checks above
    // already caught dangerous schemes and invisible characters, and a browser
    // refuses to navigate to a URL this parser rejects (an invalid port, an
    // unclosed IPv6 literal), so treating it as a phishing host only produced
    // noise on relative or hand-typed links.
    let parsed;
    try {
      parsed = new URL(raw);
    } catch {
      return false;
    }
    // Do not allow untrusted links to invoke non-web protocols through the URL scanner.
    if (!['http:', 'https:', 'mailto:'].includes(parsed.protocol)) return true;
    // URL normalizes default ports away; any remaining HTTP(S) port is nonstandard.
    if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.port) return true;
    // Userinfo can disguise the actual destination host (brand.example@attacker.example).
    if (parsed.username || parsed.password) return true;
    // HTTP does not protect the destination or message content in transit.
    if (parsed.protocol === 'http:') return true;
    const domain = parsed.hostname.toLowerCase();

    if (detectHomographAttack(domain)) return true;
    const lookalike = checkLookalikeBrand(domain);
    if (lookalike) return true;

    const brandHost = isOfficialBrandHost(domain);

    // shorteners (brand-owned t.co / goo.gl exempt on official hosts)
    for (const s of SHORTENER_SET) {
      if ((s === 't.co' || s === 'goo.gl') && brandHost) continue;
      if (domain === s || domain.endsWith('.' + s)) return true;
    }

    if (brandHost) {
      // official hosts still fail on open-redirect params
      if (OPEN_REDIRECT_REGEX.test(raw) && /https?%3a%2f%2f|https?:\/\/[^.]/i.test(raw)) return true;
      return false;
    }

    for (const tld of SUSPICIOUS_TLD_SET) {
      if (domain.endsWith(tld.startsWith('.') ? tld : '.' + tld)) return true;
    }

    // A bare IP literal is unusual for a public link, but a private or
    // loopback address points at the user's own network: an intranet host, a
    // router page, a dev server. Flagging those trains people to ignore the
    // warning. Only public IP literals stay suspicious.
    if (IP_HOSTNAME_REGEX.test(domain)) return !isPrivateIpAddress(domain);
    if (IPV6_HOSTNAME_REGEX.test(domain)) return !isPrivateIpv6Address(domain);
    if (domain.split('.').length > 4) return true;
    if (domain.length > 75) return true;
    // hyphen abuse: 3+ hyphen-separated labels in the registrable SLD
    const reg = getRegistrableDomain(domain);
    const sld = reg.split('.')[0];
    if ((sld.match(/-/g) || []).length >= 3) return true;

    // open-redirect parameters pointing off-host
    if (OPEN_REDIRECT_REGEX.test(raw) && /(https?%3a%2f%2f|https?:\/\/)/i.test(raw)) return true;

    // A keyword only counts when it stands as its own label or as a
    // hyphen/underscore-separated word. Plain substring matching flagged
    // accountant.com (contains "account") and myaccount.example, which are
    // ordinary domains that merely contain the word.
    const KEYWORD_WORDS = ['secure', 'verify', 'account', 'login', 'signin', 'update', 'confirm', 'banking', 'credential'];
    const labels = domain.split('.');
    if (labels.length < 2) return false;
    // The registrable label is the one just before the TLD; a keyword there
    // means the domain *is* that keyword's own site (secure.com, account.com),
    // which the old code also spared.
    const registrable = labels[labels.length - 2];
    for (const kw of KEYWORD_WORDS) {
      if (registrable === kw) continue;
      // A keyword anywhere else — a subdomain label or a compound registrable
      // name such as secure-login.example.com — is a deception.
      for (const label of labels.slice(0, -2)) {
        if (label.split(/[-_]+/).includes(kw)) return true;
      }
      if (registrable.split(/[-_]+/).includes(kw)) return true;
    }
    return false;
  }

  function isDomainSuspicious(domain) {
    if (!domain) return false;
    const lowerDomain = domain.toLowerCase();
    if (detectHomographAttack(lowerDomain)) return true;
    if (checkLookalikeBrand(lowerDomain)) return true;
    for (const tld of SUSPICIOUS_TLD_SET) {
      if (lowerDomain.endsWith(tld.startsWith('.') ? tld : '.' + tld)) return true;
    }
    if (IP_HOSTNAME_REGEX.test(lowerDomain)) return true;
    if (IPV6_HOSTNAME_REGEX.test(lowerDomain)) return true;
    if (/[0-9]{4,}/.test(lowerDomain)) return true;
    return false;
  }

  /**
   * Display-name vs sender-domain impersonation:
   * "PayPal Service <random@mail.example>" is a classic combo-spoof.
   *
   * A brand must stand as a whole token, or open a camel-case compound such as
   * "PayPalService". A bare substring match flagged "Purchaser" (contains
   * "chase") and "groups" (contains "ups") — ordinary names and company words.
   */
  function detectDisplayNameImpersonation(sender) {
    if (!sender || !sender.name || !sender.domain) return null;
    if (isOfficialBrandHost(sender.domain)) return null;

    const rawName = String(sender.name);
    const lowerName = rawName.toLowerCase();
    const words = rawName.split(/[^A-Za-z0-9]+/).filter(Boolean).map((w) => w.toLowerCase());
    const domain = sender.domain;

    for (const brand of BRAND_SET) {
      // The name is exactly the brand: "Chase <x@random.example>".
      if (words.includes(brand)) {
        return { brand, reason: `Display name claims '${brand}' but mail originates from ${domain}` };
      }

      // A brand opening a camel-case compound: "PayPalService". The boundary
      // must be a capital or a digit in the original text — "upside" and
      // "upsell" stay legitimate.
      if (lowerName.startsWith(brand) && /[A-Z0-9]/.test(rawName.charAt(brand.length))) {
        return { brand, reason: `Display name claims '${brand}' but mail originates from ${domain}` };
      }

      // A lookalike token, e.g. "PayPa1" folded onto "paypal".
      for (const word of words) {
        if (word.length >= 4 && skeleton(word) === brand && word !== brand) {
          return { brand, reason: `Display name claims '${brand}' but mail originates from ${domain}` };
        }
      }
    }
    return null;
  }

  /* ===================================================================
   * Weighted scoring + logistic calibration.
   * Sub-score caps preserved for the Threat Inspector UI:
   *   urgency 0-40, trust 0-45, links 0-45, attachments 0-50
   * ================================================================== */
  const LOGISTIC_MIDPOINT = 42;
  const LOGISTIC_SCALE = 12;
  function squash(score) {
    const c = 1 / (1 + Math.exp(-((score - LOGISTIC_MIDPOINT) / LOGISTIC_SCALE)));
    return Math.min(Math.max(c, 0.04), 0.97);
  }

  function heuristicDetect(emailContent = {}, links = [], attachments = []) {
    const text = emailContent?.text || '';
    const subject = emailContent?.subject || '';
    const sender = emailContent?.sender || {};
    const emailLinks = emailContent?.links || [];
    const emailAttachments = emailContent?.attachments || [];
    // Callers pass emailContent as well as its links and attachments, so the
    // same entry can arrive twice. De-duplicating by identity keeps each link
    // and attachment counted once however the function is called.
    const allLinks = [...emailLinks];
    for (const link of links) {
      if (!allLinks.includes(link)) allLinks.push(link);
    }
    const allAttachments = [...emailAttachments];
    for (const att of attachments) {
      if (!allAttachments.includes(att)) allAttachments.push(att);
    }

    let urgencyScore = 0, senderTrustScore = 0, linkRiskScore = 0, attachmentRiskScore = 0;
    const reasons = [];

    // ---- 1. urgency & pressure language ----
    const urgencyKeywords = [
      'urgent','immediate','verify','account','suspend','locked','click here',
      'confirm','update','security','unauthorized','limited time','act now',
      'expire','password','credential','bank','paypal','amazon','microsoft',
      'apple','google','invoice','receipt','order','shipment','delivery',
      'refund','tax','irs','government','legal','court'
    ];
    const fullText = `${subject} ${text}`.toLowerCase();
    // Word-boundary match. `includes` fired `tax` on "taxi" and `account` on
    // "accounting", inflating the urgency score on ordinary mail.
    const foundUrgency = [...new Set(
      urgencyKeywords.filter((kw) => {
        if (!kw.includes(' ')) {
          return new RegExp(`\\b${kw}\\b`, 'i').test(fullText);
        }
        return fullText.includes(kw);
      })
    )];
    if (foundUrgency.length > 0) {
      urgencyScore = Math.min(foundUrgency.length * 8, 40);
      reasons.push(`Urgency signals: ${foundUrgency.slice(0, 3).join(', ')}`);
    }

    // ---- 2. sender identity analysis ----
    if (sender.domain) {
      const lookalike = checkLookalikeBrand(sender.domain);
      if (lookalike) {
        senderTrustScore += 45;
        reasons.push(lookalike.reason);
      } else if (isDomainSuspicious(sender.domain)) {
        senderTrustScore += 30;
        reasons.push(`Suspicious sender domain: ${sender.domain}`);
      }

      const impersonation = detectDisplayNameImpersonation(sender);
      if (impersonation) {
        senderTrustScore += 34;
        reasons.push(impersonation.reason);
      }

      if (sender.email) {
        const emailLower = String(sender.email).toLowerCase();
        const prefixes = ['security@','support@','admin@','noreply@','no-reply@','billing@','service@'];
        if (prefixes.some(p => emailLower.startsWith(p)) && isDomainSuspicious(sender.domain)) {
          senderTrustScore += 25;
          reasons.push(`Security persona from unverified domain: ${sender.email}`);
        }
      }

      // Lookalike(45) + impersonation(34) + persona(25) can reach 104 against a
      // documented cap of 45. The other three sub-scores are clamped; this one
      // was not, so the Threat Inspector drew a bar past its own maximum.
      senderTrustScore = Math.min(senderTrustScore, 45);
    }

    // ---- 3. link inspection ----
    let suspiciousLinkCount = 0;
    const analyzedLinks = allLinks.map(link => {
      if (!link || !link.href) return null;
      let isSusp = isUrlSuspicious(link.href);
      let linkReason = '';

      // Explain the transport warning even when the host looks legitimate.
      try {
        if (new URL(link.href).protocol === 'http:') {
          linkReason = 'Unencrypted HTTP link (connection can be intercepted)';
        }
      } catch {}

      let host = '';
      try { host = new URL(link.href, 'https://example.invalid').hostname.toLowerCase(); } catch {}
      const lookalike = checkLookalikeBrand(host);
      if (lookalike) { isSusp = true; linkReason = lookalike.reason; }

      const displayText = typeof link.text === 'string' ? link.text.trim() : '';
      // Treat www.-prefixed link text as a URL, but not arbitrary dotted labels such as filenames.
      const isAbsoluteWebUrl = /^https?:\/\//i.test(displayText);
      const isSchemeLessWebUrl = /^www\.(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d{1,5})?(?:[/?#]|$)/i.test(displayText);
      if (isAbsoluteWebUrl || isSchemeLessWebUrl) {
        try {
          const displayUrl = isAbsoluteWebUrl ? displayText : `https://${displayText}`;
          const textHost = new URL(displayUrl).hostname.toLowerCase();
          const hrefHost = new URL(link.href).hostname.toLowerCase();
          if (textHost !== hrefHost) {
            isSusp = true;
            linkReason = `Destination (${hrefHost}) hides behind display text (${textHost})`;
          }
        } catch {}
      }

      if (isSusp) {
        suspiciousLinkCount++;
        return { ...link, suspicious: true, reason: linkReason || 'Suspicious URL pattern' };
      }
      return { ...link, suspicious: false };
    }).filter(Boolean);

    if (suspiciousLinkCount > 0) {
      linkRiskScore = Math.min(suspiciousLinkCount * 16, 45);
      reasons.push(`${suspiciousLinkCount} suspicious link(s) detected`);
    }

    // ---- 4. attachment inspection ----
    let dangerousAttachmentCount = 0;
    const analyzedAttachments = allAttachments.map(att => {
      const filename = typeof att === 'string' ? att : att?.name || '';
      const analysis = analyzeAttachment(filename);
      if (analysis.dangerous) {
        dangerousAttachmentCount++;
        reasons.push(`Dangerous attachment: ${analysis.reason}`);
        return { name: filename, dangerous: true, reason: analysis.reason };
      }
      return { name: filename, dangerous: false };
    });

    if (dangerousAttachmentCount > 0) {
      attachmentRiskScore = Math.min(dangerousAttachmentCount * 35, 50);
    }

    // ---- 5. content-level signals ----
    // `text` is textContent, where tags never appear, so testing the text for
    // '<form' could never fire. The content script counts the elements instead.
    if (emailContent?.hasFormElements) {
      reasons.push('Interactive form elements inside email');
    }
    if (hasInvisible(text)) {
      reasons.push('Invisible / zero-width obfuscation characters in body');
    }

    const rawLetters = text.replace(/[^a-zA-Z]/g, '');
    const capsCount = (rawLetters.match(/[A-Z]/g) || []).length;
    if (rawLetters.length > 20 && capsCount / rawLetters.length > 0.35) {
      reasons.push('Excessive capitalization detected');
    }

    const genericGreetings = ['dear customer','dear user','hello customer','valued customer','dear sir/madam'];
    if (genericGreetings.some(g => fullText.includes(g))) {
      reasons.push('Generic unpersonalized greeting');
    }

    // ---- aggregate with logistic calibration ----
    let totalRisk = urgencyScore + senderTrustScore + linkRiskScore + attachmentRiskScore;
    if (dangerousAttachmentCount > 0) totalRisk = Math.max(totalRisk, 70); // floor for weaponized attachments
    totalRisk = Math.min(totalRisk, 100);

    const confidence = squash(totalRisk);

    let label = 'legitimate_email';
    if (confidence >= 0.65 || dangerousAttachmentCount > 0) label = 'phishing_email';
    else if (confidence >= 0.35) label = 'uncertain';

    return {
      label,
      confidence,
      engine: 'heuristic-v1.1',
      reasons: prioritiseReasons([...new Set(reasons)]),
      processingTime: 0,
      links: analyzedLinks,
      attachments: analyzedAttachments,
      signals: {
        urgencyScore,
        senderTrustScore,
        linkRiskScore,
        attachmentRiskScore,
        totalRiskScore: totalRisk
      },
      allScores: {
        legitimate_email: Number((1 - confidence).toFixed(3)),
        phishing_email: Number(confidence.toFixed(3)),
        legitimate_url: Number((1 - confidence).toFixed(3)),
        phishing_url: Number(confidence.toFixed(3))
      }
    };
  }

  /* ---- exports ---- */
  root.PhishNet = root.PhishNet || {};
  Object.assign(root.PhishNet, {
    heuristicDetect,
    isUrlSuspicious,
    isDomainSuspicious,
    checkLookalikeBrand,
    analyzeAttachment,
    detectHomographAttack,
    detectDisplayNameImpersonation,
    skeleton,
    damerauLevenshtein,
    levenshteinDistance,
    getRegistrableDomain,
    isOfficialBrandHost
  });

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      heuristicDetect,
      isUrlSuspicious,
      isDomainSuspicious,
      checkLookalikeBrand,
      analyzeAttachment,
      detectHomographAttack,
      detectDisplayNameImpersonation,
      skeleton,
      damerauLevenshtein,
      levenshteinDistance,
      getRegistrableDomain,
      isOfficialBrandHost
    };
  }
})();
