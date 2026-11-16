/** Shared validation for incoming settings and values restored from storage. */
import { MAX_WHITELIST_ENTRIES, normalizeWhitelist, normalizeWhitelistEntry } from './whitelist-entry.mjs';

export const DEFAULT_SETTINGS = Object.freeze({
  autoScan: true,
  sensitivityThreshold: 0.7,
  highlightLinks: true,
  showTooltip: true,
  theme: 'auto',
  // Trust is a user decision. Major providers are not proof of sender authenticity.
  whitelist: Object.freeze([]),
});

const booleanSettings = new Set(['autoScan', 'highlightLinks', 'showTooltip']);
// Chrome and Firefox expose different theme choices to their respective popups.
const allowedThemes = new Set(['auto', 'light', 'dark']);

/**
 * Whether an entry restored from storage is still usable.
 *
 * Storage is normalised entry by entry rather than field by field, so one bad
 * value cannot discard the whole list — or, worse, survive and break every
 * later lookup.
 */
function isValidStoredEntry(entry) {
  return typeof entry === 'string' && normalizeWhitelistEntry(entry).ok;
}

function isValidSetting(key, value, themes = allowedThemes) {
  if (booleanSettings.has(key)) return typeof value === 'boolean';
  if (key === 'sensitivityThreshold') {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 1;
  }
  if (key === 'theme') return themes.has(value);
  if (key === 'whitelist') {
    return Array.isArray(value) &&
      value.length <= MAX_WHITELIST_ENTRIES &&
      value.every(isValidStoredEntry);
  }
  return false;
}

export function validateSettingsPatch(patch, themes = allowedThemes) {
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
    return 'settings must be an object';
  }
  for (const [key, value] of Object.entries(patch)) {
    if (!Object.hasOwn(DEFAULT_SETTINGS, key)) return `Unknown setting: ${key}`;
    if (!isValidSetting(key, value, themes)) return `Invalid ${key} setting`;
  }
  return null;
}

/** Ignore invalid stored fields individually, retaining legitimate preferences. */
export function normalizeStoredSettings(stored) {
  const source = stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {};
  return Object.fromEntries(Object.entries(DEFAULT_SETTINGS).map(([key, fallback]) => {
    const value = source[key];

    // A whitelist is validated as a whole rather than field by field: if any
    // entry is unusable the list falls back to the defaults. One corrupt value
    // used to survive into the worker, where `item.toLowerCase()` threw on
    // every scan and silently disabled scanning entirely.
    if (key === 'whitelist') {
      const recovered = normalizeWhitelist(value);
      return [key, recovered.ok ? recovered.value : [...fallback]];
    }

    const validated = isValidSetting(key, value) ? value : fallback;
    return [key, validated];
  }));
}
