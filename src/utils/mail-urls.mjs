// Keep popup-triggered scans scoped to the same mail origins as the manifest's
// content script. Exact hosts prevent lookalike subdomains from being trusted.
const MAIL_HOSTS = new Set([
  'mail.google.com',
  'outlook.live.com',
  'outlook.office.com',
  'outlook.office365.com'
]);

export function isSupportedMailTabUrl(value) {
  if (typeof value !== 'string') return false;
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && MAIL_HOSTS.has(url.hostname);
  } catch {
    return false;
  }
}

/**
 * Whether a message came from a supported mail tab.
 *
 * `chrome.runtime.sendMessage` reaches every extension context, so a message
 * arriving with `sender.tab` must be checked against the same origins the
 * content script is allowed to run on. A tab that cannot be matched is not a
 * mail tab, whatever URL it reports.
 *
 * @param {unknown} sender the `sender` argument Chrome passes to a listener
 * @returns {boolean}
 */
export function isSupportedMailTabSender(sender) {
  if (!sender || typeof sender !== 'object') return false;
  if (!sender.tab || typeof sender.tab !== 'object') return false;
  const url = sender.tab.url || sender.url;
  return isSupportedMailTabUrl(url);
}
