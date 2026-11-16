/**
 * Broadcasting to the tabs that can actually receive a message.
 *
 * `chrome.tabs.query({})` returns every tab, and the workers used to send to all
 * of them on every settings or status change. Most have no content script, so
 * the message is dropped and the error swallowed. Restricting the audience to
 * tabs on a supported mail origin keeps the broadcast meaningful and the tab
 * list small.
 */
import { isSupportedMailTabUrl } from './mail-urls.mjs';

/**
 * Send `payload` to every tab running the PhishNet content script.
 *
 * `sendMessage` must return a promise. Firefox and Chrome both do, but a
 * rejected send is expected whenever a tab closes or navigates mid-broadcast —
 * the message is advisory, so failures are collected rather than thrown.
 *
 * @param {{query: (q: object) => Promise<object[]>, send: (tabId: number, msg: object) => Promise<unknown>}} tabs
 * @param {object} payload
 * @returns {Promise<{sent: number, failed: number}>}
 */
export async function broadcastToMailTabs(tabs, payload) {
  const all = await tabs.query({});
  const targets = (all || []).filter(
    (tab) => tab && tab.id != null && isSupportedMailTabUrl(tab.url)
  );

  let sent = 0;
  let failed = 0;
  for (const tab of targets) {
    try {
      await tabs.send(tab.id, payload);
      sent += 1;
    } catch {
      failed += 1;
    }
  }
  return { sent, failed };
}