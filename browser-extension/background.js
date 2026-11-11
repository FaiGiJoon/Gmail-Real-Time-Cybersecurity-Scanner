/**
 * Service worker. Classic (non-module) worker so it can importScripts the shared core.
 * Keeps no state in memory: MV3 workers are stopped after ~30s idle.
 *
 * The content script on mail.google.com reads the open email's original source from the page
 * and sends it here. This worker runs the shared core on it, adds the optional network checks
 * (Safe Browsing with your key, domain age through RDAP) and paints the toolbar badge.
 */
importScripts('scanner-core.js', 'mime.js', 'engine.js');

function getSettings() {
  return chrome.storage.local.get(['SAFE_BROWSING_API_KEY', 'config']).then(function (s) {
    return { keys: { SAFE_BROWSING_API_KEY: s.SAFE_BROWSING_API_KEY || '' }, config: s.config || {} };
  });
}

const engine = ScanEngine.createEngine({ fetch: fetch.bind(self), getSettings: getSettings });

const BADGE = {
  green: { text: 'OK', color: '#188038' },
  yellow: { text: '!', color: '#e37400' },
  red: { text: '!!', color: '#d93025' },
  scanning: { text: '…', color: '#5f6368' },
  error: { text: '?', color: '#5f6368' }
};

function badge(tabId, kind, title) {
  if (tabId === undefined) return;
  const b = kind && BADGE[kind];
  chrome.action.setBadgeText({ tabId, text: b ? b.text : '' });
  if (b) chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
  chrome.action.setTitle({ tabId, title: title || 'Gmail Cybersecurity Scanner' });
}

const handlers = {
  scanRaw: (m) => engine.scanRaw(m.raw, { id: m.messageId, threadId: m.threadId }),
  badge: (m, sender) => badge(sender.tab && sender.tab.id, m.kind, m.title)
};

chrome.runtime.onMessage.addListener((m, sender, sendResponse) => {
  const h = handlers[m && m.type];
  if (!h) return false;
  Promise.resolve().then(() => h(m, sender)).then(
    (data) => sendResponse({ ok: true, data }),
    (err) => sendResponse({ ok: false, error: String((err && err.message) || err) })
  );
  return true; // async response
});

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') chrome.tabs.create({ url: 'options.html?welcome=1' });
});
