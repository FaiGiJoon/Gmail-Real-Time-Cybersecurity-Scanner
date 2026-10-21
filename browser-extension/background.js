/**
 * Service worker. Classic (non-module) worker so it can importScripts the shared core.
 * Keeps no state in memory: MV3 workers are stopped after ~30s idle.
 */
importScripts('scanner-core.js', 'engine.js');

function getToken(interactive) {
  return new Promise(function (resolve, reject) {
    chrome.identity.getAuthToken({ interactive: interactive !== false }, function (token) {
      if (chrome.runtime.lastError || !token) reject(new Error((chrome.runtime.lastError && chrome.runtime.lastError.message) || 'No token'));
      else resolve(token);
    });
  });
}

function getSettings() {
  return chrome.storage.local.get(['SAFE_BROWSING_API_KEY', 'config']).then(function (s) {
    return { keys: { SAFE_BROWSING_API_KEY: s.SAFE_BROWSING_API_KEY || '' }, config: s.config || {} };
  });
}

const engine = ScanEngine.createEngine({ fetch: fetch.bind(self), getToken: getToken, getSettings: getSettings });

const handlers = {
  scan: (m) => engine.scanMessage(m.messageId, !!m.deep),
  recent: () => engine.listRecent(10),
  resolveThread: (m) => engine.newestInThread(m.threadId),
  neutralize: (m) => engine.neutralize(m.threadId),
  // The token cache can hold a revoked token; drop it so the next call re-authorizes.
  signOut: () => getToken(false).then((t) => new Promise((r) => chrome.identity.removeCachedAuthToken({ token: t }, r)))
};

chrome.runtime.onMessage.addListener((m, sender, sendResponse) => {
  const h = handlers[m && m.type];
  if (!h) return false;
  Promise.resolve().then(() => h(m)).then(
    (data) => sendResponse({ ok: true, data }),
    (err) => sendResponse({ ok: false, error: String((err && err.message) || err) })
  );
  return true; // async response
});
