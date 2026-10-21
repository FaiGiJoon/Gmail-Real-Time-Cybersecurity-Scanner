/**
 * Reads which message/thread is open in Gmail so the popup can scan it. It only reads ids from the
 * page; no email content leaves the page from here. Gmail's markup is not a public API, so this is
 * best effort: when it fails the popup falls back to the list of recent messages.
 */
chrome.runtime.onMessage.addListener((m, sender, sendResponse) => {
  if (!m || m.type !== 'currentMessage') return false;
  const msgs = document.querySelectorAll('[data-legacy-message-id]');
  const threads = document.querySelectorAll('[data-legacy-thread-id]');
  sendResponse({
    messageId: msgs.length ? msgs[msgs.length - 1].getAttribute('data-legacy-message-id') : null,
    threadId: threads.length ? threads[threads.length - 1].getAttribute('data-legacy-thread-id') : null
  });
  return false;
});
