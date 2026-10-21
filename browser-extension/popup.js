/** Popup controller. Renders with textContent only: email data is untrusted. */
const $ = (id) => document.getElementById(id);
let current = null; // {messageId, threadId}

function send(msg) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, (res) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      if (!res || !res.ok) return reject(new Error((res && res.error) || 'Unknown error'));
      resolve(res.data);
    });
  });
}

function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }

function render(r) {
  $('state').textContent = (r.deep ? 'Deep scan' : 'Standard scan') + ': ' + (r.subject || '(no subject)');
  const v = $('verdict');
  v.textContent = r.status + ' (' + r.score + '/100)';
  v.className = r.level;
  const list = $('findings');
  clear(list);
  const real = r.findings.filter((f) => f.severity !== 'info');
  if (!real.length) {
    const li = document.createElement('li');
    li.textContent = 'No problems found by the checks that ran.';
    list.appendChild(li);
  }
  real.forEach((f) => {
    const li = document.createElement('li');
    const sev = document.createElement('span'); sev.className = 'sev ' + (f.severity === 'critical' || f.severity === 'high' ? 'red' : 'yellow'); sev.textContent = f.severity + ' ';
    const t = document.createElement('b'); t.textContent = f.title;
    const d = document.createElement('div'); d.className = 'detail'; d.textContent = f.detail + (f.evidence ? ' [' + f.evidence + ']' : '');
    li.append(sev, t, d);
    list.appendChild(li);
  });
  const nc = $('notchecked');
  nc.hidden = !r.incomplete;
  nc.textContent = r.incomplete ? 'Not checked: ' + r.skipped.join('; ') : '';
  $('actions').hidden = false;
  $('deep').hidden = !!r.deep;
}

async function scan(messageId, threadId, deep) {
  $('error').textContent = '';
  $('state').textContent = deep ? 'Running deep scan...' : 'Scanning...';
  try {
    const r = await send({ type: 'scan', messageId, deep });
    current = { messageId, threadId: r.threadId || threadId };
    $('picker').hidden = true;
    render(r);
  } catch (e) {
    // Never show a clean state after a failed scan.
    $('verdict').textContent = '';
    clear($('findings'));
    $('state').textContent = 'Scan failed. This email was NOT checked.';
    $('error').textContent = e.message;
  }
}

async function showRecent() {
  try {
    const items = await send({ type: 'recent' });
    const p = $('picker');
    clear(p);
    const h = document.createElement('div'); h.textContent = 'Pick a message to scan:'; p.appendChild(h);
    items.forEach((m) => {
      const b = document.createElement('button');
      b.textContent = m.from + ' - ' + m.snippet.slice(0, 60);
      b.addEventListener('click', () => scan(m.id, m.threadId, false));
      p.appendChild(b);
    });
    $('state').textContent = 'Could not detect the open message.';
  } catch (e) {
    $('state').textContent = 'Could not reach Gmail.';
    $('error').textContent = e.message;
  }
}

async function detectOpenMessage() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !/^https:\/\/mail\.google\.com\//.test(tab.url || '')) return null;
  try {
    const info = await chrome.tabs.sendMessage(tab.id, { type: 'currentMessage' });
    if (info && info.messageId) return info;
    if (info && info.threadId) {
      const id = await send({ type: 'resolveThread', threadId: info.threadId });
      if (id) return { messageId: id, threadId: info.threadId };
    }
  } catch (e) { /* content script not present: fall back to the list */ }
  return null;
}

document.addEventListener('DOMContentLoaded', async () => {
  $('deep').addEventListener('click', () => current && scan(current.messageId, current.threadId, true));
  $('neutralize').addEventListener('click', async () => {
    if (!current || !confirm('Move this conversation to Spam and mark it read? Nothing is deleted.')) return;
    try { await send({ type: 'neutralize', threadId: current.threadId }); $('state').textContent = 'Moved to Spam.'; $('actions').hidden = true; }
    catch (e) { $('error').textContent = e.message; }
  });
  const open = await detectOpenMessage();
  if (open) scan(open.messageId, open.threadId, false); else showRecent();
});
