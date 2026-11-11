/** Popup controller. Shows the result for the email open in the active Gmail tab. Renders with textContent only. */
const V = globalThis.ScanView;
const $ = (id) => document.getElementById(id);
const el = (t, p, k) => V.el(document, t, p, k);
const UI_DEFAULTS = { showBanner: true, autoScan: true };
let tab = null;
let poll = null;

if (window.matchMedia('(prefers-color-scheme: dark)').matches) document.body.classList.add('gcs-dark');

function show(...nodes) {
  const m = $('main');
  while (m.firstChild) m.removeChild(m.firstChild);
  nodes.forEach((n) => n && m.appendChild(n));
}

function empty(iconNames, title, text, buttons, level) {
  return el('div', { class: 'empty' }, [
    el('span', { class: 'gcs-badge gcs-' + (level || 'grey') }, [V.icon(document, iconNames, 28)]),
    el('h2', { text: title }),
    el('p', { text }),
    buttons ? el('div', { class: 'buttons', style: 'justify-content:center' }, buttons) : null
  ]);
}

function btn(label, iconName, onclick, primary) {
  return el('button', { class: 'gcs-btn' + (primary ? ' gcs-btn-primary' : ''), type: 'button', onclick }, [iconName ? V.icon(document, iconName, 16) : null, label]);
}

const rescan = () => chrome.tabs.sendMessage(tab.id, { type: 'rescan' }).then(refresh).catch(refresh);
const showInPage = () => chrome.tabs.sendMessage(tab.id, { type: 'showBanner' }).then(() => window.close()).catch(() => {});

function render(st) {
  clearTimeout(poll);
  if (!st.hasMessage && st.status === 'none') {
    return show(empty('shield', 'Open an email', 'Open any message in Gmail and it is checked right away.'));
  }
  if (st.status === 'scanning') {
    poll = setTimeout(refresh, 500);
    return show(el('div', { class: 'empty' }, [el('div', { class: 'gcs-spinner', style: 'margin:8px auto 14px', role: 'status', 'aria-label': 'Scanning' }), el('h2', { text: 'Scanning…' }), el('p', { text: st.subject || '' })]));
  }
  if (st.status === 'idle') {
    return show(empty('shield', 'Not scanned yet', 'Automatic scanning is off.', [btn('Scan this email', 'shield', rescan, true)]));
  }
  if (st.status === 'error') {
    return show(
      empty(['shield', 'alert'], 'This email was NOT checked', 'The scan failed, so treat this email with care.', [btn('Try again', 'refresh', rescan, true)]),
      el('p', { class: 'error-text', text: st.error })
    );
  }
  const r = st.result;
  show(
    el('div', { class: 'hero gcs-' + r.level }, [
      V.levelIcon(document, r.level, 24),
      el('div', { class: 'hero-text' }, [
        el('p', { class: 'gcs-title gcs-' + r.level, text: V.LEVELS[r.level].label }),
        el('p', { class: 'gcs-sub', text: V.LEVELS[r.level].hint })
      ]),
      V.scoreRing(document, r.score, r.level)
    ]),
    st.subject ? el('p', { class: 'subject', text: st.subject, title: st.subject }) : null,
    V.details(document, r),
    el('div', { class: 'buttons' }, [btn('Scan again', 'refresh', rescan), btn('Show in Gmail', null, showInPage)])
  );
}

async function refresh() {
  try {
    const st = await chrome.tabs.sendMessage(tab.id, { type: 'getState' });
    render(st || { status: 'none' });
  } catch (e) {
    show(empty('refresh', 'Reload Gmail', 'The scanner starts on Gmail tabs opened after it was installed. Reload this tab once.', [
      btn('Reload tab', 'refresh', () => { chrome.tabs.reload(tab.id); window.close(); }, true)
    ]));
  }
}

async function initToggles() {
  const s = await chrome.storage.local.get('ui');
  const ui = { ...UI_DEFAULTS, ...(s.ui || {}) };
  for (const k of Object.keys(UI_DEFAULTS)) {
    $(k).checked = !!ui[k];
    $(k).addEventListener('change', async () => {
      const cur = { ...UI_DEFAULTS, ...((await chrome.storage.local.get('ui')).ui || {}) };
      cur[k] = $(k).checked;
      await chrome.storage.local.set({ ui: cur });
      if (tab) setTimeout(refresh, 400);
    });
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  $('settings').appendChild(V.icon(document, 'gear', 18));
  initToggles();
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !/^https:\/\/mail\.google\.com\//.test(tab.url || '')) {
    tab = null;
    return show(empty('shield', 'Open Gmail', 'This scanner works inside Gmail. Open an email there to see its safety check.', [
      btn('Open Gmail', null, () => { chrome.tabs.create({ url: 'https://mail.google.com/' }); window.close(); }, true)
    ]));
  }
  refresh();
});
