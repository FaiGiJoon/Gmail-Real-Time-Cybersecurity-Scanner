/** Popup controller. Shows the result for the email open in the active Gmail tab. Renders with textContent only. */
const V = globalThis.ScanView;
const $ = (id) => document.getElementById(id);
const el = (t, p, k) => V.el(document, t, p, k);
const UI_DEFAULTS = { showBanner: true, autoScan: true, scanCount: 25, autoSpam: false };
const COUNTS = [10, 25, 50, 100, 200, 500];
let ui = { ...UI_DEFAULTS };
let picked = null; // ids ticked in the results list; null = not chosen yet
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

const ask = (type, extra) => chrome.tabs.sendMessage(tab.id, { type, ...(extra || {}) });
const scanInbox = () => { picked = null; return ask('scanInbox', { count: ui.scanCount }).then(refresh).catch(refresh); };

async function saveUi(patch) {
  ui = { ...UI_DEFAULTS, ...((await chrome.storage.local.get('ui')).ui || {}), ...patch };
  await chrome.storage.local.set({ ui });
}

/** "Scan the newest [n] emails" and "Afterwards [do what]" controls. */
function scanSetup() {
  const count = el('select', { id: 'scanCount', onchange: (e) => saveUi({ scanCount: Number(e.target.value) }) },
    COUNTS.map((n) => el('option', { value: n, selected: n === ui.scanCount, text: String(n) })));
  const after = el('select', { id: 'autoSpam', onchange: (e) => saveUi({ autoSpam: e.target.value === 'spam' }).then(refresh) }, [
    el('option', { value: 'show', selected: !ui.autoSpam, text: 'Show me the results' }),
    el('option', { value: 'spam', selected: ui.autoSpam, text: 'Report dangerous ones as spam' })
  ]);
  return el('div', { class: 'setup' }, [
    el('label', { class: 'field' }, [el('span', { text: 'Scan the newest' }), count, el('span', { text: 'emails' })]),
    el('label', { class: 'field' }, [el('span', { text: 'Afterwards' }), after]),
    ui.autoSpam ? el('p', { class: 'setup-note', text: 'Emails rated "Likely dangerous" are moved to Spam without asking. Trusted senders are never touched. You can undo it from the Spam folder.' }) : null,
    ui.scanCount > 50 ? el('p', { class: 'setup-note', text: 'Larger scans page through your mail list in this tab. Leave the tab alone until it finishes.' }) : null
  ]);
}

function inboxView(inbox) {
  const items = inbox.items;
  const scanning = inbox.status === 'running';
  const acting = inbox.status === 'acting';
  const done = items.filter((i) => i.status === 'done' || i.status === 'error').length;
  const risky = items.filter((i) => i.level === 'red' && i.action !== 'spam').length;
  const careful = items.filter((i) => i.level === 'yellow' && i.action !== 'spam').length;
  const failed = items.filter((i) => i.status === 'error').length;
  const reported = items.filter((i) => i.action === 'spam').length;
  const actFailed = items.filter((i) => i.action === 'failed').length;
  const queue = items.filter((i) => i.action === 'queued' || i.action === 'working').length;

  // Default ticks (the dangerous ones) are chosen once, when the scan has finished.
  if (picked === null && !scanning) picked = new Set(items.filter((i) => i.level === 'red' && !i.trusted && i.action !== 'spam').map((i) => i.id));
  const ticked = picked || new Set();
  const canPick = (i) => !scanning && !acting && i.status === 'done' && i.action !== 'spam' && !!i.legacyThread;
  const chosen = items.filter((i) => ticked.has(i.id) && canPick(i));

  let title, sub, level;
  if (scanning) { title = 'Scanning ' + done + ' of ' + items.length + '…'; sub = 'Keep this Gmail tab open.'; level = 'grey'; }
  else if (acting) { title = 'Reporting spam… ' + queue + ' left'; sub = 'Opening each email and pressing Report spam. Leave this tab alone.'; level = 'grey'; }
  else {
    title = items.length + ' emails checked';
    const parts = [];
    if (risky) parts.push(risky + ' likely dangerous');
    if (careful) parts.push(careful + ' to be careful with');
    if (reported) parts.push(reported + ' reported as spam' + (inbox.auto ? ' automatically' : ''));
    if (failed) parts.push(failed + ' not checked');
    if (actFailed) parts.push(actFailed + ' could not be reported');
    sub = parts.length ? parts.join(' · ') : 'Nothing suspicious found.';
    level = risky ? 'red' : careful || failed || actFailed ? 'yellow' : 'green';
  }

  // Worst first once finished; list order while scanning.
  const rank = { red: 0, yellow: 1, undefined: 2, green: 3 };
  const sorted = scanning ? items : items.slice().sort((a, b) => rank[a.level] - rank[b.level]);
  const reportBtn = btn('Report ' + chosen.length + ' as spam', null, () => ask('reportSpam', { ids: chosen.map((i) => i.id) }).then(refresh).catch(refresh), true);
  reportBtn.id = 'report';
  reportBtn.disabled = !chosen.length;

  return [
    el('div', { class: 'hero gcs-' + level }, [
      level === 'grey' ? el('span', { class: 'gcs-badge gcs-grey' }, [el('span', { class: 'gcs-spinner', role: 'status', 'aria-label': 'Working' })]) : V.levelIcon(document, level, 24),
      el('div', { class: 'hero-text' }, [el('p', { class: 'gcs-title gcs-' + level, text: title }), el('p', { class: 'gcs-sub', text: sub })]),
      scanning || acting ? btn('Stop', null, () => ask('stopInbox').then(refresh).catch(refresh)) : null
    ]),
    inbox.note ? el('p', { class: 'setup-note', text: inbox.note }) : null,
    el('ul', { class: 'inbox' }, sorted.map((it) => {
      const state = it.action === 'spam' ? 'gone' : it.status === 'done' ? it.level : it.status === 'error' ? 'error' : 'wait';
      const note = it.action === 'spam' ? 'Reported as spam'
        : it.action === 'working' ? 'Reporting…' : it.action === 'queued' ? 'Waiting to report'
        : it.action === 'failed' ? 'Not reported: ' + it.actionError
        : it.status === 'done' ? (it.count ? it.top + (it.count > 1 ? ' +' + (it.count - 1) : '') : 'Looks safe')
        : it.status === 'error' ? 'Not checked: ' + it.error : it.status === 'scanning' ? 'Scanning…' : 'Waiting';
      const tick = el('input', {
        type: 'checkbox', class: 'pick', checked: ticked.has(it.id) && canPick(it), disabled: !canPick(it),
        'aria-label': 'Select "' + it.subject + '" to report as spam',
        onchange: (e) => { if (e.target.checked) ticked.add(it.id); else ticked.delete(it.id); render(lastState); }
      });
      return el('li', { class: 'inbox-item' + (it.action === 'spam' ? ' is-gone' : '') }, [
        tick,
        el('button', {
          class: 'inbox-row', type: 'button', disabled: !it.legacyThread || it.action === 'spam' || acting, title: it.legacyThread ? 'Open this email' : '',
          onclick: () => ask('openThread', { legacyThread: it.legacyThread }).then(() => window.close()).catch(() => {})
        }, [
          el('span', { class: 'dot dot-' + state, 'aria-hidden': 'true' }),
          el('span', { class: 'inbox-text' }, [
            el('span', { class: 'inbox-subject', text: it.subject }),
            el('span', { class: 'inbox-note inbox-' + (it.action === 'failed' ? 'red' : state), text: (it.from ? it.from + ' · ' : '') + note })
          ]),
          it.status === 'done' && it.action !== 'spam' ? el('span', { class: 'inbox-score', text: String(it.score), title: 'Safety score out of 100' }) : null
        ])
      ]);
    })),
    scanning || acting ? null : el('div', { class: 'buttons' }, [reportBtn, btn('New scan', 'refresh', () => ask('clearInbox').then(() => { picked = null; refresh(); }))])
  ];
}

let lastState = null;

function render(st) {
  clearTimeout(poll);
  lastState = st;
  const inbox = st.inbox || { status: 'none', items: [] };
  if (!st.hasMessage && inbox.status === 'collecting') {
    poll = setTimeout(refresh, 500);
    return show(el('div', { class: 'empty' }, [
      el('div', { class: 'gcs-spinner', style: 'margin:8px auto 14px', role: 'status', 'aria-label': 'Working' }),
      el('h2', { text: 'Finding emails… ' + (inbox.found || 0) + ' of ' + inbox.wanted }),
      el('p', { text: 'Paging through your mail list. Leave this tab alone.' }),
      el('div', { class: 'buttons', style: 'justify-content:center' }, [btn('Stop', null, () => ask('stopInbox').then(refresh).catch(refresh))])
    ]));
  }
  if (inbox.status !== 'none' && inbox.items.length && (!st.hasMessage || inbox.status === 'acting')) {
    if (inbox.status === 'running' || inbox.status === 'acting') poll = setTimeout(refresh, 600);
    return show(...inboxView(inbox));
  }
  if (!st.hasMessage && st.status === 'none') {
    if (st.listCount) {
      return show(
        empty('shield', 'Connected to Gmail', 'Open any email and it is checked right away, or scan your mail list now.', null, 'green'),
        scanSetup(),
        el('div', { class: 'buttons', style: 'justify-content:center' }, [btn('Scan inbox', 'shield', scanInbox, true)])
      );
    }
    return show(empty('shield', 'Connected to Gmail', 'Open any message and it is checked right away.', null, 'green'));
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
  ui = { ...UI_DEFAULTS, ...((await chrome.storage.local.get('ui')).ui || {}) };
  for (const k of ['autoScan', 'showBanner']) {
    $(k).checked = !!ui[k];
    $(k).addEventListener('change', async () => {
      await saveUi({ [k]: $(k).checked });
      if (tab) setTimeout(refresh, 400);
    });
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  $('settings').appendChild(V.icon(document, 'gear', 18));
  await initToggles();
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  // tab.url is only visible with the activeTab grant; the content script answering is the real test.
  if (!tab || (tab.url && !/^https:\/\/mail\.google\.com\//.test(tab.url))) {
    tab = null;
    return show(empty('shield', 'Open Gmail', 'This scanner works inside Gmail. Open an email there to see its safety check.', [
      btn('Open Gmail', null, () => { chrome.tabs.create({ url: 'https://mail.google.com/' }); window.close(); }, true)
    ]));
  }
  refresh();
});
