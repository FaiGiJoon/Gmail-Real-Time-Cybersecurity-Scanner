/**
 * Runs on mail.google.com. Works like a normal content-script extension: no Google Cloud project,
 * no OAuth client, no sign-in. When you open an email it:
 *   1. finds the open message in the page,
 *   2. reads its original source from Gmail's own "Show original" page (same tab, same login),
 *   3. hands the source to the service worker, which runs the shared scanning core,
 *   4. shows the verdict in a banner above the message and on the toolbar icon.
 * The email source only goes to this extension's service worker. Optional checks (Safe Browsing
 * with your key, domain age via rdap.org) send link URLs / domain names, as listed in the options.
 *
 * Gmail's markup is not a public API, so selectors here are best effort. When the banner cannot be
 * placed above the message it floats in the bottom-right corner instead.
 */
(() => {
  if (window.top !== window) return; // not inside Gmail's iframes
  const V = globalThis.ScanView;
  const UI_DEFAULTS = { showBanner: true, autoScan: true };
  const MAX_SOURCE = 25 * 1024 * 1024;

  let ui = { ...UI_DEFAULTS };
  let current = { key: null, status: 'none' }; // status: none | idle | scanning | done | error
  let open = false;
  let dismissed = null;
  let seq = 0;
  let host = null;
  let shadow = null;
  let timer = null;
  const cache = new Map(); // message id -> result, for this tab only

  function send(msg) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(msg, (res) => {
        if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
        if (!res || !res.ok) return reject(new Error((res && res.error) || 'Unknown error'));
        resolve(res.data);
      });
    });
  }
  const badge = (kind, title) => send({ type: 'badge', kind, title }).catch(() => {});

  const visible = (n) => !!(n && n.offsetParent !== null && n.getClientRects().length);

  /** The newest expanded, visible message in the open conversation. */
  function openMessage() {
    const nodes = [...document.querySelectorAll('[data-message-id], [data-legacy-message-id]')]
      .filter((n) => visible(n) && n.querySelector('.a3s'));
    const n = nodes[nodes.length - 1];
    if (!n) return null;
    let id = (n.getAttribute('data-message-id') || '').replace(/^#/, '');
    if (!/^msg-[af]:[\w-]+$/.test(id)) {
      const legacy = n.getAttribute('data-legacy-message-id') || '';
      if (!/^[0-9a-f]{6,20}$/i.test(legacy)) return null;
      id = 'msg-f:' + BigInt('0x' + legacy).toString();
    }
    const th = n.closest('[data-thread-perm-id]');
    const subject = [...document.querySelectorAll('h2.hP')].find(visible);
    return {
      id,
      threadId: th ? th.getAttribute('data-thread-perm-id') : '',
      subject: subject ? subject.textContent.trim() : '',
      node: n
    };
  }

  function decodeEntities(s) {
    return s.replace(/&(#x[0-9a-f]+|#\d+|lt|gt|amp|quot|apos|#39|nbsp);/gi, (m, e) => {
      const k = e.toLowerCase();
      if (k[0] === '#') {
        const cp = k[1] === 'x' ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10);
        return cp > 0 && cp < 0x110000 ? String.fromCodePoint(cp) : '';
      }
      return { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'", nbsp: ' ' }[k] || m;
    });
  }

  /** Reads the message source from Gmail's "Show original" view, using this tab's own login. */
  async function fetchSource(id) {
    const m = location.pathname.match(/^\/mail\/u\/\d+\//);
    const url = (m ? m[0] : '/mail/u/0/') + '?view=om&permmsgid=' + encodeURIComponent(id);
    const res = await fetch(url, { credentials: 'include' });
    if (!res.ok) throw new Error('Gmail answered HTTP ' + res.status + ' when asked for the original message.');
    const html = await res.text();
    if (html.length > MAX_SOURCE) throw new Error('This email is over 25 MB, too large to scan in the browser.');
    const pre = html.match(/<pre[^>]*id="?raw_message_text"?[^>]*>([\s\S]*?)<\/pre>/i) || html.match(/<pre[^>]*>([\s\S]*?)<\/pre>/i);
    if (!pre || pre[1].length < 20) throw new Error('Gmail did not return the original message (Show original).');
    return decodeEntities(pre[1].replace(/<[^>]+>/g, ''));
  }

  async function scan(msg) {
    const my = ++seq;
    current = { key: msg.id, status: 'scanning', subject: msg.subject };
    render(msg.node);
    badge('scanning', 'Scanning this email…');
    try {
      const raw = await fetchSource(msg.id);
      const result = await send({ type: 'scanRaw', raw, messageId: msg.id, threadId: msg.threadId });
      if (my !== seq) return;
      cache.set(msg.id, result);
      if (cache.size > 50) cache.delete(cache.keys().next().value);
      current = { key: msg.id, status: 'done', result, subject: msg.subject };
      badge(result.level, V.LEVELS[result.level].label + ' · safety ' + result.score + '/100');
    } catch (e) {
      if (my !== seq) return;
      // Never show a clean state after a failed scan.
      current = { key: msg.id, status: 'error', error: String(e.message || e), subject: msg.subject };
      badge('error', 'This email was not checked');
    }
    render(openMessage() ? openMessage().node : null);
  }

  // ---------------------------------------------------------------------------
  // Banner
  // ---------------------------------------------------------------------------

  function isDarkAround(node) {
    for (let n = node; n && n.nodeType === 1; n = n.parentElement) {
      const c = getComputedStyle(n).backgroundColor;
      const m = c.match(/rgba?\(([\d.]+),\s*([\d.]+),\s*([\d.]+)(?:,\s*([\d.]+))?/);
      if (!m || (m[4] !== undefined && Number(m[4]) < 0.5)) continue;
      return (0.2126 * m[1] + 0.7152 * m[2] + 0.0722 * m[3]) / 255 < 0.45;
    }
    return false;
  }

  function ensureHost() {
    if (host) return;
    host = document.createElement('div');
    host.id = 'gmail-cyber-scanner-banner';
    shadow = host.attachShadow({ mode: 'closed' });
    for (const f of ['view.css', 'banner.css']) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = chrome.runtime.getURL(f);
      shadow.appendChild(link);
    }
  }

  function removeHost() { if (host && host.parentNode) host.remove(); }

  function place(anchor) {
    ensureHost();
    if (anchor && anchor.parentNode) {
      if (host.nextSibling !== anchor) anchor.parentNode.insertBefore(host, anchor);
      return false;
    }
    if (host.parentNode !== document.body) document.body.appendChild(host);
    return true; // floating
  }

  function button(label, iconName, onclick, primary) {
    return V.el(document, 'button', { class: 'gcs-btn' + (primary ? ' gcs-btn-primary' : ''), type: 'button', onclick }, [
      iconName ? V.icon(document, iconName, 16) : null, label
    ]);
  }
  function iconButton(label, iconName, onclick, extra) {
    return V.el(document, 'button', { class: 'gcs-icon-btn ' + (extra || ''), type: 'button', title: label, 'aria-label': label, onclick }, [V.icon(document, iconName, 18)]);
  }

  function render(anchor) {
    if (!ui.showBanner || current.status === 'none' || dismissed === current.key) { removeHost(); return; }
    const floating = place(anchor);
    const el = (t, p, k) => V.el(document, t, p, k);
    const rescan = () => { const m = openMessage(); if (m) { cache.delete(m.id); scan(m); } };
    const close = iconButton('Hide for this email', 'close', () => { dismissed = current.key; removeHost(); });
    let level = 'grey';
    let bar;
    let body = null;

    if (current.status === 'scanning') {
      bar = [el('span', { class: 'gcs-badge gcs-grey' }, [el('span', { class: 'gcs-spinner', role: 'status', 'aria-label': 'Scanning' })]),
        el('div', { class: 'gcs-text' }, [el('p', { class: 'gcs-title', text: 'Scanning this email…' }), el('p', { class: 'gcs-sub', text: 'Checking sender, links and attachments.' })]),
        el('div', { class: 'gcs-actions' }, [close])];
    } else if (current.status === 'idle') {
      bar = [el('span', { class: 'gcs-badge gcs-grey' }, [V.icon(document, 'shield', 22)]),
        el('div', { class: 'gcs-text' }, [el('p', { class: 'gcs-title', text: 'Not scanned yet' }), el('p', { class: 'gcs-sub', text: 'Auto-scan is off.' })]),
        el('div', { class: 'gcs-actions' }, [button('Scan', 'shield', rescan, true), close])];
    } else if (current.status === 'error') {
      bar = [el('span', { class: 'gcs-badge gcs-grey' }, [V.icon(document, ['shield', 'alert'], 22)]),
        el('div', { class: 'gcs-text' }, [el('p', { class: 'gcs-title', text: 'This email was NOT checked' }), el('p', { class: 'gcs-sub', text: current.error })]),
        el('div', { class: 'gcs-actions' }, [button('Try again', 'refresh', rescan), close])];
    } else {
      const r = current.result;
      level = r.level;
      const toggle = iconButton(open ? 'Hide details' : 'Show details', 'chevron', () => { open = !open; render(anchor); }, 'gcs-chevron');
      toggle.setAttribute('aria-expanded', String(open));
      bar = [V.levelIcon(document, r.level),
        el('div', { class: 'gcs-text' }, [
          el('p', { class: 'gcs-title gcs-' + r.level, text: V.LEVELS[r.level].label }),
          el('p', { class: 'gcs-sub', text: V.summary(r), title: V.summary(r) })
        ]),
        V.scoreRing(document, r.score, r.level),
        el('div', { class: 'gcs-actions' }, [toggle, iconButton('Scan again', 'refresh', rescan), close])];
      body = el('div', { class: 'gcs-body' }, [
        V.details(document, r),
        el('div', { class: 'gcs-foot', text: 'Safety score ' + r.score + '/100 · Gmail Cybersecurity Scanner ' + (r.version || '') })
      ]);
    }

    const old = shadow.querySelector('section');
    const card = el('section', {
      class: ['gcs-root', 'gcs-banner', old ? '' : 'gcs-enter', 'gcs-' + level, open ? 'gcs-open' : '', floating ? 'gcs-floating' : '', isDarkAround(anchor || document.body) ? 'gcs-dark' : ''].join(' '),
      role: 'region', 'aria-label': 'Email security check'
    }, [el('div', { class: 'gcs-bar' }, bar), body]);
    if (old) old.replaceWith(card); else shadow.appendChild(card);
  }

  // ---------------------------------------------------------------------------
  // Following Gmail's single-page navigation
  // ---------------------------------------------------------------------------

  function check() {
    const msg = openMessage();
    if (!msg) {
      if (current.key) { seq++; current = { key: null, status: 'none' }; removeHost(); badge(null); }
      return;
    }
    if (msg.id === current.key) {
      // Gmail re-rendered around us: only re-attach, so open details and focus survive.
      if (host && shadow.querySelector('section') && ui.showBanner && dismissed !== current.key) place(msg.node);
      else render(msg.node);
      return;
    }
    open = false;
    if (cache.has(msg.id)) {
      const r = cache.get(msg.id);
      current = { key: msg.id, status: 'done', result: r, subject: msg.subject };
      badge(r.level, V.LEVELS[r.level].label + ' · safety ' + r.score + '/100');
      render(msg.node);
    } else if (ui.autoScan) {
      scan(msg);
    } else {
      current = { key: msg.id, status: 'idle', subject: msg.subject };
      badge(null);
      render(msg.node);
    }
  }

  function schedule() { clearTimeout(timer); timer = setTimeout(check, 350); }

  new MutationObserver((records) => {
    // Ignore our own banner re-renders.
    if (records.every((r) => r.target === host || (host && host.contains(r.target)))) return;
    schedule();
  }).observe(document.body, { childList: true, subtree: true });
  window.addEventListener('hashchange', schedule);

  chrome.storage.local.get('ui').then((s) => { ui = { ...UI_DEFAULTS, ...(s.ui || {}) }; schedule(); });
  chrome.storage.onChanged.addListener((changes) => {
    if (!changes.ui) return;
    ui = { ...UI_DEFAULTS, ...(changes.ui.newValue || {}) };
    const m = openMessage();
    render(m ? m.node : null);
    if (m && ui.autoScan && current.status === 'idle') scan(m);
  });

  // Requests from the popup.
  chrome.runtime.onMessage.addListener((m, sender, sendResponse) => {
    if (!m) return false;
    if (m.type === 'getState') {
      const msg = openMessage();
      sendResponse({ hasMessage: !!msg, status: current.status, result: current.result || null, error: current.error || '', subject: current.subject || (msg && msg.subject) || '' });
    } else if (m.type === 'rescan') {
      const msg = openMessage();
      if (msg) { cache.delete(msg.id); dismissed = null; scan(msg); }
      sendResponse({ started: !!msg });
    } else if (m.type === 'showBanner') {
      dismissed = null; open = true;
      const msg = openMessage();
      render(msg ? msg.node : null);
      if (host && host.isConnected) host.scrollIntoView({ behavior: 'smooth', block: 'center' });
      sendResponse({ shown: !!(host && host.isConnected) });
    } else return false;
    return false;
  });
})();
