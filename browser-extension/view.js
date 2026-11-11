/**
 * view.js - builds the result UI shared by the in-page Gmail banner and the toolbar popup.
 * Everything is created with DOM APIs and textContent: email data is untrusted, never HTML.
 */
(function (root) {
  'use strict';

  var LEVELS = {
    green: { label: 'Looks safe', hint: 'No threats found by the checks that ran.' },
    yellow: { label: 'Be careful', hint: 'Warning signs found. Check before you click, open or reply.' },
    red: { label: 'Likely dangerous', hint: "Don't click links, open attachments or reply. Use Gmail's Report spam." }
  };
  var SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

  function el(doc, tag, props, kids) {
    var n = doc.createElement(tag);
    if (props) Object.keys(props).forEach(function (k) {
      if (k === 'text') n.textContent = props[k];
      else if (k === 'class') n.className = props[k];
      else if (k.indexOf('on') === 0) n.addEventListener(k.slice(2), props[k]);
      else if (props[k] !== undefined && props[k] !== null && props[k] !== false) n.setAttribute(k, props[k] === true ? '' : props[k]);
    });
    (kids || []).forEach(function (c) { if (c) n.appendChild(typeof c === 'string' ? doc.createTextNode(c) : c); });
    return n;
  }

  var ICONS = {
    shield: 'M12 2 4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3z',
    check: 'm9 12 2 2 4-4',
    alert: 'M12 8v5M12 16.5v.5',
    cross: 'm9.5 9.5 5 5m0-5-5 5',
    chevron: 'm6 9 6 6 6-6',
    refresh: 'M20 12a8 8 0 1 1-2.3-5.7M20 4v5h-5',
    close: 'M6 6l12 12M18 6 6 18',
    gear: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm7.4-3a7.4 7.4 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7.6 7.6 0 0 0-2-1.2L14.5 3h-5l-.4 2.6a7.6 7.6 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7.4 7.4 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7.6 7.6 0 0 0 2 1.2l.4 2.6h5l.4-2.6a7.6 7.6 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.1-.4.1-.8.1-1.2z'
  };

  /** Inline SVG icon from a path list; stroke style, inherits currentColor. */
  function icon(doc, names, size) {
    var NS = 'http://www.w3.org/2000/svg';
    var svg = doc.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', size || 18);
    svg.setAttribute('height', size || 18);
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    [].concat(names).forEach(function (n) {
      var p = doc.createElementNS(NS, 'path');
      p.setAttribute('d', ICONS[n]);
      svg.appendChild(p);
    });
    return svg;
  }

  function levelIcon(doc, level, size) {
    var mark = level === 'green' ? 'check' : level === 'red' ? 'cross' : 'alert';
    return el(doc, 'span', { class: 'gcs-badge gcs-' + level }, [icon(doc, ['shield', mark], size || 22)]);
  }

  /** Small ring showing the 0-100 safety score. */
  function scoreRing(doc, score, level) {
    var NS = 'http://www.w3.org/2000/svg';
    var svg = doc.createElementNS(NS, 'svg');
    svg.setAttribute('viewBox', '0 0 36 36');
    svg.setAttribute('class', 'gcs-ring gcs-' + level);
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Safety score ' + score + ' out of 100');
    var bg = doc.createElementNS(NS, 'circle');
    bg.setAttribute('cx', 18); bg.setAttribute('cy', 18); bg.setAttribute('r', 15.5); bg.setAttribute('class', 'gcs-ring-bg');
    var fg = doc.createElementNS(NS, 'circle');
    fg.setAttribute('cx', 18); fg.setAttribute('cy', 18); fg.setAttribute('r', 15.5); fg.setAttribute('class', 'gcs-ring-fg');
    var c = 2 * Math.PI * 15.5;
    fg.setAttribute('stroke-dasharray', c.toFixed(2));
    fg.setAttribute('stroke-dashoffset', (c * (1 - Math.max(0, Math.min(100, score)) / 100)).toFixed(2));
    var t = doc.createElementNS(NS, 'text');
    t.setAttribute('x', 18); t.setAttribute('y', 18); t.setAttribute('class', 'gcs-ring-text');
    t.textContent = String(score);
    svg.append(bg, fg, t);
    return svg;
  }

  function realFindings(r) { return (r.findings || []).filter(function (f) { return f.severity !== 'info'; }); }

  function summary(r) {
    var n = realFindings(r).length;
    if (!n) return LEVELS[r.level].hint;
    return n + ' warning' + (n === 1 ? '' : 's') + ': ' + realFindings(r)[0].title + (n > 1 ? ' and more' : '');
  }

  function authChips(doc, r) {
    var a = r.auth || {};
    var wrap = el(doc, 'div', { class: 'gcs-chips', role: 'list', 'aria-label': 'Sender authentication' });
    if (!a.present) {
      wrap.appendChild(el(doc, 'span', { class: 'gcs-chip gcs-chip-na', role: 'listitem', text: 'No authentication results' }));
      return wrap;
    }
    [['SPF', a.spf], ['DKIM', a.dkim], ['DMARC', a.dmarc]].forEach(function (p) {
      var v = String(p[1] || 'none').toLowerCase();
      var cls = v === 'pass' ? 'pass' : (v === 'fail' || v === 'softfail') ? 'fail' : 'na';
      wrap.appendChild(el(doc, 'span', { class: 'gcs-chip gcs-chip-' + cls, role: 'listitem', title: p[0] + ' = ' + v }, [
        el(doc, 'b', { text: p[0] }), ' ' + v
      ]));
    });
    return wrap;
  }

  function findingsList(doc, r) {
    var list = realFindings(r);
    if (!list.length) return el(doc, 'p', { class: 'gcs-empty', text: 'No problems found by the checks that ran.' });
    return el(doc, 'ul', { class: 'gcs-findings' }, list.map(function (f) {
      return el(doc, 'li', { class: 'gcs-finding gcs-sev-' + f.severity }, [
        el(doc, 'div', { class: 'gcs-finding-head' }, [
          el(doc, 'span', { class: 'gcs-sev', text: SEV_LABEL[f.severity] || f.severity }),
          el(doc, 'span', { class: 'gcs-finding-title', text: f.title })
        ]),
        f.detail ? el(doc, 'div', { class: 'gcs-finding-detail', text: f.detail }) : null,
        f.evidence ? el(doc, 'code', { class: 'gcs-evidence', text: String(f.evidence).slice(0, 300) }) : null
      ]);
    }));
  }

  function notChecked(doc, r) {
    if (!r.incomplete || !(r.skipped || []).length) return null;
    return el(doc, 'details', { class: 'gcs-notchecked' }, [
      el(doc, 'summary', { text: 'Not checked (' + r.skipped.length + ')' }),
      el(doc, 'ul', {}, r.skipped.map(function (s) { return el(doc, 'li', { text: s }); }))
    ]);
  }

  function facts(doc, r) {
    var from = r.from || {};
    var bits = [];
    if (from.email) bits.push('From ' + from.email);
    bits.push((r.urls || []).length + ' link' + ((r.urls || []).length === 1 ? '' : 's'));
    bits.push((r.attachmentsCount || 0) + ' attachment' + (r.attachmentsCount === 1 ? '' : 's'));
    return el(doc, 'div', { class: 'gcs-facts', text: bits.join('  ·  ') });
  }

  /** Full details block: auth chips, facts, findings, not-checked list. */
  function details(doc, r) {
    return el(doc, 'div', { class: 'gcs-details' }, [
      el(doc, 'div', { class: 'gcs-row' }, [authChips(doc, r), facts(doc, r)]),
      findingsList(doc, r),
      notChecked(doc, r)
    ]);
  }

  root.ScanView = { LEVELS: LEVELS, el: el, icon: icon, levelIcon: levelIcon, scoreRing: scoreRing, summary: summary, details: details, realFindings: realFindings };
})(typeof globalThis !== 'undefined' ? globalThis : this);
