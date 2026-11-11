/**
 * mime.js - turns a raw RFC 822 email (the text Gmail shows under "Show original") into the same
 * shape as a Gmail API `messages.get?format=full` response, so the shared core can analyze it with
 * Core.fromGmailApi(). This is what lets the extension work without any Google Cloud / OAuth setup:
 * the content script reads the original message from the Gmail tab the user is already signed in to.
 *
 * Plain JS, no DOM. Runs in the service worker and in node tests.
 */
(function (root, factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.Mime = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var MAX_DEPTH = 12;
  var MAX_PARTS = 200;
  // The core only looks at the first 4 KB of an attachment (magic bytes, PDF/ICS markers),
  // so keep a little more than that and drop the rest instead of passing megabytes around.
  var ATTACH_B64_KEEP = 12000; // multiple of 4, about 9 KB of bytes

  function splitHeadAndBody(text) {
    var m = /\r?\n\r?\n/.exec(text);
    if (!m) return { head: text, body: '' };
    return { head: text.slice(0, m.index), body: text.slice(m.index + m[0].length) };
  }

  /** @return {{name:string, value:string}[]} in order, folded lines joined. */
  function parseHeaders(head) {
    var out = [];
    var lines = head.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (/^[ \t]/.test(line) && out.length) {
        out[out.length - 1].value += ' ' + line.replace(/^[ \t]+/, '');
        continue;
      }
      var c = line.indexOf(':');
      if (c <= 0) continue;
      out.push({ name: line.slice(0, c).trim(), value: line.slice(c + 1).trim() });
    }
    return out;
  }

  function header(list, name) {
    var n = name.toLowerCase();
    for (var i = 0; i < list.length; i++) if (list[i].name.toLowerCase() === n) return list[i].value;
    return '';
  }

  /** Reads a parameter such as boundary="x" or filename*=UTF-8''a.pdf from a header value. */
  function param(value, name) {
    var re = new RegExp('(?:^|;)\\s*' + name + '(\\*)?\\s*=\\s*("([^"]*)"|[^;]*)', 'i');
    var m = re.exec(value || '');
    if (!m) return '';
    var v = m[3] !== undefined ? m[3] : String(m[2]).trim();
    if (m[1]) { // RFC 2231: charset'lang'percent-encoded
      var q = v.split("'");
      try { v = decodeURIComponent(q.length >= 3 ? q.slice(2).join("'") : v); } catch (e) { /* keep raw */ }
    }
    return v;
  }

  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  function bytesToBase64(bytes) {
    var out = '';
    for (var i = 0; i < bytes.length; i += 3) {
      var a = bytes[i], b = bytes[i + 1], c = bytes[i + 2];
      out += B64[a >> 2] + B64[((a & 3) << 4) | ((b || 0) >> 4)] +
        (b === undefined ? '=' : B64[((b & 15) << 2) | ((c || 0) >> 6)]) +
        (c === undefined ? '=' : B64[c & 63]);
    }
    return out;
  }

  function utf8Bytes(str) {
    var out = [];
    for (var i = 0; i < str.length; i++) {
      var cp = str.codePointAt(i);
      if (cp > 0xffff) i++;
      if (cp < 0x80) out.push(cp);
      else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
      else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
      else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    }
    return out;
  }

  /** Raw 8-bit text: chars under 256 are bytes as-is (the original wire bytes), anything else is UTF-8. */
  function textBytes(str) {
    for (var i = 0; i < str.length; i++) if (str.charCodeAt(i) > 255) return utf8Bytes(str);
    var out = new Array(str.length);
    for (var j = 0; j < str.length; j++) out[j] = str.charCodeAt(j);
    return out;
  }

  function quotedPrintableBytes(str) {
    var s = str.replace(/=\r?\n/g, '');
    var out = [];
    for (var i = 0; i < s.length; i++) {
      var ch = s[i];
      if (ch === '=' && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) { out.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; }
      else out = out.concat(textBytes(ch));
    }
    return out;
  }

  /** @return {{data:string, size:number}} base64 data as the Gmail API would give it. */
  function encodeBody(raw, cte, isAttachment) {
    var enc = String(cte || '').toLowerCase().trim();
    if (enc === 'base64') {
      var clean = raw.replace(/[^A-Za-z0-9+/=_-]/g, '');
      var size = Math.floor(clean.replace(/=+$/, '').length * 3 / 4);
      if (isAttachment && clean.length > ATTACH_B64_KEEP) clean = clean.slice(0, ATTACH_B64_KEEP);
      return { data: clean, size: size };
    }
    var bytes = enc === 'quoted-printable' ? quotedPrintableBytes(raw) : textBytes(raw);
    var full = bytes.length;
    if (isAttachment && bytes.length > 9000) bytes = bytes.slice(0, 9000);
    return { data: bytesToBase64(bytes), size: full };
  }

  function parsePart(text, partId, depth, counter) {
    counter.n++;
    var hb = splitHeadAndBody(text);
    var headers = parseHeaders(hb.head);
    var ct = header(headers, 'content-type') || 'text/plain';
    var mimeType = ct.split(';')[0].trim().toLowerCase() || 'text/plain';
    var disposition = header(headers, 'content-disposition');
    var filename = param(disposition, 'filename') || param(ct, 'name');
    var part = { partId: partId, mimeType: mimeType, filename: filename, headers: headers, body: { size: 0 } };

    if (mimeType.indexOf('multipart/') === 0 && depth < MAX_DEPTH) {
      var boundary = param(ct, 'boundary');
      if (boundary) {
        part.parts = splitMultipart(hb.body, boundary).slice(0, MAX_PARTS).map(function (chunk, i) {
          if (counter.n > MAX_PARTS) return null;
          return parsePart(chunk, (partId ? partId + '.' : '') + i, depth + 1, counter);
        }).filter(Boolean);
        return part;
      }
    }
    if (mimeType === 'message/rfc822' && depth < MAX_DEPTH && !/attachment/i.test(disposition)) {
      part.parts = [parsePart(hb.body, (partId ? partId + '.' : '') + '0', depth + 1, counter)];
      return part;
    }
    var isAttachment = !!filename || /attachment/i.test(disposition);
    part.body = encodeBody(hb.body, header(headers, 'content-transfer-encoding'), isAttachment);
    return part;
  }

  function splitMultipart(body, boundary) {
    var delim = '--' + boundary;
    var lines = body.split(/\r?\n/);
    var parts = [];
    var cur = null;
    for (var i = 0; i < lines.length; i++) {
      var l = lines[i];
      if (l === delim + '--' || l.replace(/\s+$/, '') === delim + '--') { if (cur) parts.push(cur.join('\n')); cur = null; break; }
      if (l === delim || l.replace(/\s+$/, '') === delim) { if (cur) parts.push(cur.join('\n')); cur = []; continue; }
      if (cur) cur.push(l);
    }
    if (cur && cur.length) parts.push(cur.join('\n'));
    return parts;
  }

  /**
   * @param {string} raw full RFC 822 source
   * @param {{id?:string, threadId?:string}} ids
   * @return {Object} Gmail API Message-shaped object
   */
  function toGmailApiMessage(raw, ids) {
    if (typeof raw !== 'string' || !/^[\w-]+:/m.test(raw.slice(0, 2000))) throw new Error('This does not look like an email source');
    var payload = parsePart(raw.replace(/^\s+/, ''), '', 0, { n: 0 });
    return { id: (ids && ids.id) || '', threadId: (ids && ids.threadId) || '', labelIds: [], payload: payload, snippet: '' };
  }

  return { toGmailApiMessage: toGmailApiMessage, parseHeaders: parseHeaders, param: param };
});
