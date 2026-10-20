// GENERATED FILE - do not edit. Source: core/scanner-core.js. Run `npm run sync-core` after changing the source.
// Chrome extension copy of the shared scanning core.
/**
 * scanner-core.js - the shared scanning brain.
 *
 * Pure JavaScript with no platform dependencies (no URL, Buffer, atob, fetch,
 * TextDecoder, optional chaining), so the exact same file runs in:
 *   - Google Apps Script (copied to ScannerCore.gs by `npm run sync-core`)
 *   - the Chrome extension service worker (copied to browser-extension/)
 *   - the Node CLI / MCP server (copied to cli-extension/)
 *
 * The platform adapters do the I/O (Gmail API calls, Safe Browsing, RDAP) and
 * pass the results in as `enrichment`. This file only decides what they mean.
 *
 * Flow:  Gmail API message --fromGmailApi()--> normalized message
 *        normalized message + enrichment + config --analyze()--> findings + score
 */
(function (root, factory) {
  var api = factory();
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
  root.ScannerCore = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var VERSION = '2.0.0';

  // ---------------------------------------------------------------------------
  // Configuration
  // ---------------------------------------------------------------------------

  var DEFAULT_CONFIG = {
    // Domains the user owns / trusts as "internal". Empty means the
    // internal-impersonation check is off (it used to be hard-coded to Spotify).
    internalDomain: '',
    vipNames: [],
    allowDomains: [],
    denyDomains: [],
    // Brands to watch for typosquatting and look-alike hostnames, with the
    // domains that are genuinely theirs.
    brands: {
      google: ['google.com', 'gmail.com', 'googlemail.com', 'youtube.com', 'goo.gl', 'g.co', 'withgoogle.com', 'googleusercontent.com', 'googleapis.com', 'gstatic.com', 'google.nl'],
      microsoft: ['microsoft.com', 'live.com', 'office.com', 'office365.com', 'outlook.com', 'microsoftonline.com', 'sharepoint.com', 'azure.com', 'windows.com', 'hotmail.com', 'xbox.com', 'bing.com', 'msn.com'],
      paypal: ['paypal.com', 'paypal.me', 'paypalobjects.com'],
      amazon: ['amazon.com', 'amazon.nl', 'amazon.de', 'amazon.co.uk', 'amazon.fr', 'amazon.es', 'amazon.it', 'amazonaws.com', 'amazon.ca', 'amzn.to', 'amzn.com', 'a.co'],
      apple: ['apple.com', 'icloud.com', 'me.com', 'itunes.com', 'apple.news'],
      netflix: ['netflix.com', 'nflxso.net'],
      facebook: ['facebook.com', 'fb.com', 'facebookmail.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'fb.me'],
      spotify: ['spotify.com', 'scdn.co', 'spotifymail.com'],
      dhl: ['dhl.com', 'dhl.de', 'dhl.nl'],
      ing: ['ing.nl', 'ing.com', 'ing.be'],
      rabobank: ['rabobank.nl', 'rabobank.com'],
      ideal: ['ideal.nl'],
      postnl: ['postnl.nl', 'postnl.com'],
      bol: ['bol.com'],
      belastingdienst: ['belastingdienst.nl']
    },
    newDomainDays: 30,
    veryNewDomainDays: 7
  };

  var SEVERITY_WEIGHT = { critical: 70, high: 40, medium: 18, low: 6, info: 0 };
  var SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

  var LINGUISTIC_WEIGHTS = {
    'urgent': 10, 'immediate action': 10, 'account suspended': 15, 'wire transfer': 20,
    'verify account': 10, 'verify your account': 10, 'password reset': 5, 'unusual activity': 10,
    'security alert': 10, 'act now': 5, 'payment overdue': 15, 'login attempt': 10,
    'final notice': 15, 'official request': 10, 'restricted access': 15, 'gift card': 20,
    'payment failed': 15, 'subscription suspended': 15, 'update billing': 15, 'premium account': 15,
    'dringend': 10, 'uw account': 5, 'betaling mislukt': 15, 'verifieer uw': 10
  };

  var SHORTENERS = [
    'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
    'shorturl.at', 'lnkd.in', 't.ly', 'rb.gy', 's.id', 'tiny.cc', 'v.gd', 'qrco.de', 'bit.do', 'trib.al',
    'soo.gd', 'urlz.fr', 'shorte.st', 'adf.ly', 'clck.ru', 'tr.ee', 'l.ead.me', 'linktr.ee', 'bl.ink'
  ];

  var DANGEROUS_EXTENSIONS = [
    'exe', 'scr', 'com', 'pif', 'bat', 'cmd', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'ps1', 'psm1',
    'msi', 'msp', 'jar', 'lnk', 'hta', 'cpl', 'reg', 'iso', 'img', 'vhd', 'vhdx', 'dll', 'sys', 'apk',
    'appx', 'msix', 'one', 'chm', 'gadget', 'application', 'scf', 'url', 'inf', 'ws'
  ];
  var MACRO_EXTENSIONS = ['docm', 'xlsm', 'pptm', 'dotm', 'xlam', 'ppam', 'xlsb'];
  var ARCHIVE_EXTENSIONS = ['zip', '7z', 'rar', 'gz', 'tar', 'tgz', 'bz2', 'cab', 'z', 'xz'];
  var DOUBLE_EXT_DECOYS = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'jpg', 'jpeg', 'png', 'gif', 'rtf', 'csv', 'mp3', 'mp4', 'zip'];

  var MAGIC = [
    { type: 'pdf', bytes: [0x25, 0x50, 0x44, 0x46] },
    { type: 'zip', bytes: [0x50, 0x4B, 0x03, 0x04] },
    { type: 'exe', bytes: [0x4D, 0x5A] },
    { type: 'png', bytes: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] },
    { type: 'jpg', bytes: [0xFF, 0xD8, 0xFF] },
    { type: 'gif', bytes: [0x47, 0x49, 0x46, 0x38] },
    { type: '7z', bytes: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C] },
    { type: 'rar', bytes: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07] },
    { type: 'lnk', bytes: [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00] },
    { type: 'rtf', bytes: [0x7B, 0x5C, 0x72, 0x74] },
    { type: 'ole', bytes: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] },
    { type: 'gz', bytes: [0x1F, 0x8B] },
    { type: 'elf', bytes: [0x7F, 0x45, 0x4C, 0x46] }
  ];
  // Extensions that legitimately share a container signature.
  var MAGIC_ALIASES = {
    zip: ['zip', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm', 'jar', 'apk', 'odt', 'ods', 'odp', 'epub', 'xlsb', 'appx', 'msix', 'vsdx', 'dotx', 'xltx'],
    ole: ['doc', 'xls', 'ppt', 'msi', 'msg', 'dot', 'xlt', 'pps', 'pub', 'vsd'],
    exe: ['exe', 'dll', 'scr', 'sys', 'com', 'cpl'],
    jpg: ['jpg', 'jpeg', 'jpe', 'jfif'],
    gz: ['gz', 'tgz']
  };

  // Common two-level public suffixes, enough for organisational-domain matching
  // without shipping the full Public Suffix List.
  var TWO_LEVEL_SUFFIXES = [
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz', 'govt.nz',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'co.kr', 'or.kr', 'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in',
    'com.br', 'net.br', 'org.br', 'gov.br', 'com.mx', 'com.ar', 'com.co', 'com.pe', 'com.ve', 'com.cn', 'net.cn', 'org.cn', 'gov.cn',
    'com.tr', 'org.tr', 'com.hk', 'com.sg', 'com.my', 'com.ph', 'com.tw', 'co.za', 'org.za', 'co.il', 'com.ua', 'com.pl', 'co.id', 'co.th', 'com.vn', 'com.eg', 'com.ng', 'co.ke'
  ];

  var FREE_MAIL_DOMAINS = [
    'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'icloud.com',
    'me.com', 'aol.com', 'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net', 'mail.com', 'yandex.com',
    'ziggo.nl', 'kpnmail.nl', 'hotmail.nl', 'live.nl', 'yahoo.nl', 'planet.nl', 'xs4all.nl'
  ];

  // ---------------------------------------------------------------------------
  // Small utilities
  // ---------------------------------------------------------------------------

  function lower(s) { return String(s === undefined || s === null ? '' : s).toLowerCase(); }

  function uniq(arr) {
    var seen = {};
    var out = [];
    for (var i = 0; i < arr.length; i++) {
      var k = String(arr[i]);
      if (!Object.prototype.hasOwnProperty.call(seen, k)) {
        seen[k] = true;
        out.push(arr[i]);
      }
    }
    return out;
  }

  function contains(arr, v) { return arr.indexOf(v) !== -1; }

  function escapeRegExp(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

  function mergeConfig(overrides) {
    var cfg = {};
    var k;
    for (k in DEFAULT_CONFIG) {
      if (Object.prototype.hasOwnProperty.call(DEFAULT_CONFIG, k)) cfg[k] = DEFAULT_CONFIG[k];
    }
    if (overrides) {
      for (k in overrides) {
        if (Object.prototype.hasOwnProperty.call(overrides, k) && overrides[k] !== undefined && overrides[k] !== null) {
          cfg[k] = overrides[k];
        }
      }
    }
    cfg.allowDomains = (cfg.allowDomains || []).map(lower);
    cfg.denyDomains = (cfg.denyDomains || []).map(lower);
    cfg.vipNames = (cfg.vipNames || []).map(function (n) { return String(n).trim(); }).filter(Boolean);
    cfg.internalDomain = lower(cfg.internalDomain).trim();
    return cfg;
  }

  /** Registrable ("organisational") domain: example.co.uk for mail.example.co.uk. */
  function orgDomain(host) {
    host = lower(host).replace(/\.$/, '');
    if (!host || /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.indexOf(':') !== -1) return host;
    var parts = host.split('.');
    if (parts.length <= 2) return host;
    var last2 = parts.slice(-2).join('.');
    if (contains(TWO_LEVEL_SUFFIXES, last2)) return parts.slice(-3).join('.');
    return last2;
  }

  function domainMatches(host, domain) {
    host = lower(host);
    domain = lower(domain);
    return host === domain || host.length > domain.length && host.slice(-(domain.length + 1)) === '.' + domain;
  }

  function isIpv4(host) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(host); }

  function isPrivateHost(host) {
    host = lower(host);
    if (host === 'localhost' || /\.(local|internal|localhost|lan|home)$/.test(host)) return true;
    if (host.indexOf(':') !== -1) {
      return host === '::1' || /^f[cd]/.test(host) || /^fe80/.test(host);
    }
    if (!isIpv4(host)) return false;
    var p = host.split('.').map(Number);
    return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 169 && p[1] === 254) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) ||
      (p[0] === 100 && p[1] >= 64 && p[1] <= 127);
  }

  /**
   * Minimal URL parser. Apps Script has no global URL class, so everything in
   * this file goes through here instead of `new URL()`.
   * @return {{href:string, protocol:string, username:string, hostname:string, port:string, pathname:string, search:string, hash:string}|null}
   */
  function parseUrl(url) {
    if (typeof url !== 'string') return null;
    var m = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^\/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/.exec(url.trim());
    if (!m) return null;
    var authority = m[2];
    var username = '';
    var at = authority.lastIndexOf('@');
    if (at !== -1) {
      username = authority.slice(0, at);
      authority = authority.slice(at + 1);
    }
    var hostname = authority;
    var port = '';
    var pm = /^(\[[^\]]*\]|[^:]*)(?::(\d*))?$/.exec(authority);
    if (pm) {
      hostname = pm[1];
      port = pm[2] || '';
    }
    hostname = lower(hostname).replace(/^\[|\]$/g, '').replace(/\.$/, '');
    if (!hostname) return null;
    return {
      href: url.trim(),
      protocol: lower(m[1]) + ':',
      username: username,
      hostname: hostname,
      port: port,
      pathname: m[3] || '/',
      search: m[4] || '',
      hash: m[5] || ''
    };
  }

  function hostOf(url) {
    var p = parseUrl(url);
    return p ? p.hostname : '';
  }

  // --- Punycode (RFC 3492) decoder, used for homograph detection -------------
  function punycodeDecode(input) {
    var base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;
    var output = [];
    var basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    var j;
    for (j = 0; j < basic; ++j) output.push(input.charCodeAt(j));
    function adapt(delta, numPoints, first) {
      var k = 0;
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
      return Math.floor(k + (base - tMin + 1) * delta / (delta + skew));
    }
    var n = initialN, i = 0, bias = initialBias;
    for (var index = basic > 0 ? basic + 1 : 0; index < input.length;) {
      var oldi = i;
      for (var w = 1, k = base; ; k += base) {
        if (index >= input.length) return null;
        var c = input.charCodeAt(index++);
        var digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
        if (digit >= base) return null;
        i += digit * w;
        var t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
        if (digit < t) break;
        w *= base - t;
      }
      var out = output.length + 1;
      bias = adapt(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      i %= out;
      output.splice(i++, 0, n);
    }
    var s = '';
    for (var x = 0; x < output.length; x++) s += String.fromCharCode(output[x]);
    return s;
  }

  function scriptOf(ch) {
    var c = ch.charCodeAt(0);
    if (c < 0x80) return /[a-z0-9-]/i.test(ch) ? 'latin' : 'other';
    if (c >= 0x0370 && c <= 0x03FF) return 'greek';
    if (c >= 0x0400 && c <= 0x052F) return 'cyrillic';
    if (c >= 0x0530 && c <= 0x058F) return 'armenian';
    if (c >= 0x0590 && c <= 0x05FF) return 'hebrew';
    if (c >= 0x0600 && c <= 0x06FF) return 'arabic';
    if (c >= 0x00C0 && c <= 0x024F) return 'latin';
    return 'other';
  }

  /** @return {{isIdn:boolean, mixedScript:boolean, decoded:string}} */
  function inspectHostname(hostname) {
    var labels = lower(hostname).split('.');
    var isIdn = false;
    var mixed = false;
    var decodedLabels = [];
    for (var i = 0; i < labels.length; i++) {
      var label = labels[i];
      if (label.slice(0, 4) === 'xn--') {
        isIdn = true;
        var d = punycodeDecode(label.slice(4));
        label = d === null ? label : d;
      } else if (/[^\x00-\x7f]/.test(label)) {
        isIdn = true;
      }
      decodedLabels.push(label);
      var scripts = {};
      for (var j = 0; j < label.length; j++) {
        var s = scriptOf(label.charAt(j));
        if (s !== 'other') scripts[s] = true;
      }
      if (Object.keys(scripts).length > 1) mixed = true;
    }
    return { isIdn: isIdn, mixedScript: mixed, decoded: decodedLabels.join('.') };
  }

  function levenshtein(a, b) {
    if (a === b) return 0;
    if (a.length < b.length) { var t = a; a = b; b = t; }
    if (b.length === 0) return a.length;
    var prev = [];
    var cur = [];
    var i, j;
    for (i = 0; i <= b.length; i++) prev[i] = i;
    for (i = 1; i <= a.length; i++) {
      cur[0] = i;
      for (j = 1; j <= b.length; j++) {
        var cost = a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1;
        cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
      }
      var tmp = prev; prev = cur; cur = tmp;
    }
    return prev[b.length];
  }

  // ---------------------------------------------------------------------------
  // Base64url / UTF-8 without atob, Buffer or TextDecoder
  // ---------------------------------------------------------------------------

  var B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  var B64_LOOKUP = (function () {
    var t = {};
    for (var i = 0; i < B64.length; i++) t[B64.charAt(i)] = i;
    t['-'] = 62;
    t['_'] = 63;
    return t;
  })();

  /** Decode standard or URL-safe base64 into an array of byte values. */
  function base64ToBytes(str) {
    var out = [];
    var buf = 0;
    var bits = 0;
    str = String(str || '');
    for (var i = 0; i < str.length; i++) {
      var ch = str.charAt(i);
      if (ch === '=') break;
      var v = B64_LOOKUP[ch];
      if (v === undefined) continue; // skip whitespace / line breaks
      buf = (buf << 6) | v;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out.push((buf >> bits) & 0xFF);
      }
    }
    return out;
  }

  function bytesToUtf8(bytes) {
    var s = '';
    var i = 0;
    while (i < bytes.length) {
      var b = bytes[i++] & 0xFF;
      var cp;
      if (b < 0x80) {
        cp = b;
      } else if (b >= 0xC2 && b < 0xE0 && i < bytes.length) {
        cp = ((b & 0x1F) << 6) | (bytes[i++] & 0x3F);
      } else if (b >= 0xE0 && b < 0xF0 && i + 1 < bytes.length) {
        cp = ((b & 0x0F) << 12) | ((bytes[i++] & 0x3F) << 6) | (bytes[i++] & 0x3F);
      } else if (b >= 0xF0 && b < 0xF5 && i + 2 < bytes.length) {
        cp = ((b & 0x07) << 18) | ((bytes[i++] & 0x3F) << 12) | ((bytes[i++] & 0x3F) << 6) | (bytes[i++] & 0x3F);
      } else {
        cp = 0xFFFD;
      }
      if (cp > 0xFFFF) {
        cp -= 0x10000;
        s += String.fromCharCode(0xD800 + (cp >> 10), 0xDC00 + (cp & 0x3FF));
      } else {
        s += String.fromCharCode(cp);
      }
    }
    return s;
  }

  function bytesToLatin1(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] & 0xFF);
    return s;
  }

  function decodeBytes(bytes, charset) {
    var cs = lower(charset);
    if (cs === 'iso-8859-1' || cs === 'latin1' || cs === 'windows-1252' || cs === 'us-ascii' || cs === 'iso-8859-15') {
      return bytesToLatin1(bytes);
    }
    return bytesToUtf8(bytes);
  }

  // ---------------------------------------------------------------------------
  // Headers and addresses
  // ---------------------------------------------------------------------------

  /** Parse a raw header block into { lowercase-name: [values...] } (top-most first), unfolding continuations. */
  function parseHeaderBlock(block) {
    var headers = {};
    var lines = String(block || '').split(/\r?\n/);
    var current = null;
    function flush() {
      if (current) {
        var name = lower(current.name);
        if (!headers[name]) headers[name] = [];
        headers[name].push(current.value.replace(/\s+/g, ' ').trim());
      }
    }
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (line === '') break;
      if (/^[ \t]/.test(line) && current) {
        current.value += ' ' + line;
        continue;
      }
      var m = /^([!-9;-~]+):(.*)$/.exec(line);
      if (m) {
        flush();
        current = { name: m[1], value: m[2] };
      }
    }
    flush();
    return headers;
  }

  function headersFromList(list) {
    var headers = {};
    for (var i = 0; i < (list || []).length; i++) {
      var name = lower(list[i].name);
      if (!headers[name]) headers[name] = [];
      headers[name].push(String(list[i].value === undefined ? '' : list[i].value).replace(/\s+/g, ' ').trim());
    }
    return headers;
  }

  function firstHeader(headers, name) {
    var v = headers && headers[lower(name)];
    return v && v.length ? v[0] : '';
  }

  /** Decode RFC 2047 encoded-words in a header value (UTF-8 / latin1; B and Q). */
  function decodeMimeWords(value) {
    return String(value || '').replace(/=\?([^?]+)\?([QqBb])\?([^?]*)\?=/g, function (m, charset, enc, text) {
      try {
        var bytes;
        if (lower(enc) === 'b') {
          bytes = base64ToBytes(text);
        } else {
          bytes = [];
          var q = text.replace(/_/g, ' ');
          for (var i = 0; i < q.length; i++) {
            if (q.charAt(i) === '=' && /^[0-9a-fA-F]{2}$/.test(q.substr(i + 1, 2))) {
              bytes.push(parseInt(q.substr(i + 1, 2), 16));
              i += 2;
            } else {
              bytes.push(q.charCodeAt(i) & 0xFF);
            }
          }
        }
        return decodeBytes(bytes, charset);
      } catch (e) {
        return m;
      }
    });
  }

  /** @return {{name:string, email:string, domain:string}} */
  function parseAddress(header) {
    var raw = decodeMimeWords(header || '').trim();
    var email = '';
    var name = '';
    var m = /<([^<>\s]+@[^<>\s]+)>/.exec(raw);
    if (m) {
      email = m[1];
      name = raw.replace(m[0], '');
    } else {
      var b = /([^\s<>"',;]+@[^\s<>"',;]+)/.exec(raw);
      if (b) {
        email = b[1];
        name = raw.replace(b[0], '');
      } else {
        name = raw;
      }
    }
    name = name.replace(/^[\s"']+|[\s"']+$/g, '').replace(/\\"/g, '"');
    email = lower(email);
    return { name: name, email: email, domain: email.indexOf('@') === -1 ? '' : email.split('@').pop() };
  }

  // ---------------------------------------------------------------------------
  // Authentication results
  // ---------------------------------------------------------------------------

  /**
   * Reads Authentication-Results. Only the top-most header is trusted because it
   * was added by the receiving server; lower ones can be forged by the sender.
   * @return {{present:boolean, spf:string, dkim:string, dmarc:string, arc:string, dkimDomains:string[], spfDomain:string, headerFrom:string, authserv:string}}
   */
  function parseAuth(headers) {
    var list = (headers && headers['authentication-results']) || [];
    var res = { present: false, spf: 'unknown', dkim: 'unknown', dmarc: 'unknown', arc: 'unknown', dkimDomains: [], spfDomain: '', headerFrom: '', authserv: '' };
    if (!list.length) return res;
    var value = list[0];
    res.present = true;
    var firstSemi = value.indexOf(';');
    res.authserv = lower(firstSemi === -1 ? value : value.slice(0, firstSemi)).trim();

    var spf = /\bspf=(\w+)/i.exec(value);
    if (spf) res.spf = lower(spf[1]);
    var dmarc = /\bdmarc=(\w+)/i.exec(value);
    if (dmarc) res.dmarc = lower(dmarc[1]);

    var dkimRe = /\bdkim=(\w+)([^;]*)/gi;
    var m;
    var dkimResults = [];
    while ((m = dkimRe.exec(value)) !== null) {
      var result = lower(m[1]);
      dkimResults.push(result);
      var d = /header\.(?:d|i)=@?([^\s;]+)/i.exec(m[2]);
      if (result === 'pass' && d) res.dkimDomains.push(lower(d[1].replace(/^.*@/, '')));
    }
    if (dkimResults.length) {
      res.dkim = contains(dkimResults, 'pass') ? 'pass' : (contains(dkimResults, 'fail') ? 'fail' : dkimResults[0]);
    }

    var mf = /smtp\.mailfrom=([^\s;]+)/i.exec(value);
    if (mf) res.spfDomain = lower(mf[1].replace(/^.*@/, ''));
    var hf = /header\.from=([^\s;]+)/i.exec(value);
    if (hf) res.headerFrom = lower(hf[1]);

    var arc = (headers['arc-authentication-results'] || [])[0] || '';
    var am = /\barc=(\w+)/i.exec(arc) || /\barc=(\w+)/i.exec(value);
    if (am) res.arc = lower(am[1]);
    return res;
  }

  // ---------------------------------------------------------------------------
  // Extraction
  // ---------------------------------------------------------------------------

  var MAX_HTML = 600000;

  function extractUrls(text) {
    var out = [];
    var re = /https?:\/\/[^\s<>"'`\]\)]+/gi;
    var m;
    text = String(text || '').slice(0, MAX_HTML);
    while ((m = re.exec(text)) !== null) {
      out.push(m[0].replace(/[.,;:!?)\]}>]+$/, ''));
    }
    return uniq(out);
  }

  /** Remove every <name ...>...</name> block in one linear pass (an unterminated block runs to the end, as browsers treat it). */
  function removeBlocks(s, name) {
    var low = s.toLowerCase();
    var open = '<' + name;
    var close = '</' + name;
    var out = [];
    var i = 0;
    for (;;) {
      var a = low.indexOf(open, i);
      while (a !== -1 && /[a-z0-9]/.test(low.charAt(a + open.length))) a = low.indexOf(open, a + 1);
      if (a === -1) { out.push(s.slice(i)); break; }
      out.push(s.slice(i, a), ' ');
      var c = low.indexOf(close, a + open.length);
      if (c === -1) break;
      var gt = low.indexOf('>', c);
      if (gt === -1) break;
      i = gt + 1;
    }
    return out.join('');
  }

  /** Remove tags in a single pass. Every tag becomes a space so surrounding text can never be glued into a new tag. */
  function removeTags(s) {
    var out = [];
    var i = 0;
    for (;;) {
      var lt = s.indexOf('<', i);
      if (lt === -1) { out.push(s.slice(i)); break; }
      out.push(s.slice(i, lt));
      var gt = s.indexOf('>', lt + 1);
      if (gt === -1) { out.push(s.slice(lt)); break; }
      out.push(' ');
      i = gt + 1;
    }
    return out.join('');
  }

  function stripTags(html) {
    var s = String(html || '').slice(0, MAX_HTML);
    s = removeBlocks(s, 'script');
    s = removeBlocks(s, 'style');
    // comments
    var out = [];
    var i = 0;
    for (;;) {
      var a = s.indexOf('<!--', i);
      if (a === -1) { out.push(s.slice(i)); break; }
      out.push(s.slice(i, a), ' ');
      var b = s.indexOf('-->', a + 4);
      if (b === -1) break;
      i = b + 3;
    }
    s = removeTags(out.join(''));
    return decodeEntities(s).replace(/\s+/g, ' ').trim();
  }

  function decodeEntities(s) {
    return String(s).replace(/&(#x?[0-9a-fA-F]+|amp|lt|gt|quot|apos|nbsp);/g, function (m, e) {
      switch (e) {
        case 'amp': return '&';
        case 'lt': return '<';
        case 'gt': return '>';
        case 'quot': return '"';
        case 'apos': return "'";
        case 'nbsp': return ' ';
      }
      var n = e.charAt(1) === 'x' || e.charAt(1) === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return isNaN(n) || n > 0x10FFFF ? m : String.fromCharCode(n > 0xFFFF ? 0xFFFD : n);
    });
  }

  var HIDDEN_STYLE = /(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?(?![.\d])|font-size\s*:\s*0(?:px|pt|em|%)?(?![.\d])|height\s*:\s*0(?:px)?(?![.\d])|width\s*:\s*0(?:px)?(?![.\d])|color\s*:\s*(?:#fff(?:fff)?|white)\b[^"']*background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white)|max-height\s*:\s*0)/i;

  /**
   * Walk the opening tags named in `names` in one linear pass.
   * Calls cb(name, attrs, innerHtml) where innerHtml runs to the matching close tag
   * (or to the end of the document if it is never closed).
   */
  function eachElement(html, names, cb) {
    var low = html.toLowerCase();
    var i = 0;
    var guard = 0;
    for (;;) {
      var lt = low.indexOf('<', i);
      if (lt === -1 || ++guard > 20000) return;
      var m = /^<([a-z][a-z0-9]*)/.exec(low.slice(lt, lt + 12));
      if (!m || names.indexOf(m[1]) === -1) { i = lt + 1; continue; }
      var gt = low.indexOf('>', lt);
      if (gt === -1) return;
      var attrs = html.slice(lt + 1 + m[1].length, gt).slice(0, 5000);
      var close = low.indexOf('</' + m[1], gt);
      var inner = html.slice(gt + 1, close === -1 ? html.length : close);
      cb(m[1], attrs, inner);
      i = gt + 1;
    }
  }

  /** @return {{url:string, text:string, isHidden:boolean}[]} */
  function extractHtmlLinks(html) {
    var links = [];
    html = String(html || '').slice(0, MAX_HTML);
    eachElement(html, ['a'], function (name, attrs, inner) {
      var hm = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
      if (!hm) return;
      var url = decodeEntities(hm[1] !== undefined ? hm[1] : (hm[2] !== undefined ? hm[2] : hm[3])).trim();
      if (!/^https?:\/\//i.test(url)) return;
      var sm = /\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(attrs);
      var style = sm ? (sm[1] !== undefined ? sm[1] : sm[2]) : '';
      var otherAttrs = attrs.replace(/\bhref\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/i, '').replace(/\bstyle\s*=\s*(?:"[^"]*"|'[^']*')/i, '');
      var hidden = HIDDEN_STYLE.test(style) || /(^|\s)hidden(\s|=|$)/i.test(otherAttrs) || /aria-hidden\s*=\s*["']?true/i.test(otherAttrs);
      links.push({ url: url, text: stripTags(inner.slice(0, 5000)), isHidden: hidden });
    });
    return links;
  }

  /** Text found inside elements hidden with CSS, used to spot hidden prompt-injection / filler. */
  function extractHiddenText(html) {
    var out = [];
    html = String(html || '').slice(0, MAX_HTML);
    eachElement(html, ['div', 'span', 'p', 'td', 'font', 'section'], function (name, attrs, inner) {
      var sm = /\bstyle\s*=\s*(?:"([^"]*)"|'([^']*)')/i.exec(attrs);
      if (!sm) return;
      var style = sm[1] !== undefined ? sm[1] : sm[2];
      if (HIDDEN_STYLE.test(style)) {
        var t = stripTags(inner.slice(0, 5000));
        if (t.length >= 20) out.push(t.slice(0, 300));
      }
    });
    return out;
  }

  // ---------------------------------------------------------------------------
  // Gmail API message -> normalized message
  // ---------------------------------------------------------------------------

  /**
   * Convert a Gmail REST `users.messages.get?format=full` response into the
   * normalized shape analyze() consumes. Works for Apps Script, Chrome and Node
   * because it only uses plain JS.
   * @param {Object} api Gmail API Message resource.
   * @return {Object} normalized message
   */
  function fromGmailApi(api) {
    var payload = (api && api.payload) || {};
    var headers = headersFromList(payload.headers || []);
    var msg = {
      id: api && api.id,
      threadId: api && api.threadId,
      labelIds: (api && api.labelIds) || [],
      internalDate: api && api.internalDate ? Number(api.internalDate) : 0,
      from: firstHeader(headers, 'from'),
      replyTo: firstHeader(headers, 'reply-to'),
      returnPath: firstHeader(headers, 'return-path'),
      sender: firstHeader(headers, 'sender'),
      to: firstHeader(headers, 'to'),
      subject: decodeMimeWords(firstHeader(headers, 'subject')),
      date: firstHeader(headers, 'date'),
      headers: headers,
      plainBody: '',
      htmlBody: '',
      attachments: [],
      snippet: (api && api.snippet) || ''
    };
    var plain = [];
    var html = [];

    function walk(part, depth) {
      if (!part || depth > 12) return;
      var mime = lower(part.mimeType);
      var partHeaders = headersFromList(part.headers || []);
      var ct = firstHeader(partHeaders, 'content-type');
      var charset = (/charset="?([^";\s]+)/i.exec(ct) || [])[1] || '';
      var filename = part.filename || '';
      var body = part.body || {};
      var isAttachment = !!filename || !!body.attachmentId;

      if (part.parts && part.parts.length) {
        for (var i = 0; i < part.parts.length; i++) walk(part.parts[i], depth + 1);
        if (!isAttachment) return;
      }
      if (isAttachment && !(part.parts && part.parts.length && mime.indexOf('multipart/') === 0)) {
        var bytes = body.data ? base64ToBytes(body.data) : null;
        msg.attachments.push({
          name: filename || '(unnamed)',
          mimeType: mime,
          size: body.size || (bytes ? bytes.length : 0),
          attachmentId: body.attachmentId || '',
          partId: part.partId || '',
          isInline: /inline/i.test(firstHeader(partHeaders, 'content-disposition')) && !filename,
          head: bytes ? bytes.slice(0, 16) : null,
          text: bytes ? bytesToLatin1(bytes.slice(0, 4096)) : ''
        });
        return;
      }
      if (body.data) {
        var text = decodeBytes(base64ToBytes(body.data), charset);
        if (mime === 'text/plain') plain.push(text);
        else if (mime === 'text/html') html.push(text);
        else if (mime === 'text/calendar') {
          msg.attachments.push({ name: 'invite.ics', mimeType: mime, size: text.length, attachmentId: '', partId: part.partId || '', isInline: true, head: null, text: text.slice(0, 4096) });
        }
      }
    }
    walk(payload, 0);
    msg.plainBody = plain.join('\n');
    msg.htmlBody = html.join('\n');
    if (!msg.plainBody && msg.htmlBody) msg.plainBody = stripTags(msg.htmlBody);
    return msg;
  }

  /** Attach bytes fetched by the adapter to an attachment record (call before analyze). */
  function setAttachmentBytes(att, bytes) {
    att.head = bytes.slice(0, 16);
    att.text = bytesToLatin1(bytes.slice(0, 4096));
    att.fetched = true;
    return att;
  }

  // ---------------------------------------------------------------------------
  // Detection helpers
  // ---------------------------------------------------------------------------

  function sniffMagic(bytes) {
    if (!bytes || !bytes.length) return null;
    for (var i = 0; i < MAGIC.length; i++) {
      var sig = MAGIC[i].bytes;
      var ok = bytes.length >= sig.length;
      for (var j = 0; ok && j < sig.length; j++) {
        if ((bytes[j] & 0xFF) !== sig[j]) ok = false;
      }
      if (ok) return MAGIC[i].type;
    }
    return null;
  }

  function extensionOf(name) {
    var n = lower(name);
    var i = n.lastIndexOf('.');
    return i === -1 ? '' : n.slice(i + 1);
  }

  function brandForHost(host, cfg) {
    // Returns {brand, official} when the host's registrable label equals a brand,
    // or contains it as a separate label. official=true when the host belongs to the brand.
    var brands = cfg.brands || {};
    host = lower(host);
    var org = orgDomain(host);
    for (var brand in brands) {
      if (!Object.prototype.hasOwnProperty.call(brands, brand)) continue;
      var officials = brands[brand];
      var isOfficial = officials.some(function (d) { return domainMatches(host, d); });
      if (isOfficial) return { brand: brand, official: true };
    }
    var firstLabel = org.split('.')[0];
    for (var b in brands) {
      if (!Object.prototype.hasOwnProperty.call(brands, b)) continue;
      var re = new RegExp('(^|[.-])' + escapeRegExp(b) + '([.-]|$)', 'i');
      if (re.test(host) && firstLabel !== b) return { brand: b, official: false, via: 'keyword' };
    }
    return null;
  }

  function typosquatOf(host, cfg) {
    host = lower(host);
    var org = orgDomain(host);
    var label = org.split('.')[0];
    var brands = cfg.brands || {};
    for (var brand in brands) {
      if (!Object.prototype.hasOwnProperty.call(brands, brand)) continue;
      if (brands[brand].some(function (d) { return domainMatches(host, d); })) return null;
    }
    for (var b in brands) {
      if (!Object.prototype.hasOwnProperty.call(brands, b)) continue;
      if (label === b || b.length < 5) {
        // Short brand names (<5 letters) only count for 1-edit look-alikes below.
      }
      var d = levenshtein(label, b);
      var limit = b.length <= 5 ? 1 : 2;
      if (d > 0 && d <= limit && label.length >= 4) return b;
      // Digit-for-letter swaps and doubled letters (paypa1, micros0ft, goog1e) are caught by distance above;
      // hyphenated impostors (paypal-secure.com) are caught by brandForHost's keyword rule.
    }
    return null;
  }

  function looksLikeUrlText(text) {
    var m = /(?:https?:\/\/)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[\/:?#\s]|$)/i.exec(text || '');
    return m ? lower(m[1]) : '';
  }

  function textHostMismatch(text, href) {
    var textHost = looksLikeUrlText(text);
    if (!textHost) return false;
    var realHost = hostOf(href);
    if (!realHost) return false;
    if (orgDomain(textHost) === orgDomain(realHost)) return false;
    return true;
  }

  var PHONE_RE = /(?:\+|\b00)?\d{1,3}[\s.\-()]{0,3}\(?\d{2,4}\)?[\s.\-]{0,3}\d{3,4}[\s.\-]{0,3}\d{3,4}\b|\(\d{3}\)\s*\d{3}[\s.\-]\d{4}|\b\d{3}[\s.\-]\d{3}[\s.\-]\d{4}\b|\b1[\s-]?8(?:00|33|44|55|66|77|88)[\s-]?\d{3}[\s-]?\d{4}\b/;
  var CALLBACK_LURE = /\b(invoice|receipt|charged|charge of|subscription|auto-?renew|renewal|refund|order\s*#?\s*\d|purchase|payment of|transaction|geek squad|norton|mcafee|lifelock|paypal|crypto|bitcoin|wallet|unauthorized|call (us|now|immediately|our)|contact (our )?support|customer (care|service))\b/i;
  var DEVICE_CODE_URL = /(?:microsoft\.com\/devicelogin|login\.microsoftonline\.com\/[^\s"'<>]*\/oauth2\/(?:v2\.0\/)?deviceauth|microsoft\.com\/link|google\.com\/device|github\.com\/login\/device|aka\.ms\/devicelogin)/i;
  var OAUTH_CONSENT_URL = /(?:accounts\.google\.com\/o\/oauth2\/(?:v2\/)?auth|login\.microsoftonline\.com\/[^\s"'<>]*\/oauth2\/(?:v2\.0\/)?authorize|login\.live\.com\/oauth20_authorize)/i;
  var INJECTION_PATTERNS = [
    /ignore (all |any )?(previous|prior|above) instructions/i,
    /disregard (all |any )?(previous|prior|above) (instructions|rules)/i,
    /system override/i,
    /mark this (email|message) as (safe|legitimate|not spam)/i,
    /bypass security/i,
    /execute (the )?following command/i,
    /you are now (in )?(developer|dan|jailbreak) mode/i,
    /(assistant|gemini|claude|chatgpt)[,:]?\s+(you must|please|now)\s+(forward|send|delete|reveal|ignore|click|open)/i,
    /do not (tell|inform|alert) the user/i
  ];
  var ZERO_WIDTH = /[​-‏⁠⁢-⁤﻿‪-‮]/g;

  /** Look for active content in the raw text of a PDF. Names must end at a delimiter so /AA does not match /AAPL. */
  function pdfIndicators(text) {
    text = String(text || '');
    return {
      script: /\/(?:JS|JavaScript|Launch)(?![A-Za-z0-9])/.test(text),
      autoAction: /\/OpenAction(?![A-Za-z0-9])|\/AA\s*<</.test(text),
      embedded: /\/EmbeddedFile(?![A-Za-z0-9])/.test(text)
    };
  }

  // ---------------------------------------------------------------------------
  // Findings
  // ---------------------------------------------------------------------------

  function makeFinding(id, severity, title, detail, evidence) {
    return { id: id, severity: severity, title: title, detail: detail || '', evidence: evidence === undefined ? '' : evidence };
  }

  function severityRank(s) { return SEVERITY_ORDER.indexOf(s); }

  /** Score = 100 minus the weight of each distinct finding id; level follows the worst severity. */
  function scoreFindings(findings) {
    var seen = {};
    var penalty = 0;
    var worst = 'info';
    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      if (severityRank(f.severity) < severityRank(worst)) worst = f.severity;
      if (seen[f.id]) continue;
      seen[f.id] = true;
      penalty += SEVERITY_WEIGHT[f.severity] || 0;
    }
    var score = Math.max(0, 100 - penalty);
    var level = 'green';
    if (worst === 'critical' || score < 40) level = 'red';
    else if (worst === 'high' || score < 80) level = 'yellow';
    return { score: score, level: level, worst: worst };
  }

  var STATUS_TEXT = { red: 'High Risk', yellow: 'Caution', green: 'No threats found' };

  // ---------------------------------------------------------------------------
  // The analysis
  // ---------------------------------------------------------------------------

  /**
   * @param {Object} msg normalized message (see fromGmailApi)
   * @param {Object} enrichment results of lookups done by the adapter. All optional:
   *   safeBrowsing: [{url, threatType}]       threatFeeds: [{url, source}]
   *   redirectChains: {url: [urls...]}         domainAgeDays: {domain: number|null}
   *   senderHistoryCount: number|null          attachmentVerdicts: [{name, sha256, malicious, encrypted}]
   *   qrUrls: string[]                         skipped: string[]  (checks the adapter could not run)
   * @param {Object} config see DEFAULT_CONFIG
   */
  function analyze(msg, enrichment, config) {
    var cfg = mergeConfig(config);
    var en = enrichment || {};
    var findings = [];
    var skipped = (en.skipped || []).slice();
    function add(id, sev, title, detail, evidence) { findings.push(makeFinding(id, sev, title, detail, evidence)); }

    var headers = msg.headers || {};
    var from = parseAddress(msg.from);
    var replyTo = parseAddress(msg.replyTo);
    var returnPath = parseAddress(msg.returnPath);
    var auth = parseAuth(headers);
    var fromOrg = orgDomain(from.domain);
    var allowListed = cfg.allowDomains.some(function (d) { return domainMatches(from.domain, d); });
    var denyListed = cfg.denyDomains.some(function (d) { return domainMatches(from.domain, d); });
    var body = String(msg.plainBody || '');
    var html = String(msg.htmlBody || '');
    var allText = body + ' ' + (html ? stripTags(html) : '');

    // --- Deny list: the user said never trust this sender --------------------
    if (denyListed) add('sender.denied', 'critical', 'Sender is on your block list', 'You marked ' + from.domain + ' as untrusted.', from.domain);

    // --- Authentication ------------------------------------------------------
    if (!auth.present) {
      if (Object.keys(headers).length === 0) skipped.push('Email authentication (headers were not available)');
      else add('auth.missing', 'medium', 'No authentication results on this email', 'The receiving server did not record SPF, DKIM or DMARC results, so the sender cannot be verified.');
    } else {
      if (auth.dmarc === 'fail') add('auth.dmarc_fail', 'high', 'DMARC failed', 'The sender domain says this email should be rejected or quarantined. It may be spoofed.', 'dmarc=fail');
      if (auth.spf === 'fail' || auth.spf === 'softfail') add('auth.spf_fail', 'medium', 'SPF ' + auth.spf, 'The sending server is not authorised by the sender domain.', 'spf=' + auth.spf);
      if (auth.dkim === 'fail') add('auth.dkim_fail', 'medium', 'DKIM signature failed', 'The message was altered or the signature is invalid.', 'dkim=fail');
      if (auth.dkim === 'none' && auth.spf !== 'pass' && auth.dmarc !== 'pass') add('auth.unauthenticated', 'medium', 'Sender is not authenticated', 'No SPF, DKIM or DMARC pass.');
      if (auth.arc === 'fail') add('auth.arc_fail', 'low', 'ARC chain failed', 'This message was forwarded and the forwarding chain does not validate.', 'arc=fail');

      // "via" mismatch: authenticated domains do not align with the visible From domain.
      if (from.domain && auth.dmarc !== 'pass') {
        var aligned = auth.dkimDomains.some(function (d) { return orgDomain(d) === fromOrg; }) ||
          (auth.spf === 'pass' && auth.spfDomain && orgDomain(auth.spfDomain) === fromOrg);
        var authedDomains = uniq(auth.dkimDomains.concat(auth.spf === 'pass' && auth.spfDomain ? [auth.spfDomain] : []));
        if (!aligned && authedDomains.length) {
          add('auth.via_mismatch', 'medium', 'Sent via a different domain', 'The From address says ' + from.domain + ' but the email was authenticated as ' + authedDomains.join(', ') + '.', authedDomains.join(', '));
        }
      }
    }

    // --- Sender identity -----------------------------------------------------
    if (replyTo.email && from.email && replyTo.email !== from.email && orgDomain(replyTo.domain) !== fromOrg) {
      var freeReply = contains(FREE_MAIL_DOMAINS, replyTo.domain) && !contains(FREE_MAIL_DOMAINS, from.domain);
      add('sender.reply_to_mismatch', freeReply ? 'high' : 'medium', 'Replies go to a different address',
        'Reply-To is ' + replyTo.email + ' but the email comes from ' + from.email + (freeReply ? ' (a free mail account). Common in business email compromise.' : '.'), replyTo.email);
    }
    if (returnPath.email && from.domain && orgDomain(returnPath.domain) !== fromOrg && auth.dmarc !== 'pass' && !auth.dkimDomains.some(function (d) { return orgDomain(d) === fromOrg; })) {
      add('sender.return_path_mismatch', 'low', 'Bounce address differs from sender', 'Return-Path is ' + returnPath.email + '.', returnPath.email);
    }

    var displayLower = lower(from.name);
    if (cfg.internalDomain && from.domain && !domainMatches(from.domain, cfg.internalDomain)) {
      var internalLabel = cfg.internalDomain.split('.')[0];
      if (displayLower.indexOf(cfg.internalDomain) !== -1 || (internalLabel.length >= 4 && displayLower.indexOf(internalLabel) !== -1)) {
        add('sender.internal_impersonation', 'high', 'Display name claims to be internal', 'The name mentions ' + cfg.internalDomain + ' but the email comes from ' + from.domain + '.', from.name);
      }
    }
    for (var v = 0; v < cfg.vipNames.length; v++) {
      var vip = lower(cfg.vipNames[v]);
      if (!vip) continue;
      var internal = cfg.internalDomain && domainMatches(from.domain, cfg.internalDomain);
      if (internal) continue;
      if (displayLower.indexOf(vip) !== -1) {
        add('sender.vip_impersonation', 'high', 'Impersonates ' + cfg.vipNames[v], 'The display name matches a protected name but the address is ' + from.email + '.', from.name);
        break;
      }
      var nameParts = displayLower.split(/\s+/);
      var vipParts = vip.split(/\s+/);
      var hit = false;
      for (var a = 0; a < nameParts.length && !hit; a++) {
        for (var b = 0; b < vipParts.length && !hit; b++) {
          if (nameParts[a] !== vipParts[b] && nameParts[a].length > 3 && vipParts[b].length > 3 && levenshtein(nameParts[a], vipParts[b]) === 1) hit = true;
        }
      }
      if (hit) { add('sender.vip_lookalike', 'medium', 'Name looks like ' + cfg.vipNames[v], 'The display name is one letter away from a protected name.', from.name); break; }
    }

    // Brand named in the display name but sent from an unrelated domain.
    if (from.domain && !allowListed) {
      var brands = cfg.brands;
      for (var brandName in brands) {
        if (!Object.prototype.hasOwnProperty.call(brands, brandName)) continue;
        if (displayLower.indexOf(brandName) === -1 || brandName.length < 4) continue;
        var official = brands[brandName].some(function (d) { return domainMatches(from.domain, d); });
        if (!official) {
          add('sender.brand_impersonation', 'high', 'Claims to be ' + brandName + ' but is not', 'The display name mentions ' + brandName + ' but the email comes from ' + from.domain + '.', from.name + ' <' + from.email + '>');
          break;
        }
      }
    }

    // First-time sender and sender-domain age.
    if (typeof en.senderHistoryCount === 'number') {
      if (en.senderHistoryCount === 0 && !allowListed) {
        add('sender.first_time', 'low', 'First email from this sender', 'You have no earlier emails from or to ' + from.email + '.', from.email);
      }
    } else if (en.senderHistoryCount === null || en.senderHistoryCount === undefined) {
      skipped.push('First-time sender check');
    }
    var sAge = en.domainAgeDays ? en.domainAgeDays[from.domain] : undefined;
    if (typeof sAge === 'number' && !allowListed) {
      if (sAge < cfg.veryNewDomainDays) add('sender.domain_new', 'high', 'Sender domain registered ' + sAge + ' day(s) ago', from.domain + ' is brand new. Phishing domains are often used within days of registration.', from.domain);
      else if (sAge < cfg.newDomainDays) add('sender.domain_young', 'medium', 'Sender domain is only ' + sAge + ' days old', from.domain + ' was registered recently.', from.domain);
    }

    // --- Links ---------------------------------------------------------------
    var htmlLinks = extractHtmlLinks(html);
    var plainUrls = extractUrls(body);
    var allUrls = uniq(plainUrls.concat(htmlLinks.map(function (l) { return l.url; })).concat(en.qrUrls || []));
    var linkHosts = uniq(allUrls.map(hostOf).filter(Boolean));

    htmlLinks.forEach(function (link) {
      if (textHostMismatch(link.text, link.url)) {
        add('link.text_mismatch', 'high', 'Link text does not match its destination', 'It says "' + link.text.slice(0, 60) + '" but goes to ' + hostOf(link.url) + '.', link.url);
      }
      if (link.isHidden) add('link.hidden', 'medium', 'Hidden link', 'A link to ' + hostOf(link.url) + ' is hidden with CSS.', link.url);
    });

    allUrls.forEach(function (url) {
      var p = parseUrl(url);
      if (!p) return;
      var host = p.hostname;
      if (cfg.allowDomains.some(function (d) { return domainMatches(host, d); })) return;
      if (cfg.denyDomains.some(function (d) { return domainMatches(host, d); })) {
        add('link.denied', 'critical', 'Link to a blocked domain', host + ' is on your block list.', url);
      }
      if (p.username) add('link.userinfo', 'high', 'Link hides its real destination', 'The URL puts "' + p.username.slice(0, 40) + '@" before the real host ' + host + '.', url);
      if (isIpv4(host)) add('link.ip_host', 'medium', 'Link goes to a raw IP address', host, url);
      var idn = inspectHostname(host);
      if (idn.isIdn) {
        add('link.homograph', idn.mixedScript ? 'high' : 'medium', idn.mixedScript ? 'Look-alike characters in a link' : 'Internationalised domain in a link',
          host + (idn.decoded !== host ? ' (shown as ' + idn.decoded + ')' : '') + (idn.mixedScript ? ' mixes alphabets, a classic homograph trick.' : ''), url);
      }
      var squat = typosquatOf(host, cfg);
      if (squat) add('link.typosquat', 'high', 'Link looks like ' + squat, host + ' is one or two letters away from ' + squat + '.', url);
      var bk = brandForHost(host, cfg);
      if (bk && !bk.official) add('link.brand_keyword', 'medium', 'Link names ' + bk.brand + ' on an unrelated domain', host + ' is not a ' + bk.brand + ' domain.', url);
      if (contains(SHORTENERS, orgDomain(host))) add('link.shortener', 'info', 'Shortened link', host + ' hides the final destination.', url);
      if (DEVICE_CODE_URL.test(url)) {
        add('link.device_code', 'medium', 'Asks you to sign in with a device code', 'Attackers send a real login page plus their own code to get access to your account.', url);
      }
      if (OAUTH_CONSENT_URL.test(url) && !from.domain.match(/(^|\.)(google|microsoft)\.com$/)) {
        add('link.oauth_consent', 'medium', 'Link opens an app-permission screen', 'OAuth consent phishing asks you to grant an attacker app access to your mailbox or files.', url);
      }
    });

    // Redirect chains (provided by the adapter after expansion).
    var chains = en.redirectChains || {};
    Object.keys(chains).forEach(function (u) {
      var chain = chains[u] || [];
      var domains = uniq(chain.map(function (c) { return orgDomain(hostOf(c)); }).filter(Boolean));
      if (domains.length >= 4) add('link.shadow_redirect', 'medium', 'Link bounces through ' + domains.length + ' domains', 'Long redirect chains are used to cloak the real destination.', chain.join(' -> '));
      var finalUrl = chain[chain.length - 1];
      if (finalUrl && finalUrl !== u) {
        var fh = hostOf(finalUrl);
        var fsquat = typosquatOf(fh, cfg);
        if (fsquat) add('link.typosquat', 'high', 'Redirect ends on a look-alike of ' + fsquat, fh + ' is one or two letters away from ' + fsquat + '.', finalUrl);
        var fbk = brandForHost(fh, cfg);
        if (fbk && !fbk.official) add('link.brand_keyword', 'medium', 'Redirect ends on an unrelated ' + fbk.brand + ' look-alike', fh, finalUrl);
        var fidn = inspectHostname(fh);
        if (fidn.mixedScript) add('link.homograph', 'high', 'Redirect ends on a look-alike domain', fh, finalUrl);
      }
    });

    // Reputation hits.
    (en.safeBrowsing || []).forEach(function (m) {
      add('link.safe_browsing', 'critical', 'Google Safe Browsing flags a link', (m.threatType || 'threat').replace(/_/g, ' ').toLowerCase() + ': ' + hostOf(m.url), m.url);
    });
    (en.threatFeeds || []).forEach(function (m) {
      add('link.threat_feed', 'critical', 'Link is on a phishing/malware feed', hostOf(m.url) + ' (' + (m.source || 'threat feed') + ')', m.url);
    });
    var ageMap = en.domainAgeDays || {};
    Object.keys(ageMap).forEach(function (d) {
      var age = ageMap[d];
      if (typeof age !== 'number' || d === from.domain) return;
      if (linkHosts.indexOf(d) === -1) return;
      if (cfg.allowDomains.some(function (x) { return domainMatches(d, x); })) return;
      if (age < cfg.veryNewDomainDays) add('link.domain_new', 'high', 'Link domain registered ' + age + ' day(s) ago', d + ' is brand new.', d);
      else if (age < cfg.newDomainDays) add('link.domain_young', 'medium', 'Link domain is only ' + age + ' days old', d + ' was registered recently.', d);
    });

    // QR codes
    if ((en.qrUrls || []).length) add('qr.found', 'info', 'QR code in an image', 'The QR code points to ' + hostOf(en.qrUrls[0]) + '.', en.qrUrls[0]);

    // --- Content -------------------------------------------------------------
    var lowerAll = lower(allText);
    var urgencyHits = [];
    var urgencyWeight = 0;
    for (var kw in LINGUISTIC_WEIGHTS) {
      if (Object.prototype.hasOwnProperty.call(LINGUISTIC_WEIGHTS, kw) && lowerAll.indexOf(kw) !== -1) {
        urgencyHits.push(kw);
        urgencyWeight += LINGUISTIC_WEIGHTS[kw];
      }
    }
    if (urgencyHits.length) {
      var usev = urgencyWeight >= 30 ? 'medium' : 'low';
      add('content.urgency', usev, 'Pressure language', 'Phrases like "' + urgencyHits.slice(0, 4).join('", "') + '" are common in scams.', urgencyHits.join(', '));
    }

    var injected = false;
    for (var ip = 0; ip < INJECTION_PATTERNS.length && !injected; ip++) {
      if (INJECTION_PATTERNS[ip].test(allText)) injected = true;
    }
    var hiddenTexts = extractHiddenText(html);
    var zeroWidthCount = (allText.match(ZERO_WIDTH) || []).length;
    if (injected) add('content.prompt_injection', 'medium', 'Contains instructions aimed at AI assistants', 'The text tries to give orders to an AI summariser or agent.');
    if (hiddenTexts.length) add('content.hidden_text', injected ? 'medium' : 'low', 'Hidden text in the email', 'Text is hidden from view with CSS, which is used to smuggle instructions or fool filters.', hiddenTexts[0]);
    if (zeroWidthCount >= 8) add('content.zero_width', 'low', 'Invisible characters in the text', zeroWidthCount + ' zero-width characters can be used to dodge keyword filters.');

    // Callback phishing: a phone number is the payload.
    var strippedBody = lowerAll.slice(0, 100000).replace(/https?:\/\/\S+/g, ' ');
    var phone = PHONE_RE.exec(strippedBody);
    var attachmentsNoInline = (msg.attachments || []).filter(function (a) { return !a.isInline; });
    var imageOnly = !body.replace(/\s+/g, '').length && !!html && /<img\b/i.test(html);
    if (phone && (CALLBACK_LURE.test(allText) || imageOnly) && linkHosts.length <= 2 && !allowListed) {
      var cbWeak = auth.present && auth.dmarc === 'pass' && (en.senderHistoryCount || 0) > 0;
      add('content.callback_phishing', cbWeak ? 'low' : 'high', 'Looks like a phone-scam email',
        'It pushes you to call ' + phone[0].trim() + ' about a charge, order or account. Callback scams contain no link so filters miss them.', phone[0].trim());
    }

    // --- Transport -----------------------------------------------------------
    var received = headers['received'] || [];
    if (received.length >= 2 && !received.some(function (r) { return /\bTLS|ESMTPS|using TLS/i.test(r); })) {
      add('transport.no_tls', 'low', 'Not encrypted in transit', 'None of the mail servers that handled this message recorded TLS.');
    }

    // --- Attachments ---------------------------------------------------------
    (msg.attachments || []).forEach(function (att) {
      var name = att.name || '';
      var ext = extensionOf(name);
      var nameParts = lower(name).split('.');
      var sniffed = sniffMagic(att.head);
      var mime = lower(att.mimeType);

      if (contains(DANGEROUS_EXTENSIONS, ext)) {
        add('attach.dangerous', 'high', 'Risky file type: .' + ext, name + ' can run code when opened.', name);
      }
      if (nameParts.length >= 3 && contains(DANGEROUS_EXTENSIONS.concat(['svg', 'html', 'htm']), ext) && contains(DOUBLE_EXT_DECOYS, nameParts[nameParts.length - 2])) {
        add('attach.double_extension', 'high', 'File pretends to be a .' + nameParts[nameParts.length - 2], name + ' ends in .' + ext + '.', name);
      }
      if (contains(MACRO_EXTENSIONS, ext)) add('attach.macro', 'medium', 'Office file with macros', name + ' can contain macros that run when enabled.', name);
      if (ext === 'svg' || mime === 'image/svg+xml' || /<svg[\s>]/i.test(att.text || '')) {
        var svgScript = /<script\b|onload\s*=|javascript:|<foreignObject|atob\(|eval\(/i.test(att.text || '');
        add('attach.svg', svgScript ? 'high' : 'medium', svgScript ? 'SVG attachment with script' : 'SVG attachment', 'SVG files can carry JavaScript and are used to smuggle phishing pages past filters.', name);
      }
      if (contains(['html', 'htm', 'xhtml', 'shtml', 'mht', 'mhtml'], ext) || mime === 'text/html' && !!name) {
        var hasForm = /<form\b|<input\b|password|atob\(|eval\(|unescape\(/i.test(att.text || '');
        add('attach.html', hasForm ? 'high' : 'medium', 'HTML attachment', 'An HTML file opens a page from your computer. Often a fake login form.', name);
      }
      if (ext === 'ics' || mime === 'text/calendar') {
        var icsLinksOrPhone = /https?:\/\//i.test(att.text || '') || PHONE_RE.test(att.text || '');
        if (icsLinksOrPhone && !allowListed) add('attach.calendar_lure', 'low', 'Calendar invite containing a link or phone number', 'Invites are used to deliver callback and phishing lures that skip normal inbox filtering.', name);
      }
      if (ext === 'eml' || mime === 'message/rfc822') add('attach.nested_email', 'low', 'Attached email', name + ' is an email inside an email and is not scanned.', name);
      if (contains(ARCHIVE_EXTENSIONS, ext) && att.encrypted) add('attach.encrypted_archive', 'high', 'Password-protected archive', name + ' is encrypted so scanners cannot see inside.', name);
      // ZIP local-file-header general purpose flag, bit 0 = the entry is encrypted.
      if (sniffed === 'zip' && att.head && att.head.length > 7 && (att.head[6] & 0x01)) {
        add('attach.encrypted_archive', 'high', 'Password-protected archive', name + ' is encrypted so scanners cannot see inside. Attackers put the password in the email body.', name);
      }
      if (att.pdfText) {
        var pdf = pdfIndicators(att.pdfText);
        if (pdf.script) add('attach.pdf_script', 'high', 'PDF contains JavaScript or a launch action', name + ' can run code when opened.', name);
        if (pdf.autoAction) add('attach.pdf_autoaction', 'medium', 'PDF runs an action on open', name + ' has an automatic action.', name);
        if (pdf.embedded) add('attach.pdf_embedded', 'medium', 'PDF carries an embedded file', name + ' hides another file inside.', name);
      }

      if (sniffed && ext) {
        var allowedExts = MAGIC_ALIASES[sniffed] || [sniffed];
        if (!contains(allowedExts, ext) && !(sniffed === 'zip' && contains(ARCHIVE_EXTENSIONS, ext)) && !(ext === 'jpeg' && sniffed === 'jpg')) {
          var executableDisguise = sniffed === 'exe' || sniffed === 'elf' || sniffed === 'lnk';
          add('attach.type_mismatch', executableDisguise ? 'high' : 'medium', 'File type does not match its name', name + ' is really a ' + sniffed.toUpperCase() + ' file.', name);
        }
      }
    });
    (en.attachmentVerdicts || []).forEach(function (v) {
      if (v.malicious && v.malicious > 0) add('attach.malicious_hash', 'critical', 'Attachment flagged as malware', (v.name || 'attachment') + ' was flagged by ' + v.malicious + ' scanner(s).', v.sha256 || v.name);
      if (v.encrypted) add('attach.encrypted_archive', 'high', 'Password-protected archive', (v.name || 'attachment') + ' is encrypted so scanners cannot see inside.', v.name);
    });

    // --- Combinations --------------------------------------------------------
    var ids = {};
    findings.forEach(function (f) { ids[f.id] = true; });
    if ((ids['auth.dmarc_fail'] || ids['auth.unauthenticated']) &&
      (ids['link.safe_browsing'] || ids['link.threat_feed'] || ids['link.text_mismatch'] || ids['link.typosquat'] || ids['link.homograph'])) {
      add('combo.spoofed_phish', 'critical', 'Spoofed sender with a suspicious link', 'The email fails authentication and contains a link that looks malicious.');
    }
    if (ids['sender.first_time'] && ids['content.urgency'] && (ids['link.brand_keyword'] || ids['sender.brand_impersonation'])) {
      add('combo.new_sender_brand_lure', 'high', 'New sender using a brand name and pressure', 'First contact, urgent wording and a brand impersonation together are typical of phishing.');
    }

    // --- Coverage ------------------------------------------------------------
    skipped = uniq(skipped);
    var scored = scoreFindings(findings);
    var sorted = findings.slice().sort(function (a, b) { return severityRank(a.severity) - severityRank(b.severity); });

    return {
      version: VERSION,
      messageId: msg.id,
      score: scored.score,
      level: scored.level,
      status: STATUS_TEXT[scored.level],
      findings: sorted,
      warnings: sorted.filter(function (f) { return f.severity !== 'info'; }).map(function (f) { return f.title; }),
      auth: { spf: auth.spf, dkim: auth.dkim, dmarc: auth.dmarc, arc: auth.arc, present: auth.present, dkimDomains: auth.dkimDomains },
      from: from,
      urls: allUrls,
      attachmentsCount: (msg.attachments || []).length,
      incomplete: skipped.length > 0,
      skipped: skipped,
      allowListed: allowListed
    };
  }

  /** Domains worth an RDAP age lookup: the sender plus link hosts that are not obviously big sites. */
  function domainsToAgeCheck(msg, config, limit) {
    var cfg = mergeConfig(config);
    var from = parseAddress(msg.from);
    var out = [];
    var known = [];
    for (var b in cfg.brands) {
      if (Object.prototype.hasOwnProperty.call(cfg.brands, b)) known = known.concat(cfg.brands[b]);
    }
    function consider(host) {
      var org = orgDomain(host);
      if (!org || isIpv4(org) || isPrivateHost(org) || contains(out, org)) return;
      if (known.some(function (d) { return domainMatches(org, d); })) return;
      if (contains(SHORTENERS, org) || contains(FREE_MAIL_DOMAINS, org)) return;
      if (cfg.allowDomains.some(function (d) { return domainMatches(org, d); })) return;
      out.push(org);
    }
    consider(from.domain);
    var urls = extractUrls(msg.plainBody).concat(extractHtmlLinks(msg.htmlBody).map(function (l) { return l.url; }));
    for (var i = 0; i < urls.length; i++) consider(hostOf(urls[i]));
    return out.slice(0, limit || 5);
  }

  /** URLs that are safe to expand without the user asking (known shorteners only). */
  function urlsToExpand(urls, deep, limit) {
    var out = [];
    for (var i = 0; i < urls.length; i++) {
      var p = parseUrl(urls[i]);
      if (!p || (p.protocol !== 'http:' && p.protocol !== 'https:')) continue;
      if (p.username || isPrivateHost(p.hostname)) continue;
      if (deep || contains(SHORTENERS, orgDomain(p.hostname))) out.push(urls[i]);
      if (out.length >= (limit || 10)) break;
    }
    return out;
  }

  /** Pick the creation date out of an RDAP domain response. @return {number|null} age in days */
  function rdapAgeDays(rdap, nowMs) {
    var events = (rdap && rdap.events) || [];
    for (var i = 0; i < events.length; i++) {
      if (lower(events[i].eventAction) === 'registration' && events[i].eventDate) {
        var t = Date.parse(events[i].eventDate);
        if (!isNaN(t)) return Math.max(0, Math.floor(((nowMs || Date.now()) - t) / 86400000));
      }
    }
    return null;
  }

  /** Build a plain-text report suitable for an email body or CLI output. */
  function formatReport(result) {
    var lines = [];
    lines.push('Security scan: ' + result.status + ' (' + result.score + '/100)');
    result.findings.forEach(function (f) {
      lines.push('[' + f.severity.toUpperCase() + '] ' + f.title + (f.detail ? ' - ' + f.detail : ''));
    });
    if (result.incomplete) lines.push('Not checked: ' + result.skipped.join('; '));
    return lines.join('\n');
  }

  return {
    VERSION: VERSION,
    DEFAULT_CONFIG: DEFAULT_CONFIG,
    SEVERITY_WEIGHT: SEVERITY_WEIGHT,
    SHORTENERS: SHORTENERS,
    analyze: analyze,
    scoreFindings: scoreFindings,
    fromGmailApi: fromGmailApi,
    setAttachmentBytes: setAttachmentBytes,
    parseHeaderBlock: parseHeaderBlock,
    headersFromList: headersFromList,
    parseAddress: parseAddress,
    parseAuth: parseAuth,
    parseUrl: parseUrl,
    hostOf: hostOf,
    orgDomain: orgDomain,
    extractUrls: extractUrls,
    extractHtmlLinks: extractHtmlLinks,
    extractHiddenText: extractHiddenText,
    stripTags: stripTags,
    decodeMimeWords: decodeMimeWords,
    base64ToBytes: base64ToBytes,
    bytesToLatin1: bytesToLatin1,
    bytesToUtf8: bytesToUtf8,
    sniffMagic: sniffMagic,
    pdfIndicators: pdfIndicators,
    inspectHostname: inspectHostname,
    typosquatOf: typosquatOf,
    levenshtein: levenshtein,
    isPrivateHost: isPrivateHost,
    mergeConfig: mergeConfig,
    domainsToAgeCheck: domainsToAgeCheck,
    urlsToExpand: urlsToExpand,
    rdapAgeDays: rdapAgeDays,
    formatReport: formatReport
  };
});
