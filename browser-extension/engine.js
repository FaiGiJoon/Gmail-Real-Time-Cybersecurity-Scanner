/**
 * engine.js - scan orchestration for the Chrome extension.
 * All I/O is injected so the same code runs in the service worker and in node tests.
 */
(function (root, factory) {
  var api = factory(typeof module !== 'undefined' && module.exports ? require('./scanner-core.js') : root.ScannerCore);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.ScanEngine = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function (Core) {
  'use strict';

  var GMAIL = 'https://gmail.googleapis.com/gmail/v1/users/me';
  var SAFE_BROWSING = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
  var RDAP = 'https://rdap.org/domain/';
  var MAX_ATTACH = 5 * 1024 * 1024;

  /**
   * @param {{fetch:Function, getToken:Function, getSettings:Function, now:Function}} env
   *   getToken(interactive) -> Promise<string>; getSettings() -> Promise<{keys:{}, config:{}}>
   */
  function createEngine(env) {
    var now = env.now || Date.now;

    function gmail(method, path, query, body) {
      return env.getToken().then(function (token) {
        var url = GMAIL + path;
        if (query) {
          var parts = [];
          Object.keys(query).forEach(function (k) { parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(query[k])); });
          url += '?' + parts.join('&');
        }
        var opts = { method: method, headers: { Authorization: 'Bearer ' + token } };
        if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
        return env.fetch(url, opts);
      }).then(function (res) {
        return res.json().then(function (json) {
          if (!res.ok) throw new Error('Gmail API ' + res.status + ': ' + ((json && json.error && json.error.message) || 'request failed'));
          return json;
        });
      });
    }

    function collect(msg, settings, deep) {
      var out = { skipped: [], safeBrowsing: [], threatFeeds: [], redirectChains: {}, domainAgeDays: {}, attachmentVerdicts: [], qrUrls: [] };
      var urls = Core.extractUrls((msg.plainBody || '') + ' ' + (msg.htmlBody || '')).slice(0, 40);
      var tasks = [];

      var addr = Core.parseAddress(msg.from).email;
      if (addr) {
        tasks.push(gmail('GET', '/messages', { q: 'from:' + addr + ' -in:trash', maxResults: 3 }).then(function (r) {
          out.senderHistoryCount = (r.messages || []).filter(function (m) { return m.id !== msg.id; }).length;
        }).catch(function () { out.senderHistoryCount = null; out.skipped.push('Sender history'); }));
      } else { out.senderHistoryCount = null; }

      var sbKey = settings.keys && settings.keys.SAFE_BROWSING_API_KEY;
      if (urls.length && !sbKey) out.skipped.push('Safe Browsing (no API key set in extension options)');
      if (urls.length && sbKey) {
        tasks.push(env.fetch(SAFE_BROWSING, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-Goog-Api-Key': sbKey },
          body: JSON.stringify({
            client: { clientId: 'gmail-cyber-scanner-ext', clientVersion: Core.VERSION },
            threatInfo: {
              threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
              platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'],
              threatEntries: urls.map(function (u) { return { url: u }; })
            }
          })
        }).then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        }).then(function (j) {
          out.safeBrowsing = (j.matches || []).map(function (m) { return { url: m.threat.url, threatType: m.threatType }; });
        }).catch(function (e) { out.skipped.push('Safe Browsing (' + e.message + ')'); }));
      }

      if (Core.urlsToExpand(urls, deep, 1).length) {
        out.skipped.push('Redirect chains (browsers hide redirect targets from extensions; use the Apps Script add-on or CLI for this check)');
      }

      Core.domainsToAgeCheck(msg, settings.config, 6).forEach(function (d) {
        tasks.push(env.fetch(RDAP + encodeURIComponent(d)).then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        }).then(function (j) { out.domainAgeDays[d] = Core.rdapAgeDays(j, now()); })
          .catch(function () { out.domainAgeDays[d] = null; out.skipped.push('Domain age for ' + d); }));
      });

      (msg.attachments || []).slice(0, 5).forEach(function (att) {
        if (!att.attachmentId) return;
        if (att.size > MAX_ATTACH) { out.skipped.push('Contents of attachment ' + att.name + ' (over 5 MB)'); return; }
        tasks.push(gmail('GET', '/messages/' + encodeURIComponent(msg.id) + '/attachments/' + encodeURIComponent(att.attachmentId))
          .then(function (r) { Core.setAttachmentBytes(att, Core.base64ToBytes(r.data)); })
          .catch(function (e) { out.skipped.push('Contents of attachment ' + att.name + ' (' + e.message + ')'); }));
      });

      return Promise.all(tasks).then(function () { return out; });
    }

    return {
      scanMessage: function (id, deep) {
        return Promise.all([gmail('GET', '/messages/' + encodeURIComponent(id), { format: 'full' }), env.getSettings()]).then(function (r) {
          var msg = Core.fromGmailApi(r[0]);
          return collect(msg, r[1], !!deep).then(function (en) {
            var res = Core.analyze(msg, en, r[1].config);
            res.threadId = msg.threadId;
            res.subject = msg.subject;
            res.deep = !!deep;
            return res;
          });
        });
      },

      /** Most recent inbox messages with sender and subject, for the picker. */
      listRecent: function (n) {
        return gmail('GET', '/messages', { q: 'in:inbox', maxResults: n || 10 }).then(function (r) {
          return Promise.all((r.messages || []).map(function (m) {
            return gmail('GET', '/messages/' + m.id, { format: 'metadata', metadataHeaders: 'From' }).then(function (full) {
              var h = Core.headersFromList(((full.payload || {}).headers) || []);
              return { id: m.id, threadId: m.threadId, from: (h.from && h.from[0]) || '', snippet: full.snippet || '' };
            });
          }));
        });
      },

      /** Resolve a Gmail thread id (as seen in the page) to its newest message id. */
      newestInThread: function (threadId) {
        return gmail('GET', '/threads/' + encodeURIComponent(threadId), { format: 'minimal' }).then(function (t) {
          var msgs = t.messages || [];
          return msgs.length ? msgs[msgs.length - 1].id : null;
        });
      },

      /** Moves to Spam and marks read. Does not delete anything. */
      neutralize: function (threadId) {
        return gmail('POST', '/threads/' + encodeURIComponent(threadId) + '/modify', undefined, { addLabelIds: ['SPAM'], removeLabelIds: ['INBOX', 'UNREAD'] });
      }
    };
  }

  return { createEngine: createEngine };
});
