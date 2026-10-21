/**
 * Network lookups that feed ScannerCore.analyze(). Every lookup is optional: when one cannot run
 * (no key, quota, timeout) it is recorded in `skipped`, so the card says "not checked" instead
 * of looking clean.
 */
const Enrichment = {
  /**
   * @param {Object} msg normalized message from ScannerCore.fromGmailApi
   * @param {Object} config scanner config
   * @param {boolean} deep Deep Scan: also follow redirects on every link
   */
  collect: function (msg, config, deep) {
    const started = Date.now();
    const props = PropertiesService.getScriptProperties();
    const out = { skipped: [], safeBrowsing: [], threatFeeds: [], redirectChains: {}, domainAgeDays: {}, attachmentVerdicts: [], qrUrls: [] };
    const outOfTime = function () { return Date.now() - started > SCANNER.TIME_BUDGET_MS; };
    const urls = ScannerCore.extractUrls((msg.plainBody || '') + ' ' + (msg.htmlBody || '')).slice(0, SCANNER.MAX_URLS_TO_LOOKUP);

    // 1. First-time sender (cheap, one list call)
    try {
      const fromAddr = ScannerCore.parseAddress(msg.from).email;
      if (fromAddr) {
        const prior = GmailApi.list('from:' + fromAddr + ' -in:trash', 3).filter(function (m) { return m.id !== msg.id; });
        out.senderHistoryCount = prior.length;
      } else { out.senderHistoryCount = null; }
    } catch (e) {
      out.senderHistoryCount = null;
      out.skipped.push('Sender history (' + Enrichment.brief(e) + ')');
    }

    // 2. Safe Browsing
    const sbKey = props.getProperty('SAFE_BROWSING_API_KEY');
    if (!urls.length) {
      // nothing to look up
    } else if (!sbKey) {
      out.skipped.push('Safe Browsing (no API key set)');
    } else {
      try { out.safeBrowsing = Enrichment.safeBrowsing(urls, sbKey); }
      catch (e) { out.skipped.push('Safe Browsing (' + Enrichment.brief(e) + ')'); }
    }

    // 3. Redirect expansion: known shorteners always, everything else only on Deep Scan
    const toExpand = ScannerCore.urlsToExpand(urls, deep, deep ? 15 : 5);
    toExpand.forEach(function (u) {
      if (outOfTime()) return;
      try { out.redirectChains[u] = Enrichment.followRedirects(u); }
      catch (e) { out.skipped.push('Redirect check for ' + Enrichment.host(u)); }
    });

    // 4. Domain age via RDAP (cached per domain for a day)
    const domains = ScannerCore.domainsToAgeCheck(msg, config, 6);
    const cache = CacheService.getScriptCache();
    domains.forEach(function (d) {
      if (outOfTime()) { out.skipped.push('Domain age for ' + d + ' (time budget)'); return; }
      const key = 'rdap_' + d;
      const hit = cache.get(key);
      if (hit !== null) { out.domainAgeDays[d] = hit === 'null' ? null : Number(hit); return; }
      try {
        const res = UrlFetchApp.fetch(SCANNER.RDAP_ENDPOINT + encodeURIComponent(d), { muteHttpExceptions: true, followRedirects: true });
        if (res.getResponseCode() === 200) {
          const age = ScannerCore.rdapAgeDays(JSON.parse(res.getContentText()), Date.now());
          out.domainAgeDays[d] = age;
          cache.put(key, String(age), 86400);
        } else {
          out.domainAgeDays[d] = null;
          out.skipped.push('Domain age for ' + d + ' (registry returned ' + res.getResponseCode() + ')');
        }
      } catch (e) {
        out.domainAgeDays[d] = null;
        out.skipped.push('Domain age for ' + d);
      }
    });

    // 5. Attachments: fetch a few so magic bytes / PDF / zip checks run on real data
    const vtKey = props.getProperty('VIRUSTOTAL_API_KEY');
    let fetched = 0;
    (msg.attachments || []).forEach(function (att) {
      if (!att.attachmentId || att.fetched) return;
      if (fetched >= SCANNER.MAX_ATTACHMENTS_FETCHED || outOfTime()) {
        out.skipped.push('Contents of attachment ' + att.name + ' (limit)');
        return;
      }
      if (att.size > SCANNER.MAX_ATTACHMENT_BYTES) {
        out.skipped.push('Contents of attachment ' + att.name + ' (over 5 MB)');
        return;
      }
      try {
        const bytes = GmailApi.getAttachmentBytes(msg.id, att.attachmentId);
        ScannerCore.setAttachmentBytes(att, bytes);
        fetched++;
        if (vtKey) {
          const hash = Enrichment.sha256(bytes);
          const verdict = Enrichment.virusTotal(hash, vtKey);
          if (verdict) out.attachmentVerdicts.push({ name: att.name, sha256: hash, malicious: verdict.malicious, encrypted: false });
        }
      } catch (e) {
        out.skipped.push('Contents of attachment ' + att.name + ' (' + Enrichment.brief(e) + ')');
      }
    });
    return out;
  },

  safeBrowsing: function (urls, key) {
    const body = {
      client: { clientId: 'gmail-cyber-scanner', clientVersion: SCANNER.VERSION },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: urls.map(function (u) { return { url: u }; })
      }
    };
    const res = UrlFetchApp.fetch(SCANNER.SAFE_BROWSING_ENDPOINT, {
      method: 'post',
      contentType: 'application/json',
      headers: { 'X-Goog-Api-Key': key },
      payload: JSON.stringify(body),
      muteHttpExceptions: true
    });
    if (res.getResponseCode() !== 200) throw new Error('HTTP ' + res.getResponseCode());
    const matches = JSON.parse(res.getContentText()).matches || [];
    return matches.map(function (m) { return { url: m.threat.url, threatType: m.threatType }; });
  },

  /** Follows redirects manually, one hop at a time, without sending cookies. */
  followRedirects: function (startUrl) {
    const chain = [startUrl];
    let current = startUrl;
    for (let hop = 0; hop < SCANNER.MAX_REDIRECT_HOPS; hop++) {
      const parsed = ScannerCore.parseUrl(current);
      if (!parsed || (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') || ScannerCore.isPrivateHost(parsed.hostname)) break;
      const res = UrlFetchApp.fetch(current, { method: 'head', followRedirects: false, muteHttpExceptions: true });
      const code = res.getResponseCode();
      const headers = res.getHeaders();
      let loc = null;
      Object.keys(headers).forEach(function (k) { if (k.toLowerCase() === 'location') loc = headers[k]; });
      if (code < 300 || code >= 400 || !loc) break;
      current = Enrichment.resolve(current, String(loc));
      chain.push(current);
    }
    return chain;
  },

  resolve: function (base, loc) {
    if (/^https?:\/\//i.test(loc)) return loc;
    const p = ScannerCore.parseUrl(base);
    if (!p) return loc;
    const hostPort = p.hostname + (p.port ? ':' + p.port : '');
    if (loc.indexOf('//') === 0) return p.protocol + loc;
    if (loc.charAt(0) === '/') return p.protocol + '//' + hostPort + loc;
    return p.protocol + '//' + hostPort + '/' + loc;
  },

  sha256: function (bytes) {
    const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, GmailApi.toSigned(bytes));
    return digest.map(function (b) { return ('0' + (b & 0xFF).toString(16)).slice(-2); }).join('');
  },

  virusTotal: function (sha256, key) {
    const res = UrlFetchApp.fetch(SCANNER.VIRUSTOTAL_ENDPOINT + sha256, { headers: { 'x-apikey': key }, muteHttpExceptions: true });
    if (res.getResponseCode() !== 200) return null;
    const stats = (JSON.parse(res.getContentText()).data || {}).attributes;
    const s = stats && stats.last_analysis_stats;
    return s ? { malicious: (s.malicious || 0) >= 2 ? s.malicious : 0 } : null;
  },

  host: function (u) {
    const p = ScannerCore.parseUrl(u);
    return p ? p.hostname : 'link';
  },

  brief: function (e) {
    return String((e && e.message) || e).slice(0, 80);
  }
};
