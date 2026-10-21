/**
 * Gmail add-on entry points and scan orchestration. All detection logic lives in ScannerCore.
 */

function getContextualAddOn(e) {
  const messageId = e && e.gmail && e.gmail.messageId;
  if (!messageId) return UI.homeCard();
  return UI.resultCard(scanMessage(messageId, false, e), messageId);
}

function buildHomepage() {
  return UI.homeCard();
}

/** Runs a scan, never returns a fake "clean" result: errors become an explicit error card. */
function scanMessage(messageId, deep, e) {
  const cacheKey = 'scan_' + SCANNER.VERSION + '_' + Settings.generation() + '_' + (deep ? 'd' : 'p') + '_' + messageId;
  const cache = CacheService.getUserCache();
  const hit = cache.get(cacheKey);
  if (hit) {
    try { return JSON.parse(hit); } catch (err) { /* fall through and rescan */ }
  }
  try {
    const raw = GmailApi.getMessage(messageId);
    const msg = ScannerCore.fromGmailApi(raw);
    const settings = Settings.load();
    const enrichment = Enrichment.collect(msg, settings, deep);
    const result = ScannerCore.analyze(msg, enrichment, settings);
    result.deep = !!deep;
    result.threadId = msg.threadId;
    result.subject = msg.subject;
    result.scannedAt = Date.now();
    const json = JSON.stringify(result);
    if (json.length < 90000) cache.put(cacheKey, json, SCANNER.CACHE_SECONDS);
    return result;
  } catch (err) {
    console.error('Scan failed: ' + err.message);
    return { error: String(err.message || err), messageId: messageId };
  }
}

// --- Card actions ------------------------------------------------------------

function handleDeepScan(e) {
  const id = e.parameters.messageId;
  return UI.navigate(UI.resultCard(scanMessage(id, true, e), id));
}

function handleRescan(e) {
  const id = e.parameters.messageId;
  return UI.navigate(UI.resultCard(scanMessage(id, false, e), id));
}

function handleNeutralize(e) {
  const id = e.parameters.messageId;
  try {
    const msg = GmailApi.call('get', '/messages/' + encodeURIComponent(id), { format: 'minimal' });
    const labelId = GmailApi.ensureLabel(SCANNER.REVIEW_LABEL);
    GmailApi.modifyThread(msg.threadId, [labelId, 'SPAM'], ['INBOX', 'UNREAD']);
    return UI.notify('Moved to Spam and marked read. Nothing was deleted; undo it from the Spam folder.');
  } catch (err) {
    return UI.notify('Could not neutralize: ' + err.message);
  }
}

/** Creates a draft addressed to APWG with the original message attached. The user presses Send. */
function handleReportPhishing(e) {
  const id = e.parameters.messageId;
  try {
    const raw = GmailApi.getRawBytes(id);
    const boundary = 'scanner_' + Utilities.getUuid().replace(/-/g, '');
    const b64 = Utilities.base64Encode(GmailApi.toSigned(raw)).replace(/(.{76})/g, '$1\r\n');
    const mime =
      'To: ' + SCANNER.REPORT_ADDRESS + '\r\n' +
      'Subject: Phishing report\r\n' +
      'MIME-Version: 1.0\r\n' +
      'Content-Type: multipart/mixed; boundary="' + boundary + '"\r\n\r\n' +
      '--' + boundary + '\r\nContent-Type: text/plain; charset="UTF-8"\r\n\r\n' +
      'Reporting a suspected phishing email. The original message is attached.\r\n\r\n' +
      '--' + boundary + '\r\nContent-Type: message/rfc822; name="reported.eml"\r\n' +
      'Content-Disposition: attachment; filename="reported.eml"\r\nContent-Transfer-Encoding: base64\r\n\r\n' +
      b64 + '\r\n--' + boundary + '--';
    const draft = GmailApi.createDraft(GmailApi.toUnsigned(Utilities.newBlob(mime).getBytes()));
    return UI.notify('Draft created in your Drafts folder, addressed to ' + SCANNER.REPORT_ADDRESS + '. Review it and press Send to report.' + (draft && draft.id ? '' : ''));
  } catch (err) {
    return UI.notify('Could not create the report draft: ' + err.message);
  }
}

function handleTrustSender(e) {
  Settings.addDomain('allowDomains', e.parameters.domain);
  return UI.notify(e.parameters.domain + ' added to your trusted list. Rescan to apply.');
}

function handleBlockSender(e) {
  Settings.addDomain('denyDomains', e.parameters.domain);
  return UI.notify(e.parameters.domain + ' added to your block list. Rescan to apply.');
}

function handleOpenSettings() {
  return UI.navigate(UI.settingsCard());
}

function handleSaveSettings(e) {
  const f = (e.commonEventObject && e.commonEventObject.formInputs) || {};
  const val = function (k) { return f[k] && f[k].stringInputs ? f[k].stringInputs.value[0] : ''; };
  Settings.save({
    internalDomain: Settings.parseList(val('internalDomain'))[0] || '',
    vipNames: Settings.parseNames(val('vipNames')),
    allowDomains: Settings.parseList(val('allowDomains')),
    denyDomains: Settings.parseList(val('denyDomains'))
  });
  return UI.notify('Settings saved.');
}
