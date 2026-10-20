/** Card builders. The card shows findings with evidence and says plainly what was not checked. */
const UI = {
  SEVERITY_LABEL: { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' },

  esc: function (s) {
    return String(s === undefined || s === null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  },

  notify: function (text) {
    return CardService.newActionResponseBuilder()
      .setNotification(CardService.newNotification().setText(text))
      .build();
  },

  navigate: function (card) {
    return CardService.newActionResponseBuilder()
      .setNavigation(CardService.newNavigation().updateCard(card))
      .build();
  },

  action: function (fn, params) {
    return CardService.newAction().setFunctionName(fn).setParameters(params || {});
  },

  homeCard: function () {
    const s = CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText('Open an email to scan it. Every email you open is checked for spoofing, risky links, dangerous attachments and phishing wording. The card lists what was found and what could not be checked.'))
      .addWidget(CardService.newTextButton().setText('Settings').setOnClickAction(UI.action('handleOpenSettings')));
    return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle('Cybersecurity Scanner').setSubtitle('Version ' + SCANNER.VERSION))
      .addSection(s).build();
  },

  resultCard: function (r, messageId) {
    const builder = CardService.newCardBuilder();
    if (r.error) {
      builder.setHeader(CardService.newCardHeader().setTitle('Scan failed').setSubtitle('This email was NOT checked'));
      builder.addSection(CardService.newCardSection()
        .addWidget(CardService.newTextParagraph().setText(UI.esc(r.error)))
        .addWidget(CardService.newTextButton().setText('Try again').setOnClickAction(UI.action('handleRescan', { messageId: messageId }))));
      return builder.build();
    }
    const icon = SCANNER.LEVEL_ICONS[r.level];
    builder.setHeader(CardService.newCardHeader()
      .setTitle(r.status + ' (' + r.score + '/100)')
      .setSubtitle((r.deep ? 'Deep scan' : 'Standard scan') + (r.incomplete ? ' - some checks skipped' : ''))
      .setImageUrl(icon));

    const findings = CardService.newCardSection().setHeader('Why this score');
    const real = (r.findings || []).filter(function (f) { return f.severity !== 'info'; });
    if (!real.length) {
      findings.addWidget(CardService.newTextParagraph().setText('No problems found by the checks that ran.'));
    }
    real.slice(0, 12).forEach(function (f) {
      findings.addWidget(CardService.newDecoratedText()
        .setTopLabel(UI.SEVERITY_LABEL[f.severity] || f.severity)
        .setText('<b>' + UI.esc(f.title) + '</b>')
        .setBottomLabel(UI.esc((f.detail || '') + (f.evidence ? ' [' + f.evidence + ']' : '')))
        .setWrapText(true));
    });
    if (real.length > 12) findings.addWidget(CardService.newTextParagraph().setText('+ ' + (real.length - 12) + ' more findings'));
    builder.addSection(findings);

    const infos = (r.findings || []).filter(function (f) { return f.severity === 'info'; });
    if (infos.length || r.incomplete) {
      const notes = CardService.newCardSection().setHeader('Notes').setCollapsible(true).setNumUncollapsibleWidgets(0);
      infos.forEach(function (f) { notes.addWidget(CardService.newTextParagraph().setText(UI.esc(f.title + (f.detail ? ': ' + f.detail : '')))); });
      if (r.incomplete) notes.addWidget(CardService.newTextParagraph().setText('<b>Not checked:</b> ' + UI.esc(r.skipped.join('; '))));
      builder.addSection(notes);
    }

    const domain = r.from && r.from.domain;
    const actions = CardService.newCardSection().setHeader('Actions');
    const row = CardService.newButtonSet();
    if (!r.deep) row.addButton(CardService.newTextButton().setText('Deep scan').setOnClickAction(UI.action('handleDeepScan', { messageId: messageId })));
    row.addButton(CardService.newTextButton().setText('Neutralize').setOnClickAction(UI.action('handleNeutralize', { messageId: messageId })));
    row.addButton(CardService.newTextButton().setText('Report').setOnClickAction(UI.action('handleReportPhishing', { messageId: messageId })));
    actions.addWidget(row);
    if (domain) {
      actions.addWidget(CardService.newButtonSet()
        .addButton(CardService.newTextButton().setText('Trust ' + domain).setOnClickAction(UI.action('handleTrustSender', { domain: domain })))
        .addButton(CardService.newTextButton().setText('Block').setOnClickAction(UI.action('handleBlockSender', { domain: domain }))));
    }
    actions.addWidget(CardService.newTextButton().setText('Settings').setOnClickAction(UI.action('handleOpenSettings')));
    builder.addSection(actions);
    return builder.build();
  },

  settingsCard: function () {
    const s = Settings.load();
    const sec = CardService.newCardSection()
      .addWidget(CardService.newTextInput().setFieldName('internalDomain').setTitle('Your own domain (for internal impersonation checks)').setValue(s.internalDomain))
      .addWidget(CardService.newTextInput().setFieldName('vipNames').setTitle('VIP names, comma separated').setValue(s.vipNames.join(', ')))
      .addWidget(CardService.newTextInput().setFieldName('allowDomains').setTitle('Trusted domains').setValue(s.allowDomains.join(', ')))
      .addWidget(CardService.newTextInput().setFieldName('denyDomains').setTitle('Blocked domains').setValue(s.denyDomains.join(', ')))
      .addWidget(CardService.newTextButton().setText('Save').setOnClickAction(UI.action('handleSaveSettings')))
      .addWidget(CardService.newTextParagraph().setText('Optional API keys (Safe Browsing, VirusTotal) are set in the Apps Script project under Project Settings > Script properties.'));
    return CardService.newCardBuilder()
      .setHeader(CardService.newCardHeader().setTitle('Settings'))
      .addSection(sec).build();
  }
};
