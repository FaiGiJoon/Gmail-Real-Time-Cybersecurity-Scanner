/**
 * UI functions for the Gmail Add-on.
 */

/**
 * Builds the security card.
 * @param {Object} data Security scan data.
 * @return {GoogleAppsScript.Card_Service.Card}
 */
function createSecurityCard(data) {
  const score = calculateSecurityScore(data);
  const cardHeader = CardService.newCardHeader()
    .setTitle('Security Scan Result')
    .setSubtitle(`Security Level: ${score.level}`);

  const section = CardService.newCardSection();

  // Security Score Indicator
  const scoreIcon = getScoreIcon(score.level);
  section.addWidget(CardService.newDecoratedText()
    .setText(`Status: ${score.status}`)
    .setBottomLabel(`Score: ${score.points}/100`)
    .setStartIcon(CardService.newIconImage().setIconUrl(scoreIcon)));

  // Warnings / Security Details
  if (data.warnings && data.warnings.length > 0) {
    const warningText = data.warnings.map(w => `• ${w}`).join('\n');
    section.addWidget(CardService.newTextParagraph().setText(warningText));
  } else {
    section.addWidget(CardService.newTextParagraph().setText('No immediate threats detected.'));
  }

  // Mitigation Tools
  const toolsSection = CardService.newCardSection().setHeader('Mitigation Tools');

  toolsSection.addWidget(CardService.newTextButton()
    .setText('Neutralize Threat')
    .setBackgroundColor('#d93025')
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    .setOnClickAction(CardService.newAction()
      .setFunctionName('confirmNeutralize')
      .setParameters({messageId: data.messageId})));

  if (score.level === CONSTANTS.THREAT_LEVELS.RED) {
    toolsSection.addWidget(CardService.newTextButton()
      .setText('View Sanitized Content')
      .setOnClickAction(CardService.newAction()
        .setFunctionName('viewSanitizedContent')
        .setParameters({messageId: data.messageId})));
  }

  if (!data.isDeepScan) {
    toolsSection.addWidget(CardService.newTextButton()
      .setText('Deep Scan (Unshorten URLs)')
      .setOnClickAction(CardService.newAction()
        .setFunctionName('handleDeepScan')
        .setParameters({messageId: data.messageId})));
  }

  // Details
  const detailsSection = CardService.newCardSection().setHeader('Scan Details').setCollapsible(true);
  
  detailsSection.addWidget(CardService.newDecoratedText()
    .setText('Authentication')
    .setBottomLabel(`SPF: ${data.auth.spf}, DKIM: ${data.auth.dkim}, DMARC: ${data.auth.dmarc}`));

  detailsSection.addWidget(CardService.newDecoratedText()
    .setText('Links Found')
    .setBottomLabel(`${data.urls.length} unique URLs scanned`));

  detailsSection.addWidget(CardService.newDecoratedText()
    .setText('Attachments')
    .setBottomLabel(`${data.attachmentsCount} attachments analyzed`));

  return CardService.newCardBuilder()
    .setHeader(cardHeader)
    .addSection(section)
    .addSection(toolsSection)
    .addSection(detailsSection)
    .build();
}

/**
 * Calculates a security score and level.
 * @param {Object} data
 * @return {Object} Score details.
 */
function calculateSecurityScore(data) {
  let points = 100;
  const warnings = data.warnings || [];

  if (data.auth.dmarc === 'fail') points -= 40;
  else if (data.auth.dmarc === 'none' || data.auth.dmarc === 'unknown') points -= 10;

  if (data.auth.spf === 'fail') points -= 10;
  if (data.auth.dkim === 'fail') points -= 10;

  if (!data.senderVerified) points -= 30;

  // Specific high-risk detections
  const hasPhishingLink = warnings.some(w => w.includes('Link text mismatch') || w.includes('Malicious URL') || w.includes('homograph'));
  if (hasPhishingLink) points -= 60;

  points -= (warnings.filter(w => !w.includes('Link text mismatch') && !w.includes('Malicious URL') && !w.includes('homograph')).length * 20);

  points = Math.max(0, points);

  let level = CONSTANTS.THREAT_LEVELS.GREEN;
  let status = CONSTANTS.STATUS_TEXT.SECURE;
  if (points < 40 || hasPhishingLink) {
    level = CONSTANTS.THREAT_LEVELS.RED;
    status = CONSTANTS.STATUS_TEXT.HIGH_RISK;
  } else if (points < 80) {
    level = CONSTANTS.THREAT_LEVELS.YELLOW;
    status = CONSTANTS.STATUS_TEXT.CAUTION;
  }

  return { points, level, status };
}

/**
 * Gets icon URL based on security level.
 */
function getScoreIcon(level) {
  switch (level) {
    case CONSTANTS.THREAT_LEVELS.RED: return CONSTANTS.ICONS.RED;
    case CONSTANTS.THREAT_LEVELS.YELLOW: return CONSTANTS.ICONS.YELLOW;
    default: return CONSTANTS.ICONS.GREEN;
  }
}
