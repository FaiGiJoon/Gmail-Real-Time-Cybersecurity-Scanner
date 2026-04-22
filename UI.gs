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

  // Warnings
  if (data.warnings && data.warnings.length > 0) {
    const warningText = data.warnings.map(w => `• ${w}`).join('\n');
    section.addWidget(CardService.newTextParagraph().setText(warningText));
  } else {
    section.addWidget(CardService.newTextParagraph().setText('No immediate threats detected.'));
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

  points -= (warnings.length * 20);

  points = Math.max(0, points);

  let level = 'Green';
  let status = 'Secure';
  if (points < 40) {
    level = 'Red';
    status = 'High Risk';
  } else if (points < 80) {
    level = 'Yellow';
    status = 'Caution';
  }

  return { points, level, status };
}

/**
 * Gets icon URL based on security level.
 */
function getScoreIcon(level) {
  switch (level) {
    case 'Red': return 'https://www.gstatic.com/images/icons/material/system/1x/report_problem_red_24dp.png';
    case 'Yellow': return 'https://www.gstatic.com/images/icons/material/system/1x/warning_amber_24dp.png';
    default: return 'https://www.gstatic.com/images/icons/material/system/1x/check_circle_green_24dp.png';
  }
}
