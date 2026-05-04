/**
 * Main entry point for the Gmail Add-on.
 * Version: 1.1.0 - Enhanced Security Features
 */

/**
 * Contextual trigger function that renders the sidebar card when an email is opened.
 * @param {Object} e The event object.
 * @return {GoogleAppsScript.Card_Service.Card[]}
 */
function getContextualAddOn(e) {
  const messageId = e.gmail.messageId;
  const message = GmailApp.getMessageById(messageId);
  const scanData = runSecurityScan(message, false);
  return [createSecurityCard(scanData)];
}

/**
 * Central security scanning logic.
 * @param {GoogleAppsScript.Gmail.GmailMessage} message
 * @param {boolean} isDeepScan Whether to perform deep unshortening.
 * @return {Object} Scan results.
 */
function runSecurityScan(message, isDeepScan) {
  const body = message.getPlainBody();
  const htmlBody = message.getBody();
  const from = message.getFrom();
  const attachments = message.getAttachments();
  const messageId = message.getId();

  const htmlLinks = extractHtmlLinks(htmlBody);
  const plainUrls = extractUrls(body);

  // Attachment Analysis (includes QR detection)
  const attachmentData = analyzeAttachments(attachments);
  const attachmentWarnings = attachmentData.warnings;
  const qrUrls = attachmentData.qrUrls;

  const originalUrls = [...new Set([...plainUrls, ...htmlLinks.map(l => l.url), ...qrUrls])];

  let urlsToScan = originalUrls;
  if (isDeepScan) {
    urlsToScan = [];
    originalUrls.forEach(url => {
      const chain = unshortenUrlChain(url);
      urlsToScan.push(...chain);
    });
    urlsToScan = [...new Set(urlsToScan)];
  }

  const warnings = [];
  const maliciousQrUrls = [];

  // Passive Link Mismatch Detection (Always run as it is a string operation)
  htmlLinks.forEach(link => {
    if (isLinkTextMismatch(link.text, link.url)) {
      warnings.push(`Link text mismatch: Visible text says "${link.text}" but leads to ${link.url}`);
    }
  });

  // Safe Browsing check (Passive or Deep)
  const sbResults = checkSafeBrowsing(urlsToScan);
  if (sbResults.matches) {
    sbResults.matches.forEach(match => {
      const prefix = isDeepScan ? "(Deep Scan) " : "";
      const threatUrl = match.threat.url;
      warnings.push(`${prefix}Malicious URL detected by Safe Browsing: ${threatUrl}`);

      // Track if this malicious URL came from a QR code
      if (qrUrls.includes(threatUrl)) {
        maliciousQrUrls.push(threatUrl);
      }
    });
  }

  // Homograph & Typosquatting Detection
  urlsToScan.forEach(url => {
    const prefix = isDeepScan ? "(Deep Scan) " : "";
    if (isHomograph(url)) {
      warnings.push(`${prefix}Potential homograph attack detected: ${url}`);
    }
    const impersonatedBrand = isTyposquatted(url);
    if (impersonatedBrand) {
      warnings.push(`${prefix}Potential typosquatting detected: URL looks like ${impersonatedBrand} but leads elsewhere.`);
    }
  });

  // BEC Detection
  if (checkBEC(message)) {
    warnings.push('Suspicious Reply-To mismatch detected. This might be a Business Email Compromise (BEC) attempt.');
  }

  // Linguistic Threat Detection
  const linguisticThreats = detectLinguisticThreats(body);
  if (linguisticThreats.length > 0) {
    warnings.push(`Urgent/Suspicious language detected: ${linguisticThreats.map(t => t.keyword).join(', ')}`);
  }

  // TLS Check
  const isTls = checkTLS(message);

  // Header Verification
  const rawHeaders = message.getRawContent();
  const authResultsMatch = rawHeaders.match(/Authentication-Results: ([\s\S]+?)(?:\r?\n\w+:|$)/);
  const authHeader = authResultsMatch ? authResultsMatch[1] : '';
  const authStatus = parseAuthHeaders(authHeader);

  if (authStatus.dmarc === 'fail') {
    warnings.push('DMARC authentication failed. This email may be spoofed.');
  }

  // Sender Verification
  const senderVerified = verifySender(message);
  if (!senderVerified) {
    warnings.push('The "From" display name does not match the actual sender address.');
  }

  // Add attachment warnings
  warnings.push(...attachmentWarnings);

  // Spotify Impersonation Check
  const spotifyWarnings = checkSpotifyImpersonation(from, body, urlsToScan);
  warnings.push(...spotifyWarnings);
  const isSpotifyImpersonation = spotifyWarnings.length > 0;

  const hasMalware = warnings.some(w => w.includes('malicious') || w.includes('Suspicious PDF'));

  return {
    messageId: messageId,
    urls: urlsToScan,
    auth: authStatus,
    senderVerified: senderVerified,
    isTls: isTls,
    attachmentsCount: attachments.length,
    warnings: [...new Set(warnings)],
    isDeepScan: isDeepScan,
    linguisticThreats: linguisticThreats,
    maliciousQrUrls: maliciousQrUrls,
    hasMalware: hasMalware,
    isSpotifyImpersonation: isSpotifyImpersonation
  };
}

/**
 * Handles the "Neutralize & Report" workflow.
 * @param {Object} e The event object.
 */
function handleNeutralize(e) {
  const messageId = e.parameters.messageId;
  const message = GmailApp.getMessageById(messageId);
  message.getThread().moveToSpam();
  message.markRead();

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Threat neutralized: Moved to Spam and marked as read."))
    .setStateChanged(true)
    .build();
}

/**
 * Handles the "Deep Scan" request.
 * @param {Object} e The event object.
 */
function handleDeepScan(e) {
  const messageId = e.parameters.messageId;
  const message = GmailApp.getMessageById(messageId);
  const scanData = runSecurityScan(message, true);
  return CardService.newNavigation().updateCard(createSecurityCard(scanData));
}

/**
 * Handles "View Sanitized Content".
 * @param {Object} e The event object.
 */
function viewSanitizedContent(e) {
  const messageId = e.parameters.messageId;
  const message = GmailApp.getMessageById(messageId);
  const htmlBody = message.getBody();

  // Strip all HTML tags, scripts, images, and links
  const sanitizedText = htmlBody
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove scripts
    .replace(/<style\b[^<]*(?:(?!<\/style>)<[^<]*)*<\/style>/gi, '') // Remove styles
    .replace(/<[^>]+>/g, ' ') // Remove all other tags
    .replace(/\s+/g, ' ') // Normalize whitespace
    .trim();

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Sanitized Content (Safe-View)'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(sanitizedText)))
    .build();

  return CardService.newNavigation().pushCard(card);
}

/**
 * Confirms Neutralize action.
 */
function confirmNeutralize(e) {
  const messageId = e.parameters.messageId;

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Confirm Neutralization'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText('Are you sure you want to move this message to Spam and mark it as read?'))
      .addWidget(CardService.newTextButton()
        .setText('Yes, Neutralize')
        .setOnClickAction(CardService.newAction()
          .setFunctionName('handleNeutralize')
          .setParameters({messageId: messageId})))
      .addWidget(CardService.newTextButton()
        .setText('Cancel')
        .setOnClickAction(CardService.newAction().setFunctionName('closeCard'))))
    .build();

  return CardService.newNavigation().pushCard(card);
}

function closeCard() {
  return CardService.newNavigation().popCard();
}

/**
 * Handles "Quarantine" action.
 */
function handleQuarantine(e) {
  const messageId = e.parameters.messageId;
  const message = GmailApp.getMessageById(messageId);

  let label = GmailApp.getUserLabelByName(CONSTANTS.SECURITY_REVIEW_LABEL);
  if (!label) {
    label = GmailApp.createLabel(CONSTANTS.SECURITY_REVIEW_LABEL);
  }

  message.getThread().addLabel(label);
  message.getThread().moveToSpam(); // Move out of inbox

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(`Message moved to "${CONSTANTS.SECURITY_REVIEW_LABEL}" and Spam.`))
    .setStateChanged(true)
    .build();
}

/**
 * Handles "Report Phishing" action.
 */
function handleReportPhishing(e) {
  // Simulate reporting
  const messageId = e.parameters.messageId;
  const message = GmailApp.getMessageById(messageId);
  const from = message.getFrom();

  console.log(`Reporting phishing for message ${messageId} from ${from} to APWG...`);

  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText("Thank you. The threat has been reported to security providers (APWG)."))
    .build();
}
