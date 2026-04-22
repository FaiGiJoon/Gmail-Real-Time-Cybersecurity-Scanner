/**
 * Main entry point for the Gmail Add-on.
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
  const originalUrls = [...new Set([...plainUrls, ...htmlLinks.map(l => l.url)])];

  let urlsToScan = originalUrls;
  if (isDeepScan) {
    urlsToScan = originalUrls.map(url => unshortenUrl(url));
  }

  const warnings = [];

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
      warnings.push(`${prefix}Malicious URL detected by Safe Browsing: ${match.threat.url}`);
    });
  }

  // Homograph Detection
  urlsToScan.forEach(url => {
    if (isHomograph(url)) {
      const prefix = isDeepScan ? "(Deep Scan) " : "";
      warnings.push(`${prefix}Potential homograph attack detected: ${url}`);
    }
  });

  // Header Verification
  const rawHeaders = message.getRawContent();
  const authResultsMatch = rawHeaders.match(/Authentication-Results: ([\s\S]+?)(?:\r?\n\w+:|$)/);
  const authHeader = authResultsMatch ? authResultsMatch[1] : '';
  const authStatus = parseAuthHeaders(authHeader);

  if (authStatus.dmarc === 'fail') {
    warnings.push('DMARC authentication failed. This email may be spoofed.');
  }

  // Sender Verification
  const senderVerified = verifySender(from);
  if (!senderVerified) {
    warnings.push('The "From" display name does not match the actual sender address.');
  }

  // Attachment Analysis
  const attachmentWarnings = analyzeAttachments(attachments);
  warnings.push(...attachmentWarnings);

  return {
    messageId: messageId,
    urls: urlsToScan,
    auth: authStatus,
    senderVerified: senderVerified,
    attachmentsCount: attachments.length,
    warnings: [...new Set(warnings)],
    isDeepScan: isDeepScan
  };
}

/**
 * Handles the "Neutralize & Report" workflow.
 * @param {Object} e The event object.
 */
function handleNeutralize(e) {
  const messageId = e.parameters.messageId;
  const message = GmailApp.getMessageById(messageId);
  message.moveToSpam();
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
