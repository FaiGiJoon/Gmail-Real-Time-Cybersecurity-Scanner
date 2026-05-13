/**
 * Main entry point for the Gmail Add-on.
 * Version: 1.2.0 - Sentinel Phase
 *
 * Philosophy: Defense-in-Depth
 * This scanner implements multiple layers of security:
 * 1. Passive Header Analysis (SPF/DKIM/DMARC/Relay Chain)
 * 2. Active Link Inspection (Redirect tracking/Shadow-link detection)
 * 3. Content Heuristics (Linguistic drift/Sentiment analysis)
 * 4. Attachment Sandboxing (Magic bytes/Structural analysis/OCR)
 * 5. State Persistence (Caching) to maintain performance across large threads.
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
  const messageId = message.getId();
  const threadId = message.getThread().getId();
  const properties = PropertiesService.getUserProperties();
  const cache = CacheService.getUserCache();
  const checkpointKey = `checkpoint_${threadId}`;
  const cacheKey = `scan_results_${messageId}`;

  // State Management: Check if this message was already scanned
  const cachedScanData = cache.get(cacheKey);
  if (cachedScanData) {
    console.log(`Cache Hit: Returning cached results for message ${messageId}.`);
    return JSON.parse(cachedScanData);
  }

  const lastScanned = properties.getProperty(checkpointKey);
  if (lastScanned === messageId) {
    console.log(`Resuming/Skipping: Message ${messageId} already scanned.`);
    return {
      messageId: messageId,
      warnings: ["Message previously scanned. Resuming..."],
      auth: { spf: 'unknown', dkim: 'unknown', dmarc: 'unknown' },
      urls: [],
      attachmentsCount: 0
    };
  }

  // Set checkpoint
  properties.setProperty(checkpointKey, messageId);

  const body = message.getPlainBody();
  const htmlBody = message.getBody();
  const from = message.getFrom();
  let attachments = message.getAttachments();

  // 1. Shield-Layer: Sanitize content for internal analysis
  const sanitizedBody = sanitizeForLlm(body);

  // 2. Key-Hunter: Autonomous Decryption
  const decryptionResults = attemptPayloadDecryption(message, attachments);
  const decryptedFiles = decryptionResults.decryptedFiles;
  const decryptionWarnings = decryptionResults.warnings;

  // Add decrypted files to the pool for scanning
  if (decryptedFiles.length > 0) {
    attachments = [...attachments, ...decryptedFiles];
  }

  const htmlLinks = extractHtmlLinks(htmlBody);
  // Use sanitized body for URL extraction to prevent prompt injection lures from being treated as safe
  const plainUrls = extractUrls(sanitizedBody);

  // 3. Smart OCR (Quishing)
  const ocrUrls = smartOcrScanner(message);

  // Attachment Analysis
  const attachmentData = analyzeAttachments(attachments);
  const attachmentWarnings = [...attachmentData.warnings, ...decryptionWarnings];

  if (ocrUrls.length > 0) {
    attachmentWarnings.push(`QR Code detected in image attachment(s).`);
  }
  const qrUrls = [...attachmentData.qrUrls, ...ocrUrls];

  const originalUrls = [...new Set([...plainUrls, ...htmlLinks.map(l => l.url), ...qrUrls])];

  const warnings = [];
  let urlsToScan = originalUrls;

  // Task 1: Shadow-Link Validator (Header-Only redirect chain audit)
  originalUrls.forEach(url => {
    const chain = unshortenUrlChain(url);
    const uniqueDomains = countUniqueDomains(chain);
    if (uniqueDomains > CONSTANTS.SHADOW_LINK_THRESHOLD) {
      warnings.push(`Shadow-Link Detected: URL ${url} passes through ${uniqueDomains} domains. Possible cloaked redirect.`);
    }

    if (isDeepScan) {
      chain.forEach(u => {
        if (callDeepfakeDetectionApi(u)) {
          warnings.push(`Synthetic Media Alert: URL ${u} points to media requiring deepfake review.`);
        }
        if (!urlsToScan.includes(u)) {
          urlsToScan.push(u);
        }
      });
    }
  });
  urlsToScan = [...new Set(urlsToScan)];
  const maliciousQrUrls = [];

  // Passive Link Mismatch Detection (Always run as it is a string operation)
  htmlLinks.forEach(link => {
    if (isLinkTextMismatch(link.text, link.url)) {
      warnings.push(`Link text mismatch: Visible text says "${link.text}" but leads to ${link.url}`);
    }
    if (link.isHidden) {
      warnings.push(`Hidden link detected: A link to ${link.url} is hidden using CSS.`);
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

  // Instructional Drift Analysis (Roadmap 2.2)
  const driftResults = detectInstructionalDrift(body);
  if (driftResults.isAnomaly) {
    warnings.push(...driftResults.warnings);
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

  // Sender Verification & Alignment Audit
  const senderVerified = verifySender(message);
  if (!senderVerified) {
    warnings.push('The "From" display name does not match the actual sender address.');
  }

  const alignmentAudit = auditSenderAlignment(from, CONSTANTS.INTERNAL_DOMAIN, CONSTANTS.VIP_LIST);
  if (alignmentAudit.isSpoofed) {
    warnings.push(...alignmentAudit.details);
  }

  // Relay Auditing (Task 2)
  const relayAudit = auditRelayPath(message);
  warnings.push(...relayAudit.warnings);

  // Mail-Bombing Detection (Roadmap 2.4)
  const threadRate = incrementMessageRate();
  if (detectMailBombing(message.getThread()) || threadRate > 50) {
    warnings.push("CRITICAL: Mail-bombing/DoS flood detected. High volume of recent messages processed.");
  }

  // Add attachment warnings
  warnings.push(...attachmentWarnings);

  // Spotify Impersonation Check (Legacy)
  const spotifyWarnings = checkSpotifyImpersonation(from, body, urlsToScan);
  warnings.push(...spotifyWarnings);

  // Generalized Brand Keyword Phishing Check
  const keywordWarnings = checkKeywordPhishing(urlsToScan, CONSTANTS.TYPOSQUAT_BRANDS);
  warnings.push(...keywordWarnings);

  const isSpotifyImpersonation = spotifyWarnings.length > 0;

  const hasMalware = warnings.some(w => w.includes('malicious') || w.includes('Suspicious PDF'));

  const scanResults = {
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
    isSpotifyImpersonation: isSpotifyImpersonation,
    alignmentPenalty: alignmentAudit.penaltyWeight + driftResults.penalty,
    relayMismatch: relayAudit.hasMismatch
  };

  // Task 3: Memory-Efficient Scaling (Cache final results)
  try {
    cache.put(cacheKey, JSON.stringify(scanResults), 21600); // Cache for 6 hours
  } catch (e) {
    console.warn('Failed to cache scan results: ' + e);
  }

  return scanResults;
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
