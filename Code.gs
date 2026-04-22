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
  const body = message.getPlainBody();
  const htmlBody = message.getBody();
  const from = message.getFrom();
  const attachments = message.getAttachments();

  // 1. URL Analysis
  const htmlLinks = extractHtmlLinks(htmlBody);
  const plainUrls = extractUrls(body);
  const allUrls = [...new Set([...plainUrls, ...htmlLinks.map(l => l.url)])];
  const warnings = [];

  // Check for link text mismatches
  htmlLinks.forEach(link => {
    if (isLinkTextMismatch(link.text, link.url)) {
      warnings.push(`Link text mismatch: Visible text says "${link.text}" but leads to ${link.url}`);
    }
  });

  // Unshorten and check for homographs
  const expandedUrls = allUrls.map(url => {
    const unmasked = unshortenUrl(url);
    if (isHomograph(unmasked)) {
      warnings.push(`Potential homograph attack detected: ${unmasked}`);
    }
    return unmasked;
  });

  // Safe Browsing check
  const sbResults = checkSafeBrowsing(expandedUrls);
  if (sbResults.matches) {
    sbResults.matches.forEach(match => {
      warnings.push(`Malicious URL detected by Safe Browsing: ${match.threat.url}`);
    });
  }

  // 2. Header Verification
  const rawHeaders = message.getRawContent();
  const authResultsMatch = rawHeaders.match(/Authentication-Results: ([\s\S]+?)(?:\r?\n\w+:|$)/);
  const authHeader = authResultsMatch ? authResultsMatch[1] : '';
  const authStatus = parseAuthHeaders(authHeader);

  if (authStatus.dmarc === 'fail') {
    warnings.push('DMARC authentication failed. This email may be spoofed.');
  }

  // 3. Sender Verification
  const senderVerified = verifySender(from);
  if (!senderVerified) {
    warnings.push('The "From" display name does not match the actual sender address.');
  }

  // 4. Attachment Analysis
  const attachmentWarnings = analyzeAttachments(attachments);
  warnings.push(...attachmentWarnings);

  const scanData = {
    urls: expandedUrls,
    auth: authStatus,
    senderVerified: senderVerified,
    attachmentsCount: attachments.length,
    warnings: warnings
  };

  return [createSecurityCard(scanData)];
}
