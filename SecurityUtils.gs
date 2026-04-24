/**
 * Helper functions for cybersecurity scanning.
 * Version: 1.1.0 - Enhanced Security Features
 */

/**
 * Extracts all URLs from the email body.
 * @param {string} body The email body.
 * @return {string[]} Array of extracted URLs.
 */
function extractUrls(body) {
  const urls = body.match(CONSTANTS.URL_REGEX) || [];
  return [...new Set(urls)]; // Deduplicate
}

/**
 * Extracts links and their display text from HTML body.
 * @param {string} html The HTML email body.
 * @return {Object[]} Array of {url: string, text: string}
 */
function extractHtmlLinks(html) {
  const links = [];
  let match;
  while ((match = CONSTANTS.LINK_REGEX.exec(html)) !== null) {
    links.push({
      url: match[2],
      text: match[3].replace(/<[^>]*>?/gm, '').trim() // Strip nested HTML from text
    });
  }
  // Reset regex state since it's global
  CONSTANTS.LINK_REGEX.lastIndex = 0;
  return links;
}

/**
 * Checks if the visible text of a link matches the actual URL domain.
 * @param {string} text Visible text.
 * @param {string} url Actual URL.
 * @return {boolean} True if they appear to mismatch suspiciously.
 */
function isLinkTextMismatch(text, url) {
  // Look for anything that looks like a domain or URL in the text
  const domainRegex = /(?:https?:\/\/)?(?:www\.)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i;
  const urlInTextMatch = text.match(domainRegex);
  if (!urlInTextMatch) return false;

  try {
    const textDomain = urlInTextMatch[1].toLowerCase();
    const actualDomainMatch = url.match(domainRegex);
    if (!actualDomainMatch) return false;

    const actualDomain = actualDomainMatch[1].toLowerCase();
    
    // Check for exact match or proper subdomain
    if (actualDomain === textDomain) return false;
    if (actualDomain.endsWith('.' + textDomain)) return false;
    if (textDomain.endsWith('.' + actualDomain)) return false;

    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Checks for homograph attacks (IDN/Punycode).
 * @param {string} url The URL to check.
 * @return {boolean} True if a homograph attack is suspected.
 */
function isHomograph(url) {
  try {
    const domain = new URL(url).hostname;
    return domain.startsWith('xn--');
  } catch (e) {
    return false;
  }
}

/**
 * Checks URLs against Google Safe Browsing API.
 * Performs a passive lookup without following redirects.
 * @param {string[]} urls Array of URLs.
 * @return {Object} Results from Safe Browsing.
 */
function checkSafeBrowsing(urls) {
  if (!urls || urls.length === 0) return {};

  let apiKey = CONSTANTS.SAFE_BROWSING_API_KEY;
  // Try to get from Script Properties if placeholder is still there
  if (apiKey === 'YOUR_SAFE_BROWSING_API_KEY') {
    apiKey = PropertiesService.getScriptProperties().getProperty('SAFE_BROWSING_API_KEY');
  }

  if (!apiKey) {
    console.warn('Safe Browsing API Key not configured.');
    return {};
  }

  const endpoint = `${CONSTANTS.SAFE_BROWSING_ENDPOINT}?key=${apiKey}`;
  const payload = {
    client: {
      clientId: "cybersecurity-scanner-addon",
      clientVersion: "1.0.0"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: urls.map(url => ({ url: url }))
    }
  };

  const options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  try {
    const response = UrlFetchApp.fetch(endpoint, options);
    return JSON.parse(response.getContentText());
  } catch (e) {
    console.error('Error calling Safe Browsing API: ' + e);
    return {};
  }
}

/**
 * Unmasks shortened URLs recursively using a loop.
 * @param {string} url The URL to unmask.
 * @return {string[]} All URLs in the redirect chain.
 */
function unshortenUrlChain(url) {
  const chain = [url];
  let currentUrl = url;
  let depth = 0;
  const maxDepth = 5;

  while (depth < maxDepth) {
    try {
      const response = UrlFetchApp.fetch(currentUrl, {
        followRedirects: false,
        muteHttpExceptions: true
      });
      const location = response.getHeaders()['Location'];

      if (location && location !== currentUrl && !chain.includes(location)) {
        currentUrl = location;
        chain.push(currentUrl);
        depth++;
      } else {
        break;
      }
    } catch (e) {
      break;
    }
  }
  return chain;
}

/**
 * Checks for typosquatting by comparing against known brands.
 * @param {string} url The URL to check.
 * @return {string|null} The brand being impersonated, or null.
 */
function isTyposquatted(url) {
  try {
    const domain = new URL(url).hostname.toLowerCase();
    // Simplified main domain extraction (gets the part before the TLD)
    const parts = domain.split('.');
    if (parts.length < 2) return null;

    // Handle some common multi-part TLDs like .co.uk
    let mainDomain = parts[parts.length - 2];
    if (['co', 'com', 'org', 'net', 'edu', 'gov'].includes(mainDomain) && parts.length > 2) {
      mainDomain = parts[parts.length - 3];
    }

    for (const brand of CONSTANTS.TYPOSQUAT_BRANDS) {
      if (mainDomain === brand) continue;

      const distance = levenshteinDistance(mainDomain, brand);
      // If distance is small (1 or 2 edits), it might be typosquatted
      if (distance > 0 && distance <= 2) {
        return brand;
      }
    }
  } catch (e) {}
  return null;
}

/**
 * Levenshtein distance algorithm.
 */
function levenshteinDistance(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) matrix[i] = [i];
  for (let j = 0; j <= a.length; j++) matrix[0][j] = j;

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Checks for BEC by comparing From and Reply-To headers.
 * @param {GoogleAppsScript.Gmail.GmailMessage} message
 * @return {boolean} True if suspicious.
 */
function checkBEC(message) {
  const from = message.getFrom();
  const replyTo = message.getReplyTo();

  if (!replyTo || from === replyTo) return false;

  const getDomain = (email) => {
    const match = email.match(/<(.+)>|([^\s]+@[^\s]+)/);
    const addr = match ? (match[1] || match[2]) : email;
    return addr.split('@').pop().toLowerCase();
  };

  const fromDomain = getDomain(from);
  const replyToDomain = getDomain(replyTo);

  return fromDomain !== replyToDomain;
}

/**
 * Detects linguistic threats in message body.
 * @param {string} body
 * @return {string[]} Detected keywords.
 */
function detectLinguisticThreats(body) {
  const lowerBody = body.toLowerCase();
  return CONSTANTS.URGENT_KEYWORDS.filter(keyword => lowerBody.includes(keyword));
}

/**
 * Checks if email was sent via TLS.
 * @param {GoogleAppsScript.Gmail.GmailMessage} message
 * @return {boolean} True if TLS was used.
 */
function checkTLS(message) {
  const raw = message.getRawContent();
  // Look for "version=TLS" or "with ESMTPS" or similar in Received headers
  const receivedHeaders = raw.match(/^Received: [\s\S]+?(?=\r?\n\w+:|$)/gm) || [];
  return receivedHeaders.some(header => /TLS|ESMTPS/i.test(header));
}

/**
 * Parses Authentication-Results header for SPF, DKIM, and DMARC.
 * @param {string} authHeader The Authentication-Results header value.
 * @return {Object} Status of SPF, DKIM, and DMARC.
 */
function parseAuthHeaders(authHeader) {
  const results = {
    spf: 'unknown',
    dkim: 'unknown',
    dmarc: 'unknown'
  };

  if (!authHeader) return results;

  const spfMatch = authHeader.match(/spf=(\w+)/);
  const dkimMatch = authHeader.match(/dkim=(\w+)/);
  const dmarcMatch = authHeader.match(/dmarc=(\w+)/);

  if (spfMatch) results.spf = spfMatch[1];
  if (dkimMatch) results.dkim = dkimMatch[1];
  if (dmarcMatch) results.dmarc = dmarcMatch[1];

  return results;
}

/**
 * Verifies if the From display name matches the sender address.
 * @param {string} fromHeader The full From header (e.g. "Name <email@example.com>").
 * @return {boolean} True if they appear to match or if no display name is present.
 */
function verifySender(fromHeader) {
  if (!fromHeader) return true;
  
  // Extract name and email: "Display Name" <email@example.com> or email@example.com
  let displayName = '';
  let email = '';

  const match = fromHeader.match(/^(?:"?([^"]*)"?\s)?(?:<(.+)>)$/);
  if (match) {
    displayName = match[1] ? match[1].trim().toLowerCase() : '';
    email = match[2] ? match[2].trim().toLowerCase() : '';
  } else {
    // Just an email or something else
    email = fromHeader.trim().toLowerCase();
  }

  if (!displayName) return true;

  // Simple heuristic: if display name looks like an email but doesn't match the actual email
  const emailInNameMatch = displayName.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/);
  if (emailInNameMatch && emailInNameMatch[0] !== email) {
    return false;
  }

  return true;
}

/**
 * Analyzes attachments for high-risk features.
 * @param {GoogleAppsScript.Gmail.GmailAttachment[]} attachments
 * @return {Object[]} List of warnings for attachments.
 */
function analyzeAttachments(attachments) {
  const warnings = [];
  const highRiskExts = ['exe', 'scr', 'vbs', 'js', 'jar', 'bat', 'cmd', 'msi'];

  attachments.forEach(attachment => {
    const filename = attachment.getName().toLowerCase();
    const parts = filename.split('.');
    const ext = parts.pop();

    // High-risk extension
    if (highRiskExts.includes(ext)) {
      warnings.push(`High-risk file extension detected: ${filename}`);
    }

    // Double extension
    if (parts.length > 1) {
      const secondExt = parts.pop();
      const commonDocs = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt'];
      if (commonDocs.includes(secondExt) && highRiskExts.includes(ext)) {
        warnings.push(`Possible double extension attack: ${filename}`);
      }
    }

    // Encrypted ZIP check
    if (ext === 'zip') {
      try {
        Utilities.unzip(attachment);
      } catch (e) {
        if (e.message.includes('password') || e.message.includes('encrypted')) {
          warnings.push(`Encrypted ZIP file detected (often used to bypass scanners): ${filename}`);
        }
      }
    }
  });

  return warnings;
}
