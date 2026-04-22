/**
 * Helper functions for cybersecurity scanning.
 */

const SAFE_BROWSING_API_KEY = 'YOUR_SAFE_BROWSING_API_KEY'; // Placeholder

/**
 * Extracts all URLs from the email body.
 * @param {string} body The email body.
 * @return {string[]} Array of extracted URLs.
 */
function extractUrls(body) {
  const urlRegex = /https?:\/\/[^\s<"']+/g;
  const urls = body.match(urlRegex) || [];
  return [...new Set(urls)]; // Deduplicate
}

/**
 * Extracts links and their display text from HTML body.
 * @param {string} html The HTML email body.
 * @return {Object[]} Array of {url: string, text: string}
 */
function extractHtmlLinks(html) {
  const links = [];
  const linkRegex = /<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1[^>]*?>(.*?)<\/a>/gi;
  let match;
  while ((match = linkRegex.exec(html)) !== null) {
    links.push({
      url: match[2],
      text: match[3].replace(/<[^>]*>?/gm, '').trim() // Strip nested HTML from text
    });
  }
  return links;
}

/**
 * Checks if the visible text of a link matches the actual URL domain.
 * @param {string} text Visible text.
 * @param {string} url Actual URL.
 * @return {boolean} True if they appear to mismatch suspiciously.
 */
function isLinkTextMismatch(text, url) {
  const urlInTextMatch = text.match(/https?:\/\/([^\s/]+)|[a-z0-9.-]+\.[a-z]{2,}/i);
  if (!urlInTextMatch) return false;

  try {
    const textDomain = urlInTextMatch[0].includes('://') ? new URL(urlInTextMatch[0]).hostname : urlInTextMatch[0];
    const actualDomain = new URL(url).hostname;
    
    // Normalize and compare
    return !actualDomain.endsWith(textDomain.replace('www.', ''));
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
 * @param {string[]} urls Array of URLs.
 * @return {Object} Results from Safe Browsing.
 */
function checkSafeBrowsing(urls) {
  if (!urls || urls.length === 0) return {};
  if (SAFE_BROWSING_API_KEY === 'YOUR_SAFE_BROWSING_API_KEY') {
    console.warn('Safe Browsing API Key not configured.');
    return {};
  }

  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`;
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
 * Unmasks shortened URLs.
 * @param {string} url The URL to unmask.
 * @return {string} The final destination URL.
 */
function unshortenUrl(url) {
  const shorteners = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd', 'buff.ly', 'ow.ly'];
  try {
    const hostname = new URL(url).hostname;
    if (!shorteners.some(s => hostname.includes(s))) {
      return url;
    }

    const response = UrlFetchApp.fetch(url, {
      followRedirects: false,
      muteHttpExceptions: true
    });
    const location = response.getHeaders()['Location'];
    return location || url;
  } catch (e) {
    return url;
  }
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
