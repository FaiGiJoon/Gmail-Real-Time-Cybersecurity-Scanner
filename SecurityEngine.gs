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
    const fullTag = match[0];
    const url = match[2];
    const text = match[3].replace(/<[^>]*>?/gm, '').trim();

    // CSS-based hidden link detection
    let isHidden = false;
    if (/style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|height\s*:\s*0|width\s*:\s*0)[^"']*["']/i.test(fullTag)) {
      isHidden = true;
    }

    links.push({
      url: url,
      text: text,
      isHidden: isHidden
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
    const domain = new URL(url).hostname.toLowerCase();
    // Homograph Protection: Ensure the isHomograph function is triggered for any URL containing "spotify" to catch Punycode variants.
    if (domain.startsWith('xn--') || domain.includes('spotify')) {
      return domain.startsWith('xn--');
    }
    return false;
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

  // Security Hardening: Enforce PropertiesService for API keys
  const apiKey = PropertiesService.getScriptProperties().getProperty('SAFE_BROWSING_API_KEY');

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

      let nextUrl = response.getHeaders()['Location'];
      const content = response.getContentText();

      // 1. Meta-Refresh Detection
      if (!nextUrl) {
        const metaMatch = content.match(/<meta\s+http-equiv=["']refresh["']\s+content=["'][^"']*url=([^"']+)["']/i);
        if (metaMatch) nextUrl = metaMatch[1];
      }

      // 2. JavaScript window.location Detection
      if (!nextUrl) {
        const jsMatch = content.match(/window\.location(?:\.href)?\s*=\s*["']([^"']+)["']/i);
        if (jsMatch) nextUrl = jsMatch[1];
      }

      if (nextUrl && nextUrl !== currentUrl && !chain.includes(nextUrl)) {
        // Resolve relative URLs
        if (!nextUrl.startsWith('http')) {
          const urlObj = new URL(currentUrl);
          if (nextUrl.startsWith('/')) {
            const origin = urlObj.origin || `${urlObj.protocol}//${urlObj.host}`;
            nextUrl = `${origin}${nextUrl}`;
          } else {
            // Handle path-relative URLs
            const base = currentUrl.substring(0, currentUrl.lastIndexOf('/') + 1);
            nextUrl = base + nextUrl;
          }
        }
        currentUrl = nextUrl;
        chain.push(currentUrl);
        depth++;

        // Roadmap 2.3: Deepfake Auditor
        if (callDeepfakeDetectionApi(currentUrl)) {
          // Warning will be handled in Code.gs after chain is returned
        }
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
 * Verifies the actual file type using Magic Bytes (File Signatures).
 * @param {GoogleAppsScript.Base.Blob} blob
 * @return {string|null} The verified file type, or null if unknown.
 */
function verifyMagicBytes(blob) {
  const bytes = blob.getBytes().slice(0, 8); // Read first 8 bytes

  for (const [type, signature] of Object.entries(CONSTANTS.MAGIC_BYTES)) {
    const isMatch = signature.every((byte, i) => (bytes[i] & 0xFF) === byte);
    if (isMatch) return type;
  }

  return null;
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
 * Optimized Levenshtein distance algorithm (Wagner-Fischer with space optimization).
 * Complexity: O(min(N, M)) space.
 */
function levenshteinDistance(a, b) {
  if (a.length < b.length) [a, b] = [b, a];
  if (b.length === 0) return a.length;

  let previousRow = Array.from({ length: b.length + 1 }, (_, i) => i);
  let currentRow = new Array(b.length + 1);

  for (let i = 1; i <= a.length; i++) {
    currentRow[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      currentRow[j] = Math.min(
        currentRow[j - 1] + 1,      // insertion
        previousRow[j] + 1,         // deletion
        previousRow[j - 1] + cost   // substitution
      );
    }
    [previousRow, currentRow] = [currentRow, previousRow];
  }
  return previousRow[b.length];
}

/**
 * Decodes MIME-encoded headers (RFC 2047).
 * Supports Base64 and Quoted-Printable.
 */
function decodeMimeHeader(header) {
  if (!header) return "";
  return header.replace(/=\?([^?]+)\?([QB])\?([^?]+)\?=/gi, (match, charset, encoding, text) => {
    if (encoding.toUpperCase() === 'B') {
      try {
        const decoded = Utilities.newBlob(Utilities.base64Decode(text, Utilities.Charset.UTF_8)).getDataAsString();
        return decoded;
      } catch (e) {
        return text;
      }
    } else if (encoding.toUpperCase() === 'Q') {
      const bytes = [];
      const qText = text.replace(/_/g, ' ');
      for (let i = 0; i < qText.length; i++) {
        if (qText[i] === '=' && i + 2 < qText.length) {
          const hex = qText.substring(i + 1, i + 3);
          bytes.push(parseInt(hex, 16));
          i += 2;
        } else {
          bytes.push(qText.charCodeAt(i));
        }
      }
      return Utilities.newBlob(bytes, Utilities.Charset.UTF_8).getDataAsString();
    }
    return text;
  });
}

/**
 * Audits sender alignment for spoofing and VIP impersonation.
 * @param {string} senderHeader The raw From header.
 * @param {string} internalDomain The domain to protect.
 * @param {string[]} vipList List of VIP names.
 * @return {Object} Alignment audit results.
 */
function auditSenderAlignment(senderHeader, internalDomain, vipList) {
  const result = {
    isSpoofed: false,
    penaltyWeight: 0,
    details: []
  };

  if (!senderHeader) return result;

  const decodedHeader = decodeMimeHeader(senderHeader);

  // Extract email and display name
  const emailMatch = decodedHeader.match(/<([^>]+)>/);
  const emailAddress = emailMatch ? emailMatch[1].toLowerCase() : decodedHeader.toLowerCase().trim();
  const displayName = decodedHeader.replace(/<[^>]+>/g, "").replace(/["']/g, "").trim();
  const lowerDisplayName = displayName.toLowerCase();

  const senderDomain = emailAddress.split("@")[1] || "";
  const isInternalEmail = senderDomain === internalDomain.toLowerCase();

  // Rule 1: Internal Domain Impersonation in Display Name
  const lowerInternalDomain = internalDomain.toLowerCase();
  const domainParts = lowerInternalDomain.split('.');
  const domainName = domainParts[0]; // e.g., "spotify" from "spotify.com"

  if ((lowerDisplayName.includes(lowerInternalDomain) || lowerDisplayName.includes(domainName)) && !isInternalEmail) {
    result.isSpoofed = true;
    result.penaltyWeight += CONSTANTS.SENDER_ALIGNMENT_PENALTY;
    result.details.push("CRITICAL: Display name implies internal domain, but origin is external.");
  }

  // Rule 2: VIP Impersonation (Direct & Typosquatting)
  let vipFound = false;
  vipList.forEach(vip => {
    if (vipFound) return;
    const lowerVip = vip.toLowerCase();

    // Direct Match
    if (lowerDisplayName.includes(lowerVip) && !isInternalEmail) {
      result.isSpoofed = true;
      result.penaltyWeight += CONSTANTS.VIP_IMPERSONATION_PENALTY;
      result.details.push(`HIGH: Direct impersonation of VIP "${vip}" detected from external source.`);
      vipFound = true;
      return;
    }

    // Typosquatting Detection in Display Name
    const nameParts = lowerDisplayName.split(/\s+/);
    const vipParts = lowerVip.split(/\s+/);

    nameParts.forEach(part => {
      if (vipFound) return;
      vipParts.forEach(vPart => {
        if (vipFound) return;
        if (part !== vPart && part.length > 3 && vPart.length > 3) {
          const distance = levenshteinDistance(part, vPart);
          if (distance === 1) {
            result.isSpoofed = true;
            result.penaltyWeight += CONSTANTS.VIP_TYPOSQUAT_PENALTY;
            result.details.push(`MEDIUM: Potential typosquatting of VIP name part "${vPart}" as "${part}".`);
            vipFound = true;
          }
        }
      });
    });
  });

  return result;
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
 * Detects linguistic threats in message body with weighting.
 * @param {string} body
 * @return {Object[]} Detected threats with weights.
 */
function detectLinguisticThreats(body) {
  const lowerBody = body.toLowerCase();
  const threats = [];

  for (const keyword in CONSTANTS.LINGUISTIC_WEIGHTS) {
    if (lowerBody.includes(keyword)) {
      threats.push({
        keyword: keyword,
        weight: CONSTANTS.LINGUISTIC_WEIGHTS[keyword]
      });
    }
  }

  return threats;
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
 * Deep audit of delivery path (Reverse-Chain Relay Auditor).
 * @param {string} rawHeaders
 * @return {Object} Audit results and warnings.
 */
function auditDeliveryPath(rawHeaders) {
  const receivedHeaders = rawHeaders.match(/^Received: [\s\S]+?(?=\r?\n\w+:|$)/gm) || [];
  const warnings = [];

  // Parse in reverse order (originating MTA first)
  const reversed = [...receivedHeaders].reverse();

  reversed.forEach((header, index) => {
    const ipMatch = header.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
    if (ipMatch) {
      const ip = ipMatch[1];
      // Note: Full CIDR check would require a library or manual bitwise logic.
      // For this implementation, we check for direct string matches or simple prefix.
      const isTrusted = CONSTANTS.TRUSTED_RELAYS.some(cidr => isIpInCidr(ip, cidr));

      if (!isTrusted && index === 0) {
        warnings.push(`Suspicious Origin: Initial relay IP ${ip} is not in trusted CIDR blocks.`);
      }
    }
  });

  return {
    hopCount: receivedHeaders.length,
    warnings: warnings
  };
}

/**
 * Smart OCR with batching and filters (Cost-Optimized Quishing).
 */
function smartOcrScanner(message) {
  const attachments = message.getAttachments();
  const imageAttachments = attachments.filter(att => {
    const name = att.getName().toLowerCase();
    const isImage = /\.(png|jpg|jpeg|webp)$/.test(name);
    const isBigEnough = att.getSize() > 10240; // 10KB filter
    return isImage && isBigEnough;
  });

  if (imageAttachments.length === 0) return [];

  // Batch request
  const allUrls = batchDetectQrCodes(imageAttachments);
  return allUrls;
}

/**
 * Enhanced unshortenUrlChain logic. If a resolved URL points to an audio/video file,
 * flag it for "Synthetic Media Review" (Deepfake Auditor).
 */
function callDeepfakeDetectionApi(url) {
  const syntheticMediaExts = ['.mp3', '.mp4', '.wav', '.webm', '.ogg'];
  const isSyntheticCandidate = syntheticMediaExts.some(ext => url.toLowerCase().endsWith(ext));

  if (isSyntheticCandidate) {
     // Stub for 2026: In production, this would call a specialized detection API.
     console.log(`Deepfake Auditor: Flagging media for review: ${url}`);
     return true;
  }
  return false;
}

/**
 * Tracks message rates using CacheService (Persistent State Manager).
 */
function incrementMessageRate() {
  const cache = CacheService.getUserCache();
  const now = Math.floor(Date.now() / 600000); // 10-minute window ID
  const key = `msg_rate_${now}`;

  const lock = LockService.getUserLock();
  try {
    lock.waitLock(5000);
    let count = parseInt(cache.get(key) || "0");
    count++;
    cache.put(key, count.toString(), 1200); // Store for 20 mins
    return count;
  } catch (e) {
    return 0;
  } finally {
    lock.releaseLock();
  }
}

/**
 * Audits the delivery path via Received headers to detect anomalous relays.
 * @param {GoogleAppsScript.Gmail.GmailMessage} message
 * @return {string[]} Warnings if anomalies are found.
 */
function auditRelayPath(message) {
  const raw = message.getRawContent();
  const audit = auditDeliveryPath(raw);
  const warnings = audit.warnings;

  if (audit.hopCount > 10) {
    warnings.push(`Anomalous relay count detected (${audit.hopCount} hops). Possible mail-loop or routing manipulation.`);
  }

  const from = message.getFrom().toLowerCase();
  const isInternalSender = CONSTANTS.OFFICIAL_DOMAINS.some(domain => from.includes('@' + domain));

  if (isInternalSender) {
    const receivedHeaders = raw.match(/^Received: [\s\S]+?(?=\r?\n\w+:|$)/gm) || [];
    const firstHop = receivedHeaders[receivedHeaders.length - 1] || '';
    const isTrustedHop = CONSTANTS.OFFICIAL_DOMAINS.some(domain => firstHop.includes(domain)) || firstHop.includes('google.com');
    if (!isTrustedHop) {
       warnings.push('CRITICAL: Internal brand spoofing detected. Message claims to be internal but originated from an external relay.');
    }
  }

  return warnings;
}

/**
 * Verifies if the sender headers (From, Reply-To) match the claimed identity.
 * @param {GoogleAppsScript.Gmail.GmailMessage} message
 * @return {boolean} True if they appear to match or if no display name is present.
 */
function verifySender(message) {
  const headersToCheck = [message.getFrom(), message.getReplyTo()];
  
  for (const header of headersToCheck) {
    if (!header) continue;

    let displayName = '';
    let email = '';

    const match = header.match(/^(?:"?([^"]*)"?\s)?(?:<(.+)>)$/);
    if (match) {
      displayName = match[1] ? match[1].trim().toLowerCase() : '';
      email = match[2] ? match[2].trim().toLowerCase() : '';
    } else {
      email = header.trim().toLowerCase();
    }

    if (!displayName) continue;

    // Heuristic: if display name looks like an email but doesn't match the actual email
    const emailInNameMatch = displayName.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/);
    if (emailInNameMatch && emailInNameMatch[0] !== email) {
      return false;
    }

    // Spotify-specific check
    if (displayName.includes('spotify')) {
      const isLegitDomain = email.endsWith('@spotify.com') ||
                            email.endsWith('@news.spotify.com') ||
                            email.endsWith('@support.spotify.com');
      if (!isLegitDomain) {
        return false;
      }
    }
  }

  return true;
}

/**
 * Analyzes attachments for high-risk features and QR codes.
 * @param {GoogleAppsScript.Gmail.GmailAttachment[]} attachments
 * @return {Object} Warnings and extracted URLs from QR codes.
 */
function analyzeAttachments(attachments) {
  const warnings = [];
  const qrUrls = [];
  const highRiskExts = ['exe', 'scr', 'vbs', 'js', 'jar', 'bat', 'cmd', 'msi'];
  const imageExts = ['png', 'jpg', 'jpeg', 'webp'];

  attachments.forEach(attachment => {
    const filename = attachment.getName().toLowerCase();
    const parts = filename.split('.');
    const ext = parts.pop();

    // High-risk extension
    if (highRiskExts.includes(ext)) {
      warnings.push(`High-risk file extension detected: ${filename}`);
    }

    // Double extension & Magic Byte Verification
    if (parts.length > 1) {
      const secondExt = parts.pop();
      const commonDocs = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt'];
      if (commonDocs.includes(secondExt) && highRiskExts.includes(ext)) {
        warnings.push(`Possible double extension attack: ${filename}`);
      }
    }

    const verifiedType = verifyMagicBytes(attachment);
    if (verifiedType && verifiedType !== ext.toUpperCase()) {
      if (!(verifiedType === 'ZIP' && ext === 'jar')) { // Allow jar as zip
        warnings.push(`File Signature Mismatch: ${filename} claims to be .${ext} but is actually a ${verifiedType} file.`);
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

    // Malware Reputation Check (VirusTotal)
    const hash = calculateHash(attachment);
    const vtWarning = checkVirusTotal(hash, filename);
    if (vtWarning) warnings.push(vtWarning);

    // PDF Structural Analysis
    if (ext === 'pdf') {
      const pdfWarnings = scanPdfStructure(attachment);
      warnings.push(...pdfWarnings);
    }

  });

  return { warnings, qrUrls: [...new Set(qrUrls)] };
}

/**
 * Calls Google Cloud Vision API to detect QR codes in an image blob.
 * @param {GoogleAppsScript.Base.Blob} blob
 * @return {string[]} Extracted URLs.
 */
function detectQrCodes(blob) {
  // Use batchDetectQrCodes for efficient processing.
  // This function is kept for backward compatibility and single-blob use.
  return batchDetectQrCodes([blob]);
}

/**
 * Calls Google Cloud Vision API to detect QR codes in multiple images using a batch request.
 * @param {GoogleAppsScript.Base.Blob[]} blobs
 * @return {string[]} Extracted URLs.
 */
function batchDetectQrCodes(blobs) {
  const apiKey = PropertiesService.getScriptProperties().getProperty('CLOUD_VISION_API_KEY');
  if (!apiKey) {
    console.warn('Cloud Vision API Key not configured.');
    return [];
  }

  const requests = blobs.map(blob => ({
    image: { content: Utilities.base64Encode(blob.getBytes()) },
    features: [{ type: 'BARCODE_DETECTION' }, { type: 'DOCUMENT_TEXT_DETECTION' }]
  }));

  const endpoint = `${CONSTANTS.CLOUD_VISION_ENDPOINT}?key=${apiKey}`;
  const payload = { requests: requests };

  const options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  try {
    const response = UrlFetchApp.fetch(endpoint, options);
    const result = JSON.parse(response.getContentText());
    const extractedUrls = [];

    if (result.responses) {
      result.responses.forEach(resp => {

      // Deep search for URLs in all text found by OCR
      if (resp.fullTextAnnotation && resp.fullTextAnnotation.text) {
        const text = resp.fullTextAnnotation.text;
        const matches = text.match(CONSTANTS.URL_REGEX);
        if (matches) extractedUrls.push(...matches);

        // Also check for common obfuscated patterns like "hxxp" or "[.]"
        const obfuscated = text.match(/h[x]{2}ps?:\/\/[^\s<"']+/gi);
        if (obfuscated) {
          obfuscated.forEach(u => extractedUrls.push(u.replace(/h[x]{2}p/i, 'http')));
        }

        const dotObfuscated = text.match(/https?:\/\/[^\s<"']+/gi);
        if (dotObfuscated) {
          dotObfuscated.forEach(u => {
            if (u.includes('[.]')) {
              extractedUrls.push(u.replace(/\[\.\]/g, '.'));
            }
          });
        }
      }

      // Explicit barcode detection handling
      if (resp.barcodeAnnotations) {
        resp.barcodeAnnotations.forEach(anno => {
          if (anno.rawValue) {
            const matches = anno.rawValue.match(CONSTANTS.URL_REGEX);
            if (matches) extractedUrls.push(...matches);
            else if (anno.rawValue.startsWith('http')) extractedUrls.push(anno.rawValue);
          }
        });
      }
    });
    }
    return [...new Set(extractedUrls)];
  } catch (e) {
    console.error('Error calling Cloud Vision API: ' + e);
    return [];
  }
}

/**
 * Calculates SHA-256 hash of a blob.
 */
function calculateHash(blob) {
  const bytes = blob.getBytes();
  const hash = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  let hexString = '';
  for (let i = 0; i < hash.length; i++) {
    const byte = hash[i] & 0xFF;
    if (byte < 16) hexString += '0';
    hexString += byte.toString(16);
  }
  return hexString;
}

/**
 * Queries VirusTotal for a file hash.
 */
function checkVirusTotal(hash, filename) {
  let apiKey = PropertiesService.getScriptProperties().getProperty('VIRUSTOTAL_API_KEY');
  if (!apiKey) return null;

  const url = CONSTANTS.VIRUSTOTAL_ENDPOINT + hash;
  const options = {
    headers: { 'x-apikey': apiKey },
    muteHttpExceptions: true
  };

  try {
    const response = UrlFetchApp.fetch(url, options);
    if (response.getResponseCode() === 200) {
      const data = JSON.parse(response.getContentText());
      const stats = data.data.attributes.last_analysis_stats;
      if (stats.malicious > 0) {
        return `VirusTotal alert: ${filename} flagged as malicious by ${stats.malicious} engines.`;
      }
    }
  } catch (e) {
    console.error('VT Error: ' + e);
  }
  return null;
}

/**
 * Checks if an IP address is within a CIDR range.
 * (Simplified implementation for Google Apps Script V8)
 */
function isIpInCidr(ip, cidr) {
  const [range, bits] = cidr.split('/');
  const mask = ~(Math.pow(2, 32 - parseInt(bits)) - 1);

  const ipToLong = (ipAddr) => {
    return ipAddr.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
  };

  const ipLong = ipToLong(ip);
  const rangeLong = ipToLong(range);

  return (ipLong & mask) === (rangeLong & mask);
}

/**
 * Scans PDF content for suspicious elements (e.g., /JS, /JavaScript, /OpenAction).
 */
function scanPdfStructure(blob) {
  const warnings = [];
  const content = blob.getDataAsString();
  const filename = blob.getName();

  if (/\/JS|\/JavaScript/i.test(content)) {
    warnings.push(`Suspicious PDF: ${filename} contains embedded JavaScript.`);
  }
  if (/\/OpenAction|\/AA/i.test(content)) {
    warnings.push(`Suspicious PDF: ${filename} contains auto-launch actions.`);
  }
  if (/\/EmbeddedFile/i.test(content)) {
    warnings.push(`Suspicious PDF: ${filename} contains an embedded file payload.`);
  }

  return warnings;
}

/**
 * Detects if the current thread is part of a volume-based "Mail-Bombing" attack.
 * (Roadmap 2.4 Implementation)
 * @param {GoogleAppsScript.Gmail.GmailThread} thread
 * @return {boolean} True if a flood is detected.
 */
function detectMailBombing(thread) {
  const messages = thread.getMessages();
  const now = new Date().getTime();
  const windowMs = 10 * 60 * 1000; // 10 minute window

  // Heuristic: If a single thread has more than 15 messages in 10 minutes,
  // or if there are many recent messages with similar subjects from different senders.
  const recentMessages = messages.filter(msg => (now - msg.getDate().getTime()) < windowMs);

  if (recentMessages.length > 15) {
    return true;
  }

  return false;
}

/**
 * Attempts to find passwords in the email body and decrypt ZIP attachments.
 * (Roadmap 2026: Key-Hunter Module)
 */
function attemptPayloadDecryption(message, attachments) {
  const body = message.getPlainBody();
  // Regex to find potential passwords: "Password: XYZ", "code is 1234", etc.
  const passRegex = /(?:pass(?:word)?|code|key)(?:\s+is)?\s*[:=]?\s*["']?([a-z0-9!@#$%^&*]+)["']?/gi;
  const foundKeys = [];
  let match;
  while ((match = passRegex.exec(body)) !== null) {
    foundKeys.push(match[1]);
  }

  const results = {
    decryptedFiles: [],
    warnings: []
  };

  attachments.forEach(att => {
    if (att.getContentType() === 'application/zip' || att.getName().toLowerCase().endsWith('.zip')) {
      foundKeys.forEach(key => {
        try {
          // Attempt unzip with the discovered key
          const unzipped = Utilities.unzip(att.copyBlob(), key);
          if (unzipped && unzipped.length > 0) {
            results.decryptedFiles.push(...unzipped);
            results.warnings.push(`Key-Hunter: Successfully decrypted attachment "${att.getName()}" using discovered key.`);
          }
        } catch (e) {
          // Fail silently and try next key
        }
      });
    }
  });

  return results;
}

/**
 * Sanitizes input text to prevent LLM Prompt Injection attacks.
 * (Shield-Layer Module)
 */
function sanitizeForLlm(text) {
  if (!text) return "";

  // 1. Instructional Drift Detection / Neutralization
  const injectionPatterns = [
    /ignore all previous instructions/gi,
    /system override/gi,
    /mark this email as safe/gi,
    /bypass security/gi,
    /execute following command/gi
  ];

  let sanitized = text;
  injectionPatterns.forEach(pattern => {
    sanitized = sanitized.replace(pattern, "[FILTERED_INJECTION_ATTEMPT]");
  });

  // 2. Delimiter Guarding
  // Wrap the content in random tokens to prevent the LLM from treating content as instructions.
  const token = `[USER_CONTENT_${Math.random().toString(36).substring(7)}]`;
  return `${token}\n${sanitized}\n${token}`;
}

/**
 * Specialized check for Spotify-themed brand impersonation.
 */
function checkSpotifyImpersonation(fromHeader, body, urls) {
  const fromLower = fromHeader.toLowerCase();
  const bodyLower = body.toLowerCase();

  // 1. Detect if the "Display Name" claims to be Spotify
  const isClaimingToBeSpotify = fromLower.includes('spotify');

  // 2. Check if the actual email domain is legitimate
  const emailRegex = /<([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})>|([a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})/i;
  const match = fromLower.match(emailRegex);
  const email = match ? (match[1] || match[2]) : '';

  const isLegitDomain = email.endsWith('@spotify.com') ||
                        email.endsWith('@news.spotify.com') ||
                        email.endsWith('@support.spotify.com');

  const warnings = [];

  if (isClaimingToBeSpotify && !isLegitDomain) {
    warnings.push("CRITICAL: Display Name spoofing detected. Sender claims to be 'Spotify' but uses a non-Spotify domain.");
  }

  // 3. Look for "Spotify" keywords combined with high-pressure lures
  const lures = ['payment failed', 'subscription suspended', 'update billing', 'premium account'];
  const containsLure = lures.some(lure => bodyLower.includes(lure));

  if (isClaimingToBeSpotify && containsLure) {
    warnings.push("HIGH RISK: Email uses Spotify branding alongside high-pressure billing language.");
  }

  // 4. Check for "Homograph" or suspicious Spotify URLs
  urls.forEach(url => {
    try {
      const hostname = new URL(url).hostname.toLowerCase();
      // Catch Punycode variants OR literal 'spotify' in non-official domains
      if (hostname.includes('spotify') || hostname.startsWith('xn--')) {
        const isOfficial = hostname === 'spotify.com' || hostname.endsWith('.spotify.com');
        if (!isOfficial) {
          warnings.push(`SUSPICIOUS: URL ${url} looks like Spotify but is not a recognized spotify.com domain.`);
        }
      }
    } catch (e) {}
  });

  return warnings;
}
