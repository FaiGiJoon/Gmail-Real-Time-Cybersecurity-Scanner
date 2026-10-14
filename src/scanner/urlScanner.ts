import { SCANNER_CONSTANTS } from './constants.ts';
import { logger } from '../utils/logger.ts';

export interface UrlReputationResult {
  url: string;
  isMalicious: boolean;
  isHomograph: boolean;
  typosquattedBrand: string | null;
  isLinkTextMismatch: boolean;
  isIpHostname: boolean;
  riskScore: number;
  threats: string[];
}

/**
 * Calculates Levenshtein edit distance between two strings.
 */
export function levenshteinDistance(a: string, b: string): number {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix: number[][] = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Checks if URL hostname is a Punycode homograph attack.
 */
export function isHomograph(urlStr: string): boolean {
  try {
    const parsed = new URL(urlStr.startsWith('http') ? urlStr : `https://${urlStr}`);
    return parsed.hostname.toLowerCase().includes('xn--');
  } catch {
    return false;
  }
}

/**
 * Checks if a URL domain is typosquatting a popular brand.
 */
export function isTyposquatted(urlStr: string): string | null {
  try {
    const parsed = new URL(urlStr.startsWith('http') ? urlStr : `https://${urlStr}`);
    const domain = parsed.hostname.toLowerCase();
    const parts = domain.split('.');
    if (parts.length < 2) return null;

    let mainDomain = parts[parts.length - 2];
    const commonSlds = ['co', 'com', 'org', 'net', 'edu', 'gov', 'ac'];
    if (commonSlds.some(sld => sld === mainDomain) && parts.length > 2) {
      mainDomain = parts[parts.length - 3];
    }

    for (const brand of SCANNER_CONSTANTS.TYPOSQUAT_BRANDS) {
      if (mainDomain === brand) continue;
      const distance = levenshteinDistance(mainDomain, brand);
      if (distance > 0 && distance <= 2) {
        return brand;
      }
    }
  } catch {
    // Ignore invalid URLs
  }
  return null;
}

/**
 * Checks for mismatch between visible anchor text and actual destination URL.
 */
export function isLinkTextMismatch(text: string, targetUrl: string): boolean {
  if (!text || !targetUrl) return false;
  const cleanText = text.trim().toLowerCase();

  // Extract potential domain from text if text looks like a domain/URL
  const domainPattern = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/i;
  const match = cleanText.match(domainPattern);

  if (match) {
    const claimedDomain = match[0].replace(/^www\./, '');
    try {
      const targetObj = new URL(targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`);
      const actualDomain = targetObj.hostname.toLowerCase().replace(/^www\./, '');

      const isExactMatch = actualDomain === claimedDomain;
      const isSubdomainMatch = actualDomain.endsWith('.' + claimedDomain);

      if (!isExactMatch && !isSubdomainMatch) {
        return true;
      }
    } catch {
      return false;
    }
  }
  return false;
}

/**
 * Checks if hostname is a raw IP address (e.g. http://192.168.1.1/login).
 */
export function isIpHostname(urlStr: string): boolean {
  try {
    const parsed = new URL(urlStr.startsWith('http') ? urlStr : `https://${urlStr}`);
    const host = parsed.hostname;
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    return ipPattern.test(host);
  } catch {
    return false;
  }
}

/**
 * Evaluates Google Safe Browsing API if key is present.
 */
async function checkSafeBrowsing(urls: string[], apiKey?: string): Promise<Set<string>> {
  const maliciousUrls = new Set<string>();
  if (!apiKey || urls.length === 0) return maliciousUrls;

  try {
    const endpoint = `${SCANNER_CONSTANTS.SAFE_BROWSING_ENDPOINT}?key=${apiKey}`;
    const payload = {
      client: { clientId: "gmail-security-scanner", clientVersion: "1.2.0" },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: urls.map(url => ({ url }))
      }
    };

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (response.ok) {
      const data = await response.json() as any;
      if (data.matches && Array.isArray(data.matches)) {
        data.matches.forEach((m: any) => {
          if (m.threat?.url) maliciousUrls.add(m.threat.url);
        });
      }
    }
  } catch (err) {
    logger.warn("Safe Browsing API check failed, relying on heuristics.", err);
  }

  return maliciousUrls;
}

/**
 * Main URL verification function.
 */
export async function verifyUrlReputation(
  urls: string | string[],
  context?: string,
  apiKey?: string
): Promise<{
  summary: { totalUrls: number; maliciousCount: number; suspiciousCount: number; maxRiskScore: number };
  results: UrlReputationResult[];
}> {
  const urlList = Array.isArray(urls) ? urls : [urls];
  const uniqueUrls = Array.from(new Set(urlList.filter(u => typeof u === 'string' && u.trim().length > 0)));

  const safeBrowsingHits = await checkSafeBrowsing(uniqueUrls, apiKey);
  const results: UrlReputationResult[] = [];

  let maliciousCount = 0;
  let suspiciousCount = 0;
  let maxRiskScore = 0;

  for (const url of uniqueUrls) {
    const threats: string[] = [];
    let riskScore = 0;

    const homograph = isHomograph(url);
    if (homograph) {
      threats.push("Homograph Punycode attack detected (xn--)");
      riskScore += 50;
    }

    const typosquattedBrand = isTyposquatted(url);
    if (typosquattedBrand) {
      threats.push(`Typosquatting detected: potential spoof of '${typosquattedBrand}'`);
      riskScore += 40;
    }

    const mismatch = context ? isLinkTextMismatch(context, url) : false;
    if (mismatch) {
      threats.push("Link destination mismatch (anchor text differs from link target)");
      riskScore += 40;
    }

    const rawIp = isIpHostname(url);
    if (rawIp) {
      threats.push("URL uses raw IP address instead of domain hostname");
      riskScore += 30;
    }

    const isApiMalicious = safeBrowsingHits.has(url);
    if (isApiMalicious) {
      threats.push("Flagged as malicious by Google Safe Browsing threat feed");
      riskScore += 80;
    }

    const isMalicious = isApiMalicious || riskScore >= 60;
    if (isMalicious) maliciousCount++;
    else if (riskScore > 0) suspiciousCount++;

    maxRiskScore = Math.max(maxRiskScore, riskScore);

    results.push({
      url,
      isMalicious,
      isHomograph: homograph,
      typosquattedBrand,
      isLinkTextMismatch: mismatch,
      isIpHostname: rawIp,
      riskScore: Math.min(100, riskScore),
      threats
    });
  }

  return {
    summary: {
      totalUrls: uniqueUrls.length,
      maliciousCount,
      suspiciousCount,
      maxRiskScore
    },
    results
  };
}
