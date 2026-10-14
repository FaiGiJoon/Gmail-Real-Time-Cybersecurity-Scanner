import { SCANNER_CONSTANTS } from './constants.ts';
import { verifyUrlReputation } from './urlScanner.ts';
import { inspectAttachments } from './attachmentScanner.ts';
import { levenshteinDistance } from './urlScanner.ts';
import { logger } from '../utils/logger.ts';
import type { ScanEmailPayload, EmailHeader, AttachmentInput } from '../schemas/index.ts';

export interface LinguisticDriftResult {
  threatDetected: boolean;
  scorePenalty: number;
  details: string[];
}

export interface HeaderAuditResult {
  spf: string;
  dkim: string;
  dmarc: string;
  senderVerified: boolean;
  alignmentMismatch: boolean;
  vipImpersonation: boolean;
  brandImpersonation: boolean;
  badAsnDetected: boolean;
  warnings: string[];
}

export interface EmailScanResult {
  securityScore: number;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
  action: 'QUARANTINE' | 'SECURITY_REVIEW' | 'FLAG_WARNING' | 'ALLOW';
  summary: string;
  warnings: string[];
  headerAudit: HeaderAuditResult;
  urlAnalysis: Awaited<ReturnType<typeof verifyUrlReputation>>;
  attachmentAnalysis?: Awaited<ReturnType<typeof inspectAttachments>>;
  linguisticDrift: LinguisticDriftResult;
  promptInjectionDetected: boolean;
}

/**
 * Decodes MIME header encoded-words (e.g. =?UTF-8?B?...?= or =?UTF-8?Q?...?=)
 */
export function decodeMimeHeader(headerStr: string): string {
  if (!headerStr) return '';
  return headerStr.replace(/=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g, (_match, charset, encoding, text) => {
    try {
      if (encoding.toUpperCase() === 'B') {
        return Buffer.from(text, 'base64').toString('utf-8');
      } else if (encoding.toUpperCase() === 'Q') {
        const quoted = text.replace(/_/g, ' ').replace(/=([0-9A-F]{2})/gi, (_m: string, hex: string) => {
          return String.fromCharCode(parseInt(hex, 16));
        });
        return quoted;
      }
    } catch {
      return text;
    }
    return text;
  });
}

/**
 * Analyzes body text for prompt injection / LLM jailbreak attempts ("Shield-Layer").
 */
export function detectPromptInjection(text?: string): boolean {
  if (!text) return false;
  const injectionPatterns = [
    /ignore\s+(all\s+)?previous\s+instructions/gi,
    /system\s+override/gi,
    /bypass\s+security\s+filter/gi,
    /you\s+are\s+now\s+in\s+DAN\s+mode/gi,
    /do\s+anything\s+now/gi,
    /act\s+as\s+an\s+unrestricted/gi
  ];
  return injectionPatterns.some(pattern => pattern.test(text));
}

/**
 * Analyzes linguistic drift, BEC lures, and synthetic high-pressure cues.
 */
export function analyzeLinguisticDrift(text?: string): LinguisticDriftResult {
  if (!text) return { threatDetected: false, scorePenalty: 0, details: [] };

  const details: string[] = [];
  let scorePenalty = 0;

  const highPressureKeywords = ['urgent', 'immediate action', 'unauthorized', 'restricted', 'suspended', 'payment failed'];
  const lowerText = text.toLowerCase();

  const keywordCount = highPressureKeywords.filter(kw => lowerText.includes(kw)).length;
  if (keywordCount >= 3) {
    scorePenalty += 15;
    details.push("High density of urgent pressure keywords detected");
  }

  if (detectPromptInjection(text)) {
    scorePenalty += SCANNER_CONSTANTS.PROMPT_INJECTION_PENALTY;
    details.push("Instructional drift (LLM Prompt Injection attempt) detected");
  }

  const syntheticRegex = /(please act now|verify your account immediately|failure to comply|wire transfer request)/gi;
  const syntheticMatches = text.match(syntheticRegex);
  if (syntheticMatches && syntheticMatches.length >= 2) {
    scorePenalty += 10;
    details.push("Repetitive synthetic high-pressure BEC linguistic patterns detected");
  }

  for (const [keyword, weight] of Object.entries(SCANNER_CONSTANTS.LINGUISTIC_WEIGHTS)) {
    if (lowerText.includes(keyword)) {
      scorePenalty += Math.min(weight, 10);
    }
  }

  return {
    threatDetected: scorePenalty > 0,
    scorePenalty: Math.min(scorePenalty, 50),
    details
  };
}

/**
 * Audits email headers, authentication status, and sender identity alignment.
 */
export function auditHeaders(
  headers?: EmailHeader | Record<string, unknown>,
  rawSender?: string,
  internalDomain = 'spotify.com',
  vipNames = ['Daniel Ek', 'Martin Lorentzon', 'Paul Vogel']
): HeaderAuditResult {
  const warnings: string[] = [];
  const h = (headers || {}) as EmailHeader;

  const spf = (h.spf || 'unknown').toString().toLowerCase();
  const dkim = (h.dkim || 'unknown').toString().toLowerCase();
  const dmarc = (h.dmarc || 'unknown').toString().toLowerCase();

  const fromRaw = decodeMimeHeader(h.from || rawSender || '');
  let senderAddress = '';
  let displayName = '';

  const fromMatch = fromRaw.match(/(?:"?([^"]*)"?\s*)?<?([^>@]+@[^>]+)>?/);
  if (fromMatch) {
    displayName = (fromMatch[1] || '').trim();
    senderAddress = (fromMatch[2] || '').trim().toLowerCase();
  } else {
    senderAddress = fromRaw.trim().toLowerCase();
  }

  const senderDomain = senderAddress.split('@')[1] || '';

  // 1. DMARC/SPF/DKIM evaluation
  let senderVerified = true;
  if (dmarc === 'fail') {
    senderVerified = false;
    warnings.push("DMARC authentication failed");
  } else if (['none', 'unknown', 'softfail'].includes(dmarc) && spf === 'fail') {
    senderVerified = false;
    warnings.push("SPF authentication failed and DMARC is not enforcing");
  }

  // 2. Alignment mismatch (Claiming internal domain or internal VIP from external domain)
  let alignmentMismatch = false;
  const isClaimingInternal = displayName.toLowerCase().includes(internalDomain) ||
    senderAddress.includes(internalDomain) ||
    vipNames.some(vip => displayName.toLowerCase().includes(vip.toLowerCase()));

  if (isClaimingInternal && !senderDomain.endsWith(internalDomain)) {
    alignmentMismatch = true;
    warnings.push(`Sender alignment mismatch: claims internal domain '${internalDomain}' or VIP identity but sent from '${senderDomain}'`);
  }

  // 3. VIP Impersonation
  let vipImpersonation = false;
  if (displayName) {
    for (const vip of vipNames) {
      if (displayName.toLowerCase().includes(vip.toLowerCase()) && !senderDomain.endsWith(internalDomain)) {
        vipImpersonation = true;
        warnings.push(`VIP Display Name impersonation detected: claims VIP name '${vip}' from unverified domain '${senderDomain}'`);
        break;
      }
    }
  }

  // 4. Brand Impersonation
  let brandImpersonation = false;
  for (const brand of SCANNER_CONSTANTS.TYPOSQUAT_BRANDS) {
    if (displayName.toLowerCase().includes(brand) && !senderDomain.includes(brand)) {
      brandImpersonation = true;
      warnings.push(`Brand display name spoofing detected: claims brand '${brand}' from '${senderDomain}'`);
      break;
    }
  }

  // 5. Received Chain / Bad ASN audit
  let badAsnDetected = false;
  const receivedHeaders = Array.isArray(h.received)
    ? h.received
    : (typeof h.received === 'string' ? [h.received] : []);

  for (const r of receivedHeaders) {
    for (const badAsn of SCANNER_CONSTANTS.KNOWN_BAD_ASNS) {
      if (r.includes(badAsn)) {
        badAsnDetected = true;
        warnings.push(`Received relay path traversed untrusted/malicious ASN: '${badAsn}'`);
        break;
      }
    }
  }

  return {
    spf,
    dkim,
    dmarc,
    senderVerified,
    alignmentMismatch,
    vipImpersonation,
    brandImpersonation,
    badAsnDetected,
    warnings
  };
}

/**
 * Detects hidden links (CSS display:none, opacity:0, height:0, etc.)
 */
export function detectHiddenLinks(body?: string): boolean {
  if (!body) return false;
  const hiddenCssPattern = /style\s*=\s*["'][^"']*(?:display\s*:\s*none|opacity\s*:\s*0|font-size\s*:\s*0|height\s*:\s*0|visibility\s*:\s*hidden)[^"']*["']/gi;
  return hiddenCssPattern.test(body);
}

/**
 * Core function to scan full email payload.
 */
export async function scanEmailPayload(
  payload: ScanEmailPayload,
  apiKeys?: { safeBrowsingKey?: string; virusTotalKey?: string },
  orgConfig?: { internalDomain?: string; vipNames?: string[] }
): Promise<EmailScanResult> {
  const bodyText = payload.body || payload.rawEmail || '';
  const warnings: string[] = [];

  // 1. Audit Headers & Sender Identity
  const headerAudit = auditHeaders(
    payload.headers,
    payload.sender,
    orgConfig?.internalDomain || 'spotify.com',
    orgConfig?.vipNames || ['Daniel Ek', 'Martin Lorentzon', 'Paul Vogel']
  );
  warnings.push(...headerAudit.warnings);

  // 2. Extract & Inspect URLs
  const extractedUrls: string[] = [];
  const urlMatches = bodyText.match(SCANNER_CONSTANTS.URL_REGEX);
  if (urlMatches) {
    extractedUrls.push(...urlMatches);
  }

  const urlAnalysis = await verifyUrlReputation(extractedUrls, bodyText, apiKeys?.safeBrowsingKey);
  urlAnalysis.results.forEach(r => {
    r.threats.forEach(t => warnings.push(`[URL Risk] ${t}`));
  });

  // 3. Hidden Links Check
  const hasHiddenLinks = detectHiddenLinks(bodyText);
  if (hasHiddenLinks) {
    warnings.push("Hidden links detected in HTML body (CSS display:none or opacity:0)");
  }

  // 4. Inspect Attachments
  let attachmentAnalysis: Awaited<ReturnType<typeof inspectAttachments>> | undefined = undefined;
  if (payload.attachments && payload.attachments.length > 0) {
    attachmentAnalysis = await inspectAttachments(payload.attachments, apiKeys?.virusTotalKey);
    attachmentAnalysis.results.forEach(r => {
      r.suspiciousTraits.forEach(t => warnings.push(`[Attachment Risk] ${r.filename}: ${t}`));
    });
  }

  // 5. Linguistic Drift & Prompt Injection
  const linguisticDrift = analyzeLinguisticDrift(bodyText);
  linguisticDrift.details.forEach(d => warnings.push(`[Content Drift] ${d}`));
  const promptInjectionDetected = detectPromptInjection(bodyText);

  // 6. Calculate Security Score & Multipliers
  let points = 100;

  if (headerAudit.dmarc === 'fail') points -= SCANNER_CONSTANTS.DMARC_FAIL_PENALTY;
  if (!headerAudit.senderVerified) points -= 30;
  if (headerAudit.alignmentMismatch) points -= SCANNER_CONSTANTS.SENDER_ALIGNMENT_PENALTY;
  if (headerAudit.vipImpersonation) points -= SCANNER_CONSTANTS.VIP_IMPERSONATION_PENALTY;
  if (headerAudit.brandImpersonation) points -= SCANNER_CONSTANTS.BRAND_SPOOFING_PENALTY;
  if (headerAudit.badAsnDetected) points -= SCANNER_CONSTANTS.RECEIVED_CHAIN_PENALTY;

  if (urlAnalysis.summary.maliciousCount > 0) {
    points -= SCANNER_CONSTANTS.URL_THREAT_PENALTY;
  }

  if (attachmentAnalysis && attachmentAnalysis.summary.maliciousCount > 0) {
    points -= SCANNER_CONSTANTS.MALWARE_PENALTY;
  }

  if (hasHiddenLinks) points -= SCANNER_CONSTANTS.HIDDEN_LINK_PENALTY;
  if (linguisticDrift.threatDetected) points -= linguisticDrift.scorePenalty;

  // Non-Linear Composite Multipliers
  let multiplier = 1.0;
  const hasPhishingUrl = urlAnalysis.summary.maliciousCount > 0 || urlAnalysis.results.some(r => r.isHomograph || r.typosquattedBrand);

  if (headerAudit.dmarc === 'fail' && hasPhishingUrl) {
    multiplier = Math.max(multiplier, SCANNER_CONSTANTS.SCORING_MULTIPLIERS.CRITICAL_COMBO);
  }

  if (linguisticDrift.scorePenalty >= 15 && !headerAudit.senderVerified) {
    multiplier = Math.max(multiplier, SCANNER_CONSTANTS.SCORING_MULTIPLIERS.HIGH_VOLTAGE);
  }

  const basePenalty = Math.max(0, 100 - points);
  const finalScore = Math.max(0, Math.round(100 - (basePenalty * multiplier)));

  // 7. Threat Level & Mitigation Action
  let threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE' = 'SAFE';
  let action: 'QUARANTINE' | 'SECURITY_REVIEW' | 'FLAG_WARNING' | 'ALLOW' = 'ALLOW';

  if (finalScore < 30 || (attachmentAnalysis && attachmentAnalysis.summary.maliciousCount > 0)) {
    threatLevel = 'CRITICAL';
    action = 'QUARANTINE';
  } else if (finalScore < 55 || urlAnalysis.summary.maliciousCount > 0 || headerAudit.alignmentMismatch) {
    threatLevel = 'HIGH';
    action = 'QUARANTINE';
  } else if (finalScore < 75 || warnings.length > 0) {
    threatLevel = 'MEDIUM';
    action = 'SECURITY_REVIEW';
  } else if (finalScore < 90) {
    threatLevel = 'LOW';
    action = 'FLAG_WARNING';
  }

  const uniqueWarnings = Array.from(new Set(warnings));

  return {
    securityScore: finalScore,
    threatLevel,
    action,
    summary: `Email scan completed with score ${finalScore}/100. Threat Level: ${threatLevel}. Action: ${action}.`,
    warnings: uniqueWarnings,
    headerAudit,
    urlAnalysis,
    attachmentAnalysis,
    linguisticDrift,
    promptInjectionDetected
  };
}
