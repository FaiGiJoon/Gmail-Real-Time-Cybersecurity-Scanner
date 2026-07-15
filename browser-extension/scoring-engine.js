/**
 * scoring-engine.js - Core cybersecurity scanning and scoring logic for Chromium Extension.
 * Ported from Google Apps Script and CLI scoring engines to standard client-side JavaScript.
 */

export const CONSTANTS = {
  TYPOSQUAT_BRANDS: ['google', 'microsoft', 'paypal', 'amazon', 'apple', 'netflix', 'facebook', 'spotify'],
  OFFICIAL_DOMAINS: ['spotify.com', 'news.spotify.com', 'support.spotify.com'],
  INTERNAL_DOMAIN: 'spotify.com',
  VIP_LIST: ['Daniel Ek', 'Martin Lorentzon', 'Paul Vogel', 'Dustin Hoffman'],

  LINGUISTIC_WEIGHTS: {
    'urgent': 10,
    'immediate action': 10,
    'account suspended': 15,
    'wire transfer': 20,
    'verify account': 10,
    'password reset': 5,
    'unusual activity': 10,
    'security alert': 10,
    'act now': 5,
    'payment overdue': 15,
    'login attempt': 10,
    'final notice': 15,
    'official request': 10,
    'restricted access': 15,
    'gift card': 20,
    'payment failed': 15,
    'subscription suspended': 15,
    'update billing': 15,
    'premium account': 15
  },

  SCORING_MULTIPLIERS: {
    'CRITICAL_COMBO': 1.5,
    'HIGH_VOLTAGE': 1.25
  },

  QR_THREAT_PENALTY: 25,
  RELAY_AUDIT_PENALTY: 35,
  HIDDEN_LINK_PENALTY: 25,
  RECEIVED_CHAIN_PENALTY: 40,
  SENDER_ALIGNMENT_PENALTY: 35,
  VIP_IMPERSONATION_PENALTY: 30,
  VIP_TYPOSQUAT_PENALTY: 20,

  URL_REGEX: /https?:\/\/[^\s<"']+/g
};

/**
 * Optimized Levenshtein distance algorithm.
 */
export function levenshteinDistance(a, b) {
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
 * Checks for typosquatting.
 */
export function isTyposquatted(url) {
  try {
    const domain = new URL(url).hostname.toLowerCase();
    const parts = domain.split('.');
    if (parts.length < 2) return null;

    let mainDomain = parts[parts.length - 2];
    const slds = ['co', 'com', 'org', 'net', 'edu', 'gov', 'ac'];
    if (slds.includes(mainDomain) && parts.length > 2) {
      mainDomain = parts[parts.length - 3];
    }

    for (const brand of CONSTANTS.TYPOSQUAT_BRANDS) {
      if (mainDomain === brand) continue;
      const distance = levenshteinDistance(mainDomain, brand);
      if (distance > 0 && distance <= 2) return brand;
    }
  } catch (e) {}
  return null;
}

/**
 * Linguistic Drift and Sentiment Analysis.
 */
export function analyzeLinguisticDrift(text) {
  if (!text) return { threatDetected: false, scorePenalty: 0, details: [] };

  const highPressureKeywords = ['urgent', 'immediate action', 'unauthorized', 'restricted', 'suspended', 'payment failed'];
  const injectionPatterns = [/ignore all previous instructions/gi, /system override/gi, /bypass security/gi];

  let scorePenalty = 0;
  const details = [];

  const lowerText = text.toLowerCase();
  const keywordCount = highPressureKeywords.filter(kw => lowerText.includes(kw)).length;
  if (keywordCount >= 3) {
    scorePenalty += 15;
    details.push("High-density of pressure keywords detected.");
  }

  const hasInjection = injectionPatterns.some(pattern => pattern.test(text));
  if (hasInjection) {
    scorePenalty += 25;
    details.push("Instructional drift (Prompt Injection attempt) detected.");
  }

  const syntheticRegex = /(please act now|verify your account immediately|failure to comply)/gi;
  const syntheticMatches = text.match(syntheticRegex);
  if (syntheticMatches && syntheticMatches.length >= 2) {
    scorePenalty += 10;
    details.push("Repetitive synthetic linguistic patterns detected.");
  }

  return {
    threatDetected: scorePenalty > 0,
    scorePenalty: Math.min(scorePenalty, 50),
    details: details
  };
}

/**
 * Audits sender alignment for spoofing and VIP impersonation.
 */
export function auditSenderAlignment(senderHeader) {
  const result = {
    isSpoofed: false,
    penaltyWeight: 0,
    details: []
  };

  if (!senderHeader) return result;

  const emailMatch = senderHeader.match(/<([^>]+)>/);
  const emailAddress = emailMatch ? emailMatch[1].toLowerCase() : senderHeader.toLowerCase().trim();
  const displayName = senderHeader.replace(/<[^>]+>/g, "").replace(/["']/g, "").trim();
  const lowerDisplayName = displayName.toLowerCase();

  const senderDomain = emailAddress.split("@")[1] || "";
  const isInternalEmail = senderDomain === CONSTANTS.INTERNAL_DOMAIN.toLowerCase();

  const lowerInternalDomain = CONSTANTS.INTERNAL_DOMAIN.toLowerCase();
  const domainParts = lowerInternalDomain.split('.');
  const domainName = domainParts[0];

  if ((lowerDisplayName.includes(lowerInternalDomain) || lowerDisplayName.includes(domainName)) && !isInternalEmail) {
    result.isSpoofed = true;
    result.penaltyWeight += CONSTANTS.SENDER_ALIGNMENT_PENALTY;
    result.details.push("CRITICAL: Display name implies internal domain, but origin is external.");
  }

  let vipFound = false;
  CONSTANTS.VIP_LIST.forEach(vip => {
    if (vipFound) return;
    const lowerVip = vip.toLowerCase();

    if (lowerDisplayName.includes(lowerVip) && !isInternalEmail) {
      result.isSpoofed = true;
      result.penaltyWeight += CONSTANTS.VIP_IMPERSONATION_PENALTY;
      result.details.push(`HIGH: Direct impersonation of VIP "${vip}" detected from external source.`);
      vipFound = true;
      return;
    }

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
 * Calculates security score for the extension UI.
 */
export function calculateScore(data) {
  let points = 100;
  const warnings = data.warnings || [];

  if (data.authStatus?.dmarc === 'fail') points -= 40;
  else if (['none', 'unknown', undefined].includes(data.authStatus?.dmarc)) points -= 10;

  if (data.authStatus?.spf === 'fail') points -= 10;
  if (data.authStatus?.dkim === 'fail') points -= 10;

  if (!data.senderVerified) points -= 30;

  if (data.hasMalware) points -= 80;

  const hasPhishingLink = warnings.some(w =>
    w.includes('Link text mismatch') ||
    w.includes('Malicious URL') ||
    w.includes('homograph')
  );
  if (hasPhishingLink) points -= 60;

  if (data.hasMaliciousQr) points -= CONSTANTS.QR_THREAT_PENALTY;

  if (warnings.some(w => w.includes('relay count') || w.includes('brand spoofing'))) {
    points -= CONSTANTS.RELAY_AUDIT_PENALTY;
  }

  if (warnings.some(w => w.includes('Hidden link detected'))) {
    points -= CONSTANTS.HIDDEN_LINK_PENALTY;
  }

  if (data.relayMismatch) {
    points -= CONSTANTS.RECEIVED_CHAIN_PENALTY;
  }

  const drift = analyzeLinguisticDrift(data.body);
  if (drift.threatDetected) {
    points -= drift.scorePenalty;
    drift.details.forEach(detail => {
      if (!warnings.includes(detail)) warnings.push(detail);
    });
  }

  const linguisticThreatsCount = [];
  if (data.body) {
    const lowerBody = data.body.toLowerCase();
    for (const [keyword, weight] of Object.entries(CONSTANTS.LINGUISTIC_WEIGHTS)) {
      if (lowerBody.includes(keyword)) {
        points -= weight;
        if (weight >= 15) linguisticThreatsCount.push(keyword);
      }
    }
  }

  const alignment = auditSenderAlignment(data.from);
  if (alignment.isSpoofed) {
    points -= alignment.penaltyWeight;
    alignment.details.forEach(detail => {
      if (!warnings.includes(detail)) warnings.push(detail);
    });
  }

  const generalWarnings = warnings.filter(w =>
    !w.includes('Link text mismatch') &&
    !w.includes('Malicious URL') &&
    !w.includes('homograph') &&
    !w.includes('DMARC') &&
    !w.includes('From') &&
    !w.includes('QR Code detected')
  );
  points -= (generalWarnings.length * 20);

  let multiplier = 1.0;
  if (data.authStatus?.dmarc === 'fail' && hasPhishingLink) {
    multiplier = Math.max(multiplier, CONSTANTS.SCORING_MULTIPLIERS.CRITICAL_COMBO);
  }

  if (linguisticThreatsCount.length >= 2 && !data.senderVerified) {
    multiplier = Math.max(multiplier, CONSTANTS.SCORING_MULTIPLIERS.HIGH_VOLTAGE);
  }

  const basePenalty = 100 - points;
  points = 100 - (basePenalty * multiplier);

  return Math.max(0, points);
}
