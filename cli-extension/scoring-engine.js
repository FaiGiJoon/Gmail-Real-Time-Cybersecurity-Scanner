import * as levenshtein from 'levenshtein-edit-distance';

export const CONSTANTS = {
  TYPOSQUAT_BRANDS: ['google', 'microsoft', 'paypal', 'amazon', 'apple', 'netflix', 'facebook', 'spotify'],
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
  URL_REGEX: /https?:\/\/[^\s<"']+/g
};

/**
 * Linguistic Drift and Sentiment Analysis (Roadmap 2.2).
 * Detects high-pressure AI-generated patterns, repetitive structural cues,
 * and anomalous instructional language.
 */
export function analyzeLinguisticDrift(text) {
  if (!text) return { threatDetected: false, scorePenalty: 0 };

  const highPressureKeywords = ['urgent', 'immediate action', 'unauthorized', 'restricted', 'suspended', 'payment failed'];
  const injectionPatterns = [/ignore all previous instructions/gi, /system override/gi, /bypass security/gi];

  let scorePenalty = 0;
  const details = [];

  // 1. Keyword Density
  const lowerText = text.toLowerCase();
  const keywordCount = highPressureKeywords.filter(kw => lowerText.includes(kw)).length;
  if (keywordCount >= 3) {
    scorePenalty += 15;
    details.push("High-density of pressure keywords detected.");
  }

  // 2. Prompt Injection / Instructional Drift
  const hasInjection = injectionPatterns.some(pattern => pattern.test(text));
  if (hasInjection) {
    scorePenalty += 25;
    details.push("Instructional drift (Prompt Injection attempt) detected.");
  }

  // 3. Structural Synthetic Cues (Repetitive high-pressure phrases)
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

  // Linguistic Drift Analysis (Roadmap 2.2)
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

  const generalWarnings = warnings.filter(w =>
    !w.includes('Link text mismatch') &&
    !w.includes('Malicious URL') &&
    !w.includes('homograph') &&
    !w.includes('DMARC') &&
    !w.includes('From') &&
    !w.includes('QR Code detected')
  );
  points -= (generalWarnings.length * 20);

  // --- Non-Linear Multiplier (Threat Escalation) ---
  let multiplier = 1.0;

  // Critical Combo: DMARC Fail + Malicious URL
  if (data.authStatus?.dmarc === 'fail' && hasPhishingLink) {
    multiplier = Math.max(multiplier, CONSTANTS.SCORING_MULTIPLIERS.CRITICAL_COMBO);
  }

  // High Voltage: Multiple urgent lures + spoofing
  if (linguisticThreatsCount.length >= 2 && !data.senderVerified) {
    multiplier = Math.max(multiplier, CONSTANTS.SCORING_MULTIPLIERS.HIGH_VOLTAGE);
  }

  const basePenalty = 100 - points;
  points = 100 - (basePenalty * multiplier);

  return Math.max(0, points);
}

export function isTyposquatted(url) {
  try {
    const domain = new URL(url).hostname.toLowerCase();
    const parts = domain.split('.');
    if (parts.length < 2) return null;

    let mainDomain = parts[parts.length - 2];
    if (['co', 'com', 'org', 'net', 'edu', 'gov'].includes(mainDomain) && parts.length > 2) {
      mainDomain = parts[parts.length - 3];
    }

    for (const brand of CONSTANTS.TYPOSQUAT_BRANDS) {
      if (mainDomain === brand) continue;
      const distFunc = typeof levenshtein === 'function' ? levenshtein : levenshtein.default || (() => 10);
      const distance = distFunc(mainDomain, brand);
      if (distance > 0 && distance <= 2) return brand;
    }
  } catch (e) {}
  return null;
}
