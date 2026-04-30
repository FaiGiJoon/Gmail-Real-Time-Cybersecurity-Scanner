import * as levenshtein from 'levenshtein-edit-distance';

export const CONSTANTS = {
  TYPOSQUAT_BRANDS: ['google', 'microsoft', 'paypal', 'amazon', 'apple', 'netflix', 'facebook'],
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
    'gift card': 20
  },
  QR_THREAT_PENALTY: 25,
  URL_REGEX: /https?:\/\/[^\s<"']+/g
};

export function calculateScore(data) {
  let points = 100;
  const warnings = data.warnings || [];

  if (data.authStatus?.dmarc === 'fail') points -= 40;
  else if (['none', 'unknown', undefined].includes(data.authStatus?.dmarc)) points -= 10;

  if (data.authStatus?.spf === 'fail') points -= 10;
  if (data.authStatus?.dkim === 'fail') points -= 10;

  if (!data.senderVerified) points -= 30;

  const hasPhishingLink = warnings.some(w =>
    w.includes('Link text mismatch') ||
    w.includes('Malicious URL') ||
    w.includes('homograph')
  );
  if (hasPhishingLink) points -= 60;

  if (data.hasMaliciousQr) points -= CONSTANTS.QR_THREAT_PENALTY;

  if (data.body) {
    const lowerBody = data.body.toLowerCase();
    for (const [keyword, weight] of Object.entries(CONSTANTS.LINGUISTIC_WEIGHTS)) {
      if (lowerBody.includes(keyword)) {
        points -= weight;
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
