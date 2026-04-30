/**
 * Global constants for the Gmail Cybersecurity Scanner.
 */

const CONSTANTS = {
  SAFE_BROWSING_API_KEY: 'YOUR_SAFE_BROWSING_API_KEY',
  SAFE_BROWSING_ENDPOINT: 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
  CLOUD_VISION_ENDPOINT: 'https://vision.googleapis.com/v1/images:annotate',

  URL_REGEX: /https?:\/\/[^\s<"']+/g,
  LINK_REGEX: /<a\s+(?:[^>]*?\s+)?href=(["'])(.*?)\1[^>]*?>(.*?)<\/a>/gi,

  THREAT_LEVELS: {
    RED: 'Red',
    YELLOW: 'Yellow',
    GREEN: 'Green'
  },

  STATUS_TEXT: {
    HIGH_RISK: 'High Risk',
    CAUTION: 'Caution',
    SECURE: 'Secure'
  },

  ICONS: {
    RED: 'https://www.gstatic.com/images/icons/material/system/1x/report_problem_red_24dp.png',
    YELLOW: 'https://www.gstatic.com/images/icons/material/system/1x/warning_amber_24dp.png',
    GREEN: 'https://www.gstatic.com/images/icons/material/system/1x/check_circle_green_24dp.png'
  },

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
  SECURITY_REVIEW_LABEL: 'Security Review'
};
