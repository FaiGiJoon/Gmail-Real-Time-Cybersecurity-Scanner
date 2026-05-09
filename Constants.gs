/**
 * Global constants for the Gmail Cybersecurity Scanner.
 */

const CONSTANTS = {
  // Security Hardening: Do not hardcode keys. Use PropertiesService.
  SAFE_BROWSING_ENDPOINT: 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
  CLOUD_VISION_ENDPOINT: 'https://vision.googleapis.com/v1/images:annotate',
  VIRUSTOTAL_ENDPOINT: 'https://www.virustotal.com/api/v3/files/',

  // ReDoS Protected Regexes
  URL_REGEX: /https?:\/\/[^\s<"']+/g,
  LINK_REGEX: /<a\b[^>]*?\bhref=(["'])(.*?)\1[^>]*?>(.*?)<\/a>/gi,

  // Magic Bytes (File Signatures)
  MAGIC_BYTES: {
    'PDF': [0x25, 0x50, 0x44, 0x46], // %PDF
    'ZIP': [0x50, 0x4B, 0x03, 0x04], // PK..
    'EXE': [0x4D, 0x5A]             // MZ
  },

  // Trusted Relays (Example CIDRs for 2026 Audit)
  TRUSTED_RELAYS: [
    '209.85.128.0/17', // Google
    '66.102.0.0/20',   // Google
    '104.47.0.0/17'    // Microsoft/Office 365
  ],

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

  TYPOSQUAT_BRANDS: ['google', 'microsoft', 'paypal', 'amazon', 'apple', 'netflix', 'facebook', 'spotify'],

  OFFICIAL_DOMAINS: ['spotify.com', 'news.spotify.com', 'support.spotify.com'],

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

  QR_THREAT_PENALTY: 25,
  RELAY_AUDIT_PENALTY: 35,
  HIDDEN_LINK_PENALTY: 25,
  SPOTIFY_IMPERSONATION_PENALTY: 40,
  SECURITY_REVIEW_LABEL: 'Security Review',

  // Sender Identity & Domain Alignment
  INTERNAL_DOMAIN: 'spotify.com',
  VIP_LIST: ['Daniel Ek', 'Martin Lorentzon', 'Paul Vogel', 'Dustin Hoffman'],
  SENDER_ALIGNMENT_PENALTY: 35,
  VIP_IMPERSONATION_PENALTY: 30,
  VIP_TYPOSQUAT_PENALTY: 20,

  // Non-Linear Multiplier Thresholds
  SCORING_MULTIPLIERS: {
    'CRITICAL_COMBO': 1.5, // e.g., DMARC Fail + Malicious URL
    'HIGH_VOLTAGE': 1.25   // e.g., Multiple urgent lures + spoofing
  }
};
