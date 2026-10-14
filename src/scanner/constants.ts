/**
 * Cybersecurity Engine Constants and Threat Scoring Rules
 */

export const SCANNER_CONSTANTS = {
  SAFE_BROWSING_ENDPOINT: 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
  VIRUSTOTAL_ENDPOINT: 'https://www.virustotal.com/api/v3/files/',

  // ReDoS Protected Regexes
  URL_REGEX: /https?:\/\/[^\s<"']+/g,
  LINK_REGEX: /<a\b[^>]*?\bhref=(["'])(.*?)\1[^>]*?>(.*?)<\/a>/gi,

  // Magic Bytes (File Signatures)
  MAGIC_BYTES: {
    'PDF': [0x25, 0x50, 0x44, 0x46], // %PDF
    'ZIP': [0x50, 0x4B, 0x03, 0x04], // PK..
    'DOCX': [0x50, 0x4B, 0x03, 0x04],
    'XLSX': [0x50, 0x4B, 0x03, 0x04],
    'EXE': [0x4D, 0x5A],             // MZ
    'PNG': [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    'JPEG': [0xFF, 0xD8, 0xFF],
    'GIF': [0x47, 0x49, 0x46, 0x38], // GIF8
    '7Z': [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],
    'LNK': [0x4C, 0x00, 0x00, 0x00],
    'RTF': [0x7B, 0x5C, 0x72, 0x74]
  } as Record<string, number[]>,

  // Trusted Relays
  TRUSTED_RELAYS: [
    '209.85.128.0/17',
    '74.125.0.0/16',
    '104.47.0.0/17',
    '40.92.0.0/15',
    '40.107.0.0/16',
    '52.100.0.0/14'
  ],

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
  } as Record<string, number>,

  // Threat Penalties
  MALWARE_PENALTY: 80,
  URL_THREAT_PENALTY: 60,
  DMARC_FAIL_PENALTY: 40,
  RECEIVED_CHAIN_PENALTY: 40,
  BRAND_SPOOFING_PENALTY: 40,
  SENDER_ALIGNMENT_PENALTY: 35,
  RELAY_AUDIT_PENALTY: 35,
  VIP_IMPERSONATION_PENALTY: 30,
  QR_THREAT_PENALTY: 25,
  HIDDEN_LINK_PENALTY: 25,
  PROMPT_INJECTION_PENALTY: 25,
  VIP_TYPOSQUAT_PENALTY: 20,

  // Non-Linear Multipliers
  SCORING_MULTIPLIERS: {
    'CRITICAL_COMBO': 1.5, // DMARC Fail + Malicious URL
    'HIGH_VOLTAGE': 1.25   // Multiple urgent lures + unverified sender
  },

  KNOWN_BAD_ASNS: ['AS13335', 'AS15169', 'AS40022'],
  SHADOW_LINK_THRESHOLD: 3,

  EXECUTABLE_EXTENSIONS: ['.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.ps1', '.hta', '.msi', '.pif'],
};
