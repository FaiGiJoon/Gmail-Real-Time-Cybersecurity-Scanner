/**
 * Global constants for the Gmail Cybersecurity Scanner.
 */

const CONSTANTS = {
  SAFE_BROWSING_API_KEY: 'YOUR_SAFE_BROWSING_API_KEY',
  SAFE_BROWSING_ENDPOINT: 'https://safebrowsing.googleapis.com/v4/threatMatches:find',

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
  }
};
