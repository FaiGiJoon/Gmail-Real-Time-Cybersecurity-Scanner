/**
 * Constants for the Apps Script add-on.
 * API keys are never stored here: set them under Project Settings > Script properties.
 *   SAFE_BROWSING_API_KEY   (recommended)  Google Safe Browsing v4 lookups
 *   VIRUSTOTAL_API_KEY      (optional)     attachment hash reputation
 *   CLOUD_VISION_API_KEY    (optional)     QR codes inside image attachments
 */
const SCANNER = {
  VERSION: '2.0.0',
  REVIEW_LABEL: 'Security Review',
  CACHE_SECONDS: 21600,            // CacheService maximum (6 hours)
  TIME_BUDGET_MS: 20000,           // stop optional lookups after this long; the card must render in time
  MAX_ATTACHMENTS_FETCHED: 5,
  MAX_ATTACHMENT_BYTES: 5 * 1024 * 1024,
  MAX_URLS_TO_LOOKUP: 40,
  MAX_REDIRECT_HOPS: 5,
  REPORT_ADDRESS: 'reportphishing@apwg.org',
  GMAIL_API: 'https://gmail.googleapis.com/gmail/v1/users/me',
  SAFE_BROWSING_ENDPOINT: 'https://safebrowsing.googleapis.com/v4/threatMatches:find',
  VISION_ENDPOINT: 'https://vision.googleapis.com/v1/images:annotate',
  VIRUSTOTAL_ENDPOINT: 'https://www.virustotal.com/api/v3/files/',
  RDAP_ENDPOINT: 'https://rdap.org/domain/',
  LEVEL_ICONS: {
    red: 'https://www.gstatic.com/images/icons/material/system/1x/report_problem_red_24dp.png',
    yellow: 'https://www.gstatic.com/images/icons/material/system/1x/warning_amber_24dp.png',
    green: 'https://www.gstatic.com/images/icons/material/system/1x/check_circle_green_24dp.png'
  }
};
