# Chromium Browser Extension Migration Plan

This document outlines the architecture, code porting strategy, and security considerations for migrating the Gmail Cybersecurity Scanner from a Google Workspace Add-on (Google Apps Script) into a standalone Chromium Browser Extension using Manifest V3.

---

## 1. Directory Structure

The browser extension will be housed under a new `browser-extension/` directory with the following structure:

```
browser-extension/
├── manifest.json         # Manifest V3 configuration defining permissions, background scripts, and popup
├── background.js        # Background service worker (OAuth 2.0 flow, scan coordination)
├── content.js           # Content script (optional, for warning banner injection in Gmail UI)
├── popup.html           # Popup interface UI (mimics the Add-on's security card)
├── popup.js             # UI controller for the popup interface
├── options.html         # Settings/configuration interface (e.g., custom API keys)
├── options.js           # Controller for the options interface
├── scoring-engine.js    # Port of the modular threat scoring engine (matching SecurityEngine.gs)
└── lib/
    ├── jszip.min.js     # Lightweight JSZip library for attachment ZIP analysis
    └── crypto-helper.js # Web Crypto API wrappers (SHA-256 calculation, etc.)
```

---

## 2. API & Utility Migration Strategy

Google Apps Script APIs must be mapped to their modern Browser/Extension equivalents:

| Apps Script API | Extension Equivalent |
| :--- | :--- |
| `UrlFetchApp.fetch` | Standard `fetch()` API |
| `PropertiesService` (API Keys) | `chrome.storage.local` or a secure backend proxy |
| `CacheService` | `chrome.storage.local` with manual expiration timestamps |
| `GmailApp` | Gmail REST API (`https://gmail.googleapis.com/v1/users/me/...`) via `fetch()` with OAuth2 |
| `Utilities.computeDigest` | Web Crypto API (`crypto.subtle.digest('SHA-256', ...)`) |
| `Utilities.base64Encode` | Standard `btoa()` or Base64 ArrayBuffer encoders |
| `Utilities.unzip` | Lightweight client-side library like `JSZip` |

---

## 3. Security Warning: API Key Exposure in Client-Side Code

Browser extensions distribute raw JavaScript/HTML files directly to the end-user. Hardcoding any API keys (such as Safe Browsing, VirusTotal, or Google Cloud Vision) inside the extension package makes them trivial to extract, leading to key theft, quota abuse, and billing liabilities.

### Security Options

#### Option 1: Secure Backend Proxy (Recommended)
Establish a lightweight backend proxy (e.g., Google Cloud Functions, AWS Lambda, or a Node.js server) to handle the security API lookups.
* **Mechanism:** The extension calls the proxy server with the target domain/hash/image payload. The proxy server attaches the hidden API key, invokes the third-party endpoint, and returns only the finalized classification result back to the extension.
* **Pros:** Complete API key safety; enables centralized rate-limiting, request auditing, and global caching.
* **Cons:** Introduces additional hosting infrastructure and potential operational costs.

#### Option 2: User-Provided API Keys
Incorporate an "Options" page in the extension where advanced users can input their personal Google Cloud and VirusTotal API keys. These keys are stored locally using `chrome.storage.local`.
* **Mechanism:** The extension uses `chrome.storage.local.get` to fetch the user-provided keys for direct `fetch()` calls.
* **Pros:** Zero backend maintenance or costs for extension developers; highly customizable.
* **Cons:** Degrades the user experience for non-technical users who may find API key generation too complex.

#### Option 3: Origin/Referer Restriction (Partial Solution)
Restrict the API keys inside Google Cloud Console to allow calls only from specific Chrome Extension IDs or HTTP referers.
* **Mechanism:** The GCP Console restricts the Cloud Vision API key by extension origin (`chrome-extension://<EXTENSION_ID>`).
* **Pros:** Simple, direct client-to-API communication.
* **Cons:** Does not protect VirusTotal keys (as VirusTotal does not support client-side origin/referer locks); dynamically-generated development IDs during testing can bypass or break constraints.

---

## 4. OAuth 2.0 Credentials Setup

To authenticate with the Gmail REST API in a standard Chrome Extension:
1. Go to the **Google Cloud Console**.
2. Create a new **OAuth client ID** and select application type **Chrome extension**.
3. Retrieve your unique **Extension ID** (generated when you load the unpacked directory in `chrome://extensions`).
4. Enter this Extension ID into the GCP console client ID registration to authorize the extension.
5. Replace `"client_id": "YOUR_OAUTH_CLIENT_ID.apps.googleusercontent.com"` in `manifest.json` with the actual client ID provided by GCP.

---

## 5. Next Steps

1. Create extension scaffolding (manifest.json, background.js, popup.html, popup.js).
2. Establish communication with Gmail REST API using standard MV3 Chrome Extension techniques.
3. Adapt the scoring engine for standard ES module architecture.
