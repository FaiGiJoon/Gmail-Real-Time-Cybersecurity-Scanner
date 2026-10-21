# Gmail Real-Time Cybersecurity Scanner

Scans the Gmail message you have open and shows a score with the reasons behind it. It runs in three places that share one detection engine:

| Component | Where it runs | Good for |
| :-- | :-- | :-- |
| Gmail add-on (Apps Script) | Side panel in Gmail | Daily use, redirect checks, trusted/blocked sender lists |
| Chrome extension | Toolbar popup on mail.google.com | Quick scan of the open message |
| CLI / MCP server | Terminal or Gemini CLI | Scanning recent mail, scripting, AI-assisted triage (read-only by default) |

The engine lives in `core/scanner-core.js` and is copied into each component by `npm run sync-core`. Never edit the generated copies (`ScannerCore.gs`, `browser-extension/scanner-core.js`, `cli-extension/scanner-core.cjs`).

## What it checks

- Authentication: SPF, DKIM, DMARC, ARC (from the top-most Authentication-Results header only), sender "via" mismatch, Reply-To / Return-Path mismatch
- Impersonation: brand and VIP names, your own domain (all configurable)
- Sender: first email from this address, domain age through RDAP, your trusted and blocked lists
- Links: text/target mismatch, hidden links, punycode and mixed-script look-alikes, user-info tricks, raw IP hosts, typosquats, shorteners, device-code and OAuth consent URLs, Safe Browsing hits
- Content: pressure language, callback-phishing patterns, hidden text and prompt-injection markers, zero-width characters
- Attachments: dangerous and double extensions, macro files, SVG/HTML/ICS, magic-byte mismatches, encrypted archives, PDF scripts and embedded files

Every result lists findings with severity and evidence. Checks that could not run (no API key, quota, timeout) are listed under "Not checked" so a skipped check never looks like a clean one. A failed scan shows an error, never a green card.

## Install: Gmail add-on (recommended first)

1. Create an Apps Script project (script.google.com) and install clasp: `npm i -g @google/clasp`.
2. `clasp login`, then `clasp create --type standalone --title "Cybersecurity Scanner"` (or `clasp clone <scriptId>`).
3. `clasp push`. `.claspignore` makes sure only `.gs` files and `appsscript.json` are uploaded.
4. In the editor choose Deploy > Test deployments > Gmail add-on > Install.
5. Optional keys, under Project Settings > Script properties: `SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`.
6. Open any email in Gmail. The first time, Google asks you to authorize the scopes below.

### Permissions, and why the Google screen looks scary

| Scope | Why |
| :-- | :-- |
| `gmail.addons.execute`, `gmail.addons.current.message.readonly` | Run in Gmail and read the open message |
| `gmail.modify` | Read message content through the Gmail API, add the Security Review label, move to Spam, mark read. Cannot permanently delete and cannot send |
| `script.external_request` | Safe Browsing, RDAP, link expansion |

Reporting creates a draft addressed to reportphishing@apwg.org with the original attached. You press Send, so the add-on does not need a send scope. The add-on never uses `GmailApp`, because that would require Google's full-access scope.

`gmail.modify` is a restricted scope. For your own account (or a small group of test users) that only means an "unverified app" warning you click through. Publishing this add-on publicly would require Google's restricted-scope verification and an annual security assessment, so keep it unpublished.

If your OAuth consent screen is External and in Testing, Google expires the refresh token after 7 days. Move the project to your own Workspace domain (Internal) or re-authorize weekly.

## Install: Chrome extension

1. In Google Cloud Console create an OAuth client of type **Chrome Extension**. It needs the extension ID, which comes from a stable key: generate a key pair, put the public key in `manifest.json` as `"key"`, load the folder unpacked, and read the ID on `chrome://extensions`.
2. Replace `REPLACE_WITH_YOUR_CHROME_EXTENSION_OAUTH_CLIENT_ID` in `browser-extension/manifest.json` with the client id.
3. Add yourself as a test user on the consent screen and enable the Gmail API for the project.
4. Click the toolbar icon on an open email. If the open message cannot be detected (Gmail's page markup is not a public API), pick from the recent-message list instead.

The extension cannot read redirect targets (browsers hide them), so it reports redirect chains as not checked.

## Install: CLI / MCP

See `cli-extension/GEMINI.md`. It is read-only unless `SCANNER_ALLOW_WRITE=1`, and `quarantine_thread` also needs `confirm: true`.

## Develop

```
npm test            # sync check + core + add-on + extension + CLI tests, no installs needed
npm run sync-core   # after editing core/scanner-core.js
```

The add-on tests run the real `.gs` files in a sandbox with no global `URL`, `atob`, `fetch` or `Buffer`, like Apps Script. They cannot prove behavior against live Gmail: do the checklist in `docs/DEPLOY_CHECKLIST.md` once on a test account.

## Privacy

Nothing is stored except your settings (property store) and a cache of verdicts (6 hours). When enabled, link URLs go to Google Safe Browsing, domain names go to rdap.org, attachment hashes go to VirusTotal, and passive scans send HEAD requests to known URL shorteners only. Deep Scan requests every link in the message from Google's servers, which tells the sender someone opened it.

More: `docs/ADR-001-shared-core-and-scopes.md`, `docs/DEBUG_REPORT.md`, `docs/AUTOMATION.md`.
