# Debug report: the six high-severity bugs

| # | Bug | Root cause | Fix | Regression test |
| :-- | :-- | :-- | :-- | :-- |
| 1 | Deep Scan returned cached passive result | Cache lookup ran before `isDeepScan` was considered | Cache key includes mode, version and settings generation | `deep scan is not served from the passive cache` |
| 2 | Failed scan resumed as "clean" | Checkpoint written before scan, never cleared, read back as an empty result | Checkpoint removed; errors return an error card; failures are not cached | `failed fetch yields an error result`, `failed scans are not cached` |
| 3 | Chrome popup always "Secure" | Popup was a mock with `alert()` buttons, scoring engine unused | Popup calls the service worker, which uses Gmail API + shared core; failure shows "NOT checked" | `engine.test.js` (API failure rejects, spoofed mail not green) |
| 4 | Passive scan fetched every link | Redirect expansion ran for all URLs on every open | Passive: known shorteners only, max 5; Deep Scan: max 15; private hosts blocked; manual hop loop with HEAD | `passive scan only expands known shorteners` |
| 5 | Scopes did not match actions | Manifest had `gmail.readonly` but code labeled, spammed and marked read | `gmail.modify` via REST (no `GmailApp`), narrow list asserted by a test | `manifest scopes are narrow and consistent` |
| 6 | Report Phishing only logged | Handler printed to console and claimed success | Creates a real draft to APWG with the original attached; user sends it | `report creates a draft to APWG and sends nothing` |

## Found while fixing
- The add-on relied on global `URL`, which Apps Script does not provide. The tests now run in a sandbox without it.
- `Utilities.unzip` has no password parameter, so the "Key-Hunter" archive cracking could not work. Removed; encrypted archives are detected from the zip header and reported.
- Relay/ASN auditing used a mock ASN function and the deepfake check was a stub. Removed rather than shipped as fake coverage.
- During end-to-end testing a wrong field name (`address` instead of `email`) silently disabled the first-time-sender check. Fixed; the add-on test that scans a benign message now exercises it.
- CLI read only the first message and only top-level text/plain, and hard-coded `senderVerified: true`. Replaced by the core; every message in a thread is scanned.
- `quarantine_thread` was callable by the model with no confirmation. Now needs `confirm: true` and `SCANNER_ALLOW_WRITE=1`.
