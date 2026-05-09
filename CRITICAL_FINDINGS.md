# Security Audit & Critical Findings Report

## 1. Security & Bypass Analysis
### 1.1 Recursive URI Bypasses
*   **Finding:** The `unshortenUrlChain` function in `SecurityEngine.gs` only respects the `Location` HTTP header.
*   **Risk:** Attackers can use HTML-based redirects (Meta-Refresh) or JavaScript-based redirects (`window.location`) to bypass the unshortening logic, hiding the final malicious destination from the scanner.
*   **Recommendation:** Implement basic parsing of the response body for `<meta http-equiv="refresh"` and `window.location` patterns during the unshortening process.

### 1.2 Regex Denial of Service (ReDoS)
*   **Finding:** While current regexes are simple, the `LINK_REGEX` has potential for optimization.
*   **Risk:** A specially crafted email with thousands of `<a>` tags or malformed attributes could cause significant execution delays.
*   **Recommendation:** Refactor regexes to avoid nested quantifiers and use more specific character classes.

### 1.3 API Key Hardening
*   **Finding:** `SAFE_BROWSING_API_KEY` has a placeholder in `Constants.gs`, but the logic still allows it to be hardcoded.
*   **Risk:** Hardcoded keys are leaked if the script is shared with other editors.
*   **Recommendation:** Enforce the use of `PropertiesService` for all sensitive API keys. Remove the ability to hardcode keys in `Constants.gs`.

## 2. Robustness & MIME Edge Cases
### 2.1 MIME Complexity & Hidden Payloads
*   **Finding:** The scanner relies on `getPlainBody()` and `getBody()`.
*   **Risk:** Malicious content can be hidden in non-standard MIME parts or using specific charsets (e.g., UTF-7) that `getPlainBody()` might not decode as expected by a security tool.
*   **Recommendation:** Use `getRawContent()` for deep inspection when high risk is detected, and ensure proper charset handling using `Utilities.newBlob(bytes).getDataAsString(charset)`.

### 2.2 Attachment "Magic Byte" Verification
*   **Finding:** Attachment analysis is limited to filename extensions.
*   **Risk:** "Double Extension" attacks (e.g., `invoice.pdf.exe`) or renamed executables (e.g., `malware.exe` renamed to `malware.jpg`) will bypass the current extension-based filter.
*   **Recommendation:** Implement Magic Byte (File Signature) verification for common high-risk types (PDF, ZIP, EXE) to verify the actual file type regardless of extension.

## 3. Execution & Quota Optimization
### 3.1 The 6-Minute Wall (State Management)
*   **Finding:** Scans are atomic and have no persistence.
*   **Risk:** Large threads (50+ messages) will consistently time out, leaving the user unprotected for those threads.
*   **Recommendation:** Implement a "Checkpoint" system using `CacheService` or `PropertiesService` to store the ID of the last scanned message in a thread, allowing subsequent runs to resume.

### 3.2 Safe Browsing Batching
*   **Finding:** Current logic batches URLs within a single scan.
*   **Optimization:** Safe Browsing V4 supports up to 500 entries per request. We can further optimize by global batching if processing multiple messages.

## 4. Logical & Algorithmic Improvements
### 4.1 Non-Linear Scoring (Threat Escalation)
*   **Finding:** The scoring algorithm is strictly additive/subtractive.
*   **Risk:** A combination of a "Fail" DMARC AND a "Malicious" URL is significantly more dangerous than the sum of their individual risks.
*   **Recommendation:** Implement a multiplier effect: $S = 100 - (\sum w_i \cdot I_i) \cdot M$, where $M$ increases based on the presence of high-confidence indicators.

### 4.2 Linguistic False Positives
*   **Finding:** Heuristics are currently keyword-based.
*   **Recommendation:** Use "Instructional Drift Detection" to differentiate between legitimate system alerts (often originating from specific trusted domains) and phishing lures.
