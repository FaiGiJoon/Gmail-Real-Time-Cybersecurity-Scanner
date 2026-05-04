# Gmail Real-Time Cybersecurity Scanner: Principal Architect’s Documentation

## 1. Project Vision & Architecture

### 1.1 Project Vision
The **Gmail Real-Time Cybersecurity Scanner** represents a proactive, zero-trust defense layer integrated directly into the Google Workspace ecosystem. In an era of autonomous, AI-driven social engineering, traditional perimeter-based security is insufficient. This agent operates within the message lifecycle, performing multi-dimensional analysis of incoming telemetry to neutralize sophisticated email-based threats before they can be weaponized. By leveraging Google’s global threat intelligence via the Safe Browsing V4 API and custom heuristic engines, the scanner provides a deterministic security posture for every interaction.

The core philosophy is **In-Situ Defense**: the analysis happens where the data resides, minimizing data exfiltration and ensuring that security checks are context-aware and executed at the point of ingestion.

### 1.2 Architecture Overview
The system is architected as a serverless Google Workspace Add-on, ensuring low latency and high availability by executing on Google’s distributed Apps Script runtime. The architecture follows a modular pipe-and-filter pattern, optimized for the constraints of the Google Workspace environment:

1.  **Ingestion & Trigger Layer:** The `getContextualAddOn` trigger acts as the primary hook, capturing the `messageId` and metadata context upon user interaction. This ensures scanning is performed "on-demand" and within the user's active context.
2.  **Telemetry Extraction Engine:** The `runSecurityScan` core extracts raw headers (RFC 5322), MIME-encoded body parts (Plain Text and HTML), and attachment metadata. It utilizes the `GmailApp` and `UrlFetchApp` services to aggregate data for analysis.
3.  **Analysis Pipeline:**
    *   **Cryptographic & Header Validation:** Verification of SPF, DKIM, and DMARC status via the `Authentication-Results` header.
    *   **Recursive URI Analysis:** A depth-first traversal of the URI redirect chain. For any given URL $U_0$, the engine follows $n$ redirects such that the final destination $U_n$ is evaluated: $U_0 \rightarrow U_1 \rightarrow \dots \rightarrow U_n$.
*   **Deep Attachment Inspection:** Hash-based reputation checks (VirusTotal) and structural PDF analysis to detect embedded payloads (JavaScript, OpenActions).
    *   **Behavioral Heuristics:** Comparative analysis of sender identity. The system validates that the RFC 5322 `From` address matches the `Reply-To` address and that display name spoofing is absent.
    *   **Linguistic Parsing:** A weight-based keyword analysis engine that identifies high-pressure urgency cues and social engineering triggers.
4.  **Actionable Intelligence & Mitigation:** Results are aggregated into a composite security score $S$, calculated as:
    $$S = 100 - \sum_{i=1}^{k} w_i \cdot I_i$$
    Where $w_i$ is the weight of the $i$-th security indicator and $I_i$ is a boolean flag (0 or 1) representing the presence of a threat.
    The data is then rendered via a contextual Card Service UI, providing the user with real-time "Neutralize" and "Quarantine" capabilities.

5.  **Gemini CLI Extension (Terminal Audit):** A Node.js-based extension for the Gemini CLI using the Model Context Protocol (MCP). It allows security researchers to hunt threats, analyze threads, and quarantine malicious emails directly from the terminal.

## 2. Threat Coverage Matrix

The following matrix defines the scanner’s current and roadmap capabilities across 12 critical cybercrime vectors:

| Threat Vector | Mitigation Strategy | Technical Implementation Detail |
| :--- | :--- | :--- |
| **Phishing** | Recursive URI Analysis | Safe Browsing V4 API integration + iterative `unshortenUrlChain` loop. |
| **Spear-Phishing** | Link-Text Mismatch Detection | Regex-based extraction of `href` attributes and visible text, followed by domain-level string comparison. |
| **Whaling** | Executive Impersonation Guard | Heuristic matching of display names against organizational directory patterns and RFC 5322 address validation. |
| **BEC** | Cross-Header Discrepancy | Strict logical verification of domain parity: $Domain(From) \equiv Domain(ReplyTo)$. |
| **Malware Delivery** | Deep File Inspection | Extension blacklisting + Hash-based reputation (VirusTotal) + PDF structural analysis for embedded payloads. |
| **Quishing** | Visual Link Extraction | Integration with Google Cloud Vision for OCR-based QR code decoding. Extracted URLs are recursively analyzed. |
| **Account Hijacking** | Auth Result Enforcement | State machine validation of DMARC, SPF, and DKIM status within the `Authentication-Results` header. |
| **Identity Theft** | PII Exfiltration Monitoring | Pattern-matching for Social Security Numbers, Credit Card data, and other sensitive PII patterns. |
| **Filter Rule Attacks** | Delivery Path Auditing | Analyzing `Received` headers to detect anomalous hop counts or suspicious intermediary relays. |
| **OAuth Scams** | Scoped Consent Verification | Validating the integrity of the `Authentication-Results` header to ensure OAuth requests originate from verified domains. |
| **Callback Phishing** | Social Engineering Heuristics | NLP-based weighting of "Immediate Action," "Urgent," and "Account Suspended" keyword triggers. |
| **AI-Powered Phishing** | Linguistic Drift Analysis | (Roadmap) LLM-based entropy and sentiment analysis to identify synthetically generated lures. |

## 3. Technical Implementation: Module Deep-Dive

### 3.1 Recursive URI Analysis Engine
The `unshortenUrlChain` function implements a depth-limited iterative loop to resolve URI redirects. This is critical for negating threats that hide behind multiple layers of link shorteners (e.g., Bitly $\rightarrow$ TinyURL $\rightarrow$ Malicious Destination).
*   **Maximum Depth ($d_{max}$):** 5 hops.
*   **Service:** `UrlFetchApp` with `followRedirects: false`.
*   **Logic:** For each hop, the `Location` header is extracted and appended to the analysis chain. Each link in the chain is then independently verified against the Safe Browsing API.
*   **State Tracking:** A `Set` of URLs is maintained to detect and terminate infinite redirect loops.

### 3.2 Security Scoring Algorithm
The security score is a weighted metric designed to provide a "Red/Yellow/Green" status. The deduction logic is formalized as follows:
*   **DMARC Failure:** $-40$ points.
*   **Sender Mismatch:** $-30$ points.
*   **Malicious URL/Phishing:** $-60$ points (Immediate Red Status).
*   **Quishing (Malicious QR URL):** $-25$ points.
*   **Urgent Language Detection:** Weighted deductions based on keyword severity (e.g., Wire Transfer: -20, Urgent: -10).
*   **High-Risk Attachment:** $-20$ points per file.

The final score $S$ is clamped to the range $[0, 100]$. A score $S < 40$ or the presence of a "High Risk" indicator (e.g., Safe Browsing match) results in a `THREAT_LEVEL.RED` classification.

### 3.3 Mitigation Workflows
The scanner provides two primary response actions:
1.  **Neutralize:** Executes `message.getThread().moveToSpam()` and `message.markRead()`. This effectively removes the threat from the user's focus and trains the underlying Gmail spam filters.
2.  **Quarantine:** Applies a `SECURITY_REVIEW_LABEL` to the thread and moves it out of the inbox. This allows for safe, isolated review by security personnel or the user at a later time.

## 4. Technical Stack & Dependencies

*   **Execution Environment:** Google Apps Script (V8 Engine) or Python 3.10+ (for backend analysis engines).
*   **APIs:**
    *   **Gmail API (v1):** For message ingestion and thread management.
    *   **Google Safe Browsing API (v4):** For real-time URI reputation checks.
    *   **Google Cloud Vision API:** For OCR analysis of embedded media.
*   **Authentication:** OAuth 2.0.
*   **Libraries:**
    *   `google-api-python-client` (Python implementation).
    *   `beautifulsoup4` (Python implementation for HTML parsing).
    *   `@modelcontextprotocol/sdk` (Node.js implementation for CLI).

## 5. Secure Installation & Operational Deployment

### 5.1 Google Cloud Platform (GCP) Configuration
1.  **Project Initialization:** Create a new project in the [GCP Console](https://console.cloud.google.com/).
2.  **API Enablement:** Enable the `Gmail API`, `Google Safe Browsing API`, `Google Apps Script API`, and `Cloud Vision API`.
3.  **Credential Provisioning:**
    *   **OAuth 2.0 Client ID:** Create credentials for a "Web Application" or "Desktop App".
    *   **API Key:** Generate a restricted API Key specifically for the Safe Browsing service.

### 5.2 Credential Handling (Python Integration)
When deploying the Python-based Analysis Engine:
*   **credentials.json:** This file contains the Client ID and Client Secret from GCP. It is used to initiate the OAuth flow.
*   **token.json:** This file is generated after the first successful authentication. It contains the access and refresh tokens.
*   **Security Warning:** `token.json` must be stored securely (e.g., encrypted at rest) as it provides direct access to the user's mailbox. Never commit `credentials.json` or `token.json` to version control.

### 5.3 Deployment Steps (Apps Script)
1.  **Manifest Configuration:** Deploy the `appsscript.json` file to the Apps Script project to register the required scopes.
2.  **Property Injection:** Use `PropertiesService` to securely inject the `SAFE_BROWSING_API_KEY` and `CLOUD_VISION_API_KEY`.
3.  **Trigger Setup:** Ensure the contextual trigger is active in the Apps Script project settings.

### 5.4 CLI Extension Setup (MCP)
1.  **Install Dependencies:** Navigate to `cli-extension/` and run `npm install`.
2.  **Environment Setup:** Create a `.env` file with `GMAIL_CLIENT_ID`, `GMAIL_CLIENT_SECRET`, and `GMAIL_REFRESH_TOKEN`.
3.  **MCP Registration:** Add the server to your Gemini CLI `settings.json` as detailed in `cli-extension/GEMINI.md`.

## 6. Operational Guidelines: Legal, Ethical, and Privacy Standards

### 6.1 Architectural Privacy Framework
The scanner is engineered using a **Privacy-by-Design** framework, ensuring that security analysis does not compromise the confidentiality of user communications.
*   **In-Situ Processing:** All computational analysis of email content, including header parsing and linguistic evaluation, is executed within the user's authenticated Google Workspace environment. This ensures that the **Data Residency** remains within the user's controlled tenant.
*   **Zero-Persistence Policy:** The scanner does not maintain a persistent database of email content. Analysis results are transient and exist only within the runtime context of the Add-on sidebar.
*   **Telemetry Anonymization:** URI reputation checks via the Safe Browsing API are performed using k-anonymity-like principles where possible. No user-identifiable metadata (e.g., User-ID, Message-ID) is transmitted during external API calls.

### 6.2 Compliance & Regulatory Alignment
*   **GDPR (General Data Protection Regulation):** The tool serves as a technical measure to ensure the "security of processing" under Article 32. Since data remains within the organizational boundary, it simplifies the **Data Protection Impact Assessment (DPIA)** for enterprise deployments.
*   **CCPA/CPRA (California Consumer Privacy Act):** The scanner does not "sell" or "share" personal information as defined by the CCPA. It functions strictly as a "service provider" capability that enhances user safety.
*   **Ethical Usage Policy:** Use of this scanner for the surveillance or monitoring of third-party communications without explicit authorization is a violation of ethical standards and may violate the **Computer Fraud and Abuse Act (CFAA)** or similar international statutes. Users are mandated to deploy the tool only on accounts where they have legal authority.

## 7. Future-Proofing: The 2026 Defensive Roadmap
For detailed information on future enhancements—including OCR-based Quishing detection and LLM-driven linguistic analysis—please refer to the [ROADMAP_2026.md](ROADMAP_2026.md) document.
