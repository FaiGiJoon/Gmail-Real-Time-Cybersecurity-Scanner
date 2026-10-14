---
name: gmail-security-scanner
description: In-Situ Gmail cybersecurity scanner, threat hunting engine, and GCP workspace security auditor for Claude Code. Enables real-time threat analysis, authentication verification, quishing detection, attachment malware hashing, and GCP IAM auditing.
version: 1.2.0
author: Workspace Security Team
capabilities:
  - passive-header-analysis
  - active-link-inspection
  - linguistic-drift-detection
  - quishing-qr-scan
  - attachment-forensics
  - gcp-iam-audit
  - thread-quarantine
---

# Gmail Security Scanner & Workspace Auditor Skill

## Skill Overview

This skill equips Claude Code with deep email security analysis and Google Cloud Platform (GCP) auditing capabilities using the Model Context Protocol (MCP) server and standalone CLI utilities.

The underlying engine operates under an **In-Situ Defense** philosophy: zero persistent storage of email content or personally identifiable information (PII). All data processing takes place within volatile memory during runtime execution.

---

## Defense-in-Depth Architecture

The scanner applies five layered defense mechanisms:

1. **Passive Header Analysis:** Evaluates SPF, DKIM, and DMARC authentication status, reverse-chain `Received` headers, and delivery path alignment against known CIDR blocks and trusted relays.
2. **Active Link Inspection:** Tracks recursive HTTP/HTTPS redirect chains up to 5 hops, detects homographs and Punycode (`xn--`), calculates typosquatting Levenshtein edit distance, flags hidden links (CSS `display:none` or `opacity:0`), and identifies Shadow-Links traversing multiple domains.
3. **Content Heuristics:** Detects linguistic drift, high-pressure lures (wire transfers, credential resets, invoice demands), Business Email Compromise (BEC) patterns, and LLM prompt injection attempts ("Shield-Layer").
4. **Attachment Sandboxing & OCR:** Verifies file magic bytes (PDF, ZIP, PNG, JPG, GIF, 7Z, DOCX, XLSX, LNK, RTF) to catch double extension spoofs, extracts OCR text and embedded QR codes ("Quishing"), and auto-decrypts protected archives using body password extraction ("Key-Hunter").
5. **State Persistence & Rate Protection:** Uses `CacheService` and `PropertiesService` checkpointing to prevent duplicate scans and mitigate high-volume mail-bombing attacks.

---

## Skill Capabilities & MCP Tools

When connected via Model Context Protocol (MCP), Claude Code can invoke the following tools:

### 1. `get_threat_report`
Fetches a list of recent high-risk Gmail email threads matching security indicators.
- **Input Parameters:**
  - `maxResults` (number, optional, default: 10): Maximum number of threads to return.
- **Returns:** JSON summary of high-risk threads including snippet, message metadata, and thread IDs.

### 2. `analyze_thread_security`
Performs a comprehensive security scan on a specific thread.
- **Input Parameters:**
  - `threadId` (string, required): The target Gmail thread ID.
- **Returns:** Detailed security audit object containing SPF/DKIM/DMARC status, calculated composite security score, detected warnings, typosquatting alerts, and linguistic drift analysis.

### 3. `quarantine_thread`
Isolates a malicious thread by applying the "Security Review" label and moving it to Spam.
- **Input Parameters:**
  - `threadId` (string, required): The target Gmail thread ID.
- **Returns:** Confirmation message of quarantine completion.

### 4. `scan_attachment_malware`
Downloads an attachment from a specific message and computes its SHA-256 hash for forensic analysis.
- **Input Parameters:**
  - `messageId` (string, required): Gmail message ID containing the attachment.
  - `attachmentId` (string, required): Specific attachment identifier.
  - `filename` (string, optional): Attachment original filename.
- **Returns:** SHA-256 hash digest and forensic evaluation guidance.

### 5. `list_gcp_projects`
Lists all Google Cloud Platform projects accessible with current credentials.
- **Input Parameters:** None.
- **Returns:** Array of GCP project metadata objects (project ID, project number, lifecycle state).

### 6. `audit_gcp_project`
Audits the IAM policy and security posture of a target GCP project.
- **Input Parameters:**
  - `projectId` (string, required): GCP project ID.
- **Returns:** Security assessment including IAM bindings, service account roles, and identified misconfigurations or excess privileges.

---

## CLI Commands Reference

Claude Code can execute standalone CLI commands via `cli-extension/index.js` or `npm`:

```bash
# Start MCP Server on stdio (for agent integration)
npm start
# or
node cli-extension/index.js mcp

# List high-risk email threads
node cli-extension/index.js list-threads --max 10

# Perform deep security analysis on a thread
node cli-extension/index.js analyze <threadId>

# Quarantine a confirmed threat thread
node cli-extension/index.js quarantine <threadId>

# List accessible GCP projects
node cli-extension/index.js list-projects

# Audit GCP project IAM security posture
node cli-extension/index.js audit-project <projectId>
```

---

## Google Apps Script API Gateway (`GmailScanner`)

For Google Apps Script add-on contexts, the public API gateway is exposed globally via `index.gs`:

- `GmailScanner.runSecurityScan(message, isDeepScan)`: Runs the multi-layer security scan on a `GmailMessage` instance.
- `GmailScanner.calculateSecurityScore(scanData)`: Computes composite score and threat level.
- `GmailScanner.createSecurityCard(scanData)`: Generates CardService UI elements for Gmail sidebar.
- `GmailScanner.getContextualAddOn(e)`: Main contextual trigger function for Google Apps Script.

---

## Threat Intelligence & Scoring Model

The security score ($S$) is calculated using a non-linear composite formula:

$$S = \max\left(0, 100 - \left(\sum w_i \cdot I_i\right) \cdot M\right)$$

### Indicator Weights ($w_i$)

| Weight ($w_i$) | Threat Indicator ($I_i$) | Severity Level |
| :--- | :--- | :--- |
| 80 | Known Malware / Suspicious PDF Structure | Critical |
| 60 | Malicious / Homograph / Mismatch URL | High |
| 40 | DMARC Authentication Failure | Critical Spoofing |
| 40 | Received Chain Anomaly / Bad ASN | Infrastructure |
| 40 | Brand Impersonation (e.g. Spotify) | Brand Spoofing |
| 35 | Sender Alignment Mismatch | Spoofing |
| 35 | Relay Path Anomaly | Brand Spoofing |
| 30 | VIP Name Impersonation | Social Engineering |
| 25 | Malicious QR Code Link (Quishing) | Quishing |
| 25 | Hidden Link (CSS display:none / opacity:0) | Evasion |
| 25 | Instructional Drift (Prompt Injection) | AI Security |
| 20 | VIP Typosquatting Detection | Social Engineering |
| 5 - 20 | Linguistic Pressure (BEC Lures) | Social Engineering |

### Non-Linear Multipliers ($M$)

- **Critical Combo ($M = 1.5$):** Triggered when a DMARC failure coincides with a malicious or homograph URL.
- **High Voltage ($M = 1.25$):** Triggered when multiple urgent financial/credential lures originate from an unverified sender address.

---

## Claude Code Standard Operational Workflows

### Workflow 1: Threat Hunting & Isolation
1. Execute `get_threat_report` to list unhandled high-risk email threads.
2. For each suspicious thread ID, execute `analyze_thread_security`.
3. Check composite security score ($S$):
   - Score < 40 (High/Critical Threat): Execute `quarantine_thread` to isolate the threat.
   - Score 40 - 70 (Medium Threat): Inspect warnings, authentication status, and linguistic drift details.
   - Score > 70 (Low Threat / Safe): Mark verified.

### Workflow 2: Attachment Forensic Triage
1. When an email contains suspicious files or archives, call `scan_attachment_malware`.
2. Retrieve the generated SHA-256 hash.
3. Compare the hash against threat intelligence databases (VirusTotal, Hybrid Analysis).
4. If malware is confirmed, proceed to quarantine the parent thread using `quarantine_thread`.

### Workflow 3: GCP IAM Security Audit
1. Run `list_gcp_projects` to discover accessible GCP resources.
2. Run `audit_gcp_project` for each active project ID.
3. Review IAM bindings for broad permissions (`roles/owner`, `roles/editor`), external service accounts, or missing MFA requirements.
4. Report remediation steps for identified IAM anomalies.

---

## Local Verification & Unit Testing

When making changes to this codebase, verify all components using the project test suites:

```bash
# 1. Run core Google Apps Script & SecurityEngine unit tests
node run_tests.js

# 2. Run CLI extension & scoring engine tests
cd cli-extension
npm install
npm test
```

Ensure all tests pass before submitting changes or deploying updates.
