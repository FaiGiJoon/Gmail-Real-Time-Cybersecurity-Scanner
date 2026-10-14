---
name: gmail-security-scanner
description: In-Situ Gmail cybersecurity scanner and threat hunting engine powered by MCP, Bun, and TypeScript. Enables deep email inspection, URL reputation auditing, attachment forensic hashing, prompt injection defense, and non-linear threat scoring.
version: 1.2.0
author: Workspace Security Team
capabilities:
  - scan-email-payload
  - verify-url-reputation
  - inspect-attachments
  - passive-header-audit
  - linguistic-drift-detection
  - prompt-injection-defense
---

# Gmail Cybersecurity Scanner Claude Agent Skill

## Overview

This skill equips Claude Code with deep, native email threat analysis capabilities using a Model Context Protocol (MCP) server built with Bun and TypeScript. Operating under an **In-Situ Defense** framework, the scanner provides zero-persistent storage processing for volatile memory email security analysis.

---

## Capabilities & MCP Tools

### 1. `scan_email_payload`
Ingests raw email payloads, MIME headers, extracted body text, and attachment metadata to perform comprehensive multi-layer threat analysis.
- **Input Parameters:**
  - `rawEmail` (string, optional): Full RFC822 raw email source text.
  - `body` (string, optional): Extracted email body text (HTML or plain text).
  - `headers` (object, optional): Parsed email headers (`from`, `to`, `subject`, `spf`, `dkim`, `dmarc`, `received`).
  - `attachmentHashes` (array of strings, optional): Precomputed hashes.
  - `attachments` (array of objects, optional): Attachment metadata and base64/text content.
  - `sender` (string, optional): Claimed sender email or display name.
- **Output:** Comprehensive JSON threat report including composite security score (0-100), threat classification (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `SAFE`), recommended mitigation action (`QUARANTINE`, `SECURITY_REVIEW`, `FLAG_WARNING`, `ALLOW`), header audit, link reputation analysis, and linguistic drift/prompt injection flags.

### 2. `verify_url_reputation`
Evaluates extracted hyperlinks against heuristic risk factors, homograph Punycode attacks (`xn--`), typosquatting edit distances, link-anchor text mismatches, and Google Safe Browsing threat feeds.
- **Input Parameters:**
  - `urls` (string or array of strings, required): Single URL or list of URLs to analyze.
  - `context` (string, optional): Surrounding anchor text or email body context.
- **Output:** URL risk summary and per-URL breakdown including risk score, homograph flag, typosquatted brand name, link mismatch status, and threat indicators.

### 3. `inspect_attachments`
Computes cryptographic SHA-256 and MD5 file digests, verifies binary magic bytes against file extensions, detects double extension spoofs (e.g. `invoice.pdf.exe`), scans PDF structures for embedded JS or action triggers, and queries VirusTotal feeds.
- **Input Parameters:**
  - `attachments` (array of objects, required): Array of attachment input objects containing `filename`, `contentType`, `size`, `data` (base64 or string), and optional `hash`.
- **Output:** Forensic attachment analysis containing cryptographic digests, magic byte match status, detected binary types, double extension warnings, PDF suspicious traits, and threat levels (`CLEAN`, `SUSPICIOUS`, `MALICIOUS`).

---

## Standard Operational Workflows

### Workflow 1: Suspicious Email Triage & Incident Analysis
1. Extract email headers, sender address, body text, and attachment metadata from target email payload.
2. Invoke `scan_email_payload` with the structured input.
3. Review output threat level and composite security score:
   - **Score < 55 (CRITICAL / HIGH):** Flag for immediate `QUARANTINE`. Highlight identified threat factors (DMARC failure, malicious URL, typosquatting, prompt injection).
   - **Score 55 - 75 (MEDIUM):** Flag for `SECURITY_REVIEW`. Summarize warnings for security analyst review.
   - **Score > 75 (LOW / SAFE):** Flag as verified safe or low warning.

### Workflow 2: Targeted Hyperlink Reputation Audit
1. Extract suspicious URLs or hyperlinks from email body content.
2. Invoke `verify_url_reputation` with the list of extracted URLs and visible anchor text.
3. Evaluate risk scores and domain attributes:
   - Identify Punycode homographs (`xn--`), typosquatted brands (e.g., Levenshtein distance <= 2 from `google`, `spotify`, `paypal`), or anchor text mismatches.
   - Report flagged domains to security telemetry.

### Workflow 3: Attachment Forensic & Malware Analysis
1. Retrieve email attachments and pass binary data/metadata to `inspect_attachments`.
2. Inspect generated SHA-256 and MD5 cryptographic hashes.
3. Verify magic byte alignment (e.g. confirming PDF/ZIP header matches claimed extension).
4. Check for double extension spoofs (`.pdf.exe`, `.docx.vbs`) and PDF embedded scripts.
5. If malware or mismatch is detected, initiate quarantine recommendation.

---

## Safety Constraints & Privacy Guidelines

- **In-Situ Processing:** Email content, attachments, and headers must be processed strictly in volatile runtime memory. No email body text or PII is ever stored on disk or transmitted to unauthorized 3rd-party servers.
- **Credential Isolation:** API keys (Safe Browsing, VirusTotal, Cloud Vision) must be loaded securely via environment variables (`.env`). No tokens or credentials may be hardcoded.
- **PII & Credential Masking:** Structured logs and terminal outputs must mask email addresses (`u***r@d***n.com`), API keys (`[REDACTED_KEY]`), and authentication tokens.
- **Passive Telemetry:** Strictly perform passive inspection and security scoring. Active back-hacking or credential injection is prohibited.
