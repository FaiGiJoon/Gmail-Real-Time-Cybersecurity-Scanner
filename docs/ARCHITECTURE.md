# System Architecture

## Overview

The **Gmail Real-Time Cybersecurity Scanner** provides native, production-grade email security threat hunting and automated analysis for Claude Code sessions via a Model Context Protocol (MCP) server.

The architecture follows an **In-Situ Defense** philosophy: email content, attachments, and MIME headers are processed exclusively in volatile memory without persistent disk storage or unauthorized external data leakage.

```
                    ┌───────────────────────────────┐
                    │      Claude Code Agent        │
                    └───────────────┬───────────────┘
                                    │ (stdio / MCP)
                                    ▼
                    ┌───────────────────────────────┐
                    │    TypeScript MCP Server      │
                    │         (Bun Runtime)         │
                    └───────────────┬───────────────┘
                                    │
       ┌────────────────────────────┼────────────────────────────┐
       ▼                            ▼                            ▼
┌───────────────┐          ┌───────────────────┐        ┌──────────────────┐
│ Email Scanner │          │    URL Scanner    │        │Attachment Scanner│
├───────────────┤          ├───────────────────┤        ├──────────────────┤
│• MIME Headers │          │• Homograph (xn--) │        │• SHA-256 / MD5   │
│• Alignment    │          │• Typosquatting    │        │• Magic Bytes     │
│• BEC & Drift  │          │• Link Mismatch    │        │• Double Extension│
│• Injection    │          │• IP Hostnames     │        │• PDF Traits      │
│• Multiplier   │          │• Safe Browsing    │        │• VirusTotal      │
└───────────────┘          └───────────────────┘        └──────────────────┘
```

---

## Defense-in-Depth Layers

1. **Passive Header Analysis:** Evaluates SPF, DKIM, DMARC authentication status, display name alignment against internal domain (`INTERNAL_DOMAIN`), VIP impersonation, and Received header relay paths against known untrusted ASNs (`AS13335`, `AS15169`, `AS40022`).
2. **Active Link Inspection:** Extracts hyperlinks from email bodies, checks Punycode homographs (`xn--`), calculates typosquatting Levenshtein edit distance against popular brands, detects anchor text domain mismatches, raw IP hostnames, hidden links (CSS `display:none` or `opacity:0`), and queries Google Safe Browsing.
3. **Content Heuristics & AI Defense:** Analyzes linguistic drift, high-pressure BEC lures (wire transfers, credential resets, invoice demands), synthetic pattern cues, and neutralizes LLM prompt injection attempts ("Shield-Layer").
4. **Attachment Forensics:** Computes cryptographic SHA-256 and MD5 file digests, verifies binary magic bytes (PDF, ZIP, DOCX, XLSX, EXE, PNG, JPEG, GIF, 7Z, LNK, RTF), detects double extension spoofs (`.pdf.exe`), scans PDF structures for embedded scripts/launch actions, and queries VirusTotal threat feeds.
5. **Non-Linear Threat Escalation:** Uses a baseline score formula with non-linear multipliers ($M$):
   - **Critical Combo ($1.5\times$):** Triggered when a DMARC failure coincides with a malicious URL or homograph attack.
   - **High Voltage ($1.25\times$):** Triggered by high-pressure BEC keywords originating from an unverified sender.

---

## Technical Stack & Runtime

- **Runtime:** Bun v1.2+
- **Language:** TypeScript (strict mode `strict: true`)
- **Protocol:** Model Context Protocol (MCP) via `@modelcontextprotocol/sdk`
- **Validation:** Zod schemas
- **Logging:** Structured PII-masking logger
