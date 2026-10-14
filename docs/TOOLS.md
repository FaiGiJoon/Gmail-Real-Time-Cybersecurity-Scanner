# MCP Core Tools Reference

The Gmail Security Scanner MCP server exposes three primary tools for deep email threat analysis during Claude session execution.

---

## 1. `scan_email_payload`

Ingests raw email payloads, MIME headers, body text, and attachment metadata for multi-layer security auditing and threat scoring.

### Input Parameters (JSON Schema)

```json
{
  "rawEmail": "string (optional)",
  "body": "string (optional)",
  "headers": {
    "from": "string (optional)",
    "to": "string (optional)",
    "subject": "string (optional)",
    "spf": "pass | fail | softfail | neutral | none | unknown",
    "dkim": "pass | fail | none | unknown",
    "dmarc": "pass | fail | none | unknown",
    "received": "array of strings or string (optional)"
  },
  "attachments": [
    {
      "filename": "string (required)",
      "contentType": "string (optional)",
      "size": "number (optional)",
      "data": "string (optional - base64 or raw text)",
      "hash": "string (optional)"
    }
  ],
  "sender": "string (optional)"
}
```

### Response Format Example

```json
{
  "securityScore": 25,
  "threatLevel": "CRITICAL",
  "action": "QUARANTINE",
  "summary": "Email scan completed with score 25/100. Threat Level: CRITICAL. Action: QUARANTINE.",
  "warnings": [
    "DMARC authentication failed",
    "Sender alignment mismatch: claims internal domain 'spotify.com' but sent from 'evil.com'",
    "[URL Risk] Typosquatting detected: potential spoof of 'spotify'"
  ],
  "headerAudit": {
    "spf": "fail",
    "dkim": "fail",
    "dmarc": "fail",
    "senderVerified": false,
    "alignmentMismatch": true,
    "vipImpersonation": false,
    "brandImpersonation": true,
    "badAsnDetected": false,
    "warnings": [ "DMARC authentication failed" ]
  },
  "urlAnalysis": { ... },
  "attachmentAnalysis": { ... },
  "linguisticDrift": {
    "threatDetected": true,
    "scorePenalty": 15,
    "details": [ "High density of urgent pressure keywords detected" ]
  },
  "promptInjectionDetected": false
}
```

---

## 2. `verify_url_reputation`

Evaluates extracted hyperlinks against heuristic risk factors, homographs, typosquatting brands, link-anchor mismatches, and Safe Browsing threat feeds.

### Input Parameters (JSON Schema)

```json
{
  "urls": "string | array of strings (required)",
  "context": "string (optional - anchor text or email body context)"
}
```

### Response Format Example

```json
{
  "summary": {
    "totalUrls": 1,
    "maliciousCount": 1,
    "suspiciousCount": 0,
    "maxRiskScore": 80
  },
  "results": [
    {
      "url": "https://paypa1.com/login",
      "isMalicious": true,
      "isHomograph": false,
      "typosquattedBrand": "paypal",
      "isLinkTextMismatch": false,
      "isIpHostname": false,
      "riskScore": 80,
      "threats": [
        "Typosquatting detected: potential spoof of 'paypal'"
      ]
    }
  ]
}
```

---

## 3. `inspect_attachments`

Computes cryptographic SHA-256 and MD5 file digests, verifies binary magic bytes, detects double extension spoofs, scans PDF structures, and checks VirusTotal feeds.

### Input Parameters (JSON Schema)

```json
{
  "attachments": [
    {
      "filename": "invoice.pdf.exe (required)",
      "contentType": "application/x-msdownload",
      "size": 1024,
      "data": "base64 string..."
    }
  ]
}
```

### Response Format Example

```json
{
  "summary": {
    "totalAttachments": 1,
    "maliciousCount": 1,
    "suspiciousCount": 0
  },
  "results": [
    {
      "filename": "invoice.pdf.exe",
      "contentType": "application/x-msdownload",
      "size": 1024,
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "magicByteMatch": true,
      "detectedType": "EXE",
      "hasDoubleExtension": true,
      "hasExecutableExtension": true,
      "suspiciousTraits": [
        "Double extension spoof detected: 'invoice.pdf.exe' ends with executable extension '.exe'",
        "Executable attachment extension: '.exe'"
      ],
      "threatLevel": "MALICIOUS"
    }
  ]
}
```
