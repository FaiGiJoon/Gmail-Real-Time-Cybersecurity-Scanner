# Security & Privacy Policy

## In-Situ Defense Framework

The **Gmail Real-Time Cybersecurity Scanner** is built on strict **Privacy-by-Design** principles:

1. **Volatile Memory Processing:** No email content, body text, MIME headers, or attachment binary payload data is saved to disk or persistent databases.
2. **PII Masking:** Terminal logs and structured output automatically redact email addresses (`u***r@d***n.com`) and authentication keys (`[REDACTED_KEY]`).
3. **Credential Isolation:** API keys and environment configurations are isolated using `.env` templates and runtime environment variables. No secrets or tokens are stored in source code.
4. **Passive Threat Inspection:** The scanner performs passive threat inspection and scoring. Active counter-attacks, credential injection into phishing forms, or destructive actions are strictly disallowed.

---

## Input Validation & Security Controls

- **Zod Schema Enforcement:** All incoming MCP tool arguments and payload fields are parsed and validated using strict Zod schemas prior to execution.
- **ReDoS Protection:** Regular expressions in `constants.ts` are guarded against catastrophic backtracking / Denial of Service.
- **Type Safety:** The TypeScript compiler enforces `strict: true` across all modules.

---

## Vulnerability Disclosure

If you discover a security vulnerability or potential threat engine bypass, please report it privately to the project security maintainers.
