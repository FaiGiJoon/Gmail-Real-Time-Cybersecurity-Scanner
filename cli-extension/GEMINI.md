# Gmail Cybersecurity Scanner: Gemini CLI Extension

This extension enables real-time cybersecurity auditing of your Gmail inbox directly from the Gemini CLI using the Model Context Protocol (MCP).

## Tools Available

### `get_threat_report`
Fetches a list of recent high-risk threads based on attachments or suspicious keywords.
- **Parameters:** `maxResults` (number, default: 10)

### `analyze_thread_security`
Performs a deep-dive security analysis of a specific thread, calculating a security score based on headers, authentication (SPF/DKIM/DMARC), and body content.
- **Parameters:** `threadId` (string, required)

### `quarantine_thread`
Moves a suspicious thread to the Spam folder and applies the "Security Review" label.
- **Parameters:** `threadId` (string, required)

## Usage Instructions for Gemini

- **Threat Hunting:** Start by running `get_threat_report` to identify potential targets for audit.
- **Deep Analysis:** For any suspicious thread, use `analyze_thread_security` to see the composite security score ($S = 100 - \sum w_i \cdot I_i$).
- **Mitigation:** If a thread is confirmed as malicious, use `quarantine_thread` to isolate it.
- **Policy:** Always prioritize "Privacy-by-Design". Do not output full email bodies unless explicitly requested for forensic analysis.

## Configuration

To use this extension, ensure the following environment variables are set:
- `GMAIL_CLIENT_ID`
- `GMAIL_CLIENT_SECRET`
- `GMAIL_REFRESH_TOKEN`
- `GMAIL_REDIRECT_URI`

Register the server in your `settings.json`:
```json
{
  "mcpServers": {
    "gmail-security": {
      "command": "node",
      "args": ["/path/to/cli-extension/index.js"]
    }
  }
}
```
