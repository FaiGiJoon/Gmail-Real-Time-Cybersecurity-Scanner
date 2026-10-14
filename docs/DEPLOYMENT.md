# Deployment & Setup Guide

## Prerequisites

- **Bun Runtime:** Bun v1.2.0 or higher.
- **Node.js:** v18+ (optional, for legacy script execution).
- **TypeScript:** Built-in TypeScript support in Bun.

---

## Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/FaiGiJoon/Gmail-Real-Time-Cybersecurity-Scanner.git
   cd Gmail-Real-Time-Cybersecurity-Scanner
   ```

2. **Install Dependencies with Bun:**
   ```bash
   bun install
   ```

3. **Configure Environment Variables:**
   Copy `.env.example` to `.env` and populate optional API keys:
   ```bash
   cp .env.example .env
   ```

   `.env` configuration options:
   ```env
   SAFE_BROWSING_API_KEY=your_google_safe_browsing_key
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   CLOUD_VISION_API_KEY=your_cloud_vision_key
   LOG_LEVEL=info
   INTERNAL_DOMAIN=spotify.com
   VIP_NAMES=Daniel Ek,Martin Lorentzon,Paul Vogel
   ```

---

## Running the MCP Server

Start the stdio MCP server for agent execution:

```bash
bun run start
```

Or run directly:

```bash
bun run src/index.ts
```

---

## Claude Code Configuration (`.mcp.json` / `claude.json`)

To connect the MCP server to your local Claude Code session, add the server configuration to your project or global `claude.json`:

```json
{
  "mcpServers": {
    "gmail-security-scanner": {
      "command": "bun",
      "args": ["run", "src/index.ts"],
      "cwd": "/path/to/Gmail-Real-Time-Cybersecurity-Scanner",
      "env": {
        "LOG_LEVEL": "info",
        "INTERNAL_DOMAIN": "spotify.com"
      }
    }
  }
}
```

---

## Testing Verification

Run the test suite using Bun's test runner:

```bash
bun test
```

To run legacy node test suites:

```bash
bun run test:legacy
```
