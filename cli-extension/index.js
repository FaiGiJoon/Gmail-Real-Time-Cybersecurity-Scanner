import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { GmailBridge } from "./gmail-bridge.js";
import { calculateScore, isTyposquatted, CONSTANTS } from "./scoring-engine.js";
import dotenv from "dotenv";

dotenv.config();

const server = new Server(
  {
    name: "gmail-security-server",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

const bridge = new GmailBridge();

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "get_threat_report",
        description: "Fetches a summary of recent high-risk email threads for audit.",
        inputSchema: {
          type: "object",
          properties: {
            maxResults: { type: "number", default: 10 }
          }
        },
      },
      {
        name: "analyze_thread_security",
        description: "Performs a deep security analysis on a specific Gmail thread.",
        inputSchema: {
          type: "object",
          properties: {
            threadId: { type: "string" }
          },
          required: ["threadId"]
        },
      },
      {
        name: "quarantine_thread",
        description: "Isolates a suspicious thread by moving it to Spam and applying a security label.",
        inputSchema: {
          type: "object",
          properties: {
            threadId: { type: "string" }
          },
          required: ["threadId"]
        },
      }
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    await bridge.initialize();

    if (name === "get_threat_report") {
      const threads = await bridge.listHighRiskThreads(args.maxResults);
      return {
        content: [{ type: "text", text: JSON.stringify(threads, null, 2) }],
      };
    }

    if (name === "analyze_thread_security") {
      const thread = await bridge.getThreadDetails(args.threadId);
      const messages = thread.messages || [];
      const firstMsg = messages[0];
      const headers = firstMsg.payload.headers;

      const getHeader = (name) => headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value;

      const from = getHeader('From');
      const subject = getHeader('Subject');

      // Combine snippet and parts of the body if available for better analysis
      let bodyText = firstMsg.snippet || "";
      if (firstMsg.payload.parts) {
          firstMsg.payload.parts.forEach(part => {
              if (part.mimeType === "text/plain" && part.body.data) {
                  bodyText += Buffer.from(part.body.data, 'base64').toString();
              }
          });
      } else if (firstMsg.payload.body && firstMsg.payload.body.data) {
          bodyText += Buffer.from(firstMsg.payload.body.data, 'base64').toString();
      }

      const authHeader = getHeader('Authentication-Results') || '';
      const authStatus = {
        spf: authHeader.match(/spf=(\w+)/)?.[1],
        dkim: authHeader.match(/dkim=(\w+)/)?.[1],
        dmarc: authHeader.match(/dmarc=(\w+)/)?.[1]
      };

      const warnings = [];
      const urls = bodyText.match(CONSTANTS.URL_REGEX) || [];
      urls.forEach(url => {
        const brand = isTyposquatted(url);
        if (brand) warnings.push(`Potential typosquatting detected: URL looks like ${brand} but leads elsewhere.`);
      });

      const score = calculateScore({
        body: bodyText,
        authStatus: authStatus,
        senderVerified: true,
        warnings: warnings
      });

      const analysis = {
        threadId: args.threadId,
        from,
        subject,
        securityScore: score,
        warnings,
        authStatus
      };

      return {
        content: [{ type: "text", text: JSON.stringify(analysis, null, 2) }],
      };
    }

    if (name === "quarantine_thread") {
      await bridge.quarantineThread(args.threadId);
      return {
        content: [{ type: "text", text: `Thread ${args.threadId} has been quarantined successfully.` }],
      };
    }

    throw new Error(`Tool not found: ${name}`);
  } catch (error) {
    return {
      content: [{ type: "text", text: `Error: ${error.message}` }],
      isError: true,
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("Gmail Security MCP Server running on stdio");
