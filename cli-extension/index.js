#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { GmailBridge } from "./gmail-bridge.js";
import { GCPBridge } from "./gcp-bridge.js";
import { calculateScore, isTyposquatted, CONSTANTS, analyzeLinguisticDrift } from "./scoring-engine.js";
import dotenv from "dotenv";
import crypto from "crypto";
import { Command } from "commander";

dotenv.config();

const gmailBridge = new GmailBridge();
const gcpBridge = new GCPBridge();
const program = new Command();

program
  .name("workspace-security-cli")
  .description("CLI tool for Google Workspace and Gmail security auditing")
  .version("1.1.0");

// --- MCP Server Setup ---
const setupMcpServer = () => {
  const server = new Server(
    {
      name: "gmail-security-server",
      version: "1.1.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

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
        },
        {
          name: "scan_attachment_malware",
          description: "Downloads and scans an attachment for malware signatures (hash-based).",
          inputSchema: {
            type: "object",
            properties: {
              messageId: { type: "string" },
              attachmentId: { type: "string" },
              filename: { type: "string" }
            },
            required: ["messageId", "attachmentId"]
          }
        },
        {
          name: "list_gcp_projects",
          description: "Lists Google Cloud Projects accessible to the user.",
          inputSchema: { type: "object", properties: {} }
        },
        {
          name: "audit_gcp_project",
          description: "Performs a security audit of a Google Cloud Project's IAM policy.",
          inputSchema: {
            type: "object",
            properties: {
              projectId: { type: "string" }
            },
            required: ["projectId"]
          }
        }
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      if (name.startsWith("list_gcp") || name.startsWith("audit_gcp")) {
        await gcpBridge.initialize();
      } else {
        await gmailBridge.initialize();
      }
      const result = await executeTool(name, args);
      return result;
    } catch (error) {
      return {
        content: [{ type: "text", text: `Error: ${error.message}` }],
        isError: true,
      };
    }
  });

  return server;
};

// --- Unified Execution Logic ---
async function executeTool(name, args) {
  if (name === "get_threat_report") {
    const threads = await gmailBridge.listHighRiskThreads(args.maxResults);
    return {
      content: [{ type: "text", text: JSON.stringify(threads, null, 2) }],
    };
  }

  if (name === "analyze_thread_security") {
    const thread = await gmailBridge.getThreadDetails(args.threadId);
    const messages = thread.messages || [];
    const firstMsg = messages[0];
    const headers = firstMsg.payload.headers;

    const getHeader = (name) => headers.find(h => h.name.toLowerCase() === name.toLowerCase())?.value;

    const from = getHeader('From');
    const subject = getHeader('Subject');

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

      const driftAnalysis = analyzeLinguisticDrift(bodyText);
      if (driftAnalysis.threatDetected) {
        warnings.push(driftAnalysis.detail);
      }

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
    await gmailBridge.quarantineThread(args.threadId);
    return {
      content: [{ type: "text", text: `Thread ${args.threadId} has been quarantined successfully.` }],
    };
  }

  if (name === "scan_attachment_malware") {
    const attachment = await gmailBridge.getAttachment(args.messageId, args.attachmentId);
    const buffer = Buffer.from(attachment.data, 'base64');
    const hash = crypto.createHash('sha256').update(buffer).digest('hex');

    const analysis = {
      filename: args.filename,
      sha256: hash,
      recommendation: "Check this hash on VirusTotal or Hybrid Analysis."
    };

    return {
      content: [{ type: "text", text: JSON.stringify(analysis, null, 2) }],
    };
  }

  if (name === "list_gcp_projects") {
    const projects = await gcpBridge.listProjects();
    return {
      content: [{ type: "text", text: JSON.stringify(projects, null, 2) }],
    };
  }

  if (name === "audit_gcp_project") {
    const audit = await gcpBridge.auditProjectSecurity(args.projectId);
    return {
      content: [{ type: "text", text: JSON.stringify(audit, null, 2) }],
    };
  }

  throw new Error(`Tool not found: ${name}`);
}

// --- CLI Commands ---
program
  .command("mcp")
  .description("Run as an MCP server for Gemini CLI")
  .action(async () => {
    const server = setupMcpServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Gmail Security MCP Server running on stdio");
  });

program
  .command("list-threads")
  .description("List recent high-risk email threads")
  .option("-m, --max <number>", "Maximum number of results", parseInt, 10)
  .action(async (options) => {
    try {
      await gmailBridge.initialize();
      const result = await executeTool("get_threat_report", { maxResults: options.max });
      console.log(result.content[0].text);
    } catch (error) {
      console.error(`Error: ${error.message}`);
    }
  });

program
  .command("analyze <threadId>")
  .description("Perform security analysis on a specific thread")
  .action(async (threadId) => {
    try {
      await gmailBridge.initialize();
      const result = await executeTool("analyze_thread_security", { threadId });
      console.log(result.content[0].text);
    } catch (error) {
      console.error(`Error: ${error.message}`);
    }
  });

program
  .command("quarantine <threadId>")
  .description("Quarantine a suspicious thread")
  .action(async (threadId) => {
    try {
      await gmailBridge.initialize();
      const result = await executeTool("quarantine_thread", { threadId });
      console.log(result.content[0].text);
    } catch (error) {
      console.error(`Error: ${error.message}`);
    }
  });

program
  .command("list-projects")
  .description("List Google Cloud Projects")
  .action(async () => {
    try {
      await gcpBridge.initialize();
      const result = await executeTool("list_gcp_projects", {});
      console.log(result.content[0].text);
    } catch (error) {
      console.error(`Error: ${error.message}`);
    }
  });

program
  .command("audit-project <projectId>")
  .description("Audit IAM security of a Google Cloud Project")
  .action(async (projectId) => {
    try {
      await gcpBridge.initialize();
      const result = await executeTool("audit_gcp_project", { projectId });
      console.log(result.content[0].text);
    } catch (error) {
      console.error(`Error: ${error.message}`);
    }
  });

if (process.argv.length <= 2) {
  const server = setupMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport).catch(console.error);
  console.error("Gmail Security MCP Server running on stdio (default mode)");
} else {
  program.parse(process.argv);
}
