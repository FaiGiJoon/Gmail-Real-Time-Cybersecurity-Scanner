#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { GmailBridge } from "./gmail-bridge.js";
import { GCPBridge } from "./gcp-bridge.js";
import { createTools } from "./tools.js";
import dotenv from "dotenv";
import { Command } from "commander";

dotenv.config();

const gmailBridge = new GmailBridge();
const gcpBridge = new GCPBridge();
const { tools, execute } = createTools({ gmail: gmailBridge, gcp: gcpBridge });
const program = new Command();

program
  .name("workspace-security-cli")
  .description("Scan Gmail for phishing and malware. Read-only unless SCANNER_ALLOW_WRITE=1.")
  .version("2.0.0");

const setupMcpServer = () => {
  const server = new Server({ name: "gmail-security-server", version: "2.0.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    try {
      await gmailBridge.initialize();
      return await execute(name, args);
    } catch (error) {
      return { content: [{ type: "text", text: `Error: ${error.message}` }], isError: true };
    }
  });
  return server;
};

async function run(name, args) {
  try {
    await gmailBridge.initialize();
    const result = await execute(name, args);
    console.log(result.content[0].text);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exitCode = 1;
  }
}

program.command("mcp").description("Run as an MCP server").action(async () => {
  await setupMcpServer().connect(new StdioServerTransport());
  console.error("Gmail Security MCP Server running on stdio");
});
program.command("scan").description("Scan recent inbox messages").option("-m, --max <number>", "how many", (v) => parseInt(v, 10), 10)
  .action((o) => run("scan_recent", { maxResults: o.max }));
program.command("analyze <threadId>").description("Scan every message in a thread").option("--deep", "also follow every link redirect")
  .action((threadId, o) => run("analyze_thread_security", { threadId, deep: !!o.deep }));
program.command("quarantine <threadId>").description("Move a thread to Spam (needs SCANNER_ALLOW_WRITE=1)").option("--yes", "confirm")
  .action((threadId, o) => run("quarantine_thread", { threadId, confirm: !!o.yes }));

if (process.argv.length <= 2) {
  await setupMcpServer().connect(new StdioServerTransport()).catch(console.error);
  console.error("Gmail Security MCP Server running on stdio (default mode)");
} else {
  program.parse(process.argv);
}
