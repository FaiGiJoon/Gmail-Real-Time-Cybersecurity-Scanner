import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema
} from '@modelcontextprotocol/sdk/types.js';
import { TOOLS, handleToolCall } from './tools/index.ts';
import { logger } from './utils/logger.ts';

async function main() {
  logger.info("Initializing Gmail Cybersecurity Scanner MCP Server...");

  const server = new Server(
    {
      name: "gmail-security-scanner",
      version: "1.2.0"
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // Register tool list request handler
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: TOOLS };
  });

  // Register tool execution call handler
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    return await handleToolCall(name, args);
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info("Gmail Cybersecurity Scanner MCP Server active and listening on stdio.");
}

main().catch((err) => {
  logger.error("Fatal error starting MCP Server:", err);
  process.exit(1);
});
