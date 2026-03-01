#!/usr/bin/env node
/**
 * Simple MCP Echo Server for testing PII blocking.
 * It has one tool "echo" that returns whatever you send it.
 * This lets us verify the extension blocks PII before it reaches this server.
 */

const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const { StdioServerTransport } = require("@modelcontextprotocol/sdk/server/stdio.js");
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require("@modelcontextprotocol/sdk/types.js");
const fs = require("fs");

const LOG_FILE = "/tmp/mcp-echo-server.log";

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  fs.appendFileSync(LOG_FILE, line);
}

const server = new Server(
  { name: "echo-test-server", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

// List tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "echo",
        description: "Echoes back whatever text you provide. Use this to test PII blocking.",
        inputSchema: {
          type: "object",
          properties: {
            text: {
              type: "string",
              description: "The text to echo back"
            }
          },
          required: ["text"]
        }
      },
      {
        name: "store_user_info",
        description: "Stores user information (name, email, SSN, etc). Use this to test PII blocking with structured data.",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string", description: "User full name" },
            email: { type: "string", description: "User email address" },
            ssn: { type: "string", description: "Social security number" },
            notes: { type: "string", description: "Additional notes about the user" }
          },
          required: ["name"]
        }
      }
    ]
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  
  log(`TOOL CALLED: ${name} | ARGS: ${JSON.stringify(args)}`);
  
  if (name === "echo") {
    return {
      content: [{ type: "text", text: `Echo: ${args.text}` }]
    };
  }
  
  if (name === "store_user_info") {
    // If we get here, PII was NOT blocked — log it prominently
    log(`⚠️ WARNING: store_user_info received with data: ${JSON.stringify(args)}`);
    return {
      content: [{ type: "text", text: `Stored user: ${JSON.stringify(args)}` }]
    };
  }

  return {
    content: [{ type: "text", text: `Unknown tool: ${name}` }],
    isError: true,
  };
});

async function main() {
  log("=== Echo Test MCP Server starting ===");
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log("Server connected via stdio");
}

main().catch((err) => {
  log(`FATAL: ${err.message}`);
  process.exit(1);
});
