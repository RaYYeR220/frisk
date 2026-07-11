/** MCP stdio entrypoint — runs Frisk as an MCP server other agents can call. */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createMcpServer } from "./mcp.js";

const server = createMcpServer();
await server.connect(new StdioServerTransport());
