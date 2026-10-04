#!/usr/bin/env node
// `voidly-mcp-email`            → the MCP server (agent key only)
// `voidly-mcp-email owner ...`  → the human owner CLI (owner key only)
// The two paths load different modules, so the MCP server process never loads
// the owner-key reader.
import { join } from 'node:path';

if (process.argv[2] === 'owner') {
  const { runOwnerCli } = await import('./owner-cli.js');
  process.exitCode = await runOwnerCli(process.argv.slice(3));
} else {
  const { StdioServerTransport } = await import('@modelcontextprotocol/sdk/server/stdio.js');
  const { createVoidmailServer } = await import('./server.js');
  const { keyRoot, validAddress, AGENT_KEY_FILE } = await import('./keystore.js');
  const env = process.env;
  const address = validAddress(env.VOIDMAIL_ADDRESS) ? env.VOIDMAIL_ADDRESS : null;
  const agentKeyFile = env.VOIDMAIL_AGENT_KEY_FILE || (address ? join(keyRoot(env), address, AGENT_KEY_FILE) : null);
  const server = createVoidmailServer({ apiKey: env.VOIDMAIL_API_KEY || null, agentKeyFile, address, keyRoot: keyRoot(env) });
  server.connect(new StdioServerTransport()).catch(() => {
    console.error('Voidmail MCP transport could not start.');
    process.exitCode = 1;
  });
}
