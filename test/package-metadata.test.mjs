import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { VERSION } from '../dist/server.js';

// The official MCP Registry only accepts an npm package whose published
// package.json names the server. 2.0.0 shipped without it, so the Registry
// stayed on 1.2.1.
test('package.json carries the MCP Registry name and matches the served version', () => {
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.equal(pkg.mcpName, 'io.github.voidly-ai/mcp-email');
  assert.equal(pkg.version, VERSION);
  const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
  assert.equal(lock.version, pkg.version);
  assert.equal(lock.packages[''].version, pkg.version);
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  for (const pin of readme.match(/@voidly\/mcp-email@\d+\.\d+\.\d+/g) ?? []) assert.equal(pin, `@voidly/mcp-email@${pkg.version}`);
});
