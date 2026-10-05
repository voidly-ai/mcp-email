import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const manifest = JSON.parse(readFileSync(new URL('../server.json', import.meta.url), 'utf8'));

test('local Registry manifest names this exact npm release and stdio transport', () => {
  assert.equal(packageJson.mcpName, manifest.name);
  assert.equal(packageJson.name, '@voidly/mcp-email');
  assert.equal(packageJson.version, manifest.version);
  assert.equal(manifest.packages.length, 1);
  assert.equal(manifest.packages[0].registryType, 'npm');
  assert.equal(manifest.packages[0].identifier, packageJson.name);
  assert.equal(manifest.packages[0].version, packageJson.version);
  assert.equal(manifest.packages[0].transport.type, 'stdio');
  assert.equal(manifest.remotes?.length ?? 0, 0);
});
