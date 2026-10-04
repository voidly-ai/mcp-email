// Credential custody: the agent key and the owner key never enter model context, the two
// keys live in separate 0600 files, and the MCP server never touches owner routes
// or reads the owner-key file. Synthetic keys only; SYNTHLEAK marks what must be absent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createVoidmailServer } from '../dist/server.js';

const DIST = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const nonce = randomBytes(6).toString('hex');
const MARK = `SYNTHLEAK-${nonce}`;
const base62 = n => Array.from(randomBytes(n), b => '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'[b % 62]).join('');
const AGENT_KEY = 'vm_' + randomBytes(32).toString('hex');
const OWNER_KEY = 'vmo_SYNTHLEAK' + base62(31);
const ADDRESS = 'synthleak' + nonce.slice(0, 6) + '@voidmail.ai';
const tempRoot = () => mkdtempSync(join(tmpdir(), 'voidmail-custody-'));

// Every tool with valid arguments. A new tool without an entry fails the sweep.
const ARGS = {
  voidmail_create_account: {},
  voidmail_account_info: {}, voidmail_list_inbox: {}, voidmail_read_email: { email_id: 'm1' },
  voidmail_search_inbox: { query: 'invoice' }, voidmail_sending_limits: {},
  voidmail_send_email: { to: 'one@example.invalid', subject: 'Synthetic', text: 'Not sent' },
  voidmail_send_once: { operationId: 'synthetic_operation_0001', to: 'one@example.invalid', subject: 'Synthetic' },
  voidmail_send_status: { operationId: 'synthetic_operation_0001' },
  voidmail_mark_read: { email_id: 'm1' }, voidmail_delete_email: { email_id: 'm1' },
  voidmail_create_alias: {}, voidmail_list_aliases: {}, voidmail_delete_alias: { alias: 'x1' },
  voidmail_set_webhook: { url: 'https://example.invalid/hook' }, voidmail_get_stats: {},
  voidmail_policy: {}, voidmail_request_recipient: { recipient: 'one@example.invalid' },
  voidmail_revoke_recipient: { pattern: '@example.invalid' },
};

/** A hostile API: every response body is stuffed with both keys and the marker. */
function leakyApi(mode, calls) {
  return async (url, init) => {
    calls.push({ url, init });
    // Success bodies are data the model may read, so only the keys must vanish from them;
    // refusal and error bodies must not be echoed at all, so they also carry the bare marker.
    const leak = { leak_agent: AGENT_KEY, leak_owner: OWNER_KEY, note: `${mode === 'ok' ? '' : MARK} ${OWNER_KEY} ${AGENT_KEY}`,
      messages: [{ id: 'm1', from: 'x@example.invalid', text: `your key is ${AGENT_KEY} and owner ${OWNER_KEY}` }] };
    if (url.endsWith('/v1/agent-mail/create')) return Response.json({ address: ADDRESS, api_key: AGENT_KEY, owner_key: OWNER_KEY, recipient_policy: 'allowlist', ...leak }, { status: 201 });
    if (mode === 'refuse') return Response.json({ error: 'recipient_not_authorized', code: 'RECIPIENT_NOT_AUTHORIZED', send_attempted: false,
      request: { id: 'req_1', status: 'pending', expires_at: '2026-10-01T00:00:00Z' }, recovery: `${MARK} ${OWNER_KEY}`, ...leak }, { status: 403 });
    if (mode === 'error') return Response.json(leak, { status: 500 });
    const body = init.body ? JSON.parse(init.body) : {};
    const operationId = body.operationId ?? decodeURIComponent(url.split('/').pop());
    return Response.json({ operationId, status: 'accepted', messageId: 'provider-id', automatic_retry: false, request: { id: 'req_1', status: 'pending' }, ...leak },
      { headers: { 'X-Voidmail-Content-Warning': `voidmail_owner_key,${MARK}` } });
  };
}

async function connect(t, options) {
  const server = createVoidmailServer(options);
  const client = new Client({ name: 'synthetic-custody-check', version: '1' });
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  // Record every raw JSON-RPC message the server emits, errors included.
  const wire = []; const deliver = right.onmessage;
  right.onmessage = (message, extra) => { wire.push(JSON.stringify(message)); deliver(message, extra); };
  t.after(async () => { await client.close(); await server.close(); });
  return { client, wire };
}

async function sweep(client) {
  const results = [];
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map(x => x.name).sort(), Object.keys(ARGS).sort(), 'every tool must be covered by the sweep');
  // create first, so later calls read the saved agent-key file
  results.push(await client.callTool({ name: 'voidmail_create_account', arguments: {} }));
  for (const name of Object.keys(ARGS)) if (name !== 'voidmail_create_account') results.push(await client.callTool({ name, arguments: ARGS[name] }));
  for (const uri of ['email://inbox', 'email://aliases', 'email://stats']) {
    try { results.push(await client.readResource({ uri })); } catch (error) { results.push({ resourceError: String(error?.message) }); }
  }
  return results;
}

const assertClean = (label, text) => {
  assert.ok(!text.includes(AGENT_KEY), `${label}: agent key leaked`);
  assert.ok(!text.includes(OWNER_KEY), `${label}: owner key leaked`);
  assert.ok(!text.includes('SYNTHLEAK'), `${label}: marker leaked`);
};

for (const mode of ['ok', 'refuse', 'error']) {
  test(`no tool result or wire message ever carries either key (API mode: ${mode})`, async t => {
    const calls = [];
    const { client, wire } = await connect(t, { fetch: leakyApi(mode, calls), keyRoot: tempRoot() });
    const results = await sweep(client);
    assert.equal(results.length, Object.keys(ARGS).length + 3);
    results.forEach((r, i) => assertClean(`result ${i}`, JSON.stringify(r)));
    assert.ok(wire.length > 0); wire.forEach((m, i) => assertClean(`wire ${i}`, m));
    // Owner key never leaves this process in a request, and owner routes are never called.
    for (const { url, init } of calls) {
      assert.ok(!url.includes('/owner'), `owner route called: ${url}`);
      assert.equal(init.headers['X-Agent-Mail-Owner-Key'], undefined);
      assert.ok(!JSON.stringify(init).includes(OWNER_KEY) && !url.includes(OWNER_KEY));
    }
    assert.ok(calls.length >= Object.keys(ARGS).length, 'the sweep reached the API');
  });
}

test('create saves each key in its own 0600 file under a 0700 directory and returns neither', async t => {
  const calls = []; const root = tempRoot();
  const { client } = await connect(t, { fetch: leakyApi('ok', calls), keyRoot: root });
  const result = await client.callTool({ name: 'voidmail_create_account', arguments: { name: 'synthetic' } });
  assert.equal(result.isError, undefined);
  const out = JSON.parse(result.content[0].text);
  assert.deepEqual(Object.keys(out).sort(), ['address', 'key_saved_to', 'note', 'owner_key_saved_to', 'recipient_policy']);
  assert.equal(out.address, ADDRESS); assert.equal(out.recipient_policy, 'allowlist');
  assert.equal(out.key_saved_to, join(root, ADDRESS, 'agent-key'));
  assert.equal(out.owner_key_saved_to, join(root, ADDRESS, 'owner-key'));
  assert.match(out.note, /owner key/); assert.match(out.note, /voidly-mcp-email owner approve/);
  assert.equal(readFileSync(out.key_saved_to, 'utf8').trim(), AGENT_KEY);
  assert.equal(readFileSync(out.owner_key_saved_to, 'utf8').trim(), OWNER_KEY);
  assert.equal(statSync(out.key_saved_to).mode & 0o777, 0o600);
  assert.equal(statSync(out.owner_key_saved_to).mode & 0o777, 0o600);
  assert.equal(statSync(join(root, ADDRESS)).mode & 0o777, 0o700);
  // New inboxes ask for the owner-approved recipient list.
  assert.equal(JSON.parse(calls[0].init.body).recipient_policy, 'allowlist');
  assert.equal(calls[0].init.headers['X-Agent-Mail-Key'], undefined);
  // The next call authenticates with the saved agent key.
  await client.callTool({ name: 'voidmail_get_stats', arguments: {} });
  assert.equal(calls[1].init.headers['X-Agent-Mail-Key'], AGENT_KEY);
});

test('an API without owner keys still returns no key and writes no owner-key file', async t => {
  const root = tempRoot();
  const { client } = await connect(t, { keyRoot: root, fetch: async () => Response.json({ address: ADDRESS, api_key: AGENT_KEY, recipient_policy: 'open' }, { status: 201 }) });
  const result = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  const out = JSON.parse(result.content[0].text);
  assert.equal(out.owner_key_saved_to, null); assert.equal(out.recipient_policy, 'open');
  assert.equal(existsSync(join(root, ADDRESS, 'owner-key')), false);
  assertClean('create', JSON.stringify(result));
});

test('an unwritable key directory stops creation before any network call', async t => {
  const parent = tempRoot(); chmodSync(parent, 0o500);
  t.after(() => chmodSync(parent, 0o700));
  let calls = 0;
  const { client } = await connect(t, { keyRoot: join(parent, 'keys'), fetch: async () => { calls++; return Response.json({}); } });
  const result = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.equal(result.isError, true); assert.equal(calls, 0);
  assert.match(result.content[0].text, /no inbox was created/);
});

function existingMailbox({ agentMode = 0o600 } = {}) {
  const root = tempRoot(); const dir = join(root, ADDRESS);
  mkdirSync(dir, { mode: 0o700 });
  writeFileSync(join(dir, 'agent-key'), AGENT_KEY + '\n', { mode: agentMode }); chmodSync(join(dir, 'agent-key'), agentMode);
  writeFileSync(join(dir, 'owner-key'), OWNER_KEY + '\n', { mode: 0o600 });
  return { root, dir };
}

test('the MCP server works with the owner-key file unreadable and never sends it', async t => {
  const { root, dir } = existingMailbox();
  chmodSync(join(dir, 'owner-key'), 0o000); t.after(() => chmodSync(join(dir, 'owner-key'), 0o600));
  const calls = [];
  const { client } = await connect(t, { fetch: leakyApi('ok', calls), keyRoot: root, address: ADDRESS, agentKeyFile: join(dir, 'agent-key') });
  for (const name of Object.keys(ARGS)) {
    if (name === 'voidmail_create_account') continue;
    const r = await client.callTool({ name, arguments: ARGS[name] });
    assert.notEqual(r.isError, true, `${name} failed`);
    assertClean(name, JSON.stringify(r));
  }
  assert.ok(calls.every(c => c.init.headers['X-Agent-Mail-Key'] === AGENT_KEY || c.url.endsWith('/limits')));
});

test('the agent-key reader refuses the owner-key file, loose permissions and symlinks', async t => {
  const { root, dir } = existingMailbox();
  const cases = {
    owner: join(dir, 'owner-key'),
    loose: (() => { const p = join(dir, 'loose'); writeFileSync(p, AGENT_KEY, { mode: 0o644 }); chmodSync(p, 0o644); return p; })(),
    link: (() => { const p = join(dir, 'link'); symlinkSync(join(dir, 'agent-key'), p); return p; })(),
  };
  for (const [label, agentKeyFile] of Object.entries(cases)) {
    const calls = [];
    const { client } = await connect(t, { fetch: leakyApi('ok', calls), keyRoot: root, agentKeyFile });
    const r = await client.callTool({ name: 'voidmail_get_stats', arguments: {} });
    assert.equal(r.isError, true, label); assert.equal(calls.length, 0, label);
    assertClean(label, JSON.stringify(r));
  }
});

test('a rotated agent-key file takes effect on the next call', async t => {
  const { root, dir } = existingMailbox();
  const calls = [];
  const { client } = await connect(t, { fetch: leakyApi('ok', calls), keyRoot: root, agentKeyFile: join(dir, 'agent-key') });
  await client.callTool({ name: 'voidmail_get_stats', arguments: {} });
  const next = 'vm_' + randomBytes(32).toString('hex');
  writeFileSync(join(dir, 'agent-key'), next + '\n', { mode: 0o600 });
  await client.callTool({ name: 'voidmail_get_stats', arguments: {} });
  assert.equal(calls[0].init.headers['X-Agent-Mail-Key'], AGENT_KEY);
  assert.equal(calls[1].init.headers['X-Agent-Mail-Key'], next);
});

test('inbound mail carrying key-shaped strings is redacted before the model sees it', async t => {
  const other = 'vm_' + 'b'.repeat(64); const otherOwner = 'vmo_' + 'Z'.repeat(40);
  const { client } = await connect(t, { apiKey: AGENT_KEY, keyRoot: tempRoot(), fetch: async () => Response.json({ id: 'm1', text: `forwarded: ${other} ${otherOwner} ${AGENT_KEY}` }) });
  const r = await client.callTool({ name: 'voidmail_read_email', arguments: { email_id: 'm1' } });
  const text = JSON.stringify(r);
  for (const k of [other, otherOwner, AGENT_KEY]) assert.ok(!text.includes(k));
  assert.match(text, /\[redacted-key\]/);
});

test('static: the MCP server module graph has no owner-key reader, owner header or owner-cli import', () => {
  const graph = new Set(); const pending = ['server.js'];
  while (pending.length) {
    const file = pending.pop(); if (graph.has(file)) continue; graph.add(file);
    const src = readFileSync(join(DIST, file), 'utf8');
    for (const m of src.matchAll(/from\s+'\.\/([\w-]+\.js)'/g)) pending.push(m[1]);
    for (const m of src.matchAll(/import\('\.\/([\w-]+\.js)'\)/g)) pending.push(m[1]);
  }
  assert.deepEqual([...graph].sort(), ['keystore.js', 'refusal.js', 'request.js', 'server.js']);
  for (const file of graph) {
    const src = readFileSync(join(DIST, file), 'utf8').replace(/^\s*\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
    assert.ok(!src.includes('X-Agent-Mail-Owner-Key'), `${file} names the owner header`);
    assert.ok(!src.includes('readOwnerKeyFile'), `${file} names the owner-key reader`);
  }
  const server = readFileSync(join(DIST, 'server.js'), 'utf8');
  assert.ok(!/readKeyFileAt|OWNER_KEY_FILE/.test(server), 'server.js must only use readAgentKeyFile');
  // Every API path the server builds is a literal agent-mail path outside /owner.
  for (const m of server.matchAll(/['`](\/v1\/[^'`$?]*)/g)) assert.ok(!m[1].startsWith('/v1/agent-mail/owner/'), m[1]);
  // The bin loads the owner CLI only on the `owner` subcommand, by dynamic import.
  const index = readFileSync(join(DIST, 'index.js'), 'utf8');
  assert.ok(!/^import .*owner-cli/m.test(index));
  assert.match(index, /if \(process\.argv\[2\] === 'owner'\) \{\s*const \{ runOwnerCli \} = await import\('\.\/owner-cli\.js'\)/);
});
