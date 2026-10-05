// The owner CLI reads only the owner-key file, calls only /v1/agent-mail/owner/*,
// never sends or prints the agent key, and never prints the owner key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runOwnerCli } from '../dist/owner-cli.js';
import { createVoidmailServer } from '../dist/server.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

const DIST = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const nonce = randomBytes(6).toString('hex');
const base62 = n => Array.from(randomBytes(n), b => '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'[b % 62]).join('');
const AGENT_KEY = 'vm_' + randomBytes(32).toString('hex');
const OWNER_KEY = 'vmo_SYNTHLEAK' + base62(31);
const ADDRESS = 'owner' + nonce.slice(0, 6) + '@voidmail.ai';
const OWNER = 'https://api.voidly.ai/v1/agent-mail/owner';

function mailbox() {
  const root = mkdtempSync(join(tmpdir(), 'voidmail-owner-')); const dir = join(root, ADDRESS);
  mkdirSync(dir, { mode: 0o700 });
  writeFileSync(join(dir, 'agent-key'), AGENT_KEY + '\n', { mode: 0o600 });
  writeFileSync(join(dir, 'owner-key'), OWNER_KEY + '\n', { mode: 0o600 });
  return { root, dir };
}

async function run(argv, { root, respond = () => Response.json({ ok: true }), env = {}, confirm = async () => false } = {}) {
  const calls = []; const stdout = []; const stderr = [];
  const code = await runOwnerCli(argv, {
    env: { VOIDMAIL_KEY_DIR: root, ...env },
    fetch: async (url, init) => { calls.push({ url, init }); return respond(url, init); },
    stdout: l => stdout.push(l), stderr: l => stderr.push(l), confirm,
  });
  return { code, calls, out: stdout.join('\n'), err: stderr.join('\n') };
}

const EXPECT = [
  [['list'], 'GET', '/policy', undefined],
  [['approve', 'req_123', '--yes'], 'POST', '/requests/req_123/approve', undefined],
  [['deny', 'req_123'], 'POST', '/requests/req_123/deny', undefined],
  [['add', 'Friend@Example.com', '--yes'], 'POST', '/recipients', { pattern: 'friend@example.com' }],
  [['add', '@example.org', '--yes'], 'POST', '/recipients', { pattern: '@example.org' }],
  [['remove', '@example.org'], 'DELETE', '/recipients/%40example.org', undefined],
  [['lock'], 'POST', '/policy', { recipient_policy: 'allowlist', content_policy: 'enforce' }],
  [['unlock', '--yes'], 'POST', '/policy', { recipient_policy: 'open' }],
  [['rotate-agent-key'], 'POST', '/rotate-agent-key', undefined],
  [['rotate-owner-key'], 'POST', '/rotate-owner-key', undefined],
];

test('every owner command calls exactly one owner route with only the owner key, agent-key file unreadable', async t => {
  const { root, dir } = mailbox();
  chmodSync(join(dir, 'agent-key'), 0o000); t.after(() => chmodSync(join(dir, 'agent-key'), 0o600));
  for (const [argv, method, path, body] of EXPECT) {
    const fresh = { api_key: 'vm_' + randomBytes(32).toString('hex'), owner_key: 'vmo_' + base62(40) };
    const r = await run(argv, { root, respond: () => Response.json({ ...fresh, echo: `${AGENT_KEY} ${OWNER_KEY}`, pending: [{ id: 'req_123', recipient: 'friend@example.com' }] }) });
    assert.equal(r.code, 0, `${argv[0]}: ${r.err}`);
    // approve first reads GET /owner/policy to show the human the pending recipient (adversarial custody fix).
    const preflight = argv[0] === 'approve' ? 1 : 0;
    assert.equal(r.calls.length, 1 + preflight, argv[0]);
    if (preflight) { assert.equal(r.calls[0].url, OWNER + '/policy'); assert.equal(r.calls[0].init.method, 'GET'); }
    for (const { url: u, init: i } of r.calls) {
      assert.equal(i.redirect, 'error'); assert.ok(u.startsWith(OWNER + '/'));
      assert.deepEqual(Object.keys(i.headers).sort(), ['Content-Type', 'X-Agent-Mail-Owner-Key']);
      assert.ok(!JSON.stringify(i).includes(AGENT_KEY) && !u.includes(AGENT_KEY), `${argv[0]} sent the agent key`);
    }
    const { url, init } = r.calls[preflight];
    assert.equal(url, OWNER + path); assert.equal(init.method, method);
    assert.deepEqual(init.body === undefined ? undefined : JSON.parse(init.body), body);
    for (const text of [r.out, r.err]) {
      assert.ok(!text.includes(AGENT_KEY) && !text.includes(OWNER_KEY) && !text.includes('SYNTHLEAK'), `${argv[0]} printed a key`);
      assert.ok(!text.includes(fresh.api_key) && !text.includes(fresh.owner_key), `${argv[0]} printed a new key`);
    }
    // Rotations after the first change the owner key on disk; restore it for the next command.
    chmodSync(join(dir, 'owner-key'), 0o600); writeFileSync(join(dir, 'owner-key'), OWNER_KEY + '\n');
  }
});

test('expansions need confirmation; without it nothing is sent', async () => {
  const { root } = mailbox();
  // approve may make one read (GET /owner/policy) to name the recipient; nothing that changes state.
  const respond = () => Response.json({ ok: true, pending: [{ id: 'req_1', recipient: 'a@example.com' }] });
  const changes = calls => calls.filter(c => c.init.method !== 'GET');
  for (const argv of [['approve', 'req_1'], ['add', 'a@example.com'], ['unlock']]) {
    const r = await run(argv, { root, respond });
    assert.equal(r.code, 1); assert.equal(changes(r.calls).length, 0); assert.match(r.err, /Not confirmed/);
    assert.ok(r.calls.length <= (argv[0] === 'approve' ? 1 : 0));
    const yes = await run(argv, { root, respond, confirm: async () => true });
    assert.equal(yes.code, 0); assert.equal(changes(yes.calls).length, 1);
  }
});

test('rotate-agent-key saves the new key 0600 without printing it, and the MCP server uses it next', async t => {
  const { root, dir } = mailbox();
  const next = 'vm_' + randomBytes(32).toString('hex');
  const r = await run(['rotate-agent-key'], { root, respond: () => Response.json({ api_key: next }) });
  assert.equal(r.code, 0); assert.ok(!r.out.includes(next));
  assert.equal(readFileSync(join(dir, 'agent-key'), 'utf8').trim(), next);
  assert.equal(statSync(join(dir, 'agent-key')).mode & 0o777, 0o600);
  const calls = [];
  const server = createVoidmailServer({ keyRoot: root, agentKeyFile: join(dir, 'agent-key'), fetch: async (url, init) => { calls.push(init); return Response.json({}); } });
  const client = new Client({ name: 'x', version: '1' }); const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(a); await client.connect(b); t.after(async () => { await client.close(); await server.close(); });
  await client.callTool({ name: 'voidmail_get_stats', arguments: {} });
  assert.equal(calls[0].headers['X-Agent-Mail-Key'], next);
});

test('a rotation response without a valid key is reported, not saved', async () => {
  const { root, dir } = mailbox();
  const r = await run(['rotate-agent-key'], { root, respond: () => Response.json({ api_key: 'SYNTHLEAK-not-a-key' }) });
  assert.equal(r.code, 1); assert.match(r.err, /old key may already be revoked/); assert.ok(!r.err.includes('SYNTHLEAK'));
  assert.equal(readFileSync(join(dir, 'agent-key'), 'utf8').trim(), AGENT_KEY);
});

test('the CLI refuses to read the agent-key file as an owner key, and loose owner-key permissions', async () => {
  const { root, dir } = mailbox();
  let r = await run(['list'], { root, env: { VOIDMAIL_OWNER_KEY_FILE: join(dir, 'agent-key') } });
  assert.equal(r.code, 1); assert.equal(r.calls.length, 0);
  chmodSync(join(dir, 'owner-key'), 0o644);
  r = await run(['list'], { root });
  assert.equal(r.code, 1); assert.equal(r.calls.length, 0); assert.match(r.err, /mode 0600/);
});

test('refusals print local recovery text, never the server body', async () => {
  const { root } = mailbox();
  const r = await run(['list'], { root, respond: () => Response.json({ error: 'unauthorized', detail: `SYNTHLEAK-${nonce}` }, { status: 401 }) });
  assert.equal(r.code, 1); assert.match(r.err, /"code": "UNAUTHORIZED"/); assert.match(r.err, /key was not accepted/);
  assert.ok(!r.err.includes('SYNTHLEAK'));
  const np = await run(['approve', 'req_x', '--yes'], { root, respond: () => Response.json({ error: 'request_not_pending', code: 'REQUEST_NOT_PENDING', id: 'req_x', status: `SYNTHLEAK-${nonce}` }, { status: 409 }) });
  assert.equal(np.code, 1); assert.match(np.err, /already decided or has expired/); assert.ok(!np.err.includes('SYNTHLEAK'));
  const nf = await run(['deny', 'req_x'], { root, respond: () => Response.json({ error: 'request_not_found', code: 'REQUEST_NOT_FOUND' }, { status: 404 }) });
  assert.equal(nf.code, 1); assert.match(nf.err, new RegExp(`owner list --address ${ADDRESS.replace('.', '\\.')}`));
  const e = await run(['list'], { root, respond: () => Response.json({ error: `SYNTHLEAK-${nonce}` }, { status: 500 }) });
  assert.equal(e.code, 1); assert.match(e.err, /HTTP 500/); assert.ok(!e.err.includes('SYNTHLEAK'));
});

test('usage errors and unknown mailboxes make no request', async () => {
  const { root } = mailbox();
  for (const argv of [[], ['frobnicate'], ['approve'], ['approve', '../x'], ['add', 'not-an-address'], ['list', 'extra']]) {
    const r = await run(argv, { root }); assert.equal(r.code, 2, argv.join(' ')); assert.equal(r.calls.length, 0);
  }
  const r = await run(['list', '--address', 'someone-else@voidmail.ai'], { root });
  assert.equal(r.code, 1); assert.equal(r.calls.length, 0);
});

test('static: the owner CLI never names the agent-key header or reader, and only builds owner URLs', () => {
  // Code only: comments may explain what the CLI never does.
  const src = readFileSync(join(DIST, 'owner-cli.js'), 'utf8').replace(/^\s*\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '');
  assert.ok(!src.includes('X-Agent-Mail-Key'));
  assert.ok(!src.includes('readAgentKeyFile'));
  const fetches = [...src.matchAll(/requestJson\([^,]+,\s*`([^`]*)`/g)].map(m => m[1]);
  assert.deepEqual(fetches, ['${API_BASE}${OWNER_BASE}${plan.path}']);
  assert.match(src, /const OWNER_BASE = '\/v1\/agent-mail\/owner';/);
  for (const m of src.matchAll(/path: `?'?(\/[^'`]*)/g)) assert.ok(!m[1].startsWith('/v1/'), `absolute path ${m[1]}`);
});
