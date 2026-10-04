// Edge cases for the credential custody fixes
// (digit-first addresses, staged key files, owner rotation custody, approve preview,
// owner-shaped VOIDMAIL_API_KEY, invisible-character redaction). Synthetic keys only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createVoidmailServer } from '../dist/server.js';
import { runOwnerCli } from '../dist/owner-cli.js';
import { redactKeys, validAddress } from '../dist/keystore.js';

const nonce = randomBytes(6).toString('hex');
const base62 = n => Array.from(randomBytes(n), b => '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'[b % 62]).join('');
const agentKey = () => 'vm_' + randomBytes(32).toString('hex');
const ownerKey = () => 'vmo_' + base62(40);
const tempRoot = () => mkdtempSync(join(tmpdir(), 'voidmail-fix-'));

async function connect(t, options) {
  const server = createVoidmailServer(options);
  const client = new Client({ name: 'fixes', version: '1' });
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  t.after(async () => { await client.close(); await server.close(); });
  return client;
}

async function owner(argv, { env, respond, confirm = async () => false }) {
  const calls = []; const stdout = []; const stderr = []; const questions = [];
  const code = await runOwnerCli(argv, {
    env, fetch: async (url, init) => { calls.push({ url, init }); return respond(url, init); },
    stdout: l => stdout.push(l), stderr: l => stderr.push(l),
    confirm: async q => { questions.push(q); return confirm(q); },
  });
  return { code, calls, questions, out: stdout.join('\n'), err: stderr.join('\n') };
}

function ownerMailbox(address) {
  const root = tempRoot(); mkdirSync(join(root, address), { mode: 0o700 });
  const O = ownerKey(); writeFileSync(join(root, address, 'owner-key'), O + '\n', { mode: 0o600 });
  return { root, O };
}

test('address validation: Worker-minted and requested shapes pass; traversal and foreign shapes do not', () => {
  for (const ok of ['0123456789@voidmail.ai', '7abc@voidmail.ai', 'a1b@voidmail.ai', 'agent.one@voidmail.ai', 'x-y_z@voidmail.ai'])
    assert.equal(validAddress(ok), true, ok);
  for (const bad of ['..x@voidmail.ai', 'a..b@voidmail.ai', '.abc@voidmail.ai', 'abc.@voidmail.ai', 'a/b@voidmail.ai', 'a\\b@voidmail.ai',
    'ab@voidmail.ai', 'ABC@voidmail.ai', 'abc@voidmail.ai.evil', 'abc@example.com', `${'a'.repeat(31)}@voidmail.ai`, '', null])
    assert.equal(validAddress(bad), false, String(bad));
});

test('create_account: a failed API call leaves no staging directory and no key files', async t => {
  const root = tempRoot();
  const client = await connect(t, { keyRoot: root, fetch: async () => Response.json({ error: 'nope' }, { status: 500 }) });
  const r = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.equal(r.isError, true);
  assert.deepEqual(readdirSync(root), []);
});

test('create_account: an invalid api_key in the response discards the staging directory', async t => {
  const root = tempRoot();
  const client = await connect(t, { keyRoot: root, fetch: async () => Response.json({ address: `k${nonce}@voidmail.ai`, api_key: 'SYNTHLEAK', owner_key: ownerKey() }, { status: 201 }) });
  const r = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.equal(r.isError, true); assert.match(r.content[0].text, /invalid response/);
  assert.deepEqual(readdirSync(root), []);
});

test('create_account: a minted address whose key dir already has files keeps the keys in staging, never discards them', async t => {
  const root = tempRoot(); const address = `3${nonce.slice(0, 9)}@voidmail.ai`;
  mkdirSync(join(root, address), { mode: 0o700 });
  const stale = agentKey(); writeFileSync(join(root, address, 'agent-key'), stale + '\n', { mode: 0o600 });
  const A = agentKey(); const O = ownerKey(); const calls = [];
  const client = await connect(t, { keyRoot: root, fetch: async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith('/v1/agent-mail/create')) return Response.json({ address, api_key: A, owner_key: O, recipient_policy: 'allowlist' }, { status: 201 });
    return Response.json({ total: 0 });
  } });
  // Random address requested (no address argument), so the collision is only knowable after minting.
  const r = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.notEqual(r.isError, true, r.content?.[0]?.text);
  const out = JSON.parse(r.content[0].text);
  assert.equal(out.address, address);
  assert.ok(out.key_saved_to.includes('.pending-'), out.key_saved_to);
  assert.equal(readFileSync(out.key_saved_to, 'utf8').trim(), A);
  assert.equal(readFileSync(out.owner_key_saved_to, 'utf8').trim(), O);
  assert.equal(statSync(out.owner_key_saved_to).mode & 0o777, 0o600);
  assert.equal(readFileSync(join(root, address, 'agent-key'), 'utf8').trim(), stale, 'an existing key file was overwritten');
  assert.match(out.note, /move them to/);
  assert.ok(!JSON.stringify(r).includes(A) && !JSON.stringify(r).includes(O));
  // The session uses the staged agent key.
  await client.callTool({ name: 'voidmail_get_stats', arguments: {} });
  assert.equal(calls.at(-1).init.headers['X-Agent-Mail-Key'], A);
});

test('create_account: the committed mailbox directory is 0700 with 0600 files and no staging leftovers', async t => {
  const root = tempRoot(); const address = `9${nonce.slice(0, 9)}@voidmail.ai`;
  const client = await connect(t, { keyRoot: root, fetch: async () => Response.json({ address, api_key: agentKey(), owner_key: ownerKey(), recipient_policy: 'allowlist' }, { status: 201 }) });
  const r = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.notEqual(r.isError, true);
  assert.deepEqual(readdirSync(root), [address]);
  assert.equal(statSync(join(root, address)).mode & 0o777, 0o700);
  for (const f of ['agent-key', 'owner-key']) assert.equal(statSync(join(root, address, f)).mode & 0o777, 0o600);
});

test('create_account: no owner key issued removes the owner placeholder', async t => {
  const root = tempRoot(); const address = `n${nonce.slice(0, 9)}@voidmail.ai`;
  const client = await connect(t, { keyRoot: root, fetch: async () => Response.json({ address, api_key: agentKey(), recipient_policy: 'open' }, { status: 201 }) });
  const r = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.notEqual(r.isError, true);
  assert.deepEqual(readdirSync(join(root, address)), ['agent-key']);
  assert.equal(JSON.parse(r.content[0].text).owner_key_saved_to, null);
});

test('create_account: a requested address with the @voidmail.ai suffix or capitals is checked the same way', async t => {
  const root = tempRoot(); const address = `dupe${nonce.slice(0, 5)}@voidmail.ai`;
  mkdirSync(join(root, address), { mode: 0o700 });
  writeFileSync(join(root, address, 'agent-key'), agentKey() + '\n', { mode: 0o600 });
  const calls = [];
  const client = await connect(t, { keyRoot: root, fetch: async url => { calls.push(url); return Response.json({}); } });
  for (const requested of [address, address.split('@')[0].toUpperCase()]) {
    const r = await client.callTool({ name: 'voidmail_create_account', arguments: { address: requested } });
    assert.equal(r.isError, true); assert.match(r.content[0].text, /already exist/);
  }
  assert.equal(calls.length, 0);
});

test('an owner-shaped or malformed VOIDMAIL_API_KEY is refused locally with a message naming neither key', async t => {
  for (const bad of [ownerKey(), 'vm_short', 'not-a-key-at-all-but-long-enough']) {
    const calls = [];
    const client = await connect(t, { apiKey: bad, keyRoot: tempRoot(), fetch: async (url, init) => { calls.push(init); return Response.json({}); } });
    const r = await client.callTool({ name: 'voidmail_get_stats', arguments: {} });
    assert.equal(r.isError, true); assert.equal(calls.length, 0);
    assert.match(r.content[0].text, /VOIDMAIL_API_KEY does not hold an agent key/);
    assert.ok(!JSON.stringify(r).includes(bad));
  }
});

test('rotate-owner-key without VOIDMAIL_OWNER_KEY_FILE replaces <key dir>/<address>/owner-key atomically (0600)', async () => {
  const address = `ro${nonce.slice(0, 6)}@voidmail.ai`; const { root } = ownerMailbox(address);
  const fresh = ownerKey();
  const r = await owner(['rotate-owner-key', '--address', address], { env: { VOIDMAIL_KEY_DIR: root }, respond: () => Response.json({ owner_key: fresh }) });
  assert.equal(r.code, 0, r.err); assert.ok(!r.out.includes(fresh) && !r.err.includes(fresh));
  assert.equal(readFileSync(join(root, address, 'owner-key'), 'utf8').trim(), fresh);
  assert.equal(statSync(join(root, address, 'owner-key')).mode & 0o777, 0o600);
  assert.deepEqual(readdirSync(join(root, address)).sort(), ['owner-key']);
});

test('rotate-owner-key with VOIDMAIL_OWNER_KEY_FILE needs no --address', async () => {
  const vault = tempRoot(); const file = join(vault, 'my-owner-key');
  writeFileSync(file, ownerKey() + '\n', { mode: 0o600 });
  const fresh = ownerKey();
  const r = await owner(['rotate-owner-key'], { env: { VOIDMAIL_KEY_DIR: tempRoot(), VOIDMAIL_OWNER_KEY_FILE: file }, respond: () => Response.json({ owner_key: fresh }) });
  assert.equal(r.code, 0, r.err);
  assert.equal(readFileSync(file, 'utf8').trim(), fresh);
});

test('rotate-owner-key: when the file cannot be replaced, the new key goes to a new 0600 file beside it, not printed', async () => {
  const vault = tempRoot(); const file = join(vault, 'owner-key');
  writeFileSync(file, ownerKey() + '\n', { mode: 0o600 });
  const fresh = ownerKey();
  // While the request is in flight the path becomes a non-empty directory, so rename over it fails.
  const respond = () => { unlinkSync(file); mkdirSync(file); writeFileSync(join(file, 'keep'), 'x'); return Response.json({ owner_key: fresh }); };
  const r = await owner(['rotate-owner-key'], { env: { VOIDMAIL_KEY_DIR: tempRoot(), VOIDMAIL_OWNER_KEY_FILE: file }, respond });
  assert.equal(r.code, 1);
  assert.ok(!r.out.includes(fresh) && !r.err.includes(fresh), 'the key was printed although a file save worked');
  const beside = readdirSync(vault).filter(n => n.startsWith('owner-key.new-'));
  assert.equal(beside.length, 1);
  assert.equal(readFileSync(join(vault, beside[0]), 'utf8').trim(), fresh);
  assert.equal(statSync(join(vault, beside[0])).mode & 0o777, 0o600);
  assert.match(r.err, /Move it over/); assert.doesNotMatch(r.err, /run rotate-owner-key again/i);
  assert.equal(readdirSync(vault).filter(n => n.endsWith('.tmp')).length, 0, 'temp file left behind');
});

test('rotate-owner-key: when nothing can be written, the key is shown once on stderr (never stdout)', async t => {
  const ro = tempRoot(); const roFile = join(ro, 'owner-key');
  writeFileSync(roFile, ownerKey() + '\n', { mode: 0o600 });
  chmodSync(ro, 0o500); t.after(() => chmodSync(ro, 0o700));
  const fresh = ownerKey();
  const r = await owner(['rotate-owner-key'], { env: { VOIDMAIL_KEY_DIR: tempRoot(), VOIDMAIL_OWNER_KEY_FILE: roFile }, respond: () => Response.json({ owner_key: fresh }) });
  chmodSync(ro, 0o700);
  assert.equal(r.code, 1); assert.match(r.err, /shown only this once/); assert.ok(r.err.includes(fresh));
  assert.equal(r.err.split(fresh).length - 1, 1, 'shown more than once');
  assert.doesNotMatch(r.err, /run rotate-owner-key again/i);
  assert.ok(!r.out.includes(fresh));
});

test('rotate-owner-key: a response without a valid key never advises a retry that needs the old key', async () => {
  const address = `rn${nonce.slice(0, 6)}@voidmail.ai`; const { root } = ownerMailbox(address);
  const r = await owner(['rotate-owner-key', '--address', address], { env: { VOIDMAIL_KEY_DIR: root }, respond: () => Response.json({ owner_key: 'SYNTHLEAK' }) });
  assert.equal(r.code, 1); assert.doesNotMatch(r.err, /run rotate-owner-key again/i); assert.match(r.err, /owner list/);
  assert.ok(!r.err.includes('SYNTHLEAK'));
});

test('approve: an id that is not pending is refused before any change, and --yes still names the recipient', async () => {
  const address = `ap${nonce.slice(0, 6)}@voidmail.ai`; const { root } = ownerMailbox(address);
  const policy = { pending: [{ id: 'req_ok', recipient: 'friend@example.com' }] };
  const respond = (url, init) => init.method === 'GET' ? Response.json(policy) : Response.json({ approved: true });
  const miss = await owner(['approve', 'req_other', '--address', address, '--yes'], { env: { VOIDMAIL_KEY_DIR: root }, respond });
  assert.equal(miss.code, 1); assert.match(miss.err, /not pending/);
  assert.deepEqual(miss.calls.map(c => c.init.method), ['GET']);
  const hit = await owner(['approve', 'req_ok', '--address', address, '--yes'], { env: { VOIDMAIL_KEY_DIR: root }, respond });
  assert.equal(hit.code, 0, hit.err); assert.match(hit.out, /friend@example\.com/);
  assert.deepEqual(hit.calls.map(c => c.init.method), ['GET', 'POST']);
});

test('approve: control and bidi characters in a server-supplied recipient cannot rewrite the prompt', async () => {
  const address = `ab${nonce.slice(0, 6)}@voidmail.ai`; const { root } = ownerMailbox(address);
  const recipient = 'evil@attacker.example\r\u001b[2K‮elpmaxe.dooG@dneirf';
  const r = await owner(['approve', 'req_1', '--address', address], { env: { VOIDMAIL_KEY_DIR: root },
    respond: () => Response.json({ pending: [{ id: 'req_1', recipient }] }) });
  assert.equal(r.questions.length, 1);
  assert.doesNotMatch(r.questions[0], /[\r\u001b‮]/);
  assert.match(r.questions[0], /evil@attacker\.example/);
});

test('redaction: zero-width splits of either key shape and of a configured secret; plain text untouched', () => {
  const A = agentKey(); const O = ownerKey();
  const zw = ['​', '‌', '‍', '⁠', '﻿', '­'];
  const split = (k, i) => [...k].map((c, j) => j && j % 7 === 0 ? zw[(i + j) % zw.length] + c : c).join('');
  for (let i = 0; i < zw.length; i++) {
    for (const k of [A, O]) {
      const out = redactKeys(`pre ${split(k, i)} post`);
      assert.equal(out, 'pre [redacted-key] post');
    }
  }
  const custom = 'custom-secret-' + randomBytes(8).toString('hex');
  assert.equal(redactKeys(`x ${custom.slice(0, 5)}​${custom.slice(5)} y`, [custom]), 'x [redacted-key] y');
  assert.equal(redactKeys('ordinary text with vm_ and vmo_ prefixes only'), 'ordinary text with vm_ and vmo_ prefixes only');
  // A zero-width character that is not inside a key is left alone.
  assert.equal(redactKeys('a​b'), 'a​b');
});

test('redaction: adversarial near-keys stay linear (measured)', () => {
  const near = ('vm_' + 'a'.repeat(63) + '​').repeat(15000); // ~1 MB of 63-hex near misses
  const t0 = performance.now(); const out = redactKeys(near, [agentKey()]); const ms = performance.now() - t0;
  assert.equal(out, near);
  assert.ok(ms < 2000, `redaction took ${ms.toFixed(1)} ms on 1 MB`);
  console.log(`# redactKeys 1MB adversarial near-miss input: ${ms.toFixed(1)} ms`);
});

test('existing digit-first mailbox works in key-file mode through VOIDMAIL_ADDRESS-style options', async t => {
  const root = tempRoot(); const address = `1${nonce.slice(0, 9)}@voidmail.ai`; const A = agentKey();
  mkdirSync(join(root, address), { mode: 0o700 }); writeFileSync(join(root, address, 'agent-key'), A + '\n', { mode: 0o600 });
  const calls = [];
  const client = await connect(t, { keyRoot: root, address, agentKeyFile: join(root, address, 'agent-key'), fetch: async (url, init) => { calls.push(init); return Response.json({ total: 0 }); } });
  await client.callTool({ name: 'voidmail_get_stats', arguments: {} });
  assert.equal(calls[0].headers['X-Agent-Mail-Key'], A);
  assert.ok(existsSync(join(root, address, 'agent-key')));
});

test('set_webhook: an owner-only refusal is a tool result that says the webhook did not change', async t => {
  const client = await connect(t, { apiKey: agentKey(), keyRoot: tempRoot(), fetch: async () => Response.json({ error: 'owner_authorization_required', code: 'OWNER_AUTHORIZATION_REQUIRED', detail: 'SYNTHLEAK' }, { status: 403 }) });
  const r = await client.callTool({ name: 'voidmail_set_webhook', arguments: { url: 'https://hooks.example.invalid/x' } });
  assert.equal(r.isError, true);
  const out = JSON.parse(r.content[0].text);
  assert.equal(out.webhook_changed, false); assert.match(out.note, /only the human owner/);
  assert.ok(!JSON.stringify(r).includes('SYNTHLEAK'));
});
