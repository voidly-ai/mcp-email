// Adversarial custody regressions for mcp-email 1.2.0.
// Each test states the defect it proves. Synthetic keys only; SYNTHLEAK marks what must be absent.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createVoidmailServer } from '../dist/server.js';
import { runOwnerCli } from '../dist/owner-cli.js';
import { validAddress } from '../dist/keystore.js';

const nonce = randomBytes(6).toString('hex');
const base62 = n => Array.from(randomBytes(n), b => '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'[b % 62]).join('');
const agentKey = () => 'vm_' + randomBytes(32).toString('hex');
const ownerKey = () => 'vmo_SYNTHLEAK' + base62(31);
const tempRoot = () => mkdtempSync(join(tmpdir(), 'voidmail-adv-'));

async function connect(t, options) {
  const server = createVoidmailServer(options);
  const client = new Client({ name: 'adversarial', version: '1' });
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  t.after(async () => { await client.close(); await server.close(); });
  return client;
}

async function owner(argv, { env, respond, confirm = async () => false }) {
  const calls = []; const stdout = []; const stderr = []; const questions = [];
  const code = await runOwnerCli(argv, {
    env,
    fetch: async (url, init) => { calls.push({ url, init }); return respond(url, init); },
    stdout: l => stdout.push(l), stderr: l => stderr.push(l),
    confirm: async q => { questions.push(q); return confirm(q); },
  });
  return { code, calls, questions, out: stdout.join('\n'), err: stderr.join('\n') };
}

function filesUnder(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) { try { out.push(...filesUnder(p)); } catch { /* unreadable */ } }
    else if (e.isFile()) { try { out.push(readFileSync(p, 'utf8')); } catch { /* unreadable */ } }
  }
  return out;
}

// ── REGRESSION (high): the Worker mints random addresses from [a-z0-9]{10}, so ~28% start
// with a digit. ADDRESS_RE demands a leading letter, so create_account throws "invalid
// response" AFTER the mailbox exists and discards both freshly minted keys: the inbox is
// orphaned (no agent key, no owner key, owner bootstrap impossible because owner_key_hash
// is set). worker/src/routes/agentMail.ts generateAddress().
test('create_account keeps the keys of a Worker-minted address that starts with a digit', async t => {
  const root = tempRoot();
  const address = `7${nonce.slice(0, 9)}@voidmail.ai`; // same shape as generateAddress(): 10 x [a-z0-9]
  const A = agentKey(); const O = ownerKey(); const calls = [];
  const client = await connect(t, { keyRoot: root, fetch: async (url, init) => {
    calls.push({ url, init });
    if (url.endsWith('/v1/agent-mail/create')) return Response.json({ address, api_key: A, owner_key: O, recipient_policy: 'allowlist' }, { status: 201 });
    return Response.json({ total: 0 });
  } });
  const result = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.notEqual(result.isError, true, `a valid Worker address was rejected after the inbox was created: ${result.content?.[0]?.text}`);
  assert.equal(readFileSync(join(root, address, 'agent-key'), 'utf8').trim(), A, 'agent key was discarded');
  assert.equal(readFileSync(join(root, address, 'owner-key'), 'utf8').trim(), O, 'owner key was discarded');
  assert.ok(!JSON.stringify(result).includes(A) && !JSON.stringify(result).includes(O));
  // The address must also be usable later through VOIDMAIL_ADDRESS / --address.
  assert.equal(validAddress(address), true, 'VOIDMAIL_ADDRESS and the owner CLI refuse this real address');
});

test('the owner CLI accepts --address for a Worker-minted digit-first mailbox', async () => {
  const root = tempRoot(); const address = `4${nonce.slice(0, 9)}@voidmail.ai`;
  mkdirSync(join(root, address), { mode: 0o700 });
  writeFileSync(join(root, address, 'owner-key'), ownerKey() + '\n', { mode: 0o600 });
  const r = await owner(['list', '--address', address], { env: { VOIDMAIL_KEY_DIR: root }, respond: () => Response.json({ recipients: [] }) });
  assert.equal(r.code, 0, `owner CLI refused a real mailbox address: ${r.err}`);
  assert.equal(r.calls.length, 1);
});

// ── Owner custody (medium): with VOIDMAIL_OWNER_KEY_FILE (the setup the create note
// recommends: owner key kept apart from the agent host), rotate-owner-key reads the key
// from that file but writes the NEW key to <VOIDMAIL_KEY_DIR>/<address>/owner-key. The file
// the owner actually uses keeps the revoked key, and the live owner key lands in the agent
// key directory the owner was told to move it out of.
test('rotate-owner-key replaces the owner-key file it read, not a copy in the agent key directory', async () => {
  const agentRoot = tempRoot(); const vault = tempRoot();
  const address = `rot${nonce.slice(0, 6)}@voidmail.ai`;
  mkdirSync(join(agentRoot, address), { mode: 0o700 });
  writeFileSync(join(agentRoot, address, 'agent-key'), agentKey() + '\n', { mode: 0o600 });
  const ownerFile = join(vault, 'owner-key');
  writeFileSync(ownerFile, ownerKey() + '\n', { mode: 0o600 });
  const fresh = 'vmo_' + base62(40);
  const r = await owner(['rotate-owner-key', '--address', address], {
    env: { VOIDMAIL_KEY_DIR: agentRoot, VOIDMAIL_OWNER_KEY_FILE: ownerFile },
    respond: () => Response.json({ owner_key: fresh }),
  });
  assert.equal(r.code, 0, r.err);
  assert.equal(readFileSync(ownerFile, 'utf8').trim(), fresh, 'the owner-key file the owner uses still holds the revoked key');
  assert.equal(existsSync(join(agentRoot, address, 'owner-key')), false, 'the new owner key was written into the agent key directory');
});

// ── Recovery (medium): the server revokes the old owner key before the CLI saves the new
// one. If the save fails (disk full, read-only dir) the CLI drops the new key and says
// "Run rotate-owner-key again", which cannot work because the old key is already revoked
// and owner/bootstrap refuses once owner_key_hash is set. The mailbox loses its owner forever.
test('a failed save after rotate-owner-key does not lose the only valid owner key', async t => {
  const base = tempRoot(); const root = join(base, 'keys'); const vault = join(base, 'vault');
  mkdirSync(root, { mode: 0o700 }); mkdirSync(vault, { mode: 0o700 });
  const address = `sav${nonce.slice(0, 6)}@voidmail.ai`;
  const ownerFile = join(vault, 'owner-key');
  writeFileSync(ownerFile, ownerKey() + '\n', { mode: 0o600 });
  chmodSync(root, 0o500); chmodSync(vault, 0o500); // readable, not writable: every save path fails
  t.after(() => { chmodSync(root, 0o700); chmodSync(vault, 0o700); });
  const fresh = 'vmo_' + base62(40);
  const r = await owner(['rotate-owner-key', '--address', address], {
    env: { VOIDMAIL_KEY_DIR: root, VOIDMAIL_OWNER_KEY_FILE: ownerFile },
    respond: () => Response.json({ owner_key: fresh }),
  });
  chmodSync(root, 0o700); chmodSync(vault, 0o700);
  const recoverable = r.out.includes(fresh) || r.err.includes(fresh) || filesUnder(base).some(s => s.includes(fresh));
  assert.ok(recoverable, `the rotated owner key was discarded; CLI said: ${r.err}`);
  assert.ok(!/run rotate-owner-key again/i.test(r.err), 'advises a retry that needs the already-revoked owner key');
});

// ── Blind approval (medium): the agent (or a prompt-injected model) creates a request for
// any address and hands the human only an opaque id ("approve <uuid>"). `owner approve`
// asks "Approve request <uuid>?" without ever showing the recipient, so the human widens
// the allowlist to an address they never saw. The Worker's GET /owner/policy returns it.
test('owner approve shows the human the recipient before asking for confirmation', async () => {
  const root = tempRoot(); const address = `apr${nonce.slice(0, 6)}@voidmail.ai`;
  mkdirSync(join(root, address), { mode: 0o700 });
  writeFileSync(join(root, address, 'owner-key'), ownerKey() + '\n', { mode: 0o600 });
  const id = '6f2c8a1e-0000-4000-8000-00000000abcd';
  const evil = `exfil-${nonce}@attacker.example`;
  const r = await owner(['approve', id, '--address', address], {
    env: { VOIDMAIL_KEY_DIR: root },
    respond: (url, init) => url.endsWith('/owner/policy') && init.method === 'GET'
      ? Response.json({ address, recipient_policy: 'allowlist', recipients: [], pending: [{ id, recipient: evil, expires_at: '2026-10-01T00:00:00.000Z' }] })
      : Response.json({ approved: true }),
    confirm: async () => false,
  });
  assert.equal(r.questions.length, 1);
  assert.ok(r.questions[0].includes(evil), `the confirmation prompt never names the recipient being approved: "${r.questions[0]}"`);
  assert.ok(!r.calls.some(c => /\/approve$/.test(c.url)), 'declined approval still reached the API');
});

// ── Key custody (low): VOIDMAIL_API_KEY is taken verbatim. An owner key placed there (a
// likely mix-up: two keys, one env var) is sent as X-Agent-Mail-Key on every tool call,
// so the "MCP server never uses the owner key" boundary rests on configuration alone.
test('an owner-shaped VOIDMAIL_API_KEY is refused and never sent', async t => {
  const O = ownerKey(); const calls = [];
  const client = await connect(t, { apiKey: O, keyRoot: tempRoot(), fetch: async (url, init) => { calls.push({ url, init }); return Response.json({ total: 0 }); } });
  await client.callTool({ name: 'voidmail_get_stats', arguments: {} });
  for (const { url, init } of calls) assert.ok(!JSON.stringify(init).includes(O) && !url.includes(O), 'the owner key left the process as an agent credential');
});

// ── Redaction (low): the Worker's own content guard treats a key with zero-width characters
// inside it as a key (scanOutboundContent strips U+200B-U+200D/U+FEFF). The MCP redactor does
// not, so an inbound email carrying the agent key split by a zero-width space reaches the model
// intact apart from one invisible character.
test('a zero-width-split agent key in inbound mail is redacted like the plain key', async t => {
  const root = tempRoot(); const address = `zw${nonce.slice(0, 6)}@voidmail.ai`;
  const A = agentKey();
  mkdirSync(join(root, address), { mode: 0o700 });
  writeFileSync(join(root, address, 'agent-key'), A + '\n', { mode: 0o600 });
  const split = A.slice(0, 20) + '​' + A.slice(20);
  const client = await connect(t, { keyRoot: root, agentKeyFile: join(root, address, 'agent-key'), address,
    fetch: async () => Response.json({ id: 'm1', from: 'x@example.invalid', text: `SYNTHLEAK key: ${split}` }) });
  const result = await client.callTool({ name: 'voidmail_read_email', arguments: { email_id: 'm1' } });
  const seen = JSON.parse(result.content[0].text).text.replace(/[​-‍﻿]/g, '');
  assert.ok(!seen.includes(A), 'the agent key reached the model with one zero-width character inside it');
});

// ── Fail-closed gap (low): create_account checks only that the key ROOT is writable before
// minting the mailbox. If <root>/<address>/ already holds a key file (stale files, a second
// host sharing the dir), O_EXCL makes the save fail AFTER the Worker minted the keys, and the
// tool reports "the owner key is lost". For a requested address the collision is knowable up front.
test('create_account with a requested address refuses before the API call when that key dir already has keys', async t => {
  const root = tempRoot(); const address = `dup${nonce.slice(0, 6)}@voidmail.ai`;
  mkdirSync(join(root, address), { mode: 0o700 });
  writeFileSync(join(root, address, 'owner-key'), 'vmo_' + base62(40) + '\n', { mode: 0o600 });
  const calls = [];
  const client = await connect(t, { keyRoot: root, fetch: async (url, init) => {
    calls.push(url);
    return Response.json({ address, api_key: agentKey(), owner_key: 'vmo_' + base62(40), recipient_policy: 'allowlist' }, { status: 201 });
  } });
  const result = await client.callTool({ name: 'voidmail_create_account', arguments: { address: address.split('@')[0] } });
  assert.equal(calls.length, 0, `a mailbox was minted whose owner key could not be saved: ${result.content?.[0]?.text}`);
  assert.equal(statSync(join(root, address)).isDirectory(), true);
});
