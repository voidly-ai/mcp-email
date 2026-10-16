// mcp-email 2.1: `voidly-mcp-email create` and voidmail_create_account enroll a dedicated creator
// identity through Home join when none is configured, sign a create the server verifies (work proof
// + Ed25519 by the ACTIVE identity), write every key 0600 and print or return no key material.
// Synthetic keys and a synthetic API only; nothing here reaches the network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import nacl from 'tweetnacl';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createVoidmailServer } from '../dist/server.js';
import { runCreateCli } from '../dist/create-cli.js';
import { didFrom, fakeVoidly, sdkExport, sha256Hex } from './helpers/fake-home-join.mjs';

const tempRoot = () => mkdtempSync(join(tmpdir(), 'voidmail-enroll-'));
const mode = path => statSync(path).mode & 0o777;

async function cli(argv, { root, api, env = {} }) {
  const stdout = []; const stderr = [];
  const code = await runCreateCli(argv, { env: { VOIDMAIL_KEY_DIR: root, ...env }, fetch: api.handle, stdout: l => stdout.push(l), stderr: l => stderr.push(l) });
  return { code, out: stdout.join('\n'), err: stderr.join('\n') };
}

/** Every secret a run could leak: inbox keys, identity secrets (base64 and hex), API keys, signatures. */
function secretsIn(root, api) {
  const out = [];
  for (const c of api.state.creates) if (c.minted) out.push(c.minted.api_key, c.minted.owner_key);
  for (const c of api.state.calls) if (c.headers['X-Mail-Signature']) out.push(c.headers['X-Mail-Signature']);
  const idPath = join(root, 'creator', 'identity.json');
  for (const path of [idPath, join(root, 'creator', 'pending-join.json')]) {
    if (!existsSync(path)) continue;
    const id = JSON.parse(readFileSync(path, 'utf8'));
    const creds = id.credentials ?? id;
    for (const v of [creds.apiKey, creds.signingSecretKey, creds.encryptionSecretKey, creds.homeBoard?.apiKey, creds.homeBoard?.signingSecretKey, creds.homeBoard?.encryptionSecretKey]) {
      if (typeof v === 'string') { out.push(v); if (!/^[0-9a-f]+$/.test(v)) out.push(Buffer.from(v, 'base64').toString('hex')); }
    }
  }
  return out.filter(Boolean);
}
const assertNoSecrets = (label, text, secrets) => { for (const s of secrets) assert.ok(!text.includes(s), `${label} leaked a secret`); };

test('create CLI enrolls a dedicated creator DID, signs a create the server verifies, saves 0600 keys and prints no key', async () => {
  const root = tempRoot(); const api = fakeVoidly();
  const run = await cli(['--name', 'qa-agent', '--address', 'qavma'], { root, api });
  assert.equal(run.code, 0, run.err);
  // Exactly: Home join challenge, Home join commit, one signed create.
  assert.deepEqual(api.state.calls.map(c => [c.path, c.redirect]), [['/v1/home/join', 'error'], ['/v1/home/join', 'error'], ['/v1/agent-mail/create', 'error']]);
  assert.deepEqual(api.state.joins.map(j => j.action), ['challenge', 'commit']);
  const [create] = api.state.creates;
  assert.equal(create.verified, true, 'signature and work proof verify against the enrolled identity');
  assert.deepEqual(JSON.parse(create.body), { name: 'qa-agent', address: 'qavma', recipient_policy: 'allowlist' });
  // The challenge carried only public keys and API-key hashes.
  const challenge = JSON.parse(api.state.joins[0].raw);
  assert.deepEqual(Object.keys(challenge.root).sort(), ['api_key_hash', 'did', 'encryption_public_key', 'mode', 'signing_public_key']);
  assert.equal(challenge.public_profile, false);

  const address = 'qavma@voidmail.ai';
  const creatorDir = join(root, 'creator'); const identityPath = join(creatorDir, 'identity.json');
  assert.equal(mode(creatorDir), 0o700); assert.equal(mode(identityPath), 0o600);
  assert.equal(existsSync(join(creatorDir, 'pending-join.json')), false, 'the pending record is removed once the identity is saved');
  assert.equal(mode(join(root, address)), 0o700);
  for (const name of ['agent-key', 'owner-key']) assert.equal(mode(join(root, address, name)), 0o600);
  assert.equal(readFileSync(join(root, address, 'agent-key'), 'utf8').trim(), create.minted.api_key);
  assert.equal(readFileSync(join(root, address, 'owner-key'), 'utf8').trim(), create.minted.owner_key);

  // The stored identity is an agent-sdk exportCredentials() shape for the root DID that signed.
  const identity = JSON.parse(readFileSync(identityPath, 'utf8'));
  assert.equal(identity.did, create.did);
  assert.equal(api.state.identities.get(identity.did)?.status, 'active');
  const secret = Buffer.from(identity.signingSecretKey, 'base64');
  assert.equal(secret.length, 64);
  assert.equal(didFrom(new Uint8Array(secret.subarray(32))), identity.did);
  assert.equal(identity.signingPublicKey, secret.subarray(32).toString('base64'));
  assert.equal(identity.homeJoinIdentity, true);
  assert.ok(api.state.identities.has(identity.homeBoard.did), 'the board identity was enrolled with it');
  assert.equal(sha256Hex(identity.apiKey), challenge.root.api_key_hash);

  // Output: the address and paths, nothing else that is secret (not even the DID).
  assert.match(run.out, /Created qavma@voidmail\.ai/);
  for (const path of [join(root, address, 'agent-key'), join(root, address, 'owner-key'), identityPath]) assert.ok(run.out.includes(path), path);
  assert.match(run.out, /readable by the server; not end-to-end encrypted/);
  assert.match(run.out, /enrolled now/);
  assert.ok(!run.out.includes(identity.did) && !run.err.includes(identity.did));
  assert.doesNotMatch(run.out + run.err, /vm_[0-9a-f]{64}|vmo_[0-9A-Za-z]{40}/);
  assertNoSecrets('cli output', run.out + run.err, secretsIn(root, api));
  // No secret key or raw API key goes out in any request (the create's signature is its own header).
  const signature = api.state.calls[2].headers['X-Mail-Signature'];
  const requestSecrets = secretsIn(root, api).filter(s => s !== signature);
  for (const c of api.state.calls) assertNoSecrets(`request ${c.path}`, JSON.stringify({ body: c.body, headers: c.headers }), requestSecrets);
});

test('a second create reuses the stored identity without a Home join; the per-DID limit is never evaded with a new identity', async () => {
  const root = tempRoot(); const api = fakeVoidly();
  assert.equal((await cli(['--address', 'firstbox'], { root, api })).code, 0);
  const did = api.state.creates[0].did;
  const second = await cli(['--address', 'secondbox'], { root, api });
  assert.equal(second.code, 0, second.err);
  assert.match(second.out, /reused/);
  assert.equal(api.state.joins.length, 2, 'no further Home join');
  assert.equal(api.state.creates[1].did, did);
  const third = await cli(['--address', 'thirdbox'], { root, api });
  assert.equal(third.code, 1);
  assert.match(third.err, /HTTP 429.*3600 seconds.*Do not change identity or network/s);
  assert.equal(api.state.joins.length, 2, 'a limit never triggers a new identity');
  assert.equal(api.state.creates.length, 3);
  assert.equal(existsSync(join(root, 'thirdbox@voidmail.ai')), false);
  assert.deepEqual(readdirSync(root).filter(n => n.startsWith('.pending-')), [], 'no staging directory is left behind');
});

test('voidmail_create_account enrolls automatically when no creator is configured and returns paths only', async t => {
  const root = tempRoot(); const api = fakeVoidly();
  const server = createVoidmailServer({ keyRoot: root, fetch: api.handle });
  const client = new Client({ name: 'enroll-check', version: '1' });
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  const wire = []; const deliver = right.onmessage;
  right.onmessage = (message, extra) => { wire.push(JSON.stringify(message)); deliver(message, extra); };
  t.after(async () => { await client.close(); await server.close(); });

  const result = await client.callTool({ name: 'voidmail_create_account', arguments: { name: 'mcp-agent', address: 'mcpbox' } });
  assert.notEqual(result.isError, true, result.content?.[0]?.text);
  const out = JSON.parse(result.content[0].text);
  assert.equal(out.address, 'mcpbox@voidmail.ai');
  assert.equal(out.key_saved_to, join(root, 'mcpbox@voidmail.ai', 'agent-key'));
  assert.equal(out.creator_identity_file, join(root, 'creator', 'identity.json'));
  assert.match(out.creator_identity, /enrolled now/);
  assert.match(out.note, /readable by the server \(not end-to-end encrypted\)/);
  assert.equal(api.state.creates[0].verified, true);
  const secrets = secretsIn(root, api);
  assertNoSecrets('tool result', JSON.stringify(result), secrets);
  wire.forEach((m, i) => assertNoSecrets(`wire ${i}`, m, secrets));
  // The saved agent key authenticates the next call.
  await client.callTool({ name: 'voidmail_get_stats', arguments: {} });
  assert.equal(api.state.calls.at(-1).headers['X-Agent-Mail-Key'], api.state.creates[0].minted.api_key);
});

test('a join message that differs from the request is refused before anything is signed, committed or created', async () => {
  const mutate = {
    'public profile consent': m => m.replace('public-profile:false', 'public-profile:true'),
    'mail effect': m => m.replace('effect:private-home-only-no-mail-handle-wallet', 'effect:mail-wallet'),
    'other audience': m => m.replace('audience:https://api.voidly.ai/v1/home/join', 'audience:https://evil.example/v1/home/join'),
    'swapped board key': m => m.replace(/board-signing-public-key:[^\n]+/, `board-signing-public-key:${Buffer.from(nacl.sign.keyPair().publicKey).toString('base64')}`),
    'long expiry': m => m.replace(/expires-at:[^\n]+/, `expires-at:${new Date(Date.now() + 86400_000).toISOString()}`),
  };
  for (const [label, change] of Object.entries(mutate)) {
    const root = tempRoot(); const api = fakeVoidly();
    api.state.hostile.challenge = answer => { const message = change(answer.message); return { ...answer, message, message_sha256: sha256Hex(message), expires_at: message.split('\n')[17]?.slice('expires-at:'.length) }; };
    const run = await cli([], { root, api });
    assert.equal(run.code, 1, label);
    assert.match(run.err, /nothing was signed or created/, label);
    assert.deepEqual(api.state.joins.map(j => j.action), ['challenge'], `${label}: no commit`);
    assert.equal(api.state.creates.length, 0, label);
    assert.deepEqual(readdirSync(join(root, 'creator')), [], `${label}: nothing saved`);
  }
});

test('a lost commit response keeps the saved enrollment; the next run replays the same commit and makes no other identity', async () => {
  const root = tempRoot(); const api = fakeVoidly();
  api.state.hostile.dropCommit = 3;
  const first = await cli(['--address', 'lostbox'], { root, api });
  assert.equal(first.code, 1);
  assert.match(first.err, /may have committed.*run the same command again/s);
  const pending = join(root, 'creator', 'pending-join.json');
  assert.equal(mode(pending), 0o600);
  assert.equal(api.state.identities.size, 2, 'the commit landed');
  assert.equal(api.state.creates.length, 0);
  assertNoSecrets('first run output', first.out + first.err, secretsIn(root, api));
  const firstCommit = api.state.joins.find(j => j.action === 'commit').raw;

  const second = await cli(['--address', 'lostbox'], { root, api });
  assert.equal(second.code, 0, second.err);
  assert.deepEqual(api.state.joins.slice(4).map(j => j.action), ['commit'], 'no new challenge');
  assert.equal(api.state.joins.at(-1).raw, firstCommit, 'the replay is byte for byte');
  assert.equal(api.state.identities.size, 2, 'no other identity');
  assert.equal(api.state.creates[0].verified, true);
  assert.equal(existsSync(pending), false);
  assert.equal(JSON.parse(readFileSync(join(root, 'creator', 'identity.json'), 'utf8')).did, api.state.creates[0].did);
});

test('a refused commit is set aside (kept, never deleted) and reports that nothing was created', async () => {
  const root = tempRoot(); const api = fakeVoidly();
  api.state.hostile.refuseCommit = 'owner_signature_required';
  const run = await cli([], { root, api });
  assert.equal(run.code, 1);
  assert.match(run.err, /refused at commit \(owner_signature_required, HTTP 401\); nothing was created/);
  const kept = readdirSync(join(root, 'creator'));
  assert.equal(kept.length, 1); assert.match(kept[0], /^pending-join\.json\.refused-/);
  assert.equal(mode(join(root, 'creator', kept[0])), 0o600);
  assert.equal(api.state.creates.length, 0);
  delete api.state.hostile.refuseCommit;
  assert.equal((await cli([], { root, api })).code, 0, 'the next run enrolls a fresh identity');
  assert.equal(api.state.creates[0].verified, true);
});

test('Home join rate limits and a disabled route stop before any identity or create', async () => {
  for (const [status, error, pattern] of [[429, 'Registration temporarily rate limited.', /HTTP 429.*Wait at least 120 seconds.*Nothing was created/s], [503, 'home_join_disabled', /turned off.*VOIDMAIL_CREATOR_DID/s]]) {
    const root = tempRoot(); const api = fakeVoidly();
    api.state.hostile.joinStatus = { status, error, headers: status === 429 ? { 'Retry-After': '120' } : {} };
    const run = await cli([], { root, api });
    assert.equal(run.code, 1); assert.match(run.err, pattern);
    assert.equal(api.state.creates.length, 0); assert.deepEqual(readdirSync(join(root, 'creator')), []);
  }
});

test('an agent-sdk identity export works as VOIDMAIL_CREATOR_SIGNING_KEY_FILE; bad exports fail before any request', async () => {
  const { json, signing } = sdkExport();
  const dir = tempRoot(); const file = join(dir, 'agent-credentials.json');
  writeFileSync(file, JSON.stringify(json), { mode: 0o600 });
  const api = fakeVoidly();
  api.state.identities.set(json.did, { signing_public_key: Buffer.from(signing.publicKey).toString('base64'), status: 'active' });
  const root = tempRoot();
  const ok = await cli(['--address', 'sdkbox'], { root, api, env: { VOIDMAIL_CREATOR_SIGNING_KEY_FILE: file } });
  assert.equal(ok.code, 0, ok.err);
  assert.equal(api.state.creates[0].did, json.did); assert.equal(api.state.creates[0].verified, true);
  assert.equal(api.state.joins.length, 0); assert.equal(existsSync(join(root, 'creator')), false, 'a configured identity makes no creator directory');
  assert.doesNotMatch(ok.out, /creator identity/);
  for (const s of [json.signingSecretKey, json.encryptionSecretKey, json.apiKey]) assert.ok(!(ok.out + ok.err).includes(s));

  // The same file through the MCP server option, with the matching DID also set.
  const server = createVoidmailServer({ keyRoot: tempRoot(), fetch: api.handle, creatorDid: json.did, creatorSigningKeyFile: file });
  const client = new Client({ name: 'sdk-export', version: '1' });
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  const viaMcp = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.notEqual(viaMcp.isError, true, viaMcp.content?.[0]?.text);
  assert.equal(api.state.creates[1].verified, true);
  await client.close(); await server.close();

  const bad = {
    'DID mismatch': [JSON.stringify(json), { VOIDMAIL_CREATOR_DID: 'did:voidly:' + '1'.repeat(20) }, /does not match/],
    'public key mismatch': [JSON.stringify({ ...json, signingPublicKey: Buffer.from(nacl.sign.keyPair().publicKey).toString('base64') }), {}, /does not match/],
    'inconsistent secret': [JSON.stringify({ ...json, signingSecretKey: Buffer.concat([Buffer.from(signing.secretKey.subarray(0, 32)), Buffer.alloc(32, 7)]).toString('base64') }), {}, /valid Ed25519/],
    'not an export': [JSON.stringify({ hello: 'world' }), {}, /agent-sdk identity export/],
    'raw key without DID': [Buffer.from(signing.secretKey), {}, /needs VOIDMAIL_CREATOR_DID/],
  };
  const before = api.state.calls.length;
  for (const [label, [content, env, pattern]] of Object.entries(bad)) {
    const path = join(dir, label.replace(/\W/g, '-'));
    writeFileSync(path, content, { mode: 0o600 });
    const run = await cli([], { root: tempRoot(), api, env: { VOIDMAIL_CREATOR_SIGNING_KEY_FILE: path, ...env } });
    assert.equal(run.code, 1, label); assert.match(run.err, pattern, label);
    assert.ok(!run.err.includes(json.signingSecretKey), label);
  }
  const loose = join(dir, 'loose.json'); writeFileSync(loose, JSON.stringify(json), { mode: 0o644 }); chmodSync(loose, 0o644);
  const looseRun = await cli([], { root: tempRoot(), api, env: { VOIDMAIL_CREATOR_SIGNING_KEY_FILE: loose } });
  assert.equal(looseRun.code, 1); assert.match(looseRun.err, /0600/);
  assert.equal(api.state.calls.length, before, 'no request for any bad export');
});

test('CLI usage errors send nothing', async () => {
  const api = fakeVoidly();
  for (const argv of [['--address', 'ab'], ['--address', '9box'], ['--bogus'], ['--name', '']]) {
    const run = await cli(argv, { root: tempRoot(), api });
    assert.equal(run.code, 2, argv.join(' '));
  }
  const help = await cli(['--help'], { root: tempRoot(), api });
  assert.equal(help.code, 0); assert.match(help.out, /Usage: voidly-mcp-email create/);
  assert.equal(api.state.calls.length, 0);
});

test('enrollment off and nothing stored: no request and nothing written', async () => {
  const root = tempRoot(); const api = fakeVoidly();
  const run = await cli([], { root, api, env: { VOIDMAIL_CREATOR_AUTO_ENROLL: 'off' } });
  assert.equal(run.code, 1); assert.match(run.err, /automatic enrollment is off/);
  assert.equal(api.state.calls.length, 0); assert.deepEqual(readdirSync(root), []);
});

// Keep the synthetic proof check honest: a create signed by a key the server does not hold is refused.
test('the fake create verifier refuses a signature from an unenrolled key', () => {
  const api = fakeVoidly();
  const pair = nacl.sign.keyPair();
  const did = didFrom(pair.publicKey);
  const body = JSON.stringify({ name: 'x', recipient_policy: 'allowlist' });
  const ts = String(Math.floor(Date.now() / 1000)); const nonce = 'a'.repeat(32);
  const preimage = ['voidmail-create-v1', 'POST', '/v1/agent-mail/create', did, ts, nonce, sha256Hex(Buffer.from(body))].join('\n');
  let work = 0; for (; ; work++) { const h = createHash('sha256').update(['voidmail-create-pow-v1', preimage, work.toString(16).padStart(16, '0')].join('\n')).digest(); if (h[0] === 0 && h[1] === 0) break; }
  const w = work.toString(16).padStart(16, '0');
  const sig = Buffer.from(nacl.sign.detached(Buffer.from(`${preimage}\n${w}`), pair.secretKey)).toString('base64');
  return api.handle('https://api.voidly.ai/v1/agent-mail/create', { method: 'POST', body,
    headers: { 'X-Agent-DID': did, 'X-Mail-Timestamp': ts, 'X-Mail-Nonce': nonce, 'X-Mail-Pow': w, 'X-Mail-Signature': sig } })
    .then(async r => { assert.equal(r.status, 401); assert.equal((await r.json()).error, 'mail_create_invalid_identity'); });
});
