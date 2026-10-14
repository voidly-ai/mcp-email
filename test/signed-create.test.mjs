import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { chmodSync, mkdtempSync, readdirSync, readFileSync, statSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import nacl from 'tweetnacl';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createVoidmailServer } from '../dist/server.js';
import { creatorOptions } from './helpers/creator.mjs';

const API_KEY = 'vm_' + 'a'.repeat(64);
const OWNER_KEY = 'vmo_' + 'B'.repeat(40);
const ADDRESS = 'signedfixture@voidmail.ai';
const sha = value => createHash('sha256').update(value).digest();

function checkProof(init, creator) {
  const h = init.headers;
  assert.equal(init.method, 'POST');
  assert.equal(init.redirect, 'error');
  assert.equal(h['Content-Type'], 'application/json');
  assert.equal(h['X-Agent-Mail-Key'], undefined);
  assert.equal(h['X-Agent-DID'], creator.creatorDid);
  assert.match(h['X-Mail-Timestamp'], /^\d{10}$/);
  assert.ok(Math.abs(Number(h['X-Mail-Timestamp']) - Math.floor(Date.now() / 1000)) <= 300);
  assert.match(h['X-Mail-Nonce'], /^[0-9a-f]{32}$/);
  assert.match(h['X-Mail-Pow'], /^[0-9a-f]{16}$/);
  assert.match(h['X-Mail-Signature'], /^[A-Za-z0-9+/]{86}==$/);
  const bodyHash = sha(Buffer.from(init.body, 'utf8')).toString('hex');
  const preimage = ['voidmail-create-v1', 'POST', '/v1/agent-mail/create', h['X-Agent-DID'], h['X-Mail-Timestamp'], h['X-Mail-Nonce'], bodyHash].join('\n');
  const workHash = sha(['voidmail-create-pow-v1', preimage, h['X-Mail-Pow']].join('\n'));
  assert.deepEqual([...workHash.subarray(0, 2)], [0, 0]);
  const message = Buffer.from([preimage, h['X-Mail-Pow']].join('\n'));
  const signature = Buffer.from(h['X-Mail-Signature'], 'base64');
  assert.equal(signature.length, 64);
  assert.equal(nacl.sign.detached.verify(message, signature, creator.signingKeyPair.publicKey), true);
  return { bodyHash, nonce: h['X-Mail-Nonce'], signature, message };
}

async function fixture(t, fetcher, creator = creatorOptions(t)) {
  const root = mkdtempSync(join(tmpdir(), 'voidmail-signed-create-'));
  const server = createVoidmailServer({ ...creator, keyRoot: root, fetch: fetcher });
  const client = new Client({ name: 'signed-create-fixture', version: '1' });
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  t.after(async () => { await client.close(); await server.close(); });
  return { client, root, creator };
}

test('signed create sends one canonical proof and stores returned mailbox keys without exposing them', async t => {
  let calls = 0;
  const creator = creatorOptions(t);
  const { client, root } = await fixture(t, async (url, init) => {
    calls++;
    assert.equal(url, 'https://api.voidly.ai/v1/agent-mail/create');
    checkProof(init, creator);
    assert.deepEqual(JSON.parse(init.body), { name: 'fixture', recipient_policy: 'allowlist' });
    return Response.json({ address: ADDRESS, api_key: API_KEY, owner_key: OWNER_KEY, recipient_policy: 'allowlist' }, { status: 201 });
  }, creator);
  const result = await client.callTool({ name: 'voidmail_create_account', arguments: { name: 'fixture' } });
  assert.notEqual(result.isError, true, result.content?.[0]?.text);
  assert.equal(calls, 1);
  assert.equal(readFileSync(join(root, ADDRESS, 'agent-key'), 'utf8').trim(), API_KEY);
  assert.equal(readFileSync(join(root, ADDRESS, 'owner-key'), 'utf8').trim(), OWNER_KEY);
  assert.equal(statSync(join(root, ADDRESS, 'agent-key')).mode & 0o777, 0o600);
  assert.doesNotMatch(JSON.stringify(result), /vm_aaaa|vmo_BBBB|X-Mail-Signature/);
});

test('identity key mismatch at the server returns a clear 401 without storing credentials or retrying', async t => {
  let calls = 0;
  const creator = creatorOptions(t);
  const wrongPublicKey = nacl.sign.keyPair.fromSeed(new Uint8Array(32).fill(9)).publicKey;
  const { client, root } = await fixture(t, async (_url, init) => {
    calls++;
    const { signature, message } = checkProof(init, creator);
    assert.equal(nacl.sign.detached.verify(message, signature, wrongPublicKey), false);
    return Response.json({ error: 'mail_create_invalid_signature', secret: OWNER_KEY }, { status: 401 });
  }, creator);
  const result = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /HTTP 401.*DID is active/s);
  assert.doesNotMatch(JSON.stringify(result), /vmo_BBBB|mail_create_invalid_signature/);
  assert.equal(calls, 1);
  assert.deepEqual(readdirSync(root), []);
});

test('nonce replay conflict is reported without automatic replacement creation', async t => {
  let calls = 0;
  const creator = creatorOptions(t);
  const { client, root } = await fixture(t, async (_url, init) => {
    calls++;
    checkProof(init, creator);
    return Response.json({ error: 'mail_create_replay' }, { status: 409 });
  }, creator);
  const result = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /HTTP 409.*Reconcile the original inbox/s);
  assert.equal(calls, 1);
  assert.deepEqual(readdirSync(root), []);
});

test('create limit 429 preserves Retry-After and never retries or changes identity', async t => {
  let calls = 0;
  const creator = creatorOptions(t);
  const { client, root } = await fixture(t, async (_url, init) => {
    calls++;
    checkProof(init, creator);
    return Response.json({ error: 'MAILBOX_CREATION_RATE_LIMITED', scope: 'mailbox_creation_did' }, { status: 429, headers: { 'Retry-After': '37' } });
  }, creator);
  const result = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /HTTP 429.*37 seconds.*no automatic retry/is);
  assert.equal(calls, 1);
  assert.deepEqual(readdirSync(root), []);
});

test('missing creator identity and uncertain 503 never trigger an unsigned or replacement create', async t => {
  let calls = 0;
  const { client: noSigner, root: emptyRoot } = await fixture(t, async () => { calls++; return Response.json({}); }, {});
  const local = await noSigner.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.equal(local.isError, true);
  assert.match(local.content[0].text, /VOIDMAIL_CREATOR_DID/);
  assert.equal(calls, 0);
  assert.deepEqual(readdirSync(emptyRoot), []);

  const creator = creatorOptions(t);
  const { client } = await fixture(t, async (_url, init) => {
    calls++;
    checkProof(init, creator);
    return Response.json({ error: 'mail_create_commit_unknown' }, { status: 503 });
  }, creator);
  const unknown = await client.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.equal(unknown.isError, true);
  assert.match(unknown.content[0].text, /outcome may be unknown.*do not automatically retry/is);
  assert.equal(calls, 1);
});

test('unsafe creator signing-key permissions or a symlink fail before any network call', async t => {
  const creator = creatorOptions(t);
  let calls = 0;
  const link = join(mkdtempSync(join(tmpdir(), 'voidmail-creator-link-')), 'signing-key');
  symlinkSync(creator.creatorSigningKeyFile, link);
  const { client: linked } = await fixture(t, async () => { calls++; return Response.json({}); }, {
    ...creator, creatorSigningKeyFile: link,
  });
  const linkResult = await linked.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.equal(linkResult.isError, true);
  assert.equal(calls, 0);

  chmodSync(creator.creatorSigningKeyFile, 0o644);
  const { client: loose } = await fixture(t, async () => { calls++; return Response.json({}); }, creator);
  const modeResult = await loose.callTool({ name: 'voidmail_create_account', arguments: {} });
  assert.equal(modeResult.isError, true);
  assert.equal(calls, 0);
});
