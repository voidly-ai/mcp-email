// mcp-email 2.0: the MCP server decrypts sealed mail on this machine, searches locally, labels
// server-readable mail, never shows server plaintext beside a sealed envelope, never sends or
// prints a private key, and cannot change keys. Synthetic keys, mail and API only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import nacl from 'tweetnacl';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createVoidmailServer } from '../dist/server.js';
import { runOwnerCli } from '../dist/owner-cli.js';
import { boxKeyFromFile, checkKeySet, openBody, openSummary, parseEnvelope } from '../dist/mailcrypto.js';
import { redactKeys } from '../dist/keystore.js';
import { b64, fakeVoidmail, keyIdFor, mime, seal } from './helpers/fake-voidmail.mjs';

const nonce = randomBytes(6).toString('hex');
const base62 = n => Array.from(randomBytes(n), b => '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'[b % 62]).join('');
const AGENT_KEY = 'vm_' + randomBytes(32).toString('hex');
const OWNER_KEY = 'vmo_' + base62(40);
const ADDRESS = 'sealed' + nonce.slice(0, 6) + '@voidmail.ai';
const CANARY = `CANARY${nonce}`;
const stranger = () => { const k = nacl.box.keyPair(); return { kind: 'owner_recovery', key_id: keyIdFor(k.publicKey), x25519_public_key: b64(k.publicKey) }; };

async function setup(t, { register = true } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'voidmail-sealed-')); const dir = join(root, ADDRESS);
  mkdirSync(dir, { mode: 0o700 });
  writeFileSync(join(dir, 'agent-key'), AGENT_KEY + '\n', { mode: 0o600 });
  writeFileSync(join(dir, 'owner-key'), OWNER_KEY + '\n', { mode: 0o600 });
  const api = fakeVoidmail({ address: ADDRESS, ownerKey: OWNER_KEY, agentKey: AGENT_KEY });
  const owner = argv => runOwnerCli([...argv, '--address', ADDRESS, '--yes'], { env: { VOIDMAIL_KEY_DIR: root }, fetch: api.handle, stdout: () => {}, stderr: () => {} });
  if (register) assert.equal(await owner(['keys', 'init']), 0);
  const server = createVoidmailServer({ fetch: (u, i) => api.handle(u, i), keyRoot: root, address: ADDRESS, agentKeyFile: join(dir, 'agent-key') });
  const client = new Client({ name: 'synthetic-sealed-check', version: '1' });
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  const wire = []; const deliver = right.onmessage;
  right.onmessage = (message, extra) => { wire.push(JSON.stringify(message)); deliver(message, extra); };
  t.after(async () => { await client.close(); await server.close(); });
  const call = async (name, args = {}) => { const r = await client.callTool({ name, arguments: args }); let data; try { data = JSON.parse(r.content[0].text); } catch { throw new Error(`${name} ${JSON.stringify(args)}: ${r.content[0].text}`); } return { r, data }; };
  return { root, dir, api, client, call, wire, owner };
}

const secretsOf = dir => {
  const out = [];
  for (const name of ['mail-secret-key', 'mail-signing-key']) {
    try { const v = readFileSync(join(dir, name), 'utf8').trim(); const raw = Buffer.from(v.slice(4), 'hex'); out.push(v, v.slice(4), raw.toString('base64')); } catch {}
  }
  return out;
};

test('list opens sealed summaries and read opens the sealed body, all on this machine; no private key leaves it', async t => {
  const { dir, api, call, wire } = await setup(t);
  const id = await api.deliver(mime({ to: ADDRESS, subject: `Invoice ${CANARY}`, text: `Pay ${CANARY} by Friday`, html: `<p>${CANARY}</p>`, attachment: { name: 'a.pdf', content: 'PDFDATA' } }));
  // What the server keeps holds no plaintext.
  assert.ok(!JSON.stringify(api.state.emails).includes(CANARY));
  assert.ok(!Buffer.from(api.state.bodies.get(id)).toString('latin1').includes(CANARY));
  const { data: list } = await call('voidmail_list_inbox');
  const row = list.emails[0];
  assert.equal(row.id, id); assert.equal(row.storage, 'sealed'); assert.equal(row.readable, true);
  assert.equal(row.subject, `Invoice ${CANARY}`); assert.equal(row.from.address, 'sender@example.com');
  assert.match(row.text_preview, new RegExp(CANARY));
  assert.equal(row.html, undefined, 'list does not carry HTML'); assert.equal(row.envelope, undefined, 'no ciphertext reaches the model');
  assert.deepEqual(row.attachments.map(a => a.filename), ['a.pdf']);
  assert.equal(row.storage_note, undefined, 'the note is said once per list');
  assert.match(list.storage_notes.sealed, /saw it in plaintext while receiving it/);
  assert.equal(row.sealed_to.checked, true); assert.equal(row.sealed_to.warning, undefined);
  assert.equal(list.encryption.key_on_this_machine, true);
  assert.ok(!api.state.calls.some(c => c.path.endsWith('/sealed-body')), 'list does not download bodies');
  assert.equal(api.state.emails[0].is_read, 0, 'list does not mark read');

  const { data: one } = await call('voidmail_read_email', { email_id: id });
  assert.match(one.storage_note, /saw it in plaintext while receiving it/);
  assert.equal(one.storage, 'sealed'); assert.match(one.text, new RegExp(`Pay ${CANARY}`)); assert.match(one.html, new RegExp(CANARY));
  assert.deepEqual(one.attachments.map(a => [a.filename, a.size]), [['a.pdf', 7]]);
  assert.ok(api.state.calls.some(c => c.path === `/v1/agent-mail/inbox/${id}/sealed-body`));
  const secrets = secretsOf(dir);
  for (const c of api.state.calls) for (const s of secrets) assert.ok(!JSON.stringify(c).includes(s));
  for (const m of wire) for (const s of secrets) assert.ok(!m.includes(s));
  const mcpCalls = api.state.calls.filter(c => c.headers['X-Agent-Mail-Key']);
  assert.ok(mcpCalls.every(c => !c.path.includes('/owner') && c.path !== '/v1/agent-mail/inbox/search'));
});

test('plaintext beside an envelope is never shown, and every tamper fails closed with nothing shown', async t => {
  const { api, call } = await setup(t);
  const id = await api.deliver(mime({ to: ADDRESS, subject: 'Real subject', text: 'real body' }));
  api.state.emails[0].extra = { subject: `SERVER-${CANARY}`, body_text: `SERVER-${CANARY}`, from_address: `server-${nonce}@evil.example` };
  for (const tool of ['voidmail_list_inbox', 'voidmail_read_email']) {
    const { data } = await call(tool, { ...(tool === 'voidmail_read_email' ? { email_id: id } : {}) });
    const text = JSON.stringify(data);
    assert.match(text, /Real subject/); assert.ok(!text.includes(CANARY) && !text.includes('evil.example'), tool);
  }
  const make = async (subject, opts) => api.deliver(mime({ to: ADDRESS, subject: `${subject} ${CANARY}`, text: `${subject} ${CANARY}` }), opts);
  const other = await make('other'); const moved = await make('moved');
  const flippedBody = await make('flipped'); const flippedSummary = await make('summary');
  const stripped = await make('stripped'); const lying = await make('lying', { bodyRaw: mime({ to: ADDRESS, subject: 'swapped', text: 'swapped' }) });
  const get = id => api.state.emails.find(e => e.id === id);
  get(moved).envelope = { ...get(other).envelope }; api.state.bodies.set(moved, api.state.bodies.get(other));  // ciphertext moved between messages
  api.state.hostile.body = (id, bytes) => id === flippedBody ? (() => { const b = Buffer.from(bytes); b[b.length - 1] ^= 1; return b; })() : bytes;
  const s = get(flippedSummary).envelope.summary; const ct = Buffer.from(s.ciphertext, 'base64'); ct[5] ^= 1; s.ciphertext = ct.toString('base64');
  get(stripped).envelope = null;
  const cases = [[moved, 'binding_mismatch'], [flippedBody, 'decrypt_failed'], [flippedSummary, 'decrypt_failed'], [stripped, 'malformed'], [lying, 'digest_mismatch']];
  for (const [eid, reason] of cases) {
    const { data: d } = await call('voidmail_read_email', { email_id: eid });
    assert.equal(d.readable, false, eid); assert.equal(d.reason, reason, eid);
    assert.ok(!JSON.stringify(d).includes(CANARY), `${eid} leaked plaintext`);
  }
  const { data: list } = await call('voidmail_list_inbox');
  for (const eid of [moved, flippedSummary, stripped]) {
    const row = list.emails.find(e => e.id === eid);
    assert.equal(row.readable, false, eid); assert.ok(!JSON.stringify(row).includes(CANARY), eid);
  }
});

test('the sealed body is fetched only from the API host, never from a server-supplied body_url', async t => {
  const { api, call } = await setup(t);
  const id = await api.deliver(mime({ to: ADDRESS, subject: 'Hello', text: 'hi' }));
  api.state.hostile.bodyUrl = 'https://evil.example/steal';
  const { data } = await call('voidmail_read_email', { email_id: id });
  assert.equal(data.readable, true);
  assert.ok(api.state.calls.every(c => new URL(c.url).origin === 'https://api.voidly.ai'));
});

test('server-readable mail is labelled, and an unsealed row after key registration is warned about', async t => {
  const { api, call } = await setup(t);
  await api.deliver(mime({ to: ADDRESS, subject: 'Old mail', text: 'old' }), { plaintext: true, receivedAt: '2020-01-01T00:00:00.000Z' });
  await api.deliver(mime({ to: ADDRESS, subject: 'Downgraded', text: 'down' }), { plaintext: true, receivedAt: new Date(Date.now() + 3600_000).toISOString() });
  const { data } = await call('voidmail_list_inbox');
  const bySubject = Object.fromEntries(data.emails.map(e => [e.subject, e]));
  assert.equal(bySubject['Old mail'].storage, 'server-readable');
  assert.match(data.storage_notes['server-readable'], /server stored this message readable/);
  assert.equal(bySubject['Old mail'].storage_warning, undefined);
  assert.equal(bySubject.Downgraded.storage, 'server-readable');
  assert.match(bySubject.Downgraded.storage_warning, /should have stored it encrypted/);
});

test('a mailbox with no key on this machine shows sealed mail as unreadable, never as plaintext', async t => {
  const { api, call } = await setup(t, { register: false });
  const other = stranger();
  const sealed = await seal(mime({ to: ADDRESS, subject: CANARY, text: CANARY }), { recipients: [{ ...other, kind: 'agent' }], epoch: 1 }, { emailId: 'sealed_elsewhere', address: ADDRESS });
  api.state.emails.unshift({ id: 'sealed_elsewhere', sealed: true, is_read: 0, received_at: new Date().toISOString(), raw_size: 10, envelope: sealed.envelope });
  const { data } = await call('voidmail_list_inbox');
  assert.equal(data.emails[0].readable, false); assert.equal(data.emails[0].reason, 'no_local_key');
  assert.equal(data.encryption.key_on_this_machine, false); assert.match(data.encryption.note, /owner keys init/);
  assert.ok(!JSON.stringify(data).includes(CANARY));
  const { data: info } = await call('voidmail_account_info');
  assert.equal(info.local_encryption.key_on_this_machine, false);
});

test('search runs on this machine over sealed and server-readable mail, without server search or marking read', async t => {
  const { api, call } = await setup(t);
  await api.deliver(mime({ to: ADDRESS, subject: 'Legacy note', text: `legacy ${CANARY}` }), { plaintext: true, receivedAt: '2020-01-01T00:00:00.000Z' });
  for (let i = 0; i < 22; i++) await api.deliver(mime({ to: ADDRESS, subject: `Filler ${i}`, text: 'nothing here' }));
  await api.deliver(mime({ to: ADDRESS, subject: 'Quarterly invoice', text: `amount ${CANARY}` }));
  await api.deliver(mime({ to: ADDRESS, subject: 'Long letter', text: `${'words '.repeat(100)} deep-${CANARY}` }));
  const { data } = await call('voidmail_search_inbox', { query: CANARY.toLowerCase() });
  assert.equal(data.searched_on, 'this machine'); assert.equal(data.complete, true); assert.equal(data.scanned, 25);
  assert.deepEqual(data.results.map(r => [r.subject, r.storage]).sort(), [['Legacy note', 'server-readable'], ['Quarterly invoice', 'sealed']]);
  assert.match(data.note, /first 280 characters/);
  assert.ok(!api.state.calls.some(c => c.path === '/v1/agent-mail/inbox/search'), 'the server was not asked to search');
  assert.ok(!api.state.calls.some(c => /^\/v1\/agent-mail\/inbox\/[^/]+$/.test(c.path)), 'search must not open (and mark read) messages');
  // full_text also searches whole encrypted bodies, through the read-only sealed-body route.
  const { data: deep } = await call('voidmail_search_inbox', { query: `deep-${CANARY}`, full_text: true });
  assert.deepEqual(deep.results.map(r => [r.subject, r.matched_in]), [['Long letter', 'body']]);
  assert.ok(deep.encrypted_bodies_searched >= 1);
  assert.ok(api.state.emails.every(e => e.is_read === 0), 'nothing was marked read');
  const { data: partial } = await call('voidmail_search_inbox', { query: 'legacy', scan: 5 });
  assert.equal(partial.scanned, 5); assert.equal(partial.complete, false); assert.equal(partial.results.length, 0);
});

test('after rotation, old mail opens from the keyring; an extra unknown recipient is named', async t => {
  const { api, call, owner } = await setup(t);
  const oldId = await api.deliver(mime({ to: ADDRESS, subject: 'Before rotation', text: 'old key' }));
  assert.equal(await owner(['keys', 'rotate']), 0);
  const extra = stranger();
  const newId = await api.deliver(mime({ to: ADDRESS, subject: 'After rotation', text: 'new key' }), { extraRecipients: [extra] });
  const { data: before } = await call('voidmail_read_email', { email_id: oldId });
  assert.equal(before.readable, true); assert.equal(before.subject, 'Before rotation');
  const { data: after } = await call('voidmail_read_email', { email_id: newId });
  assert.equal(after.readable, true); assert.equal(after.subject, 'After rotation');
  assert.deepEqual(after.sealed_to.not_signed_by_this_mailbox, [{ kind: 'owner_recovery', key_id: extra.key_id }]);
  assert.match(after.sealed_to.warning, /Whoever holds such a key can read it/);
});

test('the MCP server needs only the mail secret key: an unreadable signing key changes nothing, a loose secret key is refused', async t => {
  const { dir, api, call } = await setup(t);
  const id = await api.deliver(mime({ to: ADDRESS, subject: 'Hello', text: 'hi' }));
  chmodSync(join(dir, 'mail-signing-key'), 0o000);
  try { const { data } = await call('voidmail_read_email', { email_id: id }); assert.equal(data.readable, true); }
  finally { chmodSync(join(dir, 'mail-signing-key'), 0o600); }
  chmodSync(join(dir, 'mail-secret-key'), 0o644);
  try { const { data: loose } = await call('voidmail_read_email', { email_id: id }); assert.equal(loose.readable, false); assert.match(loose.note, /mode 0600/); }
  finally { chmodSync(join(dir, 'mail-secret-key'), 0o600); }
});

test('decrypted mail carrying key-shaped strings is redacted before the model sees it', async t => {
  const { api, call, wire } = await setup(t);
  const planted = ['vmx_' + 'c'.repeat(64), 'vms_' + 'd'.repeat(64), 'AGE-SECRET-KEY-1' + 'Q'.repeat(58), 'AGE-SECRET-KEY-PQ-1' + 'R'.repeat(60), 'vm_' + 'e'.repeat(64)];
  const id = await api.deliver(mime({ to: ADDRESS, subject: 'keys', text: `forwarded ${planted.join(' ')}` }));
  for (const [tool, args] of [['voidmail_list_inbox', {}], ['voidmail_read_email', { email_id: id }]]) {
    const { r } = await call(tool, args);
    for (const k of planted) assert.ok(!JSON.stringify(r).includes(k), `${tool}: ${k}`);
    assert.match(JSON.stringify(r), /\[redacted-key\]/);
  }
  for (const k of planted) assert.ok(wire.every(m => !m.includes(k)), k);
  assert.equal(redactKeys('A​GE-SECRET-KEY-1' + 'Z'.repeat(58)), '[redacted-key]');
});

test('no MCP tool can register or change a key', async t => {
  const { api, client } = await setup(t);
  const { tools } = await client.listTools();
  assert.ok(!tools.some(x => /key/i.test(x.name)), 'no key tool');
  const args = { voidmail_read_email: { email_id: 'em_x' }, voidmail_search_inbox: { query: 'x' }, voidmail_send_email: { to: 'a@example.invalid', subject: 's' },
    voidmail_send_once: { operationId: 'synthetic_operation_0001', to: 'a@example.invalid', subject: 's' }, voidmail_send_status: { operationId: 'synthetic_operation_0001' },
    voidmail_mark_read: { email_id: 'em_x' }, voidmail_delete_email: { email_id: 'em_x' }, voidmail_delete_alias: { alias: 'x1' },
    voidmail_set_webhook: { url: 'https://example.invalid/h' }, voidmail_request_recipient: { recipient: 'a@example.invalid' }, voidmail_revoke_recipient: { pattern: '@example.invalid' },
    voidmail_wait_for_email: { timeout_seconds: 1 } };
  const before = api.state.calls.length;
  for (const x of tools) if (x.name !== 'voidmail_create_account') await client.callTool({ name: x.name, arguments: args[x.name] ?? {} }).catch(() => {});
  const mcp = api.state.calls.slice(before);
  assert.ok(mcp.length > 10);
  assert.ok(mcp.every(c => !c.path.includes('/keys') && !c.path.includes('/owner') && c.headers['X-Agent-Mail-Owner-Key'] === undefined));
});

test('unit: summary/body opening fails closed; key-set check enforces one signed set', async () => {
  const key = boxKeyFromFile('vmx_' + randomBytes(32).toString('hex'));
  const rcpt = { kind: 'agent', key_id: key.keyId, x25519_public_key: b64(key.publicKey) };
  const raw = mime({ to: ADDRESS, subject: 'x', text: 'body' });
  const { envelope, body } = await seal(raw, { recipients: [rcpt], epoch: 1 }, { emailId: 'sealed_1', address: ADDRESS });
  const e = parseEnvelope(JSON.stringify(envelope));
  const exp = { emailId: 'sealed_1', address: ADDRESS };
  assert.equal(openSummary(e, [key], exp).ok, true);
  assert.equal(openBody(e, body, [key], exp).ok, true);
  assert.equal(openSummary(e, [key], { emailId: 'sealed_1', address: 'other@voidmail.ai' }).reason, 'binding_mismatch');
  assert.equal(openSummary(e, [key], { emailId: 'sealed_2', address: ADDRESS }).reason, 'binding_mismatch');
  assert.equal(openSummary({ ...e, v: 2 }, [key], exp).reason, 'unsupported_version');
  assert.equal(openSummary({ ...e, alg: 'none' }, [key], exp).reason, 'unsupported_version');
  assert.equal(parseEnvelope({ ...envelope, recipients: [] }), null);
  assert.equal(parseEnvelope('{not json'), null);
  assert.equal(openBody(e, body.subarray(1), [key], exp).reason, 'body_incomplete');
  assert.equal(openBody(e, null, [key], exp).reason, 'body_incomplete');
  const other = boxKeyFromFile('vmx_' + randomBytes(32).toString('hex'));
  assert.equal(openSummary(e, [other], exp).reason, 'no_matching_key');
  // A stanza that names our key id but was wrapped for another key.
  const forged = await seal(raw, { recipients: [{ ...rcpt, x25519_public_key: b64(other.publicKey) }], epoch: 1 }, { emailId: 'sealed_1', address: ADDRESS });
  assert.equal(openSummary(parseEnvelope(forged.envelope), [key], exp).reason, 'decrypt_failed');
  // Key sets.
  const signer = nacl.sign.keyPair();
  const { bindingPreimage } = await import('./helpers/fake-voidmail.mjs');
  const entry = (r, epoch, count, s = signer) => ({ ...r, count, binding_sig: b64(nacl.sign.detached(bindingPreimage({ address: ADDRESS, epoch, count, ...r }), s.secretKey)) });
  const dirOf = (epoch, recipients, s = signer) => ({ address: ADDRESS, epoch, signing_public_key: b64(s.publicKey), recipients });
  assert.equal(checkKeySet(dirOf(1, [entry(rcpt, 1, 1)]), ADDRESS, null).ok, true);
  assert.equal(checkKeySet(dirOf(1, [entry(rcpt, 1, 2)]), ADDRESS, null).ok, false, 'count mismatch');
  assert.equal(checkKeySet(dirOf(2, [entry(rcpt, 1, 1)]), ADDRESS, null).ok, false, 'epoch mismatch');
  assert.equal(checkKeySet(dirOf(1, [entry({ ...rcpt, kind: 'owner_recovery' }, 1, 1)]), ADDRESS, null).ok, false, 'no agent key');
  assert.equal(checkKeySet({ ...dirOf(1, [entry(rcpt, 1, 1)]), address: 'other@voidmail.ai' }, ADDRESS, null).ok, false, 'other mailbox');
  assert.equal(checkKeySet(dirOf(1, [entry(rcpt, 1, 1)]), ADDRESS, { signingPublicKey: b64(nacl.sign.keyPair().publicKey), epoch: 1 }).ok, false, 'pinned signer');
  assert.equal(checkKeySet(dirOf(1, [entry(rcpt, 1, 1)]), ADDRESS, { signingPublicKey: b64(signer.publicKey), epoch: 2 }).ok, false, 'older epoch');
  assert.equal(checkKeySet(dirOf(1, []), ADDRESS, { signingPublicKey: b64(signer.publicKey), epoch: 1 }).ok, false, 'emptied set');
});

test('full-text search counts the bytes it actually downloads, not the size the server claims', async t => {
  const { dir, api } = await setup(t);
  const { searchInbox } = await import('../dist/inbox.js');
  for (let i = 0; i < 3; i++) await api.deliver(mime({ to: ADDRESS, subject: `Body ${i}`, text: `${'pad '.repeat(200)} needle-${i}` }));
  const rows = api.state.emails.map(e => ({ id: e.id, sealed: true, received_at: e.received_at, raw_size: 0, envelope: e.envelope }));
  const sizes = rows.map(r => api.state.bodies.get(r.id).length);
  let fetched = 0;
  const ctx = { dir: () => dir, address: () => ADDRESS, fetchBody: async id => { fetched++; return api.state.bodies.get(id); } };
  const out = await searchInbox('needle-0', { limit: 5, scan: 10, pageSize: 10, fullText: true, maxBodyBytes: sizes[0] },
    async (offset, size) => ({ emails: rows.slice(offset, offset + size), total: rows.length }), ctx);
  assert.equal(fetched, 1, 'only the first body fits the bound, whatever raw_size claims');
  assert.equal(out.encrypted_bodies_searched, 1);
  assert.match(out.note, /2 encrypted bodies were searched by summary only/);
});
