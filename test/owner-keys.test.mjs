// mcp-email 2.0: `voidly-mcp-email owner keys ...` makes the mailbox's encryption keys on this
// machine, registers only public material with the owner key, pins the signed key set, and
// refuses hostile servers. Synthetic keys and a synthetic API only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import nacl from 'tweetnacl';
import { runOwnerCli } from '../dist/owner-cli.js';
import { answerChallenge } from '../dist/owner-keys.js';
import { boxKeyFromFile } from '../dist/mailcrypto.js';
import { b64, bindingPreimage, fakeVoidmail, keyIdFor, unb64 } from './helpers/fake-voidmail.mjs';

const nonce = randomBytes(6).toString('hex');
const base62 = n => Array.from(randomBytes(n), b => '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'[b % 62]).join('');
const AGENT_KEY = 'vm_' + randomBytes(32).toString('hex');
const OWNER_KEY = 'vmo_' + base62(40);
const ADDRESS = 'keys' + nonce.slice(0, 6) + '@voidmail.ai';
const api = () => fakeVoidmail({ address: ADDRESS, ownerKey: OWNER_KEY, agentKey: AGENT_KEY });

function mailbox() {
  const root = mkdtempSync(join(tmpdir(), 'voidmail-keys-')); const dir = join(root, ADDRESS);
  mkdirSync(dir, { mode: 0o700 });
  writeFileSync(join(dir, 'agent-key'), AGENT_KEY + '\n', { mode: 0o600 });
  writeFileSync(join(dir, 'owner-key'), OWNER_KEY + '\n', { mode: 0o600 });
  return { root, dir };
}

async function run(argv, { root, api, confirm = async () => true, env = {} }) {
  const stdout = []; const stderr = [];
  const code = await runOwnerCli(argv, {
    env: { VOIDMAIL_KEY_DIR: root, ...env }, fetch: api.handle,
    stdout: l => stdout.push(l), stderr: l => stderr.push(l), confirm,
  });
  return { code, out: stdout.join('\n'), err: stderr.join('\n') };
}
const init = (ctx, extra = []) => run(['keys', 'init', '--address', ADDRESS, '--yes', ...extra], ctx);

const signingOf = dir => nacl.sign.keyPair.fromSeed(new Uint8Array(Buffer.from(readFileSync(join(dir, 'mail-signing-key'), 'utf8').trim().slice(4), 'hex')));

/** Add a recipient to the fake's active set at a new epoch, signed by `signer` (re-signing the rest). */
function addRecipient(fake, signer, kind) {
  const extra = nacl.box.keyPair();
  const set = fake.state.rows.filter(r => !r.retired);
  const epoch = Math.max(...fake.state.rows.map(r => r.epoch)) + 1;
  const all = [...set.map(r => ({ kind: r.kind, x25519_public_key: r.x25519_public_key, key_id: r.key_id })), { kind, x25519_public_key: b64(extra.publicKey), key_id: keyIdFor(extra.publicKey) }];
  for (const r of set) r.retired = true;
  for (const r of all) {
    const sig = nacl.sign.detached(bindingPreimage({ address: ADDRESS, epoch, count: all.length, ...r }), signer.secretKey);
    fake.state.rows.push({ epoch, ...r, signing_public_key: b64(signer.publicKey), binding_sig: b64(sig), retired: false });
  }
  return keyIdFor(extra.publicKey);
}

const secretsIn = dir => {
  const values = [];
  const add = v => { const raw = Buffer.from(v.slice(4), 'hex'); values.push(v, v.slice(4), raw.toString('base64'), raw.toString('base64url')); };
  for (const name of ['mail-secret-key', 'mail-signing-key', 'mail-secret-key.next']) {
    const p = join(dir, name); if (!existsSync(p)) continue;
    const v = readFileSync(p, 'utf8').trim(); add(v);
    if (v.startsWith('vms_')) { const pair = signingOf(dir); values.push(b64(pair.secretKey), Buffer.from(pair.secretKey).toString('hex')); }
  }
  if (existsSync(join(dir, 'keyring'))) for (const f of readdirSync(join(dir, 'keyring'))) add(readFileSync(join(dir, 'keyring', f), 'utf8').trim());
  return values;
};

function assertNoSecretLeft(fake, dir, outputs) {
  const secrets = secretsIn(dir);
  assert.ok(secrets.length >= 4);
  for (const call of fake.state.calls) {
    const wire = JSON.stringify(call);
    for (const s of secrets) assert.ok(!wire.includes(s), `a private key reached the API in ${call.method} ${call.path}`);
    assert.ok(call.path.startsWith('/v1/agent-mail/owner/'), `non-owner route ${call.path}`);
    assert.equal(call.headers['X-Agent-Mail-Key'], undefined);
    assert.ok(!wire.includes(AGENT_KEY));
  }
  for (const text of outputs) for (const s of [...secrets, OWNER_KEY, AGENT_KEY]) assert.ok(!text.includes(s), 'a key was printed');
}

test('keys init makes both keys locally (0600), proves possession, signs the set and registers only public data', async () => {
  const { root, dir } = mailbox(); const fake = api();
  let asked = null;
  const r = await run(['keys', 'init', '--address', ADDRESS], { root, api: fake, confirm: async q => { asked = q; return true; } });
  assert.equal(r.code, 0, r.err);
  assert.match(asked, /Turn on encrypted storage/); assert.match(asked, /cannot be switched back/);
  for (const name of ['mail-secret-key', 'mail-signing-key', 'mail-keys.json']) assert.equal(statSync(join(dir, name)).mode & 0o777, 0o600, name);
  assert.match(readFileSync(join(dir, 'mail-secret-key'), 'utf8'), /^vmx_[0-9a-f]{64}\n$/);
  assert.match(readFileSync(join(dir, 'mail-signing-key'), 'utf8'), /^vms_[0-9a-f]{64}\n$/);
  const box = boxKeyFromFile(readFileSync(join(dir, 'mail-secret-key'), 'utf8').trim());
  const [row] = fake.state.rows;
  assert.equal(row.key_id, box.keyId); assert.equal(row.x25519_public_key, b64(box.publicKey)); assert.equal(row.epoch, 1); assert.equal(row.kind, 'agent');
  assert.equal(row.signing_public_key, b64(signingOf(dir).publicKey));
  assert.equal(fake.state.storage, 'sealed');
  assert.deepEqual(fake.state.calls.map(c => `${c.method} ${c.path}`), [
    'GET /v1/agent-mail/owner/keys', 'POST /v1/agent-mail/owner/keys/challenge', 'POST /v1/agent-mail/owner/keys', 'GET /v1/agent-mail/owner/keys',
  ]);
  const posted = JSON.parse(fake.state.calls[2].body);
  assert.deepEqual(Object.keys(posted).sort(), ['epoch', 'recipients', 'signing_public_key']);
  assert.deepEqual(Object.keys(posted.recipients[0]).sort(), ['binding_sig', 'challenge_answer', 'challenge_id', 'key_id', 'kind', 'x25519_public_key']);
  assert.ok(fake.state.calls.every(c => c.headers['X-Agent-Mail-Owner-Key'] === OWNER_KEY));
  const record = JSON.parse(readFileSync(join(dir, 'mail-keys.json'), 'utf8'));
  assert.equal(record.epoch, 1); assert.equal(record.signing_public_key, row.signing_public_key); assert.ok(record.sealed_since);
  assert.deepEqual(record.known.map(k => k.key_id), [box.keyId]);
  assert.match(r.out, /Encrypted storage is on/); assert.match(r.out, /server-readable/); assert.match(r.out, /not end-to-end/i);
  assertNoSecretLeft(fake, dir, [r.out, r.err]);

  // Running it again changes nothing and registers nothing.
  const before = fake.state.calls.length;
  const again = await init({ root, api: fake });
  assert.equal(again.code, 0, again.err); assert.match(again.out, /already on/);
  assert.deepEqual(fake.state.calls.slice(before).map(c => c.method), ['GET']);
});

test('keys init without confirmation registers nothing but keeps the keys it made', async () => {
  const { root, dir } = mailbox(); const fake = api();
  const r = await run(['keys', 'init', '--address', ADDRESS], { root, api: fake, confirm: async () => false });
  assert.equal(r.code, 1); assert.match(r.err, /nothing was registered/);
  assert.equal(fake.state.rows.length, 0);
  assert.ok(fake.state.calls.every(c => c.method === 'GET'));
  const kept = readFileSync(join(dir, 'mail-secret-key'), 'utf8');
  const yes = await run(['keys', 'init', '--address', ADDRESS, '--yes'], { root, api: fake, confirm: async () => { throw new Error('no prompt with --yes'); } });
  assert.equal(yes.code, 0, yes.err);
  assert.equal(readFileSync(join(dir, 'mail-secret-key'), 'utf8'), kept, 'the same key is registered, not a new one');
  assert.equal(fake.state.rows[0].key_id, boxKeyFromFile(kept.trim()).keyId);
});

test('the challenge step is not a decryption oracle: any plaintext but the exact challenge is refused', async () => {
  const pop = (c, over = {}) => { const f = { ctx: 'voidmail-key-pop/1', address: ADDRESS, challengeId: c.challengeId, keyId: c.keyId, answer: 'a'.repeat(64), ...over };
    return Buffer.from([f.ctx, `address=${f.address}`, `challenge_id=${f.challengeId}`, `key_id=${f.keyId}`, `answer=${f.answer}`].join('\n')); };
  for (const plaintext of [
    () => randomBytes(32),                                                                   // a wrapped 32-byte message key
    () => Buffer.from(`voidmail-sealed-payload/1\n{"email_id":"x"}\nSubject: secret\r\n\r\nbody`), // a sealed body
    () => Buffer.from(`voidmail-sealed-summary/1\n{"subject":"secret"}`),                    // a sealed summary
    c => pop(c, { ctx: 'voidmail-key-pop/2' }),
    c => pop(c, { address: 'other@voidmail.ai' }),
    c => pop(c, { challengeId: 'f'.repeat(32) }),
    c => pop(c, { keyId: '0'.repeat(32) }),
    c => pop(c, { answer: 'A'.repeat(64) }),
    c => Buffer.concat([pop(c), Buffer.from('\nextra=1')]),
  ]) {
    const { root, dir } = mailbox(); const fake = api();
    fake.state.hostile.challengePlaintext = plaintext;
    const r = await init({ root, api: fake });
    assert.equal(r.code, 1);
    assert.match(r.err, /challenge was refused/);
    assert.equal(fake.state.rows.length, 0);
    assert.ok(!fake.state.calls.some(c => c.method === 'POST' && c.path === '/v1/agent-mail/owner/keys'), 'nothing was answered');
    assertNoSecretLeft(fake, dir, [r.out, r.err]);
  }
  // Direct unit check of the answer function.
  const key = boxKeyFromFile('vmx_' + randomBytes(32).toString('hex'));
  const eph = nacl.box.keyPair(); const n = nacl.randomBytes(24); const cid = '1'.repeat(32);
  const good = { ephemeral_public_key: b64(eph.publicKey), nonce: b64(n), ciphertext: b64(nacl.box(pop({ challengeId: cid, keyId: key.keyId }, { answer: 'b'.repeat(64) }), n, key.publicKey, eph.secretKey)) };
  assert.equal(answerChallenge(good, { address: ADDRESS, challengeId: cid, keyId: key.keyId }, key), 'b'.repeat(64));
  assert.throws(() => answerChallenge(good, { address: ADDRESS, challengeId: '2'.repeat(32), keyId: key.keyId }, key));
  assert.throws(() => answerChallenge(good, { address: ADDRESS, challengeId: cid, keyId: '3'.repeat(32) }, key));
  const flipped = Buffer.from(unb64(good.ciphertext)); flipped[3] ^= 1;
  assert.throws(() => answerChallenge({ ...good, ciphertext: b64(flipped) }, { address: ADDRESS, challengeId: cid, keyId: key.keyId }, key));
});

test('keys init refuses a set registered elsewhere, a different signing key, and an unconfirmed registration', async () => {
  // Keys already registered by another machine.
  {
    const { root } = mailbox(); const fake = api();
    const otherMachine = mailbox(); assert.equal((await init({ root: otherMachine.root, api: fake })).code, 0);
    const before = fake.state.calls.length;
    const r = await init({ root, api: fake });
    assert.equal(r.code, 1); assert.match(r.err, /already has encryption keys registered/);
    assert.ok(fake.state.calls.slice(before).every(c => c.method === 'GET'));
  }
  // This machine has a signing key; the server names a different one.
  {
    const { root } = mailbox(); const fake = api();
    assert.equal((await run(['keys', 'init', '--address', ADDRESS], { root, api: fake, confirm: async () => false })).code, 1);
    const other = mailbox(); assert.equal((await init({ root: other.root, api: fake })).code, 0);
    const before = fake.state.calls.length;
    const r = await init({ root, api: fake });
    assert.equal(r.code, 1); assert.match(r.err, /different signing key/);
    assert.ok(fake.state.calls.slice(before).every(c => c.method === 'GET'));
  }
  // The server accepts the POST but then lists nothing, or a set this machine did not sign.
  for (const after of [
    fake => { fake.state.hostile.directory = () => ({ address: ADDRESS, storage: 'sealed', epoch: 0, signing_public_key: null, recipients: [] }); },
    fake => { for (const r of fake.state.rows) r.binding_sig = b64(nacl.randomBytes(64)); },
    fake => { addRecipient(fake, nacl.sign.keyPair(), 'owner_recovery'); },
  ]) {
    const { root } = mailbox(); const fake = api();
    fake.state.hostile.afterRegister = () => after(fake);
    const r = await init({ root, api: fake });
    assert.equal(r.code, 1, r.out);
    assert.match(r.err, /did not list the key set this machine signed|WARNING/); assert.doesNotMatch(r.out, /Encrypted storage is on/);
  }
  // A bootstrapped owner key is refused by the server for key changes, with a clear sentence.
  {
    const { root } = mailbox(); const fake = api(); fake.state.hostile.bootstrappedOwner = true;
    const r = await init({ root, api: fake });
    assert.equal(r.code, 1); assert.match(r.err, /minted from its agent key/);
  }
});

test('keys status checks the whole set against the pin and flags injected or swapped keys', async () => {
  const { root, dir } = mailbox(); const fake = api();
  assert.equal((await init({ root, api: fake })).code, 0);
  const clean = await run(['keys', 'status', '--address', ADDRESS], { root, api: fake });
  assert.equal(clean.code, 0, clean.err); assert.match(clean.out, /epoch 1/); assert.doesNotMatch(clean.err, /WARNING/);

  // 1. The server adds its own "owner_recovery" key signed by a key it controls.
  const injected = (() => {
    const evil = nacl.box.keyPair(); const evilSigner = nacl.sign.keyPair(); const set = fake.state.rows.filter(r => !r.retired);
    const row = { epoch: set[0].epoch, kind: 'owner_recovery', x25519_public_key: b64(evil.publicKey), key_id: keyIdFor(evil.publicKey) };
    fake.state.rows.push({ ...row, signing_public_key: set[0].signing_public_key, binding_sig: b64(nacl.sign.detached(bindingPreimage({ address: ADDRESS, count: 2, ...row }), evilSigner.secretKey)), retired: false });
    return row.key_id;
  })();
  // The server cannot re-sign the real recipients for the larger set, so the set no longer verifies.
  const flagged = await run(['keys', 'status', '--address', ADDRESS], { root, api: fake });
  assert.equal(flagged.code, 1); assert.match(flagged.err, /WARNING: Key [0-9a-f]{32} is not signed by the set's signing key/);
  assert.doesNotMatch(flagged.out, /all signed/);
  fake.state.rows = fake.state.rows.filter(r => r.key_id !== injected);

  // 2. The server re-signs a whole new set with its own signing key.
  { const evilSigner = nacl.sign.keyPair(); addRecipient(fake, evilSigner, 'owner_recovery');
    for (const r of fake.state.rows.filter(x => !x.retired)) { r.signing_public_key = b64(evilSigner.publicKey);
      r.binding_sig = b64(nacl.sign.detached(bindingPreimage({ address: ADDRESS, count: 2, ...r }), evilSigner.secretKey)); } }
  const swapped = await run(['keys', 'status', '--address', ADDRESS], { root, api: fake });
  assert.equal(swapped.code, 1); assert.match(swapped.err, /different signing key than the one this machine pinned/);

  // 3. The server replays an older epoch.
  const fresh = mailbox(); const fake2 = api();
  assert.equal((await init({ root: fresh.root, api: fake2 })).code, 0);
  assert.equal((await run(['keys', 'rotate', '--address', ADDRESS, '--yes'], { root: fresh.root, api: fake2 })).code, 0);
  const old = fake2.state.rows.filter(r => r.epoch === 1);
  fake2.state.hostile.directory = () => ({ address: ADDRESS, storage: 'sealed', epoch: 1, signing_public_key: old[0].signing_public_key,
    recipients: old.map(r => ({ kind: r.kind, key_id: r.key_id, x25519_public_key: r.x25519_public_key, binding_sig: r.binding_sig, count: 1 })) });
  const replay = await run(['keys', 'status', '--address', ADDRESS], { root: fresh.root, api: fake2 });
  assert.equal(replay.code, 1); assert.match(replay.err, /epoch 1, older than epoch 2/);

  // 4. A key added with THIS mailbox's signing key elsewhere warns until accepted with --yes.
  const own = mailbox(); const fake3 = api();
  assert.equal((await init({ root: own.root, api: fake3 })).code, 0);
  const added = addRecipient(fake3, signingOf(own.dir), 'owner_recovery');
  const warn = await run(['keys', 'status', '--address', ADDRESS], { root: own.root, api: fake3 });
  assert.equal(warn.code, 1); assert.match(warn.err, new RegExp(`${added}.*added outside this machine`));
  const rotateBlocked = await run(['keys', 'rotate', '--address', ADDRESS, '--yes'], { root: own.root, api: fake3 });
  assert.equal(rotateBlocked.code, 1); assert.match(rotateBlocked.err, /has not seen/);
  const accept = await run(['keys', 'status', '--address', ADDRESS, '--yes'], { root: own.root, api: fake3 });
  assert.equal(accept.code, 0, accept.err);
  assert.ok(JSON.parse(readFileSync(join(own.dir, 'mail-keys.json'), 'utf8')).known.some(k => k.key_id === added));
  void dir;
});

test('keys rotate registers the next epoch, carries known recovery keys re-signed, and keeps the old key', async () => {
  const { root, dir } = mailbox(); const fake = api();
  assert.equal((await init({ root, api: fake })).code, 0);
  const recovery = addRecipient(fake, signingOf(dir), 'owner_recovery');
  assert.equal((await run(['keys', 'status', '--address', ADDRESS, '--yes'], { root, api: fake })).code, 0);
  const oldValue = readFileSync(join(dir, 'mail-secret-key'), 'utf8').trim(); const oldId = boxKeyFromFile(oldValue).keyId;
  let asked = '';
  const r = await run(['keys', 'rotate', '--address', ADDRESS], { root, api: fake, confirm: async q => { asked = q; return true; } });
  assert.equal(r.code, 0, r.err);
  assert.match(asked, new RegExp(recovery));
  const newValue = readFileSync(join(dir, 'mail-secret-key'), 'utf8').trim(); const newId = boxKeyFromFile(newValue).keyId;
  assert.notEqual(newId, oldId);
  assert.equal(readFileSync(join(dir, 'keyring', oldId), 'utf8').trim(), oldValue);
  assert.equal(statSync(join(dir, 'keyring', oldId)).mode & 0o777, 0o600);
  assert.equal(statSync(join(dir, 'keyring')).mode & 0o777, 0o700);
  assert.equal(existsSync(join(dir, 'mail-secret-key.next')), false);
  const posted = JSON.parse(fake.state.calls.filter(c => c.method === 'POST' && c.path === '/v1/agent-mail/owner/keys').pop().body);
  assert.equal(posted.epoch, 3);
  assert.deepEqual(posted.recipients.map(x => [x.kind, x.key_id, 'challenge_id' in x]).sort(), [['agent', newId, true], ['owner_recovery', recovery, false]].sort());
  const activeNow = fake.state.rows.filter(x => !x.retired);
  assert.deepEqual(activeNow.map(x => [x.kind, x.key_id, x.epoch]).sort(), [['agent', newId, 3], ['owner_recovery', recovery, 3]].sort());
  const record = JSON.parse(readFileSync(join(dir, 'mail-keys.json'), 'utf8'));
  assert.equal(record.epoch, 3);
  assert.deepEqual(record.known.map(k => k.key_id).sort(), [oldId, newId, recovery].sort());
  assertNoSecretLeft(fake, dir, [r.out, r.err]);
});

test('keys commands need the owner key, never read the agent-key file, and reject unknown subcommands', async () => {
  const { root, dir } = mailbox(); const fake = api();
  chmodSync(join(dir, 'agent-key'), 0o000);
  try { const ok = await init({ root, api: fake }); assert.equal(ok.code, 0, ok.err); }
  finally { chmodSync(join(dir, 'agent-key'), 0o600); }
  assert.equal((await run(['keys', 'bogus', '--address', ADDRESS], { root, api: fake })).code, 2);
  assert.equal((await run(['keys'], { root, api: fake })).code, 2);
  const noOwner = mailbox(); chmodSync(join(noOwner.dir, 'owner-key'), 0o644);
  const loose = await run(['keys', 'init', '--address', ADDRESS], { root: noOwner.root, api: fake });
  assert.equal(loose.code, 1); assert.match(loose.err, /owner key could not be read/);
  assert.equal(existsSync(join(noOwner.dir, 'mail-secret-key')), false, 'no key is made without the owner key');
});
