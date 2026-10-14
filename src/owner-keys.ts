// `voidly-mcp-email owner keys <init|status|rotate>`: the mailbox's encryption keys (2.0).
//
// Owner CLI only. The MCP server never imports this module, so no MCP tool can make, sign,
// register or replace a key. Everything here runs on the human's terminal with the owner key.
//
//  - Keys are made on this machine (tweetnacl): an X25519 key that mail is sealed to, and an
//    Ed25519 key that signs the mailbox's key set. Both go in 0600 files and are never sent.
//    Only public keys, key ids, an epoch, signatures and proof-of-possession answers leave
//    this machine.
//  - Proof of possession: the server seals a challenge to each new public key; this CLI opens
//    it and returns only its answer (answerChallenge refuses any other plaintext shape, so the
//    step cannot be used to unwrap a message key).
//  - Pinning: mail-keys.json records the signing key and the highest epoch verified. Every
//    key list the server returns is checked as one signed set against that pin. After a
//    registration the CLI re-reads the list and checks the exact set it signed is active.
import nacl from 'tweetnacl';
import { renameSync } from 'node:fs';
import { basename, join } from 'node:path';
import {
  AGENT_KEY_FILE, MAIL_RECORD_FILE, MAIL_SECRET_FILE, MAIL_SECRET_KEY_RE, MAIL_SIGNING_FILE, MAIL_SIGNING_KEY_RE, OWNER_KEY_FILE,
  type MailKeyRecord, ensureKeyringDir, ensureMailboxDir, pathIsFree, readKeyFileAt, readMailRecord, writeKeyFileExclusive, writeMailRecord,
} from './keystore.js';
import {
  type Binding, type BoxKey, type KeySet, type SetRecipient, POP_CONTEXT, bindingStatement, boxKeyFromFile, checkKeySet, fromB64, toB64, wipe,
} from './mailcrypto.js';
import { VoidmailRefusal } from './refusal.js';

const NEXT_SUFFIX = '.next';
const HEX32 = /^[0-9a-f]{32}$/;
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

// ── Key material (owner CLI only) ────────────────────────────────────────────

/** A new X25519 secret key, encoded for its key file. */
export function generateMailSecret(): string {
  const seed = nacl.randomBytes(nacl.box.secretKeyLength);
  try { return 'vmx_' + hex(seed); } finally { seed.fill(0); }
}

/** A new Ed25519 seed, encoded for its key file. */
export function generateSigningSeed(): string {
  const seed = nacl.randomBytes(nacl.sign.seedLength);
  try { return 'vms_' + hex(seed); } finally { seed.fill(0); }
}

export interface SigningKey { publicKey: Uint8Array; secretKey: Uint8Array }

export function signingKeyFromFile(value: string): SigningKey {
  if (!MAIL_SIGNING_KEY_RE.test(value)) throw new Error('Malformed mail signing key.');
  const seed = new Uint8Array(Buffer.from(value.slice(4), 'hex'));
  try { const pair = nacl.sign.keyPair.fromSeed(seed); return { publicKey: pair.publicKey, secretKey: pair.secretKey }; }
  finally { seed.fill(0); }
}

/** The only mail-signing-key reader in this package. */
export function readSigningKeyFile(path: string): string {
  const name = basename(path);
  if (name === AGENT_KEY_FILE || name === OWNER_KEY_FILE || name === MAIL_SECRET_FILE) throw new Error('Not a signing-key file.');
  return readKeyFileAt(path, MAIL_SIGNING_KEY_RE);
}

export function signBinding(b: Binding, signing: SigningKey): string {
  return toB64(nacl.sign.detached(bindingStatement(b), signing.secretKey));
}

/**
 * Open a key-registration challenge and return ONLY its 64-hex answer. The plaintext must be
 * exactly these five lines, for this mailbox, this challenge and this key:
 *   voidmail-key-pop/1 / address=<address> / challenge_id=<id> / key_id=<key id> / answer=<64 hex>
 * Anything else is refused, so this step can never open a stored message or message key.
 */
export function answerChallenge(sealed: unknown, expect: { address: string; challengeId: unknown; keyId: string }, key: BoxKey): string {
  if (typeof expect.challengeId !== 'string' || !HEX32.test(expect.challengeId)) throw new Error('Invalid challenge id.');
  if (expect.keyId !== key.keyId) throw new Error('The challenge is for another key.');
  const c = sealed && typeof sealed === 'object' ? sealed as Record<string, unknown> : {};
  const eph = fromB64(c.ephemeral_public_key, nacl.box.publicKeyLength);
  const nonce = fromB64(c.nonce, nacl.box.nonceLength);
  const ct = fromB64(c.ciphertext, undefined, 1024);
  if (!eph || !nonce || !ct) throw new Error('Malformed challenge.');
  const opened = nacl.box.open(ct, nonce, eph, key.secretKey);
  if (!opened) throw new Error('The challenge was not sealed to this key.');
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(opened); }
  catch { throw new Error('Malformed challenge.'); }
  finally { opened.fill(0); }
  const lines = text.split('\n');
  const want = [POP_CONTEXT, `address=${expect.address}`, `challenge_id=${expect.challengeId}`, `key_id=${key.keyId}`];
  if (lines.length !== 5 || want.some((line, i) => lines[i] !== line) || !/^answer=[0-9a-f]{64}$/.test(lines[4])) {
    throw new Error('The challenge is not a key-registration challenge for this mailbox and key.');
  }
  return lines[4].slice('answer='.length);
}

// ── Commands ─────────────────────────────────────────────────────────────────

export interface KeysContext {
  root: string;
  address: string;
  env: NodeJS.ProcessEnv;
  yes: boolean;
  out: (line: string) => void;
  err: (line: string) => void;
  confirm: (question: string) => Promise<boolean>;
  /** One owner-key request to /v1/agent-mail/owner<path>. */
  call: (plan: { method: string; path: string; body?: unknown }) => Promise<any>;
  /** Report a failed owner request; returns the exit code. */
  refusal: (error: unknown) => number;
}

export const KEYS_USAGE = `  keys init                  Make this mailbox's encryption keys here and register the public key;
                             mail that arrives afterwards is stored encrypted          (confirm)
  keys status [--yes]        Check the server's key list against the keys pinned on this machine;
                             --yes accepts keys added with this mailbox's signing key elsewhere
  keys rotate                New encryption key; the old one is kept so older mail opens (confirm)`;

export async function runKeysCommand(sub: string | undefined, ctx: KeysContext): Promise<number> {
  if (sub === 'init') return keysInit(ctx);
  if (sub === 'status') return keysStatus(ctx);
  if (sub === 'rotate') return keysRotate(ctx);
  ctx.err(`keys needs one of: init, status, rotate.\n\n${KEYS_USAGE}`);
  return 2;
}

interface Paths { dir: string; secret: string; next: string; signing: string }
function paths(ctx: KeysContext): Paths {
  const dir = ensureMailboxDir(ctx.root, ctx.address);
  return {
    dir,
    secret: join(dir, MAIL_SECRET_FILE),
    next: join(dir, MAIL_SECRET_FILE + NEXT_SUFFIX),
    signing: ctx.env.VOIDMAIL_SIGNING_KEY_FILE || join(dir, MAIL_SIGNING_FILE),
  };
}

const KEY_REFUSALS: Record<string, string> = {
  owner_authorization_required: 'The server did not accept this owner key for key changes. Encrypted storage needs the owner key issued when the mailbox was created; an owner key minted later from the agent key cannot change keys.',
  key_possession_not_proven: 'The server did not accept the proof that this machine holds the key. Nothing changed; run the command again for a fresh challenge.',
  mail_key_epoch_conflict: 'The key list changed on the server since it was read. Nothing changed. Run `keys status`, then try again.',
  mail_key_set_conflict: 'The server refused the key set (a concurrent change, or an expired challenge). Nothing changed. Run `keys status`, then try again.',
  signing_key_change_not_confirmed: 'The server holds a different signing key for this mailbox. Nothing changed. This client never replaces the signing key.',
  key_challenge_refused: 'Too many outstanding key challenges. Wait 10 minutes, then try again.',
  mail_keys_unavailable: 'The key directory is temporarily unavailable. Nothing changed; try again in a minute.',
  owner_key_from_agent_key: "This mailbox's owner key was minted from its agent key (legacy bootstrap), so it cannot register encryption keys: whoever held the agent key could have minted it. Nothing changed. For encrypted storage, create a new inbox (mcp-email 2.0 creates it with an owner key) and move to it.",
};
function keyRefusal(ctx: KeysContext, error: unknown): number {
  if (error instanceof VoidmailRefusal && KEY_REFUSALS[error.detail.code]) { ctx.err(KEY_REFUSALS[error.detail.code]); return 1; }
  return ctx.refusal(error);
}

function loadRecord(ctx: KeysContext, dir: string): MailKeyRecord | null | 'bad' {
  try { const r = readMailRecord(dir); return r && r.address === ctx.address ? r : null; }
  catch { ctx.err(`${join(dir, MAIL_RECORD_FILE)} could not be read; fix or remove it. Nothing changed.`); return 'bad'; }
}

async function serverSet(ctx: KeysContext, pin: MailKeyRecord | null): Promise<{ set: KeySet | null; storage: string | null } | number> {
  let data: unknown;
  try { data = await ctx.call({ method: 'GET', path: '/keys' }); } catch (error) { return keyRefusal(ctx, error); }
  const checked = checkKeySet(data, ctx.address, pin ? { signingPublicKey: pin.signing_public_key, epoch: pin.epoch } : null);
  if (!checked.ok) { ctx.err(`WARNING: ${checked.problem} Nothing changed. Treat stored mail as readable by whoever holds the listed keys.`); return 1; }
  return { set: checked.set, storage: checked.storage };
}

function saveRecord(ctx: KeysContext, dir: string, previous: MailKeyRecord | null, set: KeySet, sealedNow: boolean): void {
  const known = previous && previous.signing_public_key === set.signingPublicKey ? previous.known.map(k => ({ ...k })) : [];
  for (const r of set.recipients) {
    const k = known.find(x => x.key_id === r.key_id);
    if (k) { k.last_epoch = Math.max(k.last_epoch, set.epoch); k.first_epoch = Math.min(k.first_epoch, set.epoch); }
    else known.push({ kind: r.kind, key_id: r.key_id, x25519_public_key: r.x25519_public_key, first_epoch: set.epoch, last_epoch: set.epoch });
  }
  const record: MailKeyRecord = {
    v: 1, address: ctx.address, signing_public_key: set.signingPublicKey,
    epoch: Math.max(set.epoch, previous?.signing_public_key === set.signingPublicKey ? previous.epoch : 0),
    sealed_since: previous?.sealed_since ?? (sealedNow ? new Date().toISOString() : null), known,
  };
  try { writeMailRecord(dir, record); }
  catch { ctx.err(`The key pin ${join(dir, MAIL_RECORD_FILE)} could not be written. The keys are saved; run \`keys status\` to write it again.`); }
}

function loadSigning(ctx: KeysContext, p: Paths): SigningKey | null {
  try { return signingKeyFromFile(readSigningKeyFile(p.signing)); }
  catch { ctx.err(`The mail signing key could not be read from ${p.signing}. It must hold a vms_ key and be mode 0600.`); return null; }
}
function loadBox(ctx: KeysContext, path: string): BoxKey | null {
  try { return boxKeyFromFile(readKeyFileAt(path, MAIL_SECRET_KEY_RE)); }
  catch { ctx.err(`The mail secret key could not be read from ${path}. It must hold a vmx_ key and be mode 0600.`); return null; }
}

/**
 * Sign and register a full key set at `epoch`: `fresh` is the new agent key (proved by a
 * challenge), `carried` are recipients of the current verified set kept unchanged. Then read
 * the list back and require exactly this set, signed by this machine.
 */
async function registerSet(ctx: KeysContext, signing: SigningKey, epoch: number, fresh: BoxKey, carried: SetRecipient[]): Promise<KeySet | number> {
  const freshPub = toB64(fresh.publicKey);
  let challenge: any;
  try { challenge = await ctx.call({ method: 'POST', path: '/keys/challenge', body: { recipients: [{ x25519_public_key: freshPub }] } }); }
  catch (error) { return keyRefusal(ctx, error); }
  const entry = Array.isArray(challenge?.challenges) ? challenge.challenges.find((c: any) => c && c.key_id === fresh.keyId) : undefined;
  let answer: string;
  try { answer = answerChallenge(entry?.sealed, { address: ctx.address, challengeId: entry?.challenge_id, keyId: fresh.keyId }, fresh); }
  catch (error) { ctx.err(`The server's key challenge was refused: ${(error as Error).message} Nothing was registered.`); return 1; }
  const count = 1 + carried.length;
  const signingPublicKey = toB64(signing.publicKey);
  const recipients: Record<string, unknown>[] = [{
    kind: 'agent', x25519_public_key: freshPub, key_id: fresh.keyId,
    binding_sig: signBinding({ address: ctx.address, epoch, count, kind: 'agent', keyId: fresh.keyId, publicKey: freshPub }, signing),
    challenge_id: entry.challenge_id, challenge_answer: answer,
  }];
  for (const r of carried) {
    recipients.push({ kind: r.kind, x25519_public_key: r.x25519_public_key, key_id: r.key_id,
      binding_sig: signBinding({ address: ctx.address, epoch, count, kind: r.kind, keyId: r.key_id, publicKey: r.x25519_public_key }, signing) });
  }
  try { await ctx.call({ method: 'POST', path: '/keys', body: { signing_public_key: signingPublicKey, epoch, recipients } }); }
  catch (error) {
    const code = keyRefusal(ctx, error);
    ctx.err('If the outcome is unclear, run `voidly-mcp-email owner keys status` before anything else.');
    return code;
  }
  let data: unknown;
  try { data = await ctx.call({ method: 'GET', path: '/keys' }); } catch (error) { keyRefusal(ctx, error); data = null; }
  const checked = checkKeySet(data, ctx.address, { signingPublicKey, epoch });
  const want = [fresh.keyId, ...carried.map(r => r.key_id)].sort().join(',');
  if (!checked.ok || !checked.set || checked.set.epoch !== epoch || checked.set.recipients.map(r => r.key_id).sort().join(',') !== want
    || !checked.set.recipients.some(r => r.kind === 'agent' && r.key_id === fresh.keyId && r.x25519_public_key === freshPub)) {
    ctx.err(`The server did not list the key set this machine signed for epoch ${epoch}. Treat the mailbox as server-readable and run \`voidly-mcp-email owner keys status\`.`);
    return 1;
  }
  return checked.set;
}

const BACKUP = (p: Paths) => `Back up ${p.secret} and ${p.signing} somewhere safe and private. Mail stored encrypted to a lost key cannot be recovered by anyone, including Voidly.`;

async function keysInit(ctx: KeysContext): Promise<number> {
  const p = paths(ctx);
  const pin = loadRecord(ctx, p.dir); if (pin === 'bad') return 1;
  const state = await serverSet(ctx, pin); if (typeof state === 'number') return state;
  if (state.set && pathIsFree(p.signing)) {
    ctx.err(`${ctx.address} already has encryption keys registered, but ${p.signing} is not on this machine. Copy the key files from the machine that set them up (keep mode 0600). Nothing changed.`);
    return 1;
  }
  const made: string[] = [];
  try {
    if (pathIsFree(p.signing)) { writeKeyFileExclusive(p.signing, MAIL_SIGNING_KEY_RE, generateSigningSeed()); made.push(p.signing); }
    if (pathIsFree(p.secret)) { writeKeyFileExclusive(p.secret, MAIL_SECRET_KEY_RE, generateMailSecret()); made.push(p.secret); }
  } catch { ctx.err(`The key files could not be written in ${p.dir}; nothing was registered.`); return 1; }
  if (made.length) ctx.out(`Made ${made.length === 2 ? 'new keys' : 'a new key'} on this machine (mode 0600, not shown): ${made.join(', ')}.`);

  const signing = loadSigning(ctx, p); if (!signing) return 1;
  const box = loadBox(ctx, p.secret); if (!box) { wipe(signing); return 1; }
  try {
    const signingPublicKey = toB64(signing.publicKey);
    if (state.set) {
      if (state.set.signingPublicKey !== signingPublicKey) {
        ctx.err('The server lists a different signing key for this mailbox than the one on this machine. Nothing changed. Run `voidly-mcp-email owner keys status`.');
        return 1;
      }
      const agent = state.set.recipients.find(r => r.kind === 'agent');
      if (agent?.key_id === box.keyId) {
        saveRecord(ctx, p.dir, pin, state.set, true);
        ctx.out(`Encrypted storage is already on for ${ctx.address} with key ${box.keyId} (epoch ${state.set.epoch}). Nothing changed.`);
        return 0;
      }
      ctx.err(`A different encryption key (${agent?.key_id ?? 'unknown'}) is registered for ${ctx.address}. Nothing changed. Use \`voidly-mcp-email owner keys rotate\` on the machine that holds it.`);
      return 1;
    }
    const question = `Turn on encrypted storage for ${ctx.address} with key ${box.keyId}? Mail that arrives afterwards is stored encrypted to the key in ${p.secret}, and this cannot be switched back. If that key and its backups are lost, that mail cannot be read again.`;
    if (!ctx.yes && !(await ctx.confirm(question))) { ctx.err('Not confirmed; nothing was registered. The key files stay on this machine; run `keys init` again when ready.'); return 1; }
    const set = await registerSet(ctx, signing, 1, box, []);
    if (typeof set === 'number') return set;
    saveRecord(ctx, p.dir, pin, set, true);
    ctx.out(`Encrypted storage is on for ${ctx.address}. Key ${box.keyId} is registered (epoch ${set.epoch}).`);
    ctx.out('Mail that arrives from now on is stored encrypted to this key; the MCP server on this machine decrypts it. Mail stored before now stays server-readable.');
    ctx.out('The Voidly mail server still sees each incoming message in plaintext while receiving it, before it is sealed. Mail to or from outside addresses is not end-to-end encrypted.');
    ctx.out(BACKUP(p));
    return 0;
  } finally { wipe(signing, box); }
}

async function keysRotate(ctx: KeysContext): Promise<number> {
  const p = paths(ctx);
  if (pathIsFree(p.secret) || pathIsFree(p.signing)) { ctx.err('This machine has no mail keys for this mailbox. Run `voidly-mcp-email owner keys init` first.'); return 1; }
  const pin = loadRecord(ctx, p.dir); if (pin === 'bad') return 1;
  if (!pin) { ctx.err(`No key pin (${join(p.dir, MAIL_RECORD_FILE)}) on this machine. Run \`voidly-mcp-email owner keys status\` first.`); return 1; }
  const state = await serverSet(ctx, pin); if (typeof state === 'number') return state;
  if (!state.set) { ctx.err('The server lists no keys for this mailbox. Nothing changed.'); return 1; }
  const signing = loadSigning(ctx, p); if (!signing) return 1;
  const current = loadBox(ctx, p.secret); if (!current) { wipe(signing); return 1; }
  let next: BoxKey | null = null;
  try {
    if (toB64(signing.publicKey) !== state.set.signingPublicKey) { ctx.err('The server\'s key set is not signed by this machine\'s signing key. Nothing changed. Run `keys status`.'); return 1; }
    if (pathIsFree(p.next)) {
      try { writeKeyFileExclusive(p.next, MAIL_SECRET_KEY_RE, generateMailSecret()); }
      catch { ctx.err(`The new key could not be written to ${p.next}; nothing changed.`); return 1; }
    }
    next = loadBox(ctx, p.next); if (!next) return 1;
    const agent = state.set.recipients.find(r => r.kind === 'agent')!;
    let set: KeySet = state.set;
    if (agent.key_id !== next.keyId) {
      if (agent.key_id !== current.keyId) {
        ctx.err(`The server's agent key ${agent.key_id} is not this machine's key ${current.keyId}. Nothing changed. Run \`keys status\`.`);
        return 1;
      }
      const carried = state.set.recipients.filter(r => r.kind !== 'agent');
      const unknown = carried.filter(r => !pin.known.some(k => k.key_id === r.key_id));
      if (unknown.length) {
        ctx.err(`The key set includes ${unknown.map(r => r.key_id).join(', ')}, which this machine has not seen. Nothing changed. Run \`voidly-mcp-email owner keys status\` and accept the set first if you added it.`);
        return 1;
      }
      const keep = carried.length ? ` It keeps ${carried.length} recovery key(s): ${carried.map(r => r.key_id).join(', ')}.` : '';
      const question = `Rotate the encryption key for ${ctx.address}? New mail is stored encrypted to the new key ${next.keyId}; the old key ${current.keyId} is kept on this machine so older mail still opens.${keep}`;
      if (!ctx.yes && !(await ctx.confirm(question))) { ctx.err(`Not confirmed; nothing was registered. The unregistered new key stays in ${p.next}.`); return 1; }
      const done = await registerSet(ctx, signing, state.set.epoch + 1, next, carried);
      if (typeof done === 'number') return done;
      set = done;
    }
    // Keep the old key first, then make the new one active. Until the rename the MCP server
    // also reads the .next file, so no mail is unreadable in between.
    try {
      const currentValue = readKeyFileAt(p.secret, MAIL_SECRET_KEY_RE);
      const keepPath = join(ensureKeyringDir(p.dir), current.keyId);
      if (pathIsFree(keepPath)) writeKeyFileExclusive(keepPath, MAIL_SECRET_KEY_RE, currentValue);
      else if (readKeyFileAt(keepPath, MAIL_SECRET_KEY_RE) !== currentValue) throw new Error('keyring entry differs');
      renameSync(p.next, p.secret);
    } catch {
      ctx.err(`The new key is registered, but the key files could not be moved. Both keys are still on this machine (${p.secret} and ${p.next}) and the MCP server reads both. Run \`keys rotate\` again to finish.`);
      return 1;
    }
    saveRecord(ctx, p.dir, pin, set, true);
    ctx.out(`Key rotated for ${ctx.address} (epoch ${set.epoch}). New mail is stored encrypted to ${next.keyId}. The old key ${current.keyId} is kept in ${join(p.dir, 'keyring')} so older mail still opens.`);
    ctx.out(BACKUP(p));
    return 0;
  } finally { wipe(signing, current, next); }
}

async function keysStatus(ctx: KeysContext): Promise<number> {
  const p = paths(ctx);
  const pin = loadRecord(ctx, p.dir); if (pin === 'bad') return 1;
  let data: unknown;
  try { data = await ctx.call({ method: 'GET', path: '/keys' }); } catch (error) { return keyRefusal(ctx, error); }
  const checked = checkKeySet(data, ctx.address, pin ? { signingPublicKey: pin.signing_public_key, epoch: pin.epoch } : null);
  let signingPublicKey: string | null = null;
  if (!pathIsFree(p.signing)) { const s = loadSigning(ctx, p); if (s) { signingPublicKey = toB64(s.publicKey); wipe(s); } }
  const local = new Map<string, string>();
  for (const [label, path] of [['active', p.secret], ['pending rotation', p.next]] as const) {
    if (pathIsFree(path)) continue;
    const box = loadBox(ctx, path); if (box) { local.set(box.keyId, label); wipe(box); }
  }
  ctx.out(`Mailbox ${ctx.address}`);
  ctx.out(`This machine: ${local.size ? [...local].map(([id, where]) => `${id} (${where})`).join(', ') : 'no mail encryption key'}; signing key ${signingPublicKey ? 'present' : 'absent'}; pinned epoch ${pin ? pin.epoch : 'none'}.`);
  const warnings: string[] = [];
  if (!checked.ok) warnings.push(checked.problem);
  else if (!checked.set) ctx.out(`Server: no encryption key registered; storage ${checked.storage ?? 'server_readable'}. Mail is stored server-readable.`);
  else {
    const set = checked.set;
    ctx.out(`Server: epoch ${set.epoch}, storage ${set.storage ?? 'unknown'}, ${set.recipients.length} key(s), all signed by the set's signing key.`);
    const unknown: string[] = [];
    if (signingPublicKey && set.signingPublicKey !== signingPublicKey) warnings.push('The server\'s key set is signed by a different signing key than the one on this machine.');
    for (const r of set.recipients) {
      const known = pin?.known.some(k => k.key_id === r.key_id) ?? false;
      ctx.out(`  ${r.kind} ${r.key_id}${local.has(r.key_id) ? ` (on this machine, ${local.get(r.key_id)})` : ''}${known ? '' : ' (not seen by this machine before)'}`);
      if (!known && pin) unknown.push(r.key_id);
    }
    const ownSigned = signingPublicKey !== null && set.signingPublicKey === signingPublicKey;
    if (unknown.length && !(ctx.yes && ownSigned)) {
      warnings.push(`Key(s) ${unknown.join(', ')} were added outside this machine, signed with this mailbox's signing key. Whoever holds them can read mail sealed to this mailbox.${ownSigned ? ' If you added them, run `keys status --yes` to accept this set.' : ''}`);
    }
    if (set.storage === 'server_readable') warnings.push('Keys are registered, but the server reports storage as server-readable.');
    if (ownSigned && warnings.length === 0) {
      saveRecord(ctx, p.dir, pin, set, set.storage === 'sealed');
      if (unknown.length) ctx.out(`Accepted the key set at epoch ${set.epoch}, including ${unknown.join(', ')}.`);
    }
  }
  for (const w of warnings) ctx.err(`WARNING: ${w}`);
  return warnings.length ? 1 : 0;
}
