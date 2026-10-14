// Mail encryption for @voidly/mcp-email 2.0 (zero-access storage, Voidmail Phase 1).
//
// Primitives: tweetnacl only (the library the Voidly Worker uses to seal this mail).
//   - nacl.box       X25519 + XSalsa20-Poly1305: unwraps the per-message key
//   - nacl.secretbox XSalsa20-Poly1305: opens the sealed summary and body
//   - nacl.sign      Ed25519: verifies key-binding signatures
// No primitive is implemented here; this module only encodes, checks and calls tweetnacl.
// It has no way to make, sign or register a key (that is owner-keys.ts, owner CLI only).
//
// ── Wire contract (matches worker/src/lib/agentMailKeys.ts and agentMailSeal.ts) ─────────
//   x25519_public_key / signing_public_key   base64 (standard, padded) of 32 bytes
//   key_id      first 32 hex chars of SHA-256("voidmail-key-id/1\n" || raw X25519 public key)
//   binding     Ed25519 by the mailbox signing key over the UTF-8 lines
//                 voidmail-key-binding/1
//                 address=<address>
//                 epoch=<epoch>
//                 count=<recipients in the set>
//                 kind=<agent|owner_recovery>
//                 key_id=<key_id>
//                 x25519=<x25519_public_key>
//   A key set is one signing key and 1 agent + 0..3 owner_recovery recipients at one epoch.
//
//   Sealed row envelope (v 1, alg "x25519-xsalsa20poly1305-box+secretbox"):
//     { v, alg, email_id, mailbox, epoch,
//       recipients: [{ kind, key_id, ephemeral_public_key, nonce, wrapped_key }],
//       summary: { nonce, ciphertext },
//       body: { nonce, bytes, parts, part_bytes } }
//     wrapped_key = nacl.box(message key, nonce, recipient key, ephemeral secret)
//     summary     = secretbox("voidmail-sealed-summary/1\n" + JSON summary, nonce, message key)
//     body        = secretbox("voidmail-sealed-payload/1\n" + JSON header + "\n" + raw RFC 5322, nonce, message key),
//                   served as raw bytes by GET /v1/agent-mail/inbox/{id}/sealed-body (body.bytes long).
//   Inbox rows: GET /v1/agent-mail/inbox and /inbox/{id} return { id, sealed: true, envelope, ... }
//   for sealed rows; any other row is server-readable.
//   The client refuses anything bound to another mailbox or email_id, and checks the raw
//   message against the SHA-256 and size both sealed headers carry.

import nacl from 'tweetnacl';
import { createHash, timingSafeEqual } from 'node:crypto';
import { MAIL_SECRET_KEY_RE } from './keystore.js';

export const KEY_ID_RE = /^[0-9a-f]{32}$/;
export const KEY_KINDS = ['agent', 'owner_recovery'] as const;
export type KeyKind = typeof KEY_KINDS[number];
export const SEAL_ALG = 'x25519-xsalsa20poly1305-box+secretbox';
export const BINDING_CONTEXT = 'voidmail-key-binding/1';
export const POP_CONTEXT = 'voidmail-key-pop/1';
export const KEY_ID_CONTEXT = 'voidmail-key-id/1';
export const SUMMARY_CONTEXT = 'voidmail-sealed-summary/1';
export const PAYLOAD_CONTEXT = 'voidmail-sealed-payload/1';
export const MAX_RECIPIENTS = 4;
const MAX_BODY_BYTES = 16 * 1024 * 1024;

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ADDRESS_RE = /^[a-z0-9][a-z0-9._-]{1,28}[a-z0-9]@voidmail\.ai$/;
const utf8 = new TextEncoder();

/** Strict, canonical standard base64 to bytes; null when malformed or not the expected length. */
export function fromB64(value: unknown, length?: number, max = MAX_BODY_BYTES): Uint8Array | null {
  if (typeof value !== 'string' || value.length > Math.ceil(max / 3) * 4 || !B64_RE.test(value)) return null;
  const bytes = new Uint8Array(Buffer.from(value, 'base64'));
  if (length !== undefined && bytes.length !== length) return null;
  if (Buffer.from(bytes).toString('base64') !== value) return null;
  return bytes;
}
export const toB64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

// ── Key material ─────────────────────────────────────────────────────────────

export interface BoxKey { keyId: string; publicKey: Uint8Array; secretKey: Uint8Array }

export function keyIdFor(publicKey: Uint8Array): string {
  return createHash('sha256').update(KEY_ID_CONTEXT + '\n').update(publicKey).digest('hex').slice(0, 32);
}

export function boxKeyFromFile(value: string): BoxKey {
  if (!MAIL_SECRET_KEY_RE.test(value)) throw new Error('Malformed mail secret key.');
  const secretKey = new Uint8Array(Buffer.from(value.slice(4), 'hex'));
  const { publicKey } = nacl.box.keyPair.fromSecretKey(secretKey);
  return { keyId: keyIdFor(publicKey), publicKey, secretKey };
}

export function wipe(...keys: Array<{ secretKey: Uint8Array } | null | undefined>): void {
  for (const key of keys) key?.secretKey.fill(0);
}

// ── Key bindings and key sets ────────────────────────────────────────────────

export interface Binding { address: string; epoch: number; count: number; kind: KeyKind; keyId: string; publicKey: string }

export function bindingStatement(b: Binding): Uint8Array {
  if (!ADDRESS_RE.test(b.address)) throw new Error('Invalid mailbox address.');
  if (!Number.isSafeInteger(b.epoch) || b.epoch < 1) throw new Error('Invalid epoch.');
  if (!Number.isSafeInteger(b.count) || b.count < 1 || b.count > MAX_RECIPIENTS) throw new Error('Invalid recipient count.');
  if (!(KEY_KINDS as readonly string[]).includes(b.kind)) throw new Error('Invalid key kind.');
  const pub = fromB64(b.publicKey, 32);
  if (!pub || keyIdFor(pub) !== b.keyId) throw new Error('Public key and key id do not match.');
  return utf8.encode([BINDING_CONTEXT, `address=${b.address}`, `epoch=${b.epoch}`, `count=${b.count}`,
    `kind=${b.kind}`, `key_id=${b.keyId}`, `x25519=${b.publicKey}`].join('\n'));
}

/** True only for a well-formed binding with a valid signature by `signingPublicKey` (base64). */
export function verifyBinding(b: Binding, signature: unknown, signingPublicKey: unknown): boolean {
  let statement: Uint8Array;
  try { statement = bindingStatement(b); } catch { return false; }
  const sig = fromB64(signature, nacl.sign.signatureLength);
  const pub = fromB64(signingPublicKey, nacl.sign.publicKeyLength);
  if (!sig || !pub) return false;
  return nacl.sign.detached.verify(statement, sig, pub);
}

export interface SetRecipient { kind: KeyKind; key_id: string; x25519_public_key: string; binding_sig: string }
export interface KeySet { epoch: number; signingPublicKey: string; recipients: SetRecipient[]; storage: 'sealed' | 'server_readable' | null }
export type KeySetCheck = { ok: true; set: KeySet | null; storage: 'sealed' | 'server_readable' | null } | { ok: false; problem: string };

/**
 * Check a key directory (GET /v1/agent-mail/keys or /owner/keys) as ONE signed set: one epoch,
 * exactly `count` recipients, exactly one agent key, every binding signed by the set's signing
 * key, and, when pinned, that signing key and an epoch no lower than the highest seen.
 */
export function checkKeySet(data: unknown, address: string, pin: { signingPublicKey: string; epoch: number } | null): KeySetCheck {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return { ok: false, problem: 'The server did not return a key directory.' };
  const d = data as Record<string, unknown>;
  if (d.address !== undefined && d.address !== address) return { ok: false, problem: 'The key directory is for another mailbox.' };
  const storage = d.storage === 'sealed' || d.storage === 'server_readable' ? d.storage : null;
  if (!Array.isArray(d.recipients)) return { ok: false, problem: 'The key directory has no recipient list.' };
  if (d.recipients.length === 0) {
    if (pin) return { ok: false, problem: 'The server lists no keys for a mailbox this machine registered keys for.' };
    return { ok: true, set: null, storage };
  }
  const epoch = d.epoch; const signing = d.signing_public_key;
  if (typeof epoch !== 'number' || !Number.isSafeInteger(epoch) || epoch < 1) return { ok: false, problem: 'The key directory has no valid epoch.' };
  if (!fromB64(signing, 32)) return { ok: false, problem: 'The key directory has no valid signing key.' };
  if (d.recipients.length > MAX_RECIPIENTS) return { ok: false, problem: 'The key directory lists too many recipients.' };
  const count = d.recipients.length;
  const recipients: SetRecipient[] = [];
  for (const entry of d.recipients) {
    const r = entry && typeof entry === 'object' ? entry as Record<string, unknown> : {};
    if ((r.kind !== 'agent' && r.kind !== 'owner_recovery') || typeof r.key_id !== 'string' || typeof r.x25519_public_key !== 'string' || typeof r.binding_sig !== 'string') {
      return { ok: false, problem: 'A key directory entry is malformed.' };
    }
    if (r.count !== undefined && r.count !== count) return { ok: false, problem: 'A key directory entry was signed for a different number of recipients.' };
    if (!verifyBinding({ address, epoch, count, kind: r.kind, keyId: r.key_id, publicKey: r.x25519_public_key }, r.binding_sig, signing)) {
      return { ok: false, problem: `Key ${KEY_ID_RE.test(r.key_id) ? r.key_id : '(invalid id)'} is not signed by the set's signing key.` };
    }
    recipients.push({ kind: r.kind, key_id: r.key_id, x25519_public_key: r.x25519_public_key, binding_sig: r.binding_sig });
  }
  if (recipients.filter(r => r.kind === 'agent').length !== 1) return { ok: false, problem: 'The key directory does not have exactly one agent key.' };
  if (new Set(recipients.map(r => r.key_id)).size !== recipients.length) return { ok: false, problem: 'The key directory repeats a key.' };
  if (pin && pin.signingPublicKey !== signing) return { ok: false, problem: 'The key directory is signed by a different signing key than the one this machine pinned.' };
  if (pin && epoch < pin.epoch) return { ok: false, problem: `The key directory is at epoch ${epoch}, older than epoch ${pin.epoch} this machine has seen.` };
  return { ok: true, set: { epoch, signingPublicKey: signing as string, recipients, storage }, storage };
}

// ── Sealed messages ──────────────────────────────────────────────────────────

export type OpenFailure = 'malformed' | 'unsupported_version' | 'no_matching_key' | 'decrypt_failed' | 'binding_mismatch' | 'body_incomplete' | 'digest_mismatch';
export interface Stanza { kind: string; key_id: string }
export interface Envelope {
  v: 1; alg: string; email_id: string; mailbox: string; epoch: number;
  recipients: Array<{ kind: string; key_id: string; ephemeral_public_key: string; nonce: string; wrapped_key: string }>;
  summary: { nonce: string; ciphertext: string };
  body: { nonce: string; bytes: number; parts: number; part_bytes: number };
}

/** Parse a sealed envelope (object or JSON text) from a server row, or null. */
export function parseEnvelope(value: unknown): Envelope | null {
  let v = value;
  if (typeof v === 'string') { if (v.length > 65536) return null; try { v = JSON.parse(v); } catch { return null; } }
  if (!v || typeof v !== 'object' || Array.isArray(v)) return null;
  const e = v as Record<string, unknown>;
  const s = e.summary as Record<string, unknown> | undefined; const b = e.body as Record<string, unknown> | undefined;
  if (typeof e.email_id !== 'string' || typeof e.mailbox !== 'string' || typeof e.epoch !== 'number' || !Array.isArray(e.recipients)
    || !s || typeof s !== 'object' || !b || typeof b !== 'object') return null;
  if (e.recipients.length < 1 || e.recipients.length > MAX_RECIPIENTS) return null;
  for (const r of e.recipients) {
    if (!r || typeof r !== 'object') return null;
    const x = r as Record<string, unknown>;
    if (typeof x.kind !== 'string' || typeof x.key_id !== 'string' || typeof x.ephemeral_public_key !== 'string' || typeof x.nonce !== 'string' || typeof x.wrapped_key !== 'string') return null;
  }
  if (typeof s.nonce !== 'string' || typeof s.ciphertext !== 'string') return null;
  if (typeof b.nonce !== 'string' || !Number.isSafeInteger(b.bytes) || !Number.isSafeInteger(b.parts) || !Number.isSafeInteger(b.part_bytes)) return null;
  return e as unknown as Envelope;
}

export function envelopeStanzas(envelope: Envelope | null): Stanza[] {
  return envelope ? envelope.recipients.map(r => ({ kind: r.kind === 'agent' || r.kind === 'owner_recovery' ? r.kind : 'unknown', key_id: KEY_ID_RE.test(r.key_id) ? r.key_id : 'invalid' })) : [];
}

/** The message key for this envelope, or the reason there is none. The caller must wipe it. */
function unwrap(envelope: Envelope, keys: BoxKey[]): { dek: Uint8Array; keyId: string } | { error: OpenFailure } {
  if (envelope.v !== 1 || envelope.alg !== SEAL_ALG) return { error: 'unsupported_version' };
  const byId = new Map(keys.map(k => [k.keyId, k]));
  let tried = false;
  for (const r of envelope.recipients) {
    const key = byId.get(r.key_id);
    if (!key) continue;
    tried = true;
    const eph = fromB64(r.ephemeral_public_key, nacl.box.publicKeyLength);
    const nonce = fromB64(r.nonce, nacl.box.nonceLength);
    const wrapped = fromB64(r.wrapped_key, nacl.secretbox.keyLength + nacl.box.overheadLength);
    if (!eph || !nonce || !wrapped) continue;
    const dek = nacl.box.open(wrapped, nonce, eph, key.secretKey);
    if (dek && dek.length === nacl.secretbox.keyLength) return { dek, keyId: key.keyId };
    dek?.fill(0);
  }
  return { error: tried ? 'decrypt_failed' : 'no_matching_key' };
}

/** Split "<context>\n<json>[\n<rest>]" plaintext; null unless the context line matches exactly. */
function contextJson(bytes: Uint8Array, context: string, withRest: boolean): { json: Record<string, unknown>; rest: Uint8Array } | null {
  const prefix = utf8.encode(context + '\n');
  if (bytes.length < prefix.length || !bytesEqual(bytes.subarray(0, prefix.length), prefix)) return null;
  let end = bytes.length;
  if (withRest) { end = bytes.indexOf(0x0a, prefix.length); if (end < 0 || end - prefix.length > 65536) return null; }
  let json: unknown;
  try { json = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(prefix.length, end))); } catch { return null; }
  if (!json || typeof json !== 'object' || Array.isArray(json)) return null;
  return { json: json as Record<string, unknown>, rest: withRest ? bytes.subarray(end + 1) : new Uint8Array(0) };
}

export interface Expect { emailId: string; address: string | null }

function boundTo(fields: Record<string, unknown>, envelope: Envelope, expect: Expect): boolean {
  return fields.email_id === expect.emailId && envelope.email_id === expect.emailId
    && typeof fields.mailbox === 'string' && fields.mailbox === envelope.mailbox
    && (expect.address === null || envelope.mailbox === expect.address);
}

export type SummaryResult =
  | { ok: true; summary: Record<string, unknown>; keyId: string }
  | { ok: false; reason: OpenFailure };

/** Open the sealed summary (for inbox lists). Fails closed. */
export function openSummary(envelope: Envelope | null, keys: BoxKey[], expect: Expect): SummaryResult {
  if (!envelope) return { ok: false, reason: 'malformed' };
  if (envelope.email_id !== expect.emailId || (expect.address !== null && envelope.mailbox !== expect.address)) return { ok: false, reason: 'binding_mismatch' };
  const unwrapped = unwrap(envelope, keys);
  if ('error' in unwrapped) return { ok: false, reason: unwrapped.error };
  try {
    const nonce = fromB64(envelope.summary.nonce, nacl.secretbox.nonceLength);
    const ct = fromB64(envelope.summary.ciphertext, undefined, 64 * 1024);
    if (!nonce || !ct) return { ok: false, reason: 'malformed' };
    const plain = nacl.secretbox.open(ct, nonce, unwrapped.dek);
    if (!plain) return { ok: false, reason: 'decrypt_failed' };
    const parsed = contextJson(plain, SUMMARY_CONTEXT, false);
    if (!parsed) return { ok: false, reason: 'malformed' };
    if (!boundTo(parsed.json, envelope, expect)) return { ok: false, reason: 'binding_mismatch' };
    return { ok: true, summary: parsed.json, keyId: unwrapped.keyId };
  } finally { unwrapped.dek.fill(0); }
}

export type BodyResult =
  | { ok: true; raw: Uint8Array; header: Record<string, unknown>; summary: Record<string, unknown> | null; keyId: string }
  | { ok: false; reason: OpenFailure };

/**
 * Open the sealed body (the ciphertext bytes from /sealed-body). Checks: the length equals
 * `body.bytes`, the payload context and its mailbox/email_id binding, and the raw message's
 * SHA-256 and size against the payload header and the sealed summary. Fails closed.
 */
export function openBody(envelope: Envelope | null, ciphertext: Uint8Array | null, keys: BoxKey[], expect: Expect): BodyResult {
  if (!envelope) return { ok: false, reason: 'malformed' };
  if (envelope.email_id !== expect.emailId || (expect.address !== null && envelope.mailbox !== expect.address)) return { ok: false, reason: 'binding_mismatch' };
  const b = envelope.body;
  if (!ciphertext || b.bytes < nacl.secretbox.overheadLength || b.bytes > MAX_BODY_BYTES || ciphertext.length !== b.bytes) return { ok: false, reason: 'body_incomplete' };
  const nonce = fromB64(b.nonce, nacl.secretbox.nonceLength);
  if (!nonce) return { ok: false, reason: 'malformed' };
  const summary = openSummary(envelope, keys, expect);
  if (!summary.ok) return summary;
  const unwrapped = unwrap(envelope, keys);
  if ('error' in unwrapped) return { ok: false, reason: unwrapped.error };
  let plain: Uint8Array | null = null;
  try { plain = nacl.secretbox.open(ciphertext, nonce, unwrapped.dek); } finally { unwrapped.dek.fill(0); }
  if (!plain) return { ok: false, reason: 'decrypt_failed' };
  const parsed = contextJson(plain, PAYLOAD_CONTEXT, true);
  if (!parsed) { plain.fill(0); return { ok: false, reason: 'malformed' }; }
  if (!boundTo(parsed.json, envelope, expect)) { plain.fill(0); return { ok: false, reason: 'binding_mismatch' }; }
  const raw = parsed.rest;
  const digest = createHash('sha256').update(raw).digest('hex');
  if ([parsed.json, summary.summary].some(s => s.raw_sha256 !== digest || s.raw_bytes !== raw.length)) { plain.fill(0); return { ok: false, reason: 'digest_mismatch' }; }
  return { ok: true, raw, header: parsed.json, summary: summary.summary, keyId: unwrapped.keyId };
}
