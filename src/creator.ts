// The creator identity that signs an inbox create request (2.1).
//
// POST /v1/agent-mail/create admits only a request signed by an ACTIVE did:voidly agent
// identity (worker/src/routes/agentMailCreate.ts). This module supplies that signer, in order:
//  1. VOIDMAIL_CREATOR_SIGNING_KEY_FILE (+ VOIDMAIL_CREATOR_DID): either the 2.0 format, exactly
//     64 raw Ed25519 secret-key bytes, or an @voidly/agent-sdk exportCredentials() JSON file;
//  2. the dedicated creator identity this package enrolled earlier: <key dir>/creator/identity.json;
//  3. a new dedicated creator identity, enrolled now through POST /v1/home/join, the agent-sdk 4.0
//     Home join protocol (worker/src/routes/agentHomeJoin.ts). Home join always makes two private,
//     non-discoverable identities (a "root" and a "board"); the root DID signs inbox creation.
//
// Home join sends only public keys, SHA-256 hashes of locally made API keys and two signatures
// over a message the relay issues. Like agent-sdk's homeJoinCreate, the message is checked line by
// line against what was asked for before anything is signed, so the relay cannot turn the join
// into a signing oracle. Every key the commit would bind is saved (0600, in a 0700 directory, in
// agent-sdk's PendingHomeJoinRegistration format) BEFORE the commit is first sent. A commit whose
// outcome is unknown is replayed byte for byte on the next run; no retry makes another identity.
// The saved identity file uses agent-sdk's exportCredentials() shape, so the SDK can load it.
//
// No secret from this module is ever put in a tool result, a printed line, an error message or
// any request other than the Home join's public keys, hashes and signatures. JavaScript strings
// cannot be wiped; the byte arrays this module holds are zeroed after use.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, closeSync, constants, fchmodSync, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { join } from 'node:path';
import nacl from 'tweetnacl';
import { prepareKeyRoot } from './keystore.js';

const API_BASE = 'https://api.voidly.ai';
const HOME_JOIN_PATH = '/v1/home/join';
const HOME_JOIN_AUDIENCE = `audience:${API_BASE}${HOME_JOIN_PATH}`;
const PENDING_FORMAT = 'voidly-home-join-pending-v1';
export const CREATOR_DIR = 'creator';
export const CREATOR_IDENTITY_FILE = 'identity.json';
export const CREATOR_PENDING_FILE = 'pending-join.json';
const DID_RE = /^did:voidly:[1-9A-HJ-NP-Za-km-z]{1,32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const ISO_MS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const MAX_IDENTITY_BYTES = 1024 * 1024;
const MAX_CHALLENGE_WINDOW_MS = 10 * 60 * 1000;
const COMMIT_ATTEMPTS = 3;
// A committed join answers a replay from its receipt for 24 hours. Before 23 hours a refused
// replay therefore proves the commit never landed.
const RECEIPT_TRUST_MS = 23 * 60 * 60 * 1000;
const posix = process.platform !== 'win32';

export type CreatorSource = 'configured' | 'stored' | 'enrolled';
export interface CreatorSigner {
  did: string;
  /** 64-byte Ed25519 secret key. The caller zeroes it after signing. */
  secretKey: Uint8Array;
  source: CreatorSource;
  /** The stored identity file, for 'stored' and 'enrolled'; null for a configured key file. */
  file: string | null;
}

export interface CreatorOptions {
  creatorDid?: string | null;
  creatorSigningKeyFile?: string | null;
  /** Enroll a dedicated creator identity when none is configured or stored (default true). */
  autoEnroll?: boolean;
  root: string;
  fetch: typeof fetch;
}

// ── Small helpers ──────────────────────────────────────────────────────────

const b64 = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64');
const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex');
const sha256Hex = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex');
const isObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/** Canonical base64 of exactly `length` bytes, or null. */
function b64Exact(value: unknown, length: number): Uint8Array | null {
  if (typeof value !== 'string' || value.length > 4096 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== length || bytes.toString('base64') !== value) { bytes.fill(0); return null; }
  return new Uint8Array(bytes);
}

/** did:voidly:<base58 of the first 16 bytes of the Ed25519 public key> (agentHomeJoin.ts didFrom). */
export function didFromSigningKey(publicKey: Uint8Array): string {
  const prefix = publicKey.subarray(0, 16);
  let n = BigInt('0x' + hex(prefix));
  let out = '';
  while (n > 0n) { out = BASE58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of prefix) { if (b !== 0) break; out = '1' + out; }
  return 'did:voidly:' + (out || '1');
}

/** The key pair a 64-byte secret embeds, or null when its public half is not its seed's. */
function keyPairFromSecret(secret: Uint8Array): nacl.SignKeyPair | null {
  if (secret.length !== 64) return null;
  const pair = nacl.sign.keyPair.fromSeed(secret.subarray(0, 32));
  if (timingSafeEqual(Buffer.from(pair.secretKey), Buffer.from(secret))) return pair;
  pair.secretKey.fill(0);
  return null;
}

/** Read an owned regular file (no symlink, 0600 or stricter) of at most `max` bytes. */
function readPrivateFile(path: string, max: number, what: string): Buffer {
  let fd: number;
  try { fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); }
  catch { throw new Error(`${what} could not be opened safely (missing, unreadable or a symlink); no create request was sent.`); }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > max || (posix && (st.mode & 0o077) !== 0) || (typeof process.getuid === 'function' && st.uid !== process.getuid())) {
      throw new Error(`${what} must be an owned regular file with mode 0600 or stricter; no create request was sent.`);
    }
    const buf = Buffer.alloc(st.size);
    let off = 0;
    while (off < st.size) { const n = readSync(fd, buf, off, st.size - off, off); if (n === 0) break; off += n; }
    if (off !== st.size) { buf.fill(0); throw new Error(`${what} changed while it was read; no create request was sent.`); }
    return buf;
  } finally { closeSync(fd); }
}

function assertPlainDir(path: string): void {
  const st = lstatSync(path);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error('not a plain directory');
}

/** <root>/creator, 0700. Throws before anything is sent when it cannot be made. */
export function creatorDir(root: string): string {
  try {
    prepareKeyRoot(root);
    const dir = join(root, CREATOR_DIR);
    try { mkdirSync(dir, { mode: 0o700 }); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    }
    assertPlainDir(dir);
    if (posix) chmodSync(dir, 0o700);
    return dir;
  } catch {
    throw new Error('The key directory could not be written; no inbox was created. Set VOIDMAIL_KEY_DIR to a writable private directory.');
  }
}

/** False only when nothing is there; anything odd counts as present, so a later safe open refuses it. */
function exists(path: string): boolean {
  try { lstatSync(path); return true; } catch (error) { return (error as NodeJS.ErrnoException).code !== 'ENOENT'; }
}

/**
 * Publish `content` at dir/name only if nothing is there: a fsynced 0600 temp file is hard-linked
 * into place (link(2) refuses an existing name, including a planted symlink). 'exists' means
 * another writer got there first; its file is left as it is.
 */
function publishPrivateFile(dir: string, name: string, content: string): 'written' | 'exists' {
  const temp = join(dir, `.${name}.${randomBytes(8).toString('hex')}.tmp`);
  const fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    if (posix) fchmodSync(fd, 0o600);
    writeSync(fd, content);
    fsyncSync(fd);
  } finally { closeSync(fd); }
  try { linkSync(temp, join(dir, name)); return 'written'; }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST') return 'exists';
    throw error;
  } finally { try { unlinkSync(temp); } catch { /* best effort */ } }
}

/** Keep a record that can no longer be used, under a new name; never delete key material. */
function setAside(dir: string, name: string, why: string): string {
  const target = join(dir, `${name}.${why}-${new Date().toISOString().replace(/[:.]/g, '')}`);
  renameSync(join(dir, name), target);
  return target;
}

// ── Signers from files ─────────────────────────────────────────────────────

/**
 * A signer from a file: the 2.0 raw format (exactly 64 secret-key bytes; needs `did`), or an
 * agent-sdk exportCredentials() JSON (its `did` and `signingSecretKey`; `did`, when also given,
 * must match). The key pair must be internally consistent. Never echoes file content.
 */
export function loadCreatorSigner(path: string, did: string | null | undefined, what = 'Creator signing key file'): { did: string; secretKey: Uint8Array } {
  if (did != null && !DID_RE.test(did)) throw new Error('VOIDMAIL_CREATOR_DID is not a did:voidly identity; no create request was sent.');
  const buf = readPrivateFile(path, MAX_IDENTITY_BYTES, what);
  try {
    if (buf.length === 64) {
      if (!did) throw new Error('A raw 64-byte creator signing key needs VOIDMAIL_CREATOR_DID; no create request was sent. An agent-sdk identity export (JSON) names its own DID.');
      const secret = new Uint8Array(buf);
      const pair = keyPairFromSecret(secret);
      if (!pair) { secret.fill(0); throw new Error(`${what} is not a valid Ed25519 key pair; no create request was sent.`); }
      pair.secretKey.fill(0);
      return { did, secretKey: secret };
    }
    let parsed: unknown;
    try { parsed = JSON.parse(buf.toString('utf8')); } catch { parsed = null; }
    if (!isObject(parsed) || typeof parsed.did !== 'string' || typeof parsed.signingSecretKey !== 'string') {
      throw new Error(`${what} must hold exactly 64 raw Ed25519 secret-key bytes or an agent-sdk identity export (JSON with did and signingSecretKey); no create request was sent.`);
    }
    if (!DID_RE.test(parsed.did)) throw new Error(`${what} names an invalid DID; no create request was sent.`);
    if (did && did !== parsed.did) throw new Error(`VOIDMAIL_CREATOR_DID does not match the DID in ${what.toLowerCase()}; no create request was sent.`);
    const secret = b64Exact(parsed.signingSecretKey, 64);
    const pair = secret ? keyPairFromSecret(secret) : null;
    if (!secret || !pair) { secret?.fill(0); throw new Error(`${what} does not hold a valid Ed25519 signing key; no create request was sent.`); }
    const listed = parsed.signingPublicKey === undefined ? null : b64Exact(parsed.signingPublicKey, 32);
    const mismatch = parsed.signingPublicKey !== undefined && (!listed || !timingSafeEqual(Buffer.from(listed), Buffer.from(pair.publicKey)));
    pair.secretKey.fill(0);
    if (mismatch) { secret.fill(0); throw new Error(`${what} lists a signing public key that its secret key does not match; no create request was sent.`); }
    return { did: parsed.did, secretKey: secret };
  } finally { buf.fill(0); }
}

// ── Home join (agent-sdk 4.0 protocol) ─────────────────────────────────────

interface Part { mode: 'create'; did: string; signing_public_key: string; encryption_public_key: string; api_key_hash: string }
interface NewIdentity { signing: nacl.SignKeyPair; encryption: nacl.BoxKeyPair; apiKey: string }
interface Commit { action: 'commit'; operation_id: string; nonce: string; message: string; root_signature: string; board_signature: string }

function newIdentity(): NewIdentity {
  return { signing: nacl.sign.keyPair(), encryption: nacl.box.keyPair(), apiKey: randomBytes(32).toString('hex') };
}
function wipeIdentity(id: NewIdentity): void { id.signing.secretKey.fill(0); id.encryption.secretKey.fill(0); }

function partOf(id: { signing: { publicKey: Uint8Array }; encryption: { publicKey: Uint8Array }; apiKey: string }): Part {
  return { mode: 'create', did: didFromSigningKey(id.signing.publicKey), signing_public_key: b64(id.signing.publicKey),
    encryption_public_key: b64(id.encryption.publicKey), api_key_hash: sha256Hex(id.apiKey) };
}

const partLines = (side: 'root' | 'board', p: Part) => [
  `${side}-mode:${p.mode}`, `${side}-did:${p.did}`, `${side}-signing-public-key:${p.signing_public_key}`,
  `${side}-encryption-public-key:${p.encryption_public_key}`, `${side}-api-key-hash:${p.api_key_hash}`,
];

/**
 * The relay's challenge, checked line by line against the request (agent-sdk checkHomeJoinChallenge):
 * only the issue and expiry times are the relay's to choose, and they are bounded. A private join
 * (no public profile, no mail, handle or wallet) is the only effect this client will sign.
 */
function checkChallenge(c: unknown, operationId: string, root: Part, board: Part): string | null {
  if (!isObject(c)) return 'challenge_not_object';
  if (c.operation_id !== operationId) return 'operation_id_mismatch';
  if (typeof c.nonce !== 'string' || !HEX64.test(c.nonce)) return 'nonce_invalid';
  if (typeof c.message !== 'string' || c.message.length > 4096) return 'message_invalid';
  if (c.signing !== 'ed25519_exact_utf8_both_keys') return 'signing_mode_unexpected';
  if (typeof c.message_sha256 !== 'string' || c.message_sha256 !== sha256Hex(c.message)) return 'message_digest_mismatch';
  const lines = c.message.split('\n');
  if (lines.length !== 19) return 'message_shape_unexpected';
  const fixed = ['voidly-agent-home-join-v1', 'action:join', HOME_JOIN_AUDIENCE, `operation-id:${operationId}`,
    ...partLines('root', root), ...partLines('board', board), 'public-profile:false', `nonce:${c.nonce}`];
  for (let i = 0; i < fixed.length; i++) if (lines[i] !== fixed[i]) return `message_line_${i}_unexpected`;
  if (lines[18] !== 'effect:private-home-only-no-mail-handle-wallet') return 'effect_unexpected';
  const issued = lines[16].startsWith('issued-at:') ? lines[16].slice('issued-at:'.length) : '';
  const expires = lines[17].startsWith('expires-at:') ? lines[17].slice('expires-at:'.length) : '';
  if (!ISO_MS_RE.test(issued) || !ISO_MS_RE.test(expires)) return 'timestamps_invalid';
  const issuedMs = Date.parse(issued), expiresMs = Date.parse(expires);
  if (!Number.isFinite(issuedMs) || !Number.isFinite(expiresMs) || new Date(issuedMs).toISOString() !== issued
      || new Date(expiresMs).toISOString() !== expires || expiresMs <= issuedMs || expiresMs - issuedMs > MAX_CHALLENGE_WINDOW_MS) return 'timestamps_invalid';
  if (c.expires_at !== undefined && c.expires_at !== expires) return 'expires_at_mismatch';
  return null;
}

/** One bounded JSON POST to the Home join route: no redirects, 16 KiB answer bound, no body echoed. */
async function postJoin(fetcher: typeof fetch, body: string): Promise<{ status: number; data: Record<string, unknown>; retryAfter: string | null }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 20_000);
  try {
    const response = await fetcher(`${API_BASE}${HOME_JOIN_PATH}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body, redirect: 'error', signal: controller.signal,
    });
    let data: Record<string, unknown> = {};
    const chunks: Uint8Array[] = []; let size = 0; let tooLarge = false;
    const reader = response.body?.getReader();
    if (reader) {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 16 * 1024) { tooLarge = true; await reader.cancel(); break; }
          chunks.push(value);
        }
      } finally { reader.releaseLock(); }
    }
    if (!tooLarge) { try { const v = JSON.parse(Buffer.concat(chunks).toString('utf8')); if (isObject(v)) data = v; } catch { /* not JSON */ } }
    return { status: response.status, data, retryAfter: response.headers.get('Retry-After') };
  } finally { clearTimeout(timer); }
}

/** The relay's refusal word when it is a plain closed word; never other server text. */
const refusalWord = (data: Record<string, unknown>, status: number) =>
  typeof data.error === 'string' && /^[a-z0-9_]{1,64}$/.test(data.error) ? data.error : `http_${status}`;

type CommitOutcome = { ok: true } | { ok: false; word: string; status: number; uncertain: boolean };

/** Send (or replay) one exact signed commit; identical bytes on every attempt (agent-sdk homeJoinReplayCommit). */
async function sendCommit(fetcher: typeof fetch, commit: Commit, rootDid: string, boardDid: string): Promise<CommitOutcome> {
  const body = JSON.stringify({ action: 'commit', operation_id: commit.operation_id, nonce: commit.nonce, message: commit.message,
    root_signature: commit.root_signature, board_signature: commit.board_signature });
  let last: CommitOutcome = { ok: false, word: 'home_join_commit_unreachable', status: 0, uncertain: true };
  for (let attempt = 0; attempt < COMMIT_ATTEMPTS; attempt++) {
    if (attempt > 0) await new Promise(resolve => setTimeout(resolve, 250 * attempt));
    let answer;
    try { answer = await postJoin(fetcher, body); }
    catch { last = { ok: false, word: 'home_join_commit_unreachable', status: 0, uncertain: true }; continue; }
    if (answer.status === 200 || answer.status === 201) {
      const r = answer.data.root, b = answer.data.board;
      if (!isObject(r) || !isObject(b) || r.did !== rootDid || b.did !== boardDid) {
        return { ok: false, word: 'home_join_card_mismatch', status: answer.status, uncertain: true };
      }
      return { ok: true };
    }
    const word = refusalWord(answer.data, answer.status);
    last = { ok: false, word, status: answer.status, uncertain: answer.status >= 500 || word === 'join_commit_conflict' };
    if (!last.uncertain) break;
  }
  return last;
}

interface PendingRecord {
  format: typeof PENDING_FORMAT;
  baseUrl: string;
  name: string;
  commit: Commit;
  credentials: {
    did: string; apiKey: string; signingSecretKey: string; encryptionSecretKey: string;
    homeBoard: { did: string; apiKey: string; signingSecretKey: string; encryptionSecretKey: string };
    homeJoinIdentity: true;
  };
}

/** agent-sdk exportCredentials() shape for the root identity, plus the board it was joined with. */
function identityRecord(pending: PendingRecord, rootSigningPublic: Uint8Array, rootEncryptionPublic: Uint8Array): string {
  const c = pending.credentials;
  return JSON.stringify({
    did: c.did, apiKey: c.apiKey, signingSecretKey: c.signingSecretKey, encryptionSecretKey: c.encryptionSecretKey,
    signingPublicKey: b64(rootSigningPublic), encryptionPublicKey: b64(rootEncryptionPublic),
    homeBoard: { ...c.homeBoard }, homeJoinIdentity: true,
    voidmailCreator: {
      v: 1, relay: API_BASE, enrolledAt: new Date().toISOString(),
      purpose: 'Dedicated identity made by @voidly/mcp-email to sign @voidmail.ai inbox creation. Keep this file private; it holds secret keys.',
    },
  }, null, 2) + '\n';
}

/** Check a pending record before anything is replayed: every key derives its DID, the message is exactly this join, both signatures verify. */
function openPending(value: unknown): { record: PendingRecord; rootSigningPublic: Uint8Array; rootEncryptionPublic: Uint8Array; issuedMs: number } | string {
  if (!isObject(value) || value.format !== PENDING_FORMAT) return 'format_unknown';
  if (value.baseUrl !== API_BASE) return 'relay_unexpected';
  const commit = value.commit, c = value.credentials;
  if (!isObject(commit) || commit.action !== 'commit' || typeof commit.operation_id !== 'string' || !HEX64.test(commit.operation_id)
      || typeof commit.nonce !== 'string' || !HEX64.test(commit.nonce) || typeof commit.message !== 'string') return 'commit_invalid';
  if (!isObject(c) || c.homeJoinIdentity !== true || !isObject(c.homeBoard)) return 'credentials_invalid';
  const board = c.homeBoard;
  if (typeof c.apiKey !== 'string' || !HEX64.test(c.apiKey) || typeof board.apiKey !== 'string' || !HEX64.test(board.apiKey)) return 'api_key_invalid';
  const keys = [b64Exact(c.signingSecretKey, 64), b64Exact(c.encryptionSecretKey, 32), b64Exact(board.signingSecretKey, 64), b64Exact(board.encryptionSecretKey, 32)];
  const [rootSign, rootEnc, boardSign, boardEnc] = keys;
  const wipe = () => keys.forEach(k => k?.fill(0));
  try {
    if (!rootSign || !rootEnc || !boardSign || !boardEnc) return 'secret_key_invalid';
    const rootPair = keyPairFromSecret(rootSign), boardPair = keyPairFromSecret(boardSign);
    if (!rootPair || !boardPair) return 'secret_key_inconsistent';
    rootPair.secretKey.fill(0); boardPair.secretKey.fill(0);
    if (c.did !== didFromSigningKey(rootPair.publicKey) || board.did !== didFromSigningKey(boardPair.publicKey)) return 'did_mismatch';
    const rootEncPublic = nacl.box.keyPair.fromSecretKey(rootEnc), boardEncPublic = nacl.box.keyPair.fromSecretKey(boardEnc);
    const rootPart = partOf({ signing: rootPair, encryption: rootEncPublic, apiKey: c.apiKey });
    const boardPart = partOf({ signing: boardPair, encryption: boardEncPublic, apiKey: board.apiKey });
    const lines = commit.message.split('\n');
    const expiresAt = lines.length === 19 && lines[17].startsWith('expires-at:') ? lines[17].slice('expires-at:'.length) : '';
    const problem = checkChallenge({ operation_id: commit.operation_id, nonce: commit.nonce, message: commit.message,
      message_sha256: sha256Hex(commit.message), signing: 'ed25519_exact_utf8_both_keys', expires_at: expiresAt }, commit.operation_id, rootPart, boardPart);
    rootEncPublic.secretKey.fill(0); boardEncPublic.secretKey.fill(0);
    if (problem) return `commit_message_${problem}`;
    const bytes = Buffer.from(commit.message, 'utf8');
    const rootSig = b64Exact(commit.root_signature, 64), boardSig = b64Exact(commit.board_signature, 64);
    if (!rootSig || !boardSig || !nacl.sign.detached.verify(bytes, rootSig, rootPair.publicKey) || !nacl.sign.detached.verify(bytes, boardSig, boardPair.publicKey)) return 'commit_signature_mismatch';
    return { record: value as unknown as PendingRecord, rootSigningPublic: rootPair.publicKey, rootEncryptionPublic: rootEncPublic.publicKey,
      issuedMs: Date.parse(lines[16].slice('issued-at:'.length)) };
  } finally { wipe(); }
}

function joinError(word: string, status: number, retryAfter: string | null): Error {
  if (status === 429) {
    const wait = retryAfter && /^\d{1,8}$/.test(retryAfter) ? ` Wait at least ${retryAfter} seconds.` : '';
    return new Error(`Creator identity enrollment (Home join) was rate limited (HTTP 429).${wait} Nothing was created; do not change network to evade the limit.`);
  }
  if (status === 404) return new Error('This Voidly API has no Home join route (HTTP 404); nothing was created. Configure VOIDMAIL_CREATOR_DID and VOIDMAIL_CREATOR_SIGNING_KEY_FILE instead.');
  if (word === 'home_join_disabled') return new Error('Voidly Home join is turned off on the server (home_join_disabled); nothing was created. Configure an existing identity with VOIDMAIL_CREATOR_DID and VOIDMAIL_CREATOR_SIGNING_KEY_FILE instead.');
  return new Error(`Creator identity enrollment was refused before commit (${word}${status ? `, HTTP ${status}` : ''}); nothing was created.`);
}

/** Replay a saved commit. Returns the identity path, or null when the record was set aside as never committed. */
async function finishPending(dir: string, fetcher: typeof fetch): Promise<string | null> {
  const pendingPath = join(dir, CREATOR_PENDING_FILE);
  let parsed: unknown = null;
  const buf = readPrivateFile(pendingPath, MAX_IDENTITY_BYTES, 'The saved creator enrollment');
  try { parsed = JSON.parse(buf.toString('utf8')); } catch { parsed = null; } finally { buf.fill(0); }
  const opened = openPending(parsed);
  if (typeof opened === 'string') {
    const kept = setAside(dir, CREATOR_PENDING_FILE, 'invalid');
    throw new Error(`The saved creator enrollment in ${dir} is not valid (${opened}); it was kept at ${kept} and nothing was sent. Run the command again to enroll a new creator identity.`);
  }
  const { record } = opened;
  const outcome = await sendCommit(fetcher, record.commit, record.credentials.did, record.credentials.homeBoard.did);
  const committed = outcome.ok || (outcome.status === 410 && outcome.word === 'operation_recovery_expired');
  if (committed) {
    publishPrivateFile(dir, CREATOR_IDENTITY_FILE, identityRecord(record, opened.rootSigningPublic, opened.rootEncryptionPublic));
    try { unlinkSync(pendingPath); } catch { /* identity saved; a stale pending is ignored once identity.json exists */ }
    return join(dir, CREATOR_IDENTITY_FILE);
  }
  if (outcome.uncertain) {
    throw new Error(`Creator identity enrollment may have committed, but the outcome is unknown (${outcome.word}). Its keys are saved in ${pendingPath}; run the same command again later to finish it. No other identity was made.`);
  }
  if (outcome.status === 409 && (outcome.word === 'challenge_expired_or_used' || outcome.word === 'challenge_mismatch')) {
    // Within the receipt window a committed join would have answered from its receipt, so this one never landed.
    // After it the answer is ambiguous; either way the record is kept aside and a fresh enrollment starts.
    setAside(dir, CREATOR_PENDING_FILE, Date.now() - opened.issuedMs < RECEIPT_TRUST_MS ? 'never-committed' : 'unresolved');
    return null;
  }
  throw new Error(`The saved creator enrollment was refused (${outcome.word}${outcome.status ? `, HTTP ${outcome.status}` : ''}). Its keys stay in ${pendingPath}. Move that file aside to enroll a new creator identity.`);
}

/** Enroll a new dedicated creator identity. Returns the identity path, or null when another process published a pending record first. */
async function enrollNew(dir: string, fetcher: typeof fetch): Promise<string | null> {
  const root = newIdentity(), board = newIdentity();
  try {
    const rootPart = partOf(root), boardPart = partOf(board);
    const operationId = randomBytes(32).toString('hex');
    let challenge;
    try {
      challenge = await postJoin(fetcher, JSON.stringify({ action: 'challenge', operation_id: operationId, root: rootPart, board: boardPart, public_profile: false }));
    } catch { throw new Error('Creator identity enrollment could not reach the Voidly API; nothing was created.'); }
    if (challenge.status !== 202) throw joinError(refusalWord(challenge.data, challenge.status), challenge.status, challenge.retryAfter);
    const problem = checkChallenge(challenge.data, operationId, rootPart, boardPart);
    if (problem) throw new Error(`Creator identity enrollment refused the server's join message (${problem}); nothing was signed or created.`);
    const message = challenge.data.message as string;
    const bytes = Buffer.from(message, 'utf8');
    const commit: Commit = { action: 'commit', operation_id: operationId, nonce: challenge.data.nonce as string, message,
      root_signature: b64(nacl.sign.detached(bytes, root.signing.secretKey)), board_signature: b64(nacl.sign.detached(bytes, board.signing.secretKey)) };
    const pending: PendingRecord = {
      format: PENDING_FORMAT, baseUrl: API_BASE, name: 'voidmail-creator', commit,
      credentials: {
        did: rootPart.did, apiKey: root.apiKey, signingSecretKey: b64(root.signing.secretKey), encryptionSecretKey: b64(root.encryption.secretKey),
        homeBoard: { did: boardPart.did, apiKey: board.apiKey, signingSecretKey: b64(board.signing.secretKey), encryptionSecretKey: b64(board.encryption.secretKey) },
        homeJoinIdentity: true,
      },
    };
    // Every key the commit binds is on disk before the commit is first sent.
    let saved: 'written' | 'exists';
    try { saved = publishPrivateFile(dir, CREATOR_PENDING_FILE, JSON.stringify(pending, null, 2) + '\n'); }
    catch { throw new Error('The creator identity could not be saved before its commit; nothing was committed or created.'); }
    if (saved === 'exists') return null; // a concurrent run's enrollment wins; this challenge simply expires
    const outcome = await sendCommit(fetcher, commit, rootPart.did, boardPart.did);
    if (!outcome.ok) {
      if (outcome.uncertain) {
        throw new Error(`Creator identity enrollment may have committed, but the outcome is unknown (${outcome.word}). Its keys are saved in ${join(dir, CREATOR_PENDING_FILE)}; run the same command again later to finish it. No other identity was made.`);
      }
      setAside(dir, CREATOR_PENDING_FILE, 'refused');
      throw new Error(`Creator identity enrollment was refused at commit (${outcome.word}${outcome.status ? `, HTTP ${outcome.status}` : ''}); nothing was created.`);
    }
    publishPrivateFile(dir, CREATOR_IDENTITY_FILE, identityRecord(pending, root.signing.publicKey, root.encryption.publicKey));
    try { unlinkSync(join(dir, CREATOR_PENDING_FILE)); } catch { /* best effort */ }
    return join(dir, CREATOR_IDENTITY_FILE);
  } finally { wipeIdentity(root); wipeIdentity(board); }
}

/**
 * The stored dedicated creator identity, enrolling one first if needed. A saved pending enrollment
 * is always finished (or proven dead) before a new one is started.
 */
export async function ensureCreatorIdentity(root: string, fetcher: typeof fetch, autoEnroll = true): Promise<{ path: string; enrolled: boolean }> {
  // With enrollment off, a missing identity writes nothing at all.
  if (!autoEnroll && !exists(join(root, CREATOR_DIR, CREATOR_IDENTITY_FILE))) {
    throw new Error('No creator identity is configured (VOIDMAIL_CREATOR_DID and VOIDMAIL_CREATOR_SIGNING_KEY_FILE) or stored, and automatic enrollment is off (VOIDMAIL_CREATOR_AUTO_ENROLL); no create request was sent.');
  }
  const dir = creatorDir(root);
  const identityPath = join(dir, CREATOR_IDENTITY_FILE);
  if (exists(identityPath)) return { path: identityPath, enrolled: false };
  for (let round = 0; round < 3; round++) {
    if (exists(identityPath)) return { path: identityPath, enrolled: false };
    const done = exists(join(dir, CREATOR_PENDING_FILE)) ? await finishPending(dir, fetcher) : await enrollNew(dir, fetcher);
    if (done) return { path: done, enrolled: true };
  }
  throw new Error('Creator identity enrollment did not settle after three rounds; nothing was created. Try again later.');
}

/** Resolve the signer for one create request (see the header for the order). */
export async function resolveCreatorSigner(options: CreatorOptions): Promise<CreatorSigner> {
  if (options.creatorSigningKeyFile) {
    const signer = loadCreatorSigner(options.creatorSigningKeyFile, options.creatorDid);
    return { ...signer, source: 'configured', file: null };
  }
  if (options.creatorDid) {
    throw new Error('VOIDMAIL_CREATOR_DID is set without VOIDMAIL_CREATOR_SIGNING_KEY_FILE; no create request was sent. Set both, or neither to use a dedicated creator identity in the key directory.');
  }
  const { path, enrolled } = await ensureCreatorIdentity(options.root, options.fetch, options.autoEnroll !== false);
  const signer = loadCreatorSigner(path, null, 'The stored creator identity');
  return { ...signer, source: enrolled ? 'enrolled' : 'stored', file: path };
}
