// Mailbox credential files. Each credential has its own file, never two in one:
//   <root>/<address>/agent-key         the key the MCP server (the model's tools) uses
//   <root>/<address>/owner-key         the human owner's key; only the owner CLI reads it
//   <root>/<address>/mail-secret-key   X25519 secret that opens this mailbox's sealed mail (2.0).
//                                      The MCP server reads it to decrypt; it is never sent.
//   <root>/<address>/mail-signing-key  Ed25519 seed that signs key registrations (2.0). Only the
//                                      owner CLI reads it.
//   <root>/<address>/keyring/<key id>  retired mail secret keys, kept so older mail still opens
//   <root>/<address>/mail-keys.json    public record of registered keys (no secret)
// Directories are 0700 and files 0600.
// This module deliberately has NO function that reads the owner key or the mail signing key.
// The owner CLI (owner-cli.ts, owner-keys.ts) holds those readers; the MCP server never imports them.
import { closeSync, constants, fchmodSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readSync, renameSync, rmSync, unlinkSync, writeSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';

export const AGENT_KEY_FILE = 'agent-key';
export const OWNER_KEY_FILE = 'owner-key';
export const MAIL_SECRET_FILE = 'mail-secret-key';
export const MAIL_SIGNING_FILE = 'mail-signing-key';
export const MAIL_RECORD_FILE = 'mail-keys.json';
export const KEYRING_DIR = 'keyring';
export type KeyFileName = typeof AGENT_KEY_FILE | typeof OWNER_KEY_FILE;

export const AGENT_KEY_RE = /^vm_[0-9a-f]{64}$/;
export const OWNER_KEY_RE = /^vmo_[0-9A-Za-z]{40}$/;
/** X25519 secret key (mail-secret-key, keyring files). */
export const MAIL_SECRET_KEY_RE = /^vmx_[0-9a-f]{64}$/;
/** Ed25519 seed (mail-signing-key). */
export const MAIL_SIGNING_KEY_RE = /^vms_[0-9a-f]{64}$/;
// Mailbox names are 3-30 characters from [a-z0-9._-]; a randomly assigned name can start
// with a digit. The character set has no '/' or '\\', a leading '.' is impossible, and '..'
// is refused in validAddress.
const ADDRESS_RE = /^[a-z0-9][a-z0-9._-]{1,28}[a-z0-9]@voidmail\.ai$/;

// Invisible characters a key can be split with and still be a key once they are removed.
// Soft hyphen, zero-width characters, direction marks, word joiner, invisible operators
// and BOM.
const GAP = '[\\u00AD\\u180E\\u200B-\\u200F\\u2060-\\u2064\\uFEFF]*';
const AGENT_KEY_SCAN = new RegExp(`v${GAP}m${GAP}_(?:${GAP}[0-9a-fA-F]){64}`, 'g');
const OWNER_KEY_SCAN = new RegExp(`v${GAP}m${GAP}o${GAP}_(?:${GAP}[0-9A-Za-z]){40}`, 'g');
// Mail secret key (vmx_) and mail signing seed (vms_), 2.0.
const MAIL_KEY_SCAN = new RegExp(`v${GAP}m${GAP}[xs]${GAP}_(?:${GAP}[0-9a-fA-F]){64}`, 'g');
// age identities (X25519 "AGE-SECRET-KEY-1…" and post-quantum "AGE-SECRET-KEY-PQ-1…"), any case.
const AGE_KEY_SCAN = new RegExp(`A${GAP}G${GAP}E${GAP}-${GAP}S${GAP}E${GAP}C${GAP}R${GAP}E${GAP}T${GAP}-${GAP}K${GAP}E${GAP}Y${GAP}-(?:${GAP}[0-9A-Za-z-]){20,}`, 'gi');
const escapeRe = (ch: string) => ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const exactScans = new Map<string, RegExp>();
function exactScan(secret: string): RegExp {
  let re = exactScans.get(secret);
  if (!re) {
    re = new RegExp(Array.from(secret, escapeRe).join(GAP), 'g');
    if (exactScans.size > 64) exactScans.clear();
    exactScans.set(secret, re);
  }
  re.lastIndex = 0;
  return re;
}

/**
 * Key-shaped strings are replaced wherever they appear in anything a model can read,
 * including a key split by zero-width or other invisible characters.
 */
export function redactKeys(text: string, extra: Iterable<string | null | undefined> = []): string {
  let out = text.replace(AGENT_KEY_SCAN, '[redacted-key]').replace(OWNER_KEY_SCAN, '[redacted-key]')
    .replace(MAIL_KEY_SCAN, '[redacted-key]').replace(AGE_KEY_SCAN, '[redacted-key]');
  for (const secret of extra) if (secret && secret.length >= 16) out = out.replace(exactScan(secret), '[redacted-key]');
  return out;
}

export function keyRoot(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.VOIDMAIL_KEY_DIR;
  return override && override.trim() ? override : join(homedir(), '.voidly', 'mcp-email');
}

export function validAddress(address: unknown): address is string {
  return typeof address === 'string' && ADDRESS_RE.test(address) && !address.includes('..');
}

export function mailboxDir(root: string, address: string): string {
  if (!validAddress(address)) throw new Error('Invalid mailbox address for a key directory.');
  return join(root, address);
}

export function keyPath(root: string, address: string, name: KeyFileName): string {
  return join(mailboxDir(root, address), name);
}

const posix = process.platform !== 'win32';

function assertRealDirectory(path: string): void {
  const st = lstatSync(path);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error('Key directory is not a plain directory.');
}

/** Create the root (0700) so a later write cannot fail after the mailbox exists. */
export function prepareKeyRoot(root: string): void {
  mkdirSync(root, { recursive: true, mode: 0o700 });
  assertRealDirectory(root);
}

export function ensureMailboxDir(root: string, address: string): string {
  prepareKeyRoot(root);
  const dir = mailboxDir(root, address);
  try { mkdirSync(dir, { mode: 0o700 }); } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  }
  assertRealDirectory(dir);
  if (posix) chmodSync(dir, 0o700);
  return dir;
}

function writeExclusive(path: string, value: string): void {
  // O_EXCL also refuses a pre-planted symlink at this path.
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    if (posix) fchmodSync(fd, 0o600);
    writeSync(fd, value + '\n');
    fsyncSync(fd);
  } finally { closeSync(fd); }
}

/** First write of a new mailbox's keys. Refuses to overwrite anything. */
export function writeNewMailboxKeys(root: string, address: string, agentKey: string, ownerKey: string | null): { agentPath: string; ownerPath: string | null } {
  if (!AGENT_KEY_RE.test(agentKey)) throw new Error('Refusing to save a malformed agent key.');
  if (ownerKey !== null && !OWNER_KEY_RE.test(ownerKey)) throw new Error('Refusing to save a malformed owner key.');
  const dir = ensureMailboxDir(root, address);
  const agentPath = join(dir, AGENT_KEY_FILE);
  writeExclusive(agentPath, agentKey);
  let ownerPath: string | null = null;
  if (ownerKey !== null) { ownerPath = join(dir, OWNER_KEY_FILE); writeExclusive(ownerPath, ownerKey); }
  return { agentPath, ownerPath };
}

/** True if the mailbox directory for `address` already holds either key file (or is not a plain directory). */
export function mailboxHasKeys(root: string, address: string): boolean {
  const dir = mailboxDir(root, address);
  let st;
  try { st = lstatSync(dir); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return false;
    return true;
  }
  if (st.isSymbolicLink() || !st.isDirectory()) return true;
  for (const name of [AGENT_KEY_FILE, OWNER_KEY_FILE]) {
    try { lstatSync(join(dir, name)); return true; } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') return true;
    }
  }
  return false;
}

// Placeholders the length of a real key (+ newline), written before the mailbox exists so
// the disk space and both file entries are held before any key is minted. A placeholder
// never matches AGENT_KEY_RE or OWNER_KEY_RE, so no reader accepts it.
const AGENT_PLACEHOLDER = 'x'.repeat(67);
const OWNER_PLACEHOLDER = 'x'.repeat(44);

export interface KeyStaging { dir: string; agentPath: string; ownerPath: string }

/**
 * Before account creation: <root>/.pending-<random>/ (0700) holding agent-key and owner-key
 * placeholders (0600, O_EXCL, fsynced). Throws if any of it cannot be written, so the
 * caller can refuse before the mailbox exists.
 */
export function stageMailboxKeys(root: string): KeyStaging {
  prepareKeyRoot(root);
  const dir = join(root, `.pending-${randomBytes(8).toString('hex')}`);
  mkdirSync(dir, { mode: 0o700 });
  try {
    assertRealDirectory(dir);
    if (posix) chmodSync(dir, 0o700);
    const agentPath = join(dir, AGENT_KEY_FILE); const ownerPath = join(dir, OWNER_KEY_FILE);
    writeExclusive(agentPath, AGENT_PLACEHOLDER);
    writeExclusive(ownerPath, OWNER_PLACEHOLDER);
    return { dir, agentPath, ownerPath };
  } catch (error) { discardStaging({ dir }); throw error; }
}

export function discardStaging(staging: { dir: string }): void {
  try { rmSync(staging.dir, { recursive: true, force: true }); } catch { /* best effort */ }
}

function overwritePlaceholder(path: string, value: string, placeholder: string): void {
  // Same length as the placeholder, written in place: no new directory entry is needed.
  const fd = openSync(path, constants.O_WRONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size !== placeholder.length + 1) throw new Error('Staged key file changed.');
    if (posix) fchmodSync(fd, 0o600);
    const buf = Buffer.from(value + '\n', 'utf8');
    if (writeSync(fd, buf, 0, buf.length, 0) !== buf.length) throw new Error('Short write.');
    fsyncSync(fd);
  } finally { closeSync(fd); }
}

/**
 * After account creation: fill the staged placeholders with the minted keys, then move
 * the staging directory to <root>/<address> in one rename. If the move is impossible
 * (no valid address, or that directory already holds files), the keys stay in the
 * staging directory and its paths are returned: a key is never discarded.
 */
export function commitStagedKeys(staging: KeyStaging, root: string, address: string | null, agentKey: string, ownerKey: string | null):
  { agentPath: string; ownerPath: string | null; moved: boolean } {
  if (!AGENT_KEY_RE.test(agentKey)) throw new Error('Refusing to save a malformed agent key.');
  if (ownerKey !== null && !OWNER_KEY_RE.test(ownerKey)) throw new Error('Refusing to save a malformed owner key.');
  overwritePlaceholder(staging.agentPath, agentKey, AGENT_PLACEHOLDER);
  if (ownerKey !== null) overwritePlaceholder(staging.ownerPath, ownerKey, OWNER_PLACEHOLDER);
  else unlinkSync(staging.ownerPath);
  const staged = { agentPath: staging.agentPath, ownerPath: ownerKey !== null ? staging.ownerPath : null, moved: false };
  if (!validAddress(address)) return staged;
  const target = mailboxDir(root, address);
  // rename(2) replaces at most an EMPTY directory; a non-empty one, a file or a symlink refuses.
  try { if (mailboxHasKeys(root, address)) return staged; renameSync(staging.dir, target); }
  catch { return staged; }
  return { agentPath: join(target, AGENT_KEY_FILE), ownerPath: ownerKey !== null ? join(target, OWNER_KEY_FILE) : null, moved: true };
}

/**
 * Atomic replacement of one exact key file path (used for VOIDMAIL_OWNER_KEY_FILE): temp
 * file 0600 in the same directory, fsync, rename over the path.
 */
export function replaceKeyFileAt(path: string, re: RegExp, value: string): string {
  if (!re.test(value)) throw new Error('Refusing to save a malformed key.');
  const dir = dirname(path);
  const temp = join(dir, `.${basename(path)}.${randomBytes(8).toString('hex')}.tmp`);
  writeExclusive(temp, value);
  try { renameSync(temp, path); } catch (error) { try { unlinkSync(temp); } catch { /* best effort */ } throw error; }
  return path;
}

/** Last-resort save: a NEW 0600 file beside `path` (never overwrites). */
export function writeKeyBeside(path: string, re: RegExp, value: string): string {
  if (!re.test(value)) throw new Error('Refusing to save a malformed key.');
  const target = join(dirname(path), `${basename(path)}.new-${randomBytes(4).toString('hex')}`);
  writeExclusive(target, value);
  return target;
}

/** Atomic replacement used after a rotation: temp file 0600, fsync, rename. */
export function replaceKeyFile(root: string, address: string, name: KeyFileName, value: string): string {
  const re = name === AGENT_KEY_FILE ? AGENT_KEY_RE : OWNER_KEY_RE;
  if (!re.test(value)) throw new Error('Refusing to save a malformed key.');
  const dir = ensureMailboxDir(root, address);
  const target = join(dir, name);
  const temp = join(dir, `.${name}.${randomBytes(8).toString('hex')}.tmp`);
  writeExclusive(temp, value);
  try { renameSync(temp, target); } catch (error) { try { unlinkSync(temp); } catch { /* best effort */ } throw error; }
  return target;
}

/** Read a small key file without following symlinks and refuse loose permissions. */
export function readKeyFileAt(path: string, re: RegExp): string {
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw new Error('Key path is not a regular file.');
    if (posix && (st.mode & 0o077) !== 0) throw new Error('Key file is readable by other users; run chmod 600 on it.');
    const buf = Buffer.alloc(256);
    const n = readSync(fd, buf, 0, buf.length, 0);
    const value = buf.subarray(0, n).toString('utf8').trim();
    if (!re.test(value)) throw new Error('Key file does not contain a valid key.');
    return value;
  } finally { closeSync(fd); }
}

/** The only key reader the MCP server may use. It cannot read an owner-key file. */
export function readAgentKeyFile(path: string): string {
  if (path.split(/[\\/]/).pop() === OWNER_KEY_FILE) throw new Error('The MCP server never reads the owner key.');
  return readKeyFileAt(path, AGENT_KEY_RE);
}

/** Write a NEW key file (0600, O_EXCL: never overwrites, refuses a planted symlink). */
export function writeKeyFileExclusive(path: string, re: RegExp, value: string): string {
  if (!re.test(value)) throw new Error('Refusing to save a malformed key.');
  writeExclusive(path, value);
  return path;
}

/** True when nothing (file, directory or symlink) exists at `path`. */
export function pathIsFree(path: string): boolean {
  try { lstatSync(path); return false; } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return true;
    throw error;
  }
}

/** Create <dir>/keyring (0700) if needed and return it. */
export function ensureKeyringDir(dir: string): string {
  const ring = join(dir, KEYRING_DIR);
  try { mkdirSync(ring, { mode: 0o700 }); } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  }
  assertRealDirectory(ring);
  if (posix) chmodSync(ring, 0o700);
  return ring;
}

const MAX_KEYRING = 64;

/**
 * The mail secret keys the MCP server may use to open sealed mail: the active key first, then
 * a rotation's pending key, then retired keys from keyring/. It never reads the signing key, the owner key or the agent key,
 * and refuses symlinks and loose permissions like every other key reader. A missing active key
 * returns an empty list (the mailbox has no encryption key on this machine).
 */
export function readMailSecretFiles(dir: string): string[] {
  const found: string[] = [];
  // mail-secret-key.next exists only between a key rotation's registration and its last file
  // move; it is this machine's own new key, so it is read too and no new mail is unreadable.
  for (const name of [MAIL_SECRET_FILE, MAIL_SECRET_FILE + '.next']) {
    const path = join(dir, name);
    if (!pathIsFree(path)) found.push(readKeyFileAt(path, MAIL_SECRET_KEY_RE));
  }
  const ring = join(dir, KEYRING_DIR);
  let names: string[] = [];
  try {
    const st = lstatSync(ring);
    if (st.isSymbolicLink() || !st.isDirectory()) throw new Error('The keyring is not a plain directory.');
    names = readdirSync(ring).filter(name => /^[0-9a-f]{32}$/.test(name)).sort().slice(0, MAX_KEYRING);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  for (const name of names) found.push(readKeyFileAt(join(ring, name), MAIL_SECRET_KEY_RE));
  return found;
}

// ── Public key record (mail-keys.json): no secret; written by the owner CLI ─────────
// The pin for this mailbox's key directory: the signing key, the highest epoch this machine
// has verified, when the mailbox became sealed, and every recipient key this machine has
// verified as signed by that signing key (first and last epoch it was in the set).

export interface MailKeyRecordEntry { kind: 'agent' | 'owner_recovery'; key_id: string; x25519_public_key: string; first_epoch: number; last_epoch: number }
export interface MailKeyRecord { v: 1; address: string; signing_public_key: string; epoch: number; sealed_since: string | null; known: MailKeyRecordEntry[] }

const B64_32 = /^[A-Za-z0-9+/]{43}=$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/;
const epochOk = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 1;

function validRecord(value: unknown): value is MailKeyRecord {
  if (!value || typeof value !== 'object') return false;
  const r = value as Record<string, unknown>;
  if (r.v !== 1 || !validAddress(r.address) || typeof r.signing_public_key !== 'string' || !B64_32.test(r.signing_public_key) || !epochOk(r.epoch)) return false;
  if (!(r.sealed_since === null || (typeof r.sealed_since === 'string' && ISO.test(r.sealed_since)))) return false;
  if (!Array.isArray(r.known) || r.known.length > 256) return false;
  return r.known.every((k: any) => k && typeof k === 'object'
    && (k.kind === 'agent' || k.kind === 'owner_recovery')
    && typeof k.key_id === 'string' && /^[0-9a-f]{32}$/.test(k.key_id)
    && typeof k.x25519_public_key === 'string' && B64_32.test(k.x25519_public_key)
    && epochOk(k.first_epoch) && epochOk(k.last_epoch) && k.first_epoch <= k.last_epoch);
}

/** Read mail-keys.json; null when absent. A malformed or loose-permission record throws. */
export function readMailRecord(dir: string): MailKeyRecord | null {
  const path = join(dir, MAIL_RECORD_FILE);
  let fd: number;
  try { fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw new Error('The mail key record could not be read.');
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > 256 * 1024) throw new Error('The mail key record is not a small regular file.');
    if (posix && (st.mode & 0o022) !== 0) throw new Error('The mail key record is writable by other users.');
    const buf = Buffer.alloc(st.size);
    const n = readSync(fd, buf, 0, buf.length, 0);
    const parsed: unknown = JSON.parse(buf.subarray(0, n).toString('utf8'));
    if (!validRecord(parsed)) throw new Error('The mail key record is malformed.');
    return parsed;
  } finally { closeSync(fd); }
}

/** Atomically replace mail-keys.json (0600). */
export function writeMailRecord(dir: string, record: MailKeyRecord): string {
  if (!validRecord(record)) throw new Error('Refusing to save a malformed mail key record.');
  const target = join(dir, MAIL_RECORD_FILE);
  const temp = join(dir, `.${MAIL_RECORD_FILE}.${randomBytes(8).toString('hex')}.tmp`);
  const fd = openSync(temp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    if (posix) fchmodSync(fd, 0o600);
    writeSync(fd, JSON.stringify(record, null, 2) + '\n');
    fsyncSync(fd);
  } finally { closeSync(fd); }
  try { renameSync(temp, target); } catch (error) { try { unlinkSync(temp); } catch { /* best effort */ } throw error; }
  return target;
}
