// Mailbox credential files. Two credentials per mailbox, two files, never in one:
//   <root>/<address>/agent-key   the key the MCP server (the model's tools) uses
//   <root>/<address>/owner-key   the human owner's key; only the owner CLI reads it
// Directories are 0700 and files 0600.
// This module deliberately has NO function that reads the owner key. The owner
// CLI (owner-cli.ts) holds that reader, and the MCP server never imports it.
import { closeSync, constants, fchmodSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readSync, renameSync, rmSync, unlinkSync, writeSync, chmodSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';

export const AGENT_KEY_FILE = 'agent-key';
export const OWNER_KEY_FILE = 'owner-key';
export type KeyFileName = typeof AGENT_KEY_FILE | typeof OWNER_KEY_FILE;

export const AGENT_KEY_RE = /^vm_[0-9a-f]{64}$/;
export const OWNER_KEY_RE = /^vmo_[0-9A-Za-z]{40}$/;
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
  let out = text.replace(AGENT_KEY_SCAN, '[redacted-key]').replace(OWNER_KEY_SCAN, '[redacted-key]');
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

function ensureMailboxDir(root: string, address: string): string {
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
