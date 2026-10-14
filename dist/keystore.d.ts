export declare const AGENT_KEY_FILE = "agent-key";
export declare const OWNER_KEY_FILE = "owner-key";
export declare const MAIL_SECRET_FILE = "mail-secret-key";
export declare const MAIL_SIGNING_FILE = "mail-signing-key";
export declare const MAIL_RECORD_FILE = "mail-keys.json";
export declare const KEYRING_DIR = "keyring";
export type KeyFileName = typeof AGENT_KEY_FILE | typeof OWNER_KEY_FILE;
export declare const AGENT_KEY_RE: RegExp;
export declare const OWNER_KEY_RE: RegExp;
/** X25519 secret key (mail-secret-key, keyring files). */
export declare const MAIL_SECRET_KEY_RE: RegExp;
/** Ed25519 seed (mail-signing-key). */
export declare const MAIL_SIGNING_KEY_RE: RegExp;
/**
 * Key-shaped strings are replaced wherever they appear in anything a model can read,
 * including a key split by zero-width or other invisible characters.
 */
export declare function redactKeys(text: string, extra?: Iterable<string | null | undefined>): string;
export declare function keyRoot(env?: NodeJS.ProcessEnv): string;
export declare function validAddress(address: unknown): address is string;
export declare function mailboxDir(root: string, address: string): string;
export declare function keyPath(root: string, address: string, name: KeyFileName): string;
/** Create the root (0700) so a later write cannot fail after the mailbox exists. */
export declare function prepareKeyRoot(root: string): void;
export declare function ensureMailboxDir(root: string, address: string): string;
/** First write of a new mailbox's keys. Refuses to overwrite anything. */
export declare function writeNewMailboxKeys(root: string, address: string, agentKey: string, ownerKey: string | null): {
    agentPath: string;
    ownerPath: string | null;
};
/** True if the mailbox directory for `address` already holds either key file (or is not a plain directory). */
export declare function mailboxHasKeys(root: string, address: string): boolean;
export interface KeyStaging {
    dir: string;
    agentPath: string;
    ownerPath: string;
}
/**
 * Before account creation: <root>/.pending-<random>/ (0700) holding agent-key and owner-key
 * placeholders (0600, O_EXCL, fsynced). Throws if any of it cannot be written, so the
 * caller can refuse before the mailbox exists.
 */
export declare function stageMailboxKeys(root: string): KeyStaging;
export declare function discardStaging(staging: {
    dir: string;
}): void;
/**
 * After account creation: fill the staged placeholders with the minted keys, then move
 * the staging directory to <root>/<address> in one rename. If the move is impossible
 * (no valid address, or that directory already holds files), the keys stay in the
 * staging directory and its paths are returned: a key is never discarded.
 */
export declare function commitStagedKeys(staging: KeyStaging, root: string, address: string | null, agentKey: string, ownerKey: string | null): {
    agentPath: string;
    ownerPath: string | null;
    moved: boolean;
};
/**
 * Atomic replacement of one exact key file path (used for VOIDMAIL_OWNER_KEY_FILE): temp
 * file 0600 in the same directory, fsync, rename over the path.
 */
export declare function replaceKeyFileAt(path: string, re: RegExp, value: string): string;
/** Last-resort save: a NEW 0600 file beside `path` (never overwrites). */
export declare function writeKeyBeside(path: string, re: RegExp, value: string): string;
/** Atomic replacement used after a rotation: temp file 0600, fsync, rename. */
export declare function replaceKeyFile(root: string, address: string, name: KeyFileName, value: string): string;
/** Read a small key file without following symlinks and refuse loose permissions. */
export declare function readKeyFileAt(path: string, re: RegExp): string;
/** The only key reader the MCP server may use. It cannot read an owner-key file. */
export declare function readAgentKeyFile(path: string): string;
/** Write a NEW key file (0600, O_EXCL: never overwrites, refuses a planted symlink). */
export declare function writeKeyFileExclusive(path: string, re: RegExp, value: string): string;
/** True when nothing (file, directory or symlink) exists at `path`. */
export declare function pathIsFree(path: string): boolean;
/** Create <dir>/keyring (0700) if needed and return it. */
export declare function ensureKeyringDir(dir: string): string;
/**
 * The mail secret keys the MCP server may use to open sealed mail: the active key first, then
 * a rotation's pending key, then retired keys from keyring/. It never reads the signing key, the owner key or the agent key,
 * and refuses symlinks and loose permissions like every other key reader. A missing active key
 * returns an empty list (the mailbox has no encryption key on this machine).
 */
export declare function readMailSecretFiles(dir: string): string[];
export interface MailKeyRecordEntry {
    kind: 'agent' | 'owner_recovery';
    key_id: string;
    x25519_public_key: string;
    first_epoch: number;
    last_epoch: number;
}
export interface MailKeyRecord {
    v: 1;
    address: string;
    signing_public_key: string;
    epoch: number;
    sealed_since: string | null;
    known: MailKeyRecordEntry[];
}
/** Read mail-keys.json; null when absent. A malformed or loose-permission record throws. */
export declare function readMailRecord(dir: string): MailKeyRecord | null;
/** Atomically replace mail-keys.json (0600). */
export declare function writeMailRecord(dir: string, record: MailKeyRecord): string;
