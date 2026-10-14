import { type Binding, type BoxKey } from './mailcrypto.js';
/** A new X25519 secret key, encoded for its key file. */
export declare function generateMailSecret(): string;
/** A new Ed25519 seed, encoded for its key file. */
export declare function generateSigningSeed(): string;
export interface SigningKey {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}
export declare function signingKeyFromFile(value: string): SigningKey;
/** The only mail-signing-key reader in this package. */
export declare function readSigningKeyFile(path: string): string;
export declare function signBinding(b: Binding, signing: SigningKey): string;
/**
 * Open a key-registration challenge and return ONLY its 64-hex answer. The plaintext must be
 * exactly these five lines, for this mailbox, this challenge and this key:
 *   voidmail-key-pop/1 / address=<address> / challenge_id=<id> / key_id=<key id> / answer=<64 hex>
 * Anything else is refused, so this step can never open a stored message or message key.
 */
export declare function answerChallenge(sealed: unknown, expect: {
    address: string;
    challengeId: unknown;
    keyId: string;
}, key: BoxKey): string;
export interface KeysContext {
    root: string;
    address: string;
    env: NodeJS.ProcessEnv;
    yes: boolean;
    out: (line: string) => void;
    err: (line: string) => void;
    confirm: (question: string) => Promise<boolean>;
    /** One owner-key request to /v1/agent-mail/owner<path>. */
    call: (plan: {
        method: string;
        path: string;
        body?: unknown;
    }) => Promise<any>;
    /** Report a failed owner request; returns the exit code. */
    refusal: (error: unknown) => number;
}
export declare const KEYS_USAGE = "  keys init                  Make this mailbox's encryption keys here and register the public key;\n                             mail that arrives afterwards is stored encrypted          (confirm)\n  keys status [--yes]        Check the server's key list against the keys pinned on this machine;\n                             --yes accepts keys added with this mailbox's signing key elsewhere\n  keys rotate                New encryption key; the old one is kept so older mail opens (confirm)";
export declare function runKeysCommand(sub: string | undefined, ctx: KeysContext): Promise<number>;
