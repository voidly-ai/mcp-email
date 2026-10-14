export declare const KEY_ID_RE: RegExp;
export declare const KEY_KINDS: readonly ["agent", "owner_recovery"];
export type KeyKind = typeof KEY_KINDS[number];
export declare const SEAL_ALG = "x25519-xsalsa20poly1305-box+secretbox";
export declare const BINDING_CONTEXT = "voidmail-key-binding/1";
export declare const POP_CONTEXT = "voidmail-key-pop/1";
export declare const KEY_ID_CONTEXT = "voidmail-key-id/1";
export declare const SUMMARY_CONTEXT = "voidmail-sealed-summary/1";
export declare const PAYLOAD_CONTEXT = "voidmail-sealed-payload/1";
export declare const MAX_RECIPIENTS = 4;
/** Strict, canonical standard base64 to bytes; null when malformed or not the expected length. */
export declare function fromB64(value: unknown, length?: number, max?: number): Uint8Array | null;
export declare const toB64: (bytes: Uint8Array) => string;
export declare function bytesEqual(a: Uint8Array, b: Uint8Array): boolean;
export interface BoxKey {
    keyId: string;
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}
export declare function keyIdFor(publicKey: Uint8Array): string;
export declare function boxKeyFromFile(value: string): BoxKey;
export declare function wipe(...keys: Array<{
    secretKey: Uint8Array;
} | null | undefined>): void;
export interface Binding {
    address: string;
    epoch: number;
    count: number;
    kind: KeyKind;
    keyId: string;
    publicKey: string;
}
export declare function bindingStatement(b: Binding): Uint8Array;
/** True only for a well-formed binding with a valid signature by `signingPublicKey` (base64). */
export declare function verifyBinding(b: Binding, signature: unknown, signingPublicKey: unknown): boolean;
export interface SetRecipient {
    kind: KeyKind;
    key_id: string;
    x25519_public_key: string;
    binding_sig: string;
}
export interface KeySet {
    epoch: number;
    signingPublicKey: string;
    recipients: SetRecipient[];
    storage: 'sealed' | 'server_readable' | null;
}
export type KeySetCheck = {
    ok: true;
    set: KeySet | null;
    storage: 'sealed' | 'server_readable' | null;
} | {
    ok: false;
    problem: string;
};
/**
 * Check a key directory (GET /v1/agent-mail/keys or /owner/keys) as ONE signed set: one epoch,
 * exactly `count` recipients, exactly one agent key, every binding signed by the set's signing
 * key, and, when pinned, that signing key and an epoch no lower than the highest seen.
 */
export declare function checkKeySet(data: unknown, address: string, pin: {
    signingPublicKey: string;
    epoch: number;
} | null): KeySetCheck;
export type OpenFailure = 'malformed' | 'unsupported_version' | 'no_matching_key' | 'decrypt_failed' | 'binding_mismatch' | 'body_incomplete' | 'digest_mismatch';
export interface Stanza {
    kind: string;
    key_id: string;
}
export interface Envelope {
    v: 1;
    alg: string;
    email_id: string;
    mailbox: string;
    epoch: number;
    recipients: Array<{
        kind: string;
        key_id: string;
        ephemeral_public_key: string;
        nonce: string;
        wrapped_key: string;
    }>;
    summary: {
        nonce: string;
        ciphertext: string;
    };
    body: {
        nonce: string;
        bytes: number;
        parts: number;
        part_bytes: number;
    };
}
/** Parse a sealed envelope (object or JSON text) from a server row, or null. */
export declare function parseEnvelope(value: unknown): Envelope | null;
export declare function envelopeStanzas(envelope: Envelope | null): Stanza[];
export interface Expect {
    emailId: string;
    address: string | null;
}
export type SummaryResult = {
    ok: true;
    summary: Record<string, unknown>;
    keyId: string;
} | {
    ok: false;
    reason: OpenFailure;
};
/** Open the sealed summary (for inbox lists). Fails closed. */
export declare function openSummary(envelope: Envelope | null, keys: BoxKey[], expect: Expect): SummaryResult;
export type BodyResult = {
    ok: true;
    raw: Uint8Array;
    header: Record<string, unknown>;
    summary: Record<string, unknown> | null;
    keyId: string;
} | {
    ok: false;
    reason: OpenFailure;
};
/**
 * Open the sealed body (the ciphertext bytes from /sealed-body). Checks: the length equals
 * `body.bytes`, the payload context and its mailbox/email_id binding, and the raw message's
 * SHA-256 and size against the payload header and the sealed summary. Fails closed.
 */
export declare function openBody(envelope: Envelope | null, ciphertext: Uint8Array | null, keys: BoxKey[], expect: Expect): BodyResult;
