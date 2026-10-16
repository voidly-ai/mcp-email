export declare const CREATOR_DIR = "creator";
export declare const CREATOR_IDENTITY_FILE = "identity.json";
export declare const CREATOR_PENDING_FILE = "pending-join.json";
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
/** did:voidly:<base58 of the first 16 bytes of the Ed25519 public key> (agentHomeJoin.ts didFrom). */
export declare function didFromSigningKey(publicKey: Uint8Array): string;
/** <root>/creator, 0700. Throws before anything is sent when it cannot be made. */
export declare function creatorDir(root: string): string;
/**
 * A signer from a file: the 2.0 raw format (exactly 64 secret-key bytes; needs `did`), or an
 * agent-sdk exportCredentials() JSON (its `did` and `signingSecretKey`; `did`, when also given,
 * must match). The key pair must be internally consistent. Never echoes file content.
 */
export declare function loadCreatorSigner(path: string, did: string | null | undefined, what?: string): {
    did: string;
    secretKey: Uint8Array;
};
/**
 * The stored dedicated creator identity, enrolling one first if needed. A saved pending enrollment
 * is always finished (or proven dead) before a new one is started.
 */
export declare function ensureCreatorIdentity(root: string, fetcher: typeof fetch, autoEnroll?: boolean): Promise<{
    path: string;
    enrolled: boolean;
}>;
/** Resolve the signer for one create request (see the header for the order). */
export declare function resolveCreatorSigner(options: CreatorOptions): Promise<CreatorSigner>;
