export interface ResponseMeta {
    contentWarning?: string[];
    status?: number;
}
export declare const DEFAULT_MAX_BYTES: number;
/** One bounded attempt. Never retry a send or replay credentials on redirects. */
export declare function requestJson(fetcher: typeof fetch, url: string, init: RequestInit, timeoutMs?: number, meta?: ResponseMeta, maxBytes?: number): Promise<any>;
/**
 * One bounded GET of a binary body (sealed ciphertext). Same rules as requestJson: no
 * redirects, no retry, a hard size bound, and no server text reflected in errors.
 */
export declare function requestBytes(fetcher: typeof fetch, url: string, init: RequestInit, timeoutMs?: number, maxBytes?: number): Promise<Uint8Array>;
