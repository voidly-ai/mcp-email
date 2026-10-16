export declare const SERVER_READABLE_NOTE = "The Voidly server stored this message readable. It arrived before this mailbox registered an encryption key, or the mailbox has none.";
export declare const SEALED_NOTE = "Stored encrypted to this mailbox's key and decrypted on this machine. The Voidly mail server saw it in plaintext while receiving it, then stored only the encrypted copy. Encryption does not prove who sent it.";
export interface InboxContext {
    /** The mailbox's key directory, or null when this server has none (VOIDMAIL_API_KEY only). */
    dir: () => string | null;
    /** The mailbox address, when known. */
    address: () => string | null;
    /** GET the sealed body ciphertext for one message (does not mark it read). */
    fetchBody: (emailId: string) => Promise<Uint8Array>;
}
export declare function isSealedRow(row: Record<string, unknown>): boolean;
/** One message (voidmail_read_email): the sealed body is fetched and opened here. */
export declare function presentRow(row: unknown, ctx: InboxContext): Promise<unknown>;
/** A list response with each row presented; other fields (total, limit, offset) pass through. */
export declare function presentList(data: unknown, ctx: InboxContext): Promise<unknown>;
/** Presented rows, newest first, for the wait and extract tools (sealed rows opened from their summary). */
export declare function presentRows(rows: unknown[], ctx: InboxContext): Promise<unknown[]>;
export interface MessageMeta {
    id: string;
    from: string | null;
    subject: string;
    received_at: string | null;
    receivedMs: number | null;
    storage: 'sealed' | 'server-readable';
    readable: boolean;
}
/** Sender, subject and arrival time of one presented row; null for a row without an id. An unreadable sealed row has no sender or subject. */
export declare function messageMeta(row: unknown): MessageMeta | null;
/**
 * The plain text of one listed message, for code extraction: a server-readable row's stored
 * text, or a sealed body downloaded and opened here (its authenticated summary snippet when the
 * body cannot be fetched). Never HTML or attachments; nothing is marked read.
 */
export declare function messageText(raw: unknown, ctx: InboxContext): Promise<string | null>;
export declare function localEncryption(ctx: InboxContext): Promise<{
    note: string;
    error?: string | undefined;
    key_on_this_machine: boolean;
    key_ids: string[];
    pinned_epoch: number | null;
    sealed_since: string | null;
}>;
export interface SearchPage {
    emails: unknown[];
    total: number | null;
}
export interface SearchOptions {
    limit: number;
    scan: number;
    pageSize: number;
    fullText: boolean;
    maxBodyBytes: number;
}
/**
 * Search on this machine: read the newest `scan` messages page by page, decrypt the sealed
 * summaries and match `query` (case-insensitive) in subject, sender, recipients and text. With
 * `fullText`, encrypted bodies that did not match on their summary are fetched (read-only;
 * nothing is marked read) and searched too, up to `maxBodyBytes` in total.
 */
export declare function searchInbox(query: string, opts: SearchOptions, fetchPage: (offset: number, size: number) => Promise<SearchPage>, ctx: InboxContext): Promise<{
    searched_on: string;
    storage_notes: {
        sealed: string;
        'server-readable': string;
    };
    note: string;
    encryption: {
        note: string;
        error?: string | undefined;
        key_on_this_machine: boolean;
        key_ids: string[];
        pinned_epoch: number | null;
        sealed_since: string | null;
    };
    unreadable_encrypted?: number | undefined;
    encrypted_bodies_searched?: number | undefined;
    query: string;
    results: unknown[];
    scanned: number;
    total: number | null;
    complete: boolean;
}>;
