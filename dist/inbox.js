// Inbox rows as the model sees them (2.0).
//
//  - A sealed row ({ sealed: true, envelope }) is opened on this machine with the mailbox's
//    mail secret key(s): the sealed summary for lists, the sealed body (fetched from
//    /inbox/{id}/sealed-body, a URL built here, never taken from the server) for reads. Only
//    content that decrypts AND is bound to this mailbox and message id is shown. If anything
//    fails, the row is shown as unreadable: this module never falls back to a plaintext field
//    the server put beside an envelope.
//  - Any other row is shown as the server sent it, labelled storage: "server-readable". If
//    this machine registered a key before the row arrived, the row also carries a warning,
//    because the server should have sealed it.
//  - Search runs here, over decrypted and server-readable rows. The server is never asked to
//    search.
import PostalMime from 'postal-mime';
import { boxKeyFromFile, envelopeStanzas, openBody, openSummary, parseEnvelope, wipe } from './mailcrypto.js';
import { readMailRecord, readMailSecretFiles } from './keystore.js';
export const SERVER_READABLE_NOTE = 'The Voidly server stored this message readable. It arrived before this mailbox registered an encryption key, or the mailbox has none.';
export const SEALED_NOTE = 'Stored encrypted to this mailbox\'s key and decrypted on this machine. The Voidly mail server saw it in plaintext while receiving it, then stored only the encrypted copy. Encryption does not prove who sent it.';
const UNSEALED_AFTER_KEY = 'This message is stored readable although it arrived after this machine registered the mailbox\'s encryption key. The server should have stored it encrypted; treat the mailbox as server-readable and run `voidly-mcp-email owner keys status`.';
const UNREADABLE = {
    no_local_key: 'This message is stored encrypted, and no mail secret key for this mailbox is on this machine, so it cannot be read here. Run the MCP server with the mailbox\'s key directory (VOIDMAIL_ADDRESS and VOIDMAIL_KEY_DIR).',
    no_matching_key: 'This message is stored encrypted to keys that are not on this machine. It may have been sealed to a key registered elsewhere, or to a key that was lost.',
    decrypt_failed: 'This message did not decrypt with this mailbox\'s key. The stored copy may be damaged or altered; it is not shown.',
    binding_mismatch: 'This message decrypted, but it is bound to a different mailbox or message id than the one the server listed, so it is not shown.',
    digest_mismatch: 'This message decrypted, but its content does not match the fingerprint sealed with it, so it is not shown.',
    body_incomplete: 'The encrypted copy of this message is incomplete; it is not shown.',
    malformed: 'The server marked this message as encrypted but did not return a valid encrypted copy; nothing is shown.',
    unsupported_version: 'This message uses an encryption format this version of @voidly/mcp-email does not support. Update the package.',
    unparseable: 'This message decrypted but is not a parseable email; it is not shown.',
};
const PREVIEW_MAX = 1000;
const READ_TEXT_MAX = 200_000;
const READ_HTML_MAX = 400_000;
function loadKeys(ctx) {
    const dir = ctx.dir();
    if (!dir)
        return { keys: [], record: null, error: null };
    let record = null;
    try {
        record = readMailRecord(dir);
    }
    catch {
        record = null;
    }
    try {
        return { keys: readMailSecretFiles(dir).map(boxKeyFromFile), record, error: null };
    }
    catch {
        return { keys: [], record, error: 'The mail secret key file could not be read. Check that it holds a vmx_ key and is mode 0600; encrypted messages are not shown until it can be read.' };
    }
}
/** Load the keys, run `fn`, and wipe the secret key bytes afterwards. */
async function withKeys(ctx, fn) {
    const loaded = loadKeys(ctx);
    try {
        return await fn(loaded);
    }
    finally {
        wipe(...loaded.keys);
    }
}
/** Milliseconds since epoch for an ISO or "YYYY-MM-DD HH:MM:SS" (UTC) timestamp; null when unparseable. */
function parseTime(value) {
    if (typeof value !== 'string' || value.length > 40)
        return null;
    const iso = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(value) ? value.replace(' ', 'T') + 'Z' : value;
    const t = Date.parse(iso);
    return Number.isFinite(t) ? t : null;
}
const isObject = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
export function isSealedRow(row) {
    return row.sealed === true || row.envelope !== undefined || (row.seal_version !== undefined && row.seal_version !== null);
}
const str = (v, max) => typeof v === 'string' ? (v.length > max ? v.slice(0, max) : v) : null;
const addr = (a) => isObject(a)
    ? ('address' in a || 'name' in a ? { address: str(a.address, 254), name: str(a.name, 128) ?? '' } : null)
    : null;
const addrs = (v, max) => Array.isArray(v) ? v.slice(0, max).map(addr).filter(Boolean) : [];
const clip = (text, max) => {
    const value = typeof text === 'string' ? text : '';
    return value.length > max ? { text: value.slice(0, max), truncated: true } : { text: value, truncated: false };
};
/** Routing fields the server sends beside an envelope (no content). */
function sealedMeta(row) {
    const meta = { id: row.id };
    for (const field of ['received_at', 'is_read', 'raw_size', 'from_domain', 'key_epoch', 'category', 'labels']) {
        if (row[field] !== undefined)
            meta[field] = row[field];
    }
    return meta;
}
/**
 * Which keys a message is sealed to, checked against the key pin on this machine. A key this
 * machine never verified as signed by the mailbox's signing key is named: whoever holds it
 * can read the message too.
 */
function sealedTo(envelope, record) {
    const stanzas = envelopeStanzas(envelope);
    if (!record)
        return { recipients: stanzas, checked: false, note: 'No key pin on this machine, so the recipient keys were not checked. The owner can create it with `voidly-mcp-email owner keys status`.' };
    const known = new Set(record.known.map(k => k.key_id));
    const other = stanzas.filter(s => !known.has(s.key_id));
    return {
        recipients: stanzas, checked: true,
        ...(other.length ? { not_signed_by_this_mailbox: other, warning: `This message is also encrypted to ${other.length} key(s) this machine has not verified as this mailbox's. Whoever holds such a key can read it. Run \`voidly-mcp-email owner keys status\`.` } : {}),
    };
}
function fromSummary(summary) {
    const preview = clip(summary.snippet, PREVIEW_MAX);
    const attachments = Array.isArray(summary.attachments) ? summary.attachments.slice(0, 20).filter(isObject).map(a => ({
        filename: str(a.filename, 255), mime_type: str(a.mime_type, 127), size: typeof a.size === 'number' ? a.size : null, disposition: str(a.disposition, 16),
    })) : [];
    return {
        from: addr(summary.from), to: addrs(summary.to, 10), cc: addrs(summary.cc, 10), reply_to: addrs(summary.reply_to, 3),
        subject: str(summary.subject, 998) ?? '', date: str(summary.date, 64), message_id: str(summary.message_id, 998),
        in_reply_to: str(summary.in_reply_to, 998), text_preview: preview.text,
        attachments, attachments_total: typeof summary.attachments_total === 'number' ? summary.attachments_total : attachments.length,
        ...(summary.truncated === true ? { summary_truncated: true } : {}),
    };
}
function fromMime(email) {
    const text = clip(email.text, READ_TEXT_MAX);
    const out = {
        from: addr(email.from), to: addrs(email.to, 50), cc: addrs(email.cc, 50), reply_to: addrs(email.replyTo, 10),
        subject: typeof email.subject === 'string' ? email.subject : '', date: str(email.date, 64),
        message_id: str(email.messageId, 998), in_reply_to: str(email.inReplyTo, 998),
        text: text.text, ...(text.truncated ? { text_truncated: true } : {}),
        attachments: (email.attachments ?? []).slice(0, 100).map(a => ({
            filename: str(a.filename, 255), mime_type: str(a.mimeType, 127),
            size: typeof a.content === 'string' ? Buffer.byteLength(a.content) : a.content?.byteLength ?? null,
            disposition: a.disposition ?? null,
        })),
    };
    if (typeof email.html === 'string' && email.html) {
        const html = clip(email.html, READ_HTML_MAX);
        out.html = html.text;
        if (html.truncated)
            out.html_truncated = true;
    }
    return out;
}
async function presentSealed(row, loaded, ctx, mode) {
    const meta = sealedMeta(row);
    const envelope = parseEnvelope(row.envelope);
    const unreadable = (reason) => ({
        ...meta, storage: 'sealed', readable: false, reason,
        note: (reason === 'no_local_key' || reason === 'decrypt_failed') && loaded.error ? loaded.error : UNREADABLE[reason] ?? UNREADABLE.malformed,
        sealed_to: sealedTo(envelope, loaded.record),
    });
    if (typeof row.id !== 'string' || !row.id || !envelope)
        return unreadable('malformed');
    if (loaded.keys.length === 0)
        return unreadable(loaded.error ? 'decrypt_failed' : 'no_local_key');
    const expect = { emailId: row.id, address: ctx.address() };
    const summary = openSummary(envelope, loaded.keys, expect);
    if (!summary.ok)
        return unreadable(summary.reason);
    const base = { ...meta, storage: 'sealed', readable: true, decrypted_with_key: summary.keyId };
    if (mode === 'list')
        return { ...base, ...fromSummary(summary.summary), sealed_to: sealedTo(envelope, loaded.record) };
    let ciphertext;
    try {
        ciphertext = await ctx.fetchBody(row.id);
    }
    catch {
        return { ...base, ...fromSummary(summary.summary), body_error: 'The encrypted body could not be fetched; only the sealed summary is shown. Try again.', sealed_to: sealedTo(envelope, loaded.record), storage_note: SEALED_NOTE };
    }
    const body = openBody(envelope, ciphertext, loaded.keys, expect);
    if (!body.ok)
        return unreadable(body.reason);
    let email;
    try {
        email = await new PostalMime().parse(body.raw);
    }
    catch {
        body.raw.fill(0);
        return unreadable('unparseable');
    }
    body.raw.fill(0);
    return { ...base, ...fromMime(email), sealed_to: sealedTo(envelope, loaded.record), storage_note: SEALED_NOTE };
}
function presentPlain(row, loaded, mode) {
    const out = { ...row, storage: 'server-readable', ...(mode === 'list' ? {} : { storage_note: SERVER_READABLE_NOTE }) };
    const since = parseTime(loaded.record?.sealed_since);
    const at = parseTime(row.received_at);
    // Ten minutes of slack for clock differences between this machine and the server.
    if (since !== null && at !== null && at > since + 10 * 60 * 1000)
        out.storage_warning = UNSEALED_AFTER_KEY;
    return out;
}
function presentWith(row, ctx, mode, loaded) {
    if (!isObject(row))
        return Promise.resolve(row);
    return isSealedRow(row) ? presentSealed(row, loaded, ctx, mode) : Promise.resolve(presentPlain(row, loaded, mode));
}
/** One message (voidmail_read_email): the sealed body is fetched and opened here. */
export function presentRow(row, ctx) {
    return withKeys(ctx, loaded => presentWith(row, ctx, 'read', loaded));
}
/** A list response with each row presented; other fields (total, limit, offset) pass through. */
export function presentList(data, ctx) {
    return withKeys(ctx, async (loaded) => {
        if (!isObject(data))
            return data;
        const out = { ...data };
        if (Array.isArray(data.emails)) {
            const rows = [];
            for (const row of data.emails)
                rows.push(await presentWith(row, ctx, 'list', loaded));
            out.emails = rows;
        }
        out.encryption = encryptionSummary(loaded);
        out.storage_notes = STORAGE_NOTES;
        return out;
    });
}
/** Said once per list instead of on every row. */
const STORAGE_NOTES = { sealed: SEALED_NOTE, 'server-readable': SERVER_READABLE_NOTE };
function encryptionSummary(loaded) {
    return {
        key_on_this_machine: loaded.keys.length > 0,
        key_ids: loaded.keys.map(k => k.keyId),
        pinned_epoch: loaded.record?.epoch ?? null,
        sealed_since: loaded.record?.sealed_since ?? null,
        ...(loaded.error ? { error: loaded.error } : {}),
        note: loaded.keys.length > 0
            ? 'Encrypted messages are decrypted on this machine. Rows labelled server-readable were stored readable by the Voidly server.'
            : 'No mail encryption key is on this machine. Mail is stored server-readable unless the owner turns on encrypted storage with `voidly-mcp-email owner keys init`.',
    };
}
export function localEncryption(ctx) { return withKeys(ctx, loaded => Promise.resolve(encryptionSummary(loaded))); }
// ── Client-side search ───────────────────────────────────────────────────────
const lower = (v) => typeof v === 'string' ? v.toLowerCase() : '';
function searchable(row) {
    if (row.storage === 'sealed') {
        if (row.readable !== true)
            return '';
        const parts = [row.subject, row.text_preview, row.text, row.html];
        for (const a of [row.from, ...(Array.isArray(row.to) ? row.to : [])])
            if (isObject(a))
                parts.push(a.address, a.name);
        return parts.map(lower).join('\n');
    }
    return [row.subject, row.from_address, row.from_name, row.from, row.body_text, row.text, row.body_html].map(lower).join('\n');
}
/**
 * Search on this machine: read the newest `scan` messages page by page, decrypt the sealed
 * summaries and match `query` (case-insensitive) in subject, sender, recipients and text. With
 * `fullText`, encrypted bodies that did not match on their summary are fetched (read-only;
 * nothing is marked read) and searched too, up to `maxBodyBytes` in total.
 */
export async function searchInbox(query, opts, fetchPage, ctx) {
    const needle = query.toLowerCase();
    // Bodies are counted by the bytes actually downloaded, not by the size the server claims.
    let bodyBytes = 0;
    const budgeted = { ...ctx, fetchBody: async (id) => {
            if (bodyBytes >= opts.maxBodyBytes)
                throw new Error('search download bound reached');
            const bytes = await ctx.fetchBody(id);
            bodyBytes += bytes.length;
            return bytes;
        } };
    return withKeys(ctx, async (loaded) => {
        const results = [];
        let scanned = 0;
        let total = null;
        let unreadable = 0;
        let exhausted = false;
        let bodiesSearched = 0;
        let bodiesSkipped = 0;
        while (scanned < opts.scan && results.length < opts.limit) {
            const size = Math.min(opts.pageSize, opts.scan - scanned);
            const page = await fetchPage(scanned, size);
            total = page.total;
            for (const raw of page.emails) {
                if (results.length >= opts.limit)
                    break;
                scanned++;
                let row = await presentWith(raw, ctx, 'list', loaded);
                if (!isObject(row))
                    continue;
                if (row.storage === 'sealed' && row.readable !== true) {
                    unreadable++;
                    continue;
                }
                let hit = needle.length > 0 && searchable(row).includes(needle);
                if (!hit && opts.fullText && row.storage === 'sealed' && isObject(raw)) {
                    const claimed = typeof raw.raw_size === 'number' ? raw.raw_size : 0;
                    if (bodyBytes + claimed > opts.maxBodyBytes)
                        bodiesSkipped++;
                    else {
                        const full = await presentWith(raw, budgeted, 'search-body', loaded);
                        if (!isObject(full) || full.body_error)
                            bodiesSkipped++;
                        else {
                            bodiesSearched++;
                            if (full.readable === true && searchable(full).includes(needle)) {
                                hit = true;
                                row = { ...row, matched_in: 'body' };
                            }
                        }
                    }
                }
                if (hit) {
                    if (row.storage !== 'sealed' && typeof row.body_text === 'string' && row.body_text.length > PREVIEW_MAX) {
                        row = { ...row, body_text: row.body_text.slice(0, PREVIEW_MAX), body_text_truncated: true };
                    }
                    results.push(row);
                }
            }
            if (page.emails.length < size || (total !== null && scanned >= total)) {
                exhausted = true;
                break;
            }
        }
        const scope = opts.fullText
            ? `subject, sender, recipients and full text${bodiesSkipped ? ` (${bodiesSkipped} encrypted bod${bodiesSkipped === 1 ? 'y was' : 'ies were'} searched by summary only: over the download bound or not fetched)` : ''}`
            : 'subject, sender, recipients and, for encrypted messages, the first 280 characters of text (set full_text to search whole encrypted bodies)';
        return {
            query,
            results,
            scanned,
            total,
            complete: exhausted,
            ...(opts.fullText ? { encrypted_bodies_searched: bodiesSearched } : {}),
            ...(unreadable ? { unreadable_encrypted: unreadable } : {}),
            searched_on: 'this machine',
            storage_notes: STORAGE_NOTES,
            note: `Search ran on this machine over the ${scanned} newest message(s)${exhausted ? ' (all of them)' : ''}, matching ${scope}. The Voidly server did not search and nothing was marked read. Encrypted messages that could not be decrypted here were not searched.`,
            encryption: encryptionSummary(loaded),
        };
    });
}
