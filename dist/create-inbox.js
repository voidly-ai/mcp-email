// One signed inbox creation, shared by the MCP tool (voidmail_create_account) and the
// `voidly-mcp-email create` command. It returns key VALUES only to its caller, which writes
// nothing but paths to the model or the terminal.
//
// Everything that can fail on this machine fails BEFORE the mailbox exists:
//  1. a requested address whose key directory already holds keys is refused;
//  2. the creator signer is resolved (configured, stored or enrolled now) and the proof made;
//  3. both key files are pre-written (placeholders, 0600, O_EXCL) in a staging directory.
// After the API mints the keys they are written in place and the staging directory is renamed
// to <root>/<address>. If that last move is impossible, the keys stay in the staging directory;
// they are never discarded.
import { requestJson } from './request.js';
import { AGENT_KEY_RE, OWNER_KEY_RE, commitStagedKeys, discardStaging, mailboxHasKeys, stageMailboxKeys, validAddress } from './keystore.js';
import { signedCreateRequest } from './create-proof.js';
import { resolveCreatorSigner } from './creator.js';
const API_BASE = 'https://api.voidly.ai';
/** The create API takes a 3-30 character local part that starts with a letter; its exact @voidmail.ai address is reduced to that. */
export function requestedLocalPart(value) {
    const normalized = value.trim().toLowerCase();
    const local = normalized.endsWith('@voidmail.ai') ? normalized.slice(0, -'@voidmail.ai'.length) : normalized;
    return local.length >= 3 && local.length <= 30 && /^[a-z][a-z0-9._-]*[a-z0-9]$/.test(local) && !local.includes('..') ? local : null;
}
/** The inbox exists but its keys could not be written; the caller decides what to do with the agent key. */
export class CreatedButUnsavedError extends Error {
    address;
    constructor(message, address, agentKey, ownerKey) {
        super(message);
        this.name = 'CreatedButUnsavedError';
        this.address = address;
        // Not enumerable: a serialized error never carries a key.
        Object.defineProperty(this, 'agentKey', { value: agentKey, enumerable: false });
        Object.defineProperty(this, 'ownerKey', { value: ownerKey, enumerable: false });
    }
}
export async function createInbox(input, ctx) {
    let local;
    if (input.address !== undefined) {
        const checked = requestedLocalPart(input.address);
        if (!checked)
            throw new Error('Use a 3-30 character local part that starts with a letter, or its exact @voidmail.ai address; no inbox was created.');
        local = checked;
    }
    const requested = local ? `${local}@voidmail.ai` : null;
    if (requested && validAddress(requested) && mailboxHasKeys(ctx.root, requested)) {
        throw new Error(`Key files for ${requested} already exist in the key directory; no inbox was created. Reuse that inbox with VOIDMAIL_ADDRESS=${requested}, or ask the human to move the old key files first.`);
    }
    // Construct the signed body and work proof once, before making key placeholders or contacting
    // the create API. The same raw bytes are hashed and sent; there is no unsigned path.
    const body = JSON.stringify({ name: input.name || 'agent', address: local, recipient_policy: 'allowlist' });
    const signer = await resolveCreatorSigner({ ...ctx.creator, root: ctx.root, fetch: ctx.fetch });
    let signed;
    try {
        signed = signedCreateRequest(body, signer);
    }
    finally {
        signer.secretKey.fill(0);
    }
    let staging;
    try {
        staging = stageMailboxKeys(ctx.root);
    }
    catch {
        throw new Error('The key directory could not be written; no inbox was created. Set VOIDMAIL_KEY_DIR to a writable private directory.');
    }
    let data;
    const createMeta = {};
    try {
        data = await requestJson(ctx.fetch, `${API_BASE}/v1/agent-mail/create`, {
            method: 'POST', headers: signed.headers, body: signed.body,
        }, 20_000, createMeta);
    }
    catch (error) {
        discardStaging(staging);
        if (createMeta.status === 401)
            throw new Error('Voidmail create rejected the creator identity or proof (HTTP 401). Check that the DID is active and its registered Ed25519 key matches this signing file. No automatic retry.');
        if (createMeta.status === 429) {
            const wait = error instanceof Error ? error.message.match(/Wait at least \d{1,8} seconds/)?.[0] : null;
            throw new Error(`Voidmail create was rate limited (HTTP 429) by per-IP, per-DID, or shared flood controls. ${wait ? wait + '.' : 'Respect Retry-After if supplied.'} The owner can inspect aggregate abuse metrics if this is unexpected. Do not change identity or network to evade the limit; no automatic retry.`);
        }
        if (createMeta.status === 409)
            throw new Error('Voidmail create conflicted (HTTP 409): this nonce or requested address may already have been used. Reconcile the original inbox with the owner; do not automatically create another.');
        throw error;
    }
    const agentKey = typeof data?.api_key === 'string' && AGENT_KEY_RE.test(data.api_key) ? data.api_key : null;
    const ownerKey = typeof data?.owner_key === 'string' && OWNER_KEY_RE.test(data.owner_key) ? data.owner_key : null;
    if (!agentKey) {
        discardStaging(staging);
        throw new Error('Account creation returned an invalid response; outcome unknown. Do not automatically create another inbox.');
    }
    const minted = validAddress(data.address) ? data.address : null;
    let saved;
    try {
        saved = commitStagedKeys(staging, ctx.root, minted, agentKey, ownerKey);
    }
    catch {
        throw new CreatedButUnsavedError(`Inbox ${minted ?? '(address not confirmed)'} was created, but its keys could not be saved under the key directory. The agent key works for this session only${ownerKey ? ', and the owner key could not be stored' : ''}. Do not create another inbox automatically; tell the human.`, minted, agentKey, ownerKey);
    }
    const policy = data.recipient_policy === 'open' || data.recipient_policy === 'allowlist' ? data.recipient_policy : 'unknown';
    return { address: minted, agentKey, ownerKey, ...saved, policy, creator: signer.source, creatorFile: signer.file };
}
