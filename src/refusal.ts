// Closed-word policy refusals. The recovery sentences are written HERE, not copied
// from the API response: a refusal body is server-controlled bytes and nothing in
// it except closed words and validated identifiers ever reaches a model.

export const OWNER_CONSOLE_URL = 'https://voidly.ai/agent-mail/owner';

export const REFUSAL_CODES = [
  'recipient_not_authorized',
  'content_contains_credential',
  'owner_authorization_required',
  'too_many_pending_requests',
  'owner_already_set',
  'unauthorized',
  'request_not_found',
  'request_not_pending',
  'send_safety_unavailable',
  'bootstrap_not_available',
  'content_policy_floor',
  'owner_auth_rate_limited',
] as const;
export type RefusalCode = typeof REFUSAL_CODES[number];

export const CONTENT_KINDS = [
  'pem_private_key', 'voidmail_api_key', 'voidmail_owner_key', 'aws_access_key', 'github_token', 'slack_token',
  'stripe_live_key', 'anthropic_key', 'openai_key', 'google_api_key', 'private_key_hex_labeled',
] as const;

/** Codes whose refusal means the message was not handed to the mail provider. */
const SEND_REFUSALS = new Set<RefusalCode>(['recipient_not_authorized', 'content_contains_credential', 'send_safety_unavailable']);

export interface PendingRequest { id: string; status: 'pending' | 'approved' | 'denied' | 'expired'; expires_at: string | null }
export interface RefusalDetail { code: RefusalCode; request?: PendingRequest; kinds?: string[]; pendingCap?: boolean; field?: 'reply_to' }

const ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z?$/;
const STATUSES = new Set(['pending', 'approved', 'denied', 'expired']);

export function sanitizeRequest(value: unknown): PendingRequest | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const r = value as Record<string, unknown>;
  if (typeof r.id !== 'string' || !ID_RE.test(r.id)) return undefined;
  const status = typeof r.status === 'string' && STATUSES.has(r.status) ? r.status as PendingRequest['status'] : 'pending';
  const expires_at = typeof r.expires_at === 'string' && TIME_RE.test(r.expires_at) ? r.expires_at : null;
  return { id: r.id, status, expires_at };
}

export function sanitizeKinds(value: unknown): string[] {
  const list = Array.isArray(value) ? value : typeof value === 'string' ? value.split(/[,\s]+/) : [];
  return [...new Set(list.filter((k): k is string => typeof k === 'string' && (CONTENT_KINDS as readonly string[]).includes(k)))];
}

/** Map a parsed error body to a closed refusal, or null when it is not one. */
export function parseRefusal(body: unknown, httpStatus: number): RefusalDetail | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  const b = body as Record<string, unknown>;
  const word = typeof b.code === 'string' ? b.code.toLowerCase() : typeof b.error === 'string' ? b.error.toLowerCase() : null;
  const alt = typeof b.error === 'string' ? b.error.toLowerCase() : null;
  const code = [word, alt].find((w): w is RefusalCode => !!w && (REFUSAL_CODES as readonly string[]).includes(w));
  if (!code) return null;
  if (code === 'unauthorized' && httpStatus !== 401) return null;
  // A send refusal only counts as "not sent" when the server says so explicitly.
  if (SEND_REFUSALS.has(code) && b.send_attempted !== false) return null;
  const detail: RefusalDetail = { code };
  const request = sanitizeRequest(b.request);
  if (request) detail.request = request;
  if (code === 'content_contains_credential') detail.kinds = sanitizeKinds(b.kinds);
  if (code === 'recipient_not_authorized' && !request && b.request_refusal === 'too_many_pending_requests') detail.pendingCap = true;
  if (code === 'recipient_not_authorized' && b.field === 'reply_to') detail.field = 'reply_to';
  return detail;
}

const addressArg = (address: string | null) => address ? ` --address ${address}` : ' --address <mailbox address>';

/** The human-readable recovery sentence for a refusal. Local text only. */
export function recoveryText(detail: RefusalDetail, address: string | null = null): string {
  switch (detail.code) {
    case 'recipient_not_authorized': {
      if (detail.field === 'reply_to') {
        return `Nothing was sent: replyTo must be omitted, this mailbox's own address or one of its aliases, or a recipient the owner approved. Remove replyTo and send again under a new operationId. To use another reply-to address, ask for it with voidmail_request_recipient and ask the human owner to approve it with \`voidly-mcp-email owner list${addressArg(address)}\` or at ${OWNER_CONSOLE_URL}. Do not try another address to get around this.`;
      }
      const id = detail.request?.id;
      if (detail.request?.status === 'denied') {
        return 'Nothing was sent: the mailbox owner denied this recipient recently. Do not retry this address, and do not try another address, alias or account to get around the decision.';
      }
      if (!id && detail.pendingCap) {
        return `Nothing was sent: this recipient is not on the approved list, and the mailbox already has the maximum number of pending approval requests. Ask the human owner to review them with \`voidly-mcp-email owner list${addressArg(address)}\` or at ${OWNER_CONSOLE_URL}.`;
      }
      return 'Nothing was sent: this recipient is not on the list the mailbox owner approved. '
        + (id
          ? `A pending approval request (${id}) was recorded. Ask the human mailbox owner to approve it with \`voidly-mcp-email owner approve ${id}${addressArg(address)}\` or at ${OWNER_CONSOLE_URL}. `
          : `Ask the human mailbox owner to approve the recipient with \`voidly-mcp-email owner add <recipient>${addressArg(address)}\` or at ${OWNER_CONSOLE_URL}. `)
        + 'After approval, retry the same send; with voidmail_send_once reuse the same operationId. Do not try another address, alias or account to get around this.';
    }
    case 'content_contains_credential':
      return `Nothing was sent: the message appears to contain a credential${detail.kinds?.length ? ` (${detail.kinds.join(', ')})` : ''}, and this mailbox blocks that. `
        + 'Remove the key, token or private key from the subject, body and reply-to, then send the corrected message under a new operationId. Never send credentials by email. Only the mailbox owner can change this policy.';
    case 'owner_authorization_required':
      return `Only the human mailbox owner can widen this policy; the agent key can only restrict it. Use voidmail_request_recipient to ask for a recipient, and ask the owner to decide with \`voidly-mcp-email owner list${addressArg(address)}\` or at ${OWNER_CONSOLE_URL}.`;
    case 'too_many_pending_requests':
      return `This mailbox already has the maximum number of pending recipient requests. Ask the owner to approve or deny them with \`voidly-mcp-email owner list${addressArg(address)}\` before requesting more.`;
    case 'owner_already_set':
      return 'This mailbox already has an owner key. Owner actions must use that key through the owner CLI or the owner console.';
    case 'unauthorized':
      return 'The key was not accepted. Check that the key file for this address is current; after a rotation, use the new key.';
    case 'request_not_found':
      return `No approval request with that id exists for this mailbox. List the current requests with \`voidly-mcp-email owner list${addressArg(address)}\`.`;
    case 'request_not_pending':
      return 'That approval request was already decided or has expired, so nothing changed. The agent can ask again with voidmail_request_recipient if it is still needed.';
    case 'bootstrap_not_available':
      return 'An owner key can no longer be minted from the agent key for this mailbox: it was already restricted with the agent key, and bootstrap would let the agent key undo that. The restriction stays in force. For a mailbox with an owner, create a new one with voidmail_create_account and move to it.';
    case 'content_policy_floor':
      return "This mailbox's owner key was minted from its agent key (legacy bootstrap), so the credential guard can be set to observe or enforce but never off.";
    case 'owner_auth_rate_limited':
      return 'Too many failed owner-key attempts came from this network in the last hour, so owner calls are refused for now. Wait at least an hour, then use the exact owner key from its file. No automatic retry.';
    case 'send_safety_unavailable':
      return 'Nothing was sent: the mail safety checks were temporarily unavailable. Wait at least a minute, then retry the same send; with voidmail_send_once reuse the same operationId.';
  }
}

export class VoidmailRefusal extends Error {
  readonly detail: RefusalDetail;
  constructor(detail: RefusalDetail) {
    super(recoveryText(detail));
    this.detail = detail;
  }
  /** Structured, model-safe view. No server text, no request bytes. */
  view(address: string | null = null): Record<string, unknown> {
    const out: Record<string, unknown> = { error: this.detail.code, code: this.detail.code.toUpperCase() };
    if (SEND_REFUSALS.has(this.detail.code)) out.send_attempted = false;
    if (this.detail.request) out.request = this.detail.request;
    if (this.detail.kinds) out.kinds = this.detail.kinds;
    if (this.detail.field) out.field = this.detail.field;
    out.recovery = recoveryText(this.detail, address);
    return out;
  }
}
