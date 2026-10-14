export declare const OWNER_CONSOLE_URL = "https://voidly.ai/agent-mail/owner";
export declare const REFUSAL_CODES: readonly ["recipient_not_authorized", "content_contains_credential", "owner_authorization_required", "too_many_pending_requests", "owner_already_set", "unauthorized", "request_not_found", "request_not_pending", "send_safety_unavailable", "bootstrap_not_available", "content_policy_floor", "owner_auth_rate_limited", "key_possession_not_proven", "mail_key_epoch_conflict", "mail_key_set_conflict", "signing_key_change_not_confirmed", "key_challenge_refused", "mail_keys_unavailable", "owner_key_from_agent_key"];
export type RefusalCode = typeof REFUSAL_CODES[number];
export declare const CONTENT_KINDS: readonly ["pem_private_key", "voidmail_api_key", "voidmail_owner_key", "aws_access_key", "github_token", "slack_token", "stripe_live_key", "anthropic_key", "openai_key", "google_api_key", "private_key_hex_labeled"];
export interface PendingRequest {
    id: string;
    status: 'pending' | 'approved' | 'denied' | 'expired';
    expires_at: string | null;
}
export interface RefusalDetail {
    code: RefusalCode;
    request?: PendingRequest;
    kinds?: string[];
    pendingCap?: boolean;
    field?: 'reply_to';
}
export declare function sanitizeRequest(value: unknown): PendingRequest | undefined;
export declare function sanitizeKinds(value: unknown): string[];
/** Map a parsed error body to a closed refusal, or null when it is not one. */
export declare function parseRefusal(body: unknown, httpStatus: number): RefusalDetail | null;
/** The human-readable recovery sentence for a refusal. Local text only. */
export declare function recoveryText(detail: RefusalDetail, address?: string | null): string;
export declare class VoidmailRefusal extends Error {
    readonly detail: RefusalDetail;
    constructor(detail: RefusalDetail);
    /** Structured, model-safe view. No server text, no request bytes. */
    view(address?: string | null): Record<string, unknown>;
}
