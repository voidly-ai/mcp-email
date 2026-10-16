import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
export declare const VERSION = "2.1.0";
export interface VoidmailServerOptions {
    /** Explicit agent key (VOIDMAIL_API_KEY). */
    apiKey?: string | null;
    /** Path to an agent-key file; read on every call so a rotation takes effect at once. */
    agentKeyFile?: string | null;
    /** Mailbox address, used only to write key paths and owner CLI instructions. */
    address?: string | null;
    /** Where voidmail_create_account saves key files (default ~/.voidly/mcp-email or VOIDMAIL_KEY_DIR). */
    keyRoot?: string;
    /** Already enrolled, active creator DID; unrelated to the mailbox agent key. */
    creatorDid?: string | null;
    /** Owned 0600 file: the creator identity's 64 raw Ed25519 secret-key bytes, or an agent-sdk identity export (JSON). */
    creatorSigningKeyFile?: string | null;
    /** With no creator configured, enroll a dedicated creator identity in the key directory (default true). */
    autoEnrollCreator?: boolean;
    fetch?: typeof fetch;
}
export declare function createVoidmailServer(options?: VoidmailServerOptions): McpServer;
