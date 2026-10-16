import { type CreatorOptions, type CreatorSource } from './creator.js';
/** The create API takes a 3-30 character local part that starts with a letter; its exact @voidmail.ai address is reduced to that. */
export declare function requestedLocalPart(value: string): string | null;
export interface CreatedInbox {
    address: string | null;
    agentKey: string;
    ownerKey: string | null;
    agentPath: string;
    ownerPath: string | null;
    moved: boolean;
    policy: 'open' | 'allowlist' | 'unknown';
    creator: CreatorSource;
    creatorFile: string | null;
}
/** The inbox exists but its keys could not be written; the caller decides what to do with the agent key. */
export declare class CreatedButUnsavedError extends Error {
    readonly agentKey: string;
    readonly ownerKey: string | null;
    readonly address: string | null;
    constructor(message: string, address: string | null, agentKey: string, ownerKey: string | null);
}
export declare function createInbox(input: {
    name?: string;
    address?: string;
}, ctx: {
    root: string;
    fetch: typeof fetch;
    creator: Omit<CreatorOptions, 'root' | 'fetch'>;
}): Promise<CreatedInbox>;
