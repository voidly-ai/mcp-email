/**
 * Make one proof for the exact JSON string that will be transmitted (worker
 * routes/agentMailCreate.ts). Nothing here goes to an MCP result. The caller owns
 * `signer.secretKey` and zeroes it afterwards.
 */
export declare function signedCreateRequest(body: string, signer: {
    did: string;
    secretKey: Uint8Array;
}): {
    body: string;
    headers: Record<string, string>;
};
