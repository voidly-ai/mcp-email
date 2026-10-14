/** Make one proof for the exact JSON string that will be transmitted. Nothing here goes to an MCP result. */
export declare function signedCreateRequest(body: string, creatorDid: string | null | undefined, signingKeyFile: string | null | undefined): {
    body: string;
    headers: Record<string, string>;
};
