export interface CreateCliIO {
    fetch?: typeof fetch;
    env?: NodeJS.ProcessEnv;
    stdout?: (line: string) => void;
    stderr?: (line: string) => void;
}
export declare function runCreateCli(argv: string[], io?: CreateCliIO): Promise<number>;
