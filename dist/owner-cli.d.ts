export interface OwnerCliIO {
    fetch?: typeof fetch;
    env?: NodeJS.ProcessEnv;
    stdout?: (line: string) => void;
    stderr?: (line: string) => void;
    confirm?: (question: string) => Promise<boolean>;
}
export declare function runOwnerCli(argv: string[], io?: OwnerCliIO): Promise<number>;
