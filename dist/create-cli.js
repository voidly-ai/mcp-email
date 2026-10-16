// `voidly-mcp-email create [--name <name>] [--address <local part>]`: make one inbox from a
// terminal. It signs with the configured creator identity, or this machine's dedicated creator
// identity (enrolled first through Voidly Home join when none exists), writes the agent-key and
// owner-key files (0600) and prints ONLY the inbox address and file paths. No key, signature or
// API key is ever printed; every line also passes through the key redactor.
import { keyRoot, redactKeys } from './keystore.js';
import { CreatedButUnsavedError, createInbox, requestedLocalPart } from './create-inbox.js';
const USAGE = `Usage: voidly-mcp-email create [--name <agent name>] [--address <local part>]

Creates one @voidmail.ai inbox and saves its keys on this machine:
  <key dir>/<address>/agent-key   for the MCP server (VOIDMAIL_ADDRESS=<address>)
  <key dir>/<address>/owner-key   for you: approves recipients (voidly-mcp-email owner ...)
The key dir is VOIDMAIL_KEY_DIR, default ~/.voidly/mcp-email. Keys are never printed.

The create request is signed by an agent identity. Set VOIDMAIL_CREATOR_DID and
VOIDMAIL_CREATOR_SIGNING_KEY_FILE to use your own (a raw 64-byte key file or an
@voidly/agent-sdk identity export). Otherwise this command uses <key dir>/creator/identity.json,
enrolling a dedicated one through Voidly Home join the first time (VOIDMAIL_CREATOR_AUTO_ENROLL=off
turns that off). Each identity may create 2 inboxes a day.`;
const autoEnrollOff = (value) => !!value && /^(0|off|false|no)$/i.test(value.trim());
export async function runCreateCli(argv, io = {}) {
    const env = io.env ?? process.env;
    const secrets = new Set();
    const out = (line) => (io.stdout ?? ((l) => process.stdout.write(l + '\n')))(redactKeys(line, secrets));
    const err = (line) => (io.stderr ?? ((l) => process.stderr.write(l + '\n')))(redactKeys(line, secrets));
    let name;
    let address;
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        const value = (flag) => a === flag ? argv[++i] : a.slice(flag.length + 1);
        if (a === '--help' || a === '-h') {
            out(USAGE);
            return 0;
        }
        else if (a === '--name' || a.startsWith('--name='))
            name = value('--name');
        else if (a === '--address' || a.startsWith('--address='))
            address = value('--address');
        else {
            err(USAGE);
            return 2;
        }
    }
    if (name !== undefined && (!name.trim() || name.length > 128)) {
        err('--name needs 1-128 characters.\n\n' + USAGE);
        return 2;
    }
    if (address !== undefined && !requestedLocalPart(address)) {
        err('--address needs a 3-30 character local part that starts with a letter, or its exact @voidmail.ai address.\n\n' + USAGE);
        return 2;
    }
    const root = keyRoot(env);
    let created;
    try {
        created = await createInbox({ name: name?.trim(), address }, {
            root, fetch: io.fetch ?? fetch,
            creator: {
                creatorDid: env.VOIDMAIL_CREATOR_DID || null,
                creatorSigningKeyFile: env.VOIDMAIL_CREATOR_SIGNING_KEY_FILE || null,
                autoEnroll: !autoEnrollOff(env.VOIDMAIL_CREATOR_AUTO_ENROLL),
            },
        });
    }
    catch (error) {
        if (error instanceof CreatedButUnsavedError) {
            secrets.add(error.agentKey);
            if (error.ownerKey)
                secrets.add(error.ownerKey);
            // Keys are never printed, so an unsaved key cannot be recovered from this terminal.
            err(`Inbox ${error.address ?? '(address not confirmed)'} was created, but its keys could not be saved under ${root}, so this machine cannot use it. Fix the key directory (free space, permissions) before creating another inbox; do not repeat the command in a loop.`);
            return 1;
        }
        err(error instanceof Error ? error.message : 'Inbox creation failed; nothing was printed or saved.');
        return 1;
    }
    secrets.add(created.agentKey);
    if (created.ownerKey)
        secrets.add(created.ownerKey);
    const address_ = created.address ?? '(address not confirmed by the API)';
    out(`Created ${address_}`);
    out(`  agent key: ${created.agentPath} (saved, not shown)`);
    if (created.ownerPath)
        out(`  owner key: ${created.ownerPath} (saved, not shown)`);
    else
        out('  owner key: none issued, so this inbox has no owner control');
    if (created.creatorFile)
        out(`  creator identity: ${created.creatorFile} (${created.creator === 'enrolled' ? 'enrolled now' : 'reused'})`);
    out(`  recipient policy: ${created.policy}`);
    if (!created.moved)
        out(`The keys could not be placed in ${root}/${created.address ?? '<address>'}/ and were kept where shown. Move them there (keep mode 0600).`);
    out('');
    out('Next:');
    out(`  1. Start the MCP server with VOIDMAIL_ADDRESS=${created.address ?? '<address>'}${env.VOIDMAIL_KEY_DIR ? ` and VOIDMAIL_KEY_DIR=${root}` : ''}.`);
    if (created.ownerPath) {
        out('  2. Move the owner-key file where your agent cannot read it (mode 0600 does not stop an agent running as you),');
        out(`     and approve recipients with: voidly-mcp-email owner approve <request id> --address ${created.address ?? '<address>'}`);
    }
    out(`Mail to this inbox is readable by the server; not end-to-end encrypted. To store it encrypted to your own key, run: voidly-mcp-email owner keys init --address ${created.address ?? '<address>'}`);
    return 0;
}
