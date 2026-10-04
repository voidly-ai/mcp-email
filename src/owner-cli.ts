// `voidly-mcp-email owner <command>`: the human mailbox owner's tool.
//
// It reads ONE credential, the owner-key file, and calls ONLY /v1/agent-mail/owner/*.
// It never reads the agent-key file and never sends X-Agent-Mail-Key. After
// rotate-agent-key it writes the new agent key to the agent-key file (0600) without
// printing it; after rotate-owner-key it atomically replaces the exact owner-key file it
// read (VOIDMAIL_OWNER_KEY_FILE when set), never a copy under the agent key directory.
// The server revokes the old owner key before the new one is saved, so if saving fails the
// new key is written to a fresh 0600 file beside it, and as a last resort shown once on
// the human's terminal: the only valid owner key is never discarded.
// The MCP server process never loads this module (see index.ts).
import { readdirSync } from 'node:fs';
import { basename, join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { requestJson } from './request.js';
import { VoidmailRefusal } from './refusal.js';
import { AGENT_KEY_FILE, AGENT_KEY_RE, OWNER_KEY_FILE, OWNER_KEY_RE, keyRoot, readKeyFileAt, redactKeys, replaceKeyFile, replaceKeyFileAt, validAddress, writeKeyBeside } from './keystore.js';

const API_BASE = 'https://api.voidly.ai';
const OWNER_BASE = '/v1/agent-mail/owner';

export interface OwnerCliIO {
  fetch?: typeof fetch;
  env?: NodeJS.ProcessEnv;
  stdout?: (line: string) => void;
  stderr?: (line: string) => void;
  confirm?: (question: string) => Promise<boolean>;
}

const USAGE = `Usage: voidly-mcp-email owner <command> [argument] [--address <name@voidmail.ai>] [--yes]

Commands (owner key only):
  list                       Show the policy, approved recipients and pending requests
  approve <request-id>       Approve a pending recipient request        (widens: confirm)
  deny <request-id>          Deny a pending recipient request
  add <address|@domain>      Approve a recipient or a whole domain      (widens: confirm)
  remove <address|@domain>   Remove an approved recipient
  lock                       Recipient allowlist + credential blocking on
  unlock                     Let the agent email any address            (widens: confirm)
  rotate-agent-key           Revoke the agent key; the new one is saved to the agent-key file
  rotate-owner-key           Replace the owner key; the new one replaces the owner-key file it was read from

The owner key is read from <key dir>/<address>/owner-key (key dir: VOIDMAIL_KEY_DIR,
default ~/.voidly/mcp-email) or from VOIDMAIL_OWNER_KEY_FILE.`;

// Honest wording for an owner rotation whose outcome is unknown. "Run it again" would be
// wrong: a retry needs the old owner key, which the server may already have revoked.
const OWNER_ROTATE_UNKNOWN = 'The old owner key may already be revoked. Check with `voidly-mcp-email owner list`: if the old key is still accepted, nothing changed and rotating is safe to try later; if it is refused, this mailbox no longer has a working owner key on this machine.';

/** A server-supplied string, made safe to show in a terminal prompt. */
function printable(value: string): string | null {
  const clean = value.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/g, '');
  return clean && clean.length <= 254 ? clean : null;
}

const REQUEST_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
const PATTERN_RE = /^(?:[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64})?@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;

async function ttyConfirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try { return (await rl.question(`${question} Type yes to continue: `)).trim().toLowerCase() === 'yes'; }
  finally { rl.close(); }
}

/** The only owner-key reader in this package. */
function readOwnerKeyFile(path: string): string {
  if (basename(path) === AGENT_KEY_FILE) throw new Error('The owner CLI never reads the agent key.');
  return readKeyFileAt(path, OWNER_KEY_RE);
}

function resolveAddress(flag: string | undefined, env: NodeJS.ProcessEnv, root: string): string | null {
  const given = flag ?? env.VOIDMAIL_ADDRESS;
  if (given !== undefined) return validAddress(given) ? given : null;
  try {
    const found = readdirSync(root, { withFileTypes: true }).filter(d => d.isDirectory() && validAddress(d.name)).map(d => d.name);
    return found.length === 1 ? found[0] : null;
  } catch { return null; }
}

export async function runOwnerCli(argv: string[], io: OwnerCliIO = {}): Promise<number> {
  const env = io.env ?? process.env;
  const out = io.stdout ?? ((line: string) => process.stdout.write(line + '\n'));
  const err = io.stderr ?? ((line: string) => process.stderr.write(line + '\n'));
  const confirm = io.confirm ?? ttyConfirm;

  const positional: string[] = []; let addressFlag: string | undefined; let yes = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--yes' || a === '-y') yes = true;
    else if (a === '--address') { addressFlag = argv[++i]; if (addressFlag === undefined) { err(USAGE); return 2; } }
    else if (a.startsWith('--address=')) addressFlag = a.slice('--address='.length);
    else if (a === '--help' || a === '-h') { out(USAGE); return 0; }
    else positional.push(a);
  }
  const [command, arg, ...rest] = positional;
  if (!command || rest.length) { err(USAGE); return 2; }

  type Plan = { method: string; path: string; body?: unknown; widens?: string; rotate?: 'agent' | 'owner'; approveId?: string };
  let plan: Plan;
  const needArg = (re: RegExp, what: string): string | null => (arg && re.test(arg)) ? arg : (err(`${command} needs a valid ${what}.\n\n${USAGE}`), null);
  switch (command) {
    case 'list': if (arg) { err(USAGE); return 2; } plan = { method: 'GET', path: '/policy' }; break;
    case 'approve': { const id = needArg(REQUEST_ID_RE, 'request id'); if (!id) return 2;
      plan = { method: 'POST', path: `/requests/${encodeURIComponent(id)}/approve`, widens: `Approve request ${id}?`, approveId: id }; break; }
    case 'deny': { const id = needArg(REQUEST_ID_RE, 'request id'); if (!id) return 2;
      plan = { method: 'POST', path: `/requests/${encodeURIComponent(id)}/deny` }; break; }
    case 'add': { const p = needArg(PATTERN_RE, 'address or @domain'); if (!p) return 2;
      plan = { method: 'POST', path: '/recipients', body: { pattern: p.toLowerCase() }, widens: `Let the agent email ${p.toLowerCase()}${p.startsWith('@') ? ' (every address at that domain)' : ''}?` }; break; }
    case 'remove': { const p = needArg(PATTERN_RE, 'address or @domain'); if (!p) return 2;
      plan = { method: 'DELETE', path: `/recipients/${encodeURIComponent(p.toLowerCase())}` }; break; }
    case 'lock': if (arg) { err(USAGE); return 2; } plan = { method: 'POST', path: '/policy', body: { recipient_policy: 'allowlist', content_policy: 'enforce' } }; break;
    case 'unlock': if (arg) { err(USAGE); return 2; }
      plan = { method: 'POST', path: '/policy', body: { recipient_policy: 'open' }, widens: 'Let the agent email ANY address with no approval?' }; break;
    case 'rotate-agent-key': if (arg) { err(USAGE); return 2; } plan = { method: 'POST', path: '/rotate-agent-key', rotate: 'agent' }; break;
    case 'rotate-owner-key': if (arg) { err(USAGE); return 2; } plan = { method: 'POST', path: '/rotate-owner-key', rotate: 'owner' }; break;
    default: err(USAGE); return 2;
  }

  const root = keyRoot(env);
  const address = resolveAddress(addressFlag, env, root);
  const ownerKeyPath = env.VOIDMAIL_OWNER_KEY_FILE || (address ? join(root, address, OWNER_KEY_FILE) : null);
  // rotate-agent-key writes <key dir>/<address>/agent-key; rotate-owner-key writes the file it read.
  if (!ownerKeyPath || (plan.rotate === 'agent' && !address)) { err('Name the mailbox with --address <name@voidmail.ai> (or VOIDMAIL_ADDRESS).'); return 2; }
  let ownerKey: string;
  try { ownerKey = readOwnerKeyFile(ownerKeyPath); }
  catch { err(`The owner key could not be read from ${ownerKeyPath}. It must hold a vmo_ key and be mode 0600.`); return 1; }

  const call = (plan: { method: string; path: string; body?: unknown }) => requestJson(io.fetch ?? fetch, `${API_BASE}${OWNER_BASE}${plan.path}`, {
    method: plan.method,
    headers: { 'Content-Type': 'application/json', 'X-Agent-Mail-Owner-Key': ownerKey },
    body: plan.body === undefined ? undefined : JSON.stringify(plan.body),
  });
  const refusal = (error: unknown): number => {
    if (error instanceof VoidmailRefusal) { err(JSON.stringify(error.view(address), null, 2)); return 1; }
    err(error instanceof Error ? redactKeys(error.message, [ownerKey]) : 'Owner request failed.');
    return 1;
  };

  // approve: show the human WHICH recipient a request id stands for before widening. The
  // agent (possibly prompt-injected) chose that recipient; an opaque id is not consent.
  if (plan.approveId) {
    let policy: any;
    try { policy = await call({ method: 'GET', path: '/policy' }); } catch (error) { return refusal(error); }
    const entry = Array.isArray(policy?.pending) ? policy.pending.find((p: any) => p && p.id === plan.approveId) : undefined;
    const recipient = typeof entry?.recipient === 'string' ? printable(entry.recipient) : null;
    if (!recipient) {
      err(`Request ${plan.approveId} is not pending for this mailbox (already decided, expired or unknown); nothing changed. See ${`voidly-mcp-email owner list${address ? ` --address ${address}` : ''}`}.`);
      return 1;
    }
    plan.widens = `Approve request ${plan.approveId} for recipient ${recipient}? The agent will be able to email ${recipient}.`;
    if (yes) out(`Approving request ${plan.approveId} for recipient ${recipient}.`);
  }

  if (plan.widens && !yes && !(await confirm(plan.widens))) { err('Not confirmed; nothing changed. Pass --yes to confirm without a prompt.'); return 1; }

  let data: any;
  try { data = await call(plan); }
  catch (error) {
    const code = refusal(error);
    if (plan.rotate === 'agent') err('The old agent key may already be revoked. Running rotate-agent-key again is safe.');
    if (plan.rotate === 'owner') err(OWNER_ROTATE_UNKNOWN);
    return code;
  }

  if (plan.rotate === 'agent') {
    const fresh = [data?.api_key, data?.agent_key].find((v): v is string => typeof v === 'string' && AGENT_KEY_RE.test(v));
    if (!fresh) {
      err('The agent key was rotated but the response had no valid new key; the old key may already be revoked. Run rotate-agent-key again.');
      return 1;
    }
    let saved: string;
    try { saved = replaceKeyFile(root, address!, AGENT_KEY_FILE, fresh); }
    catch { err('The agent key was rotated but the new key could not be saved; run rotate-agent-key again.'); return 1; }
    out(`Agent key rotated. The old key stopped working. The new key was saved to ${saved} (not shown). An MCP server that reads that file picks it up on its next call; one configured with VOIDMAIL_API_KEY needs the new key.`);
    return 0;
  }

  if (plan.rotate === 'owner') {
    const fresh = typeof data?.owner_key === 'string' && OWNER_KEY_RE.test(data.owner_key) ? data.owner_key as string : null;
    if (!fresh) { err(`The owner key was rotated but the response had no valid new key. ${OWNER_ROTATE_UNKNOWN}`); return 1; }
    // The old key is already revoked server-side: this key must survive a failed save.
    try {
      const saved = replaceKeyFileAt(ownerKeyPath, OWNER_KEY_RE, fresh);
      out(`Owner key rotated. The new key replaced ${saved} (not shown). The old owner key stopped working.`);
      return 0;
    } catch { /* fall through */ }
    try {
      const beside = writeKeyBeside(ownerKeyPath, OWNER_KEY_RE, fresh);
      err(`Owner key rotated, but ${ownerKeyPath} could not be replaced. The new key was saved to ${beside} (mode 0600, not shown). Move it over ${ownerKeyPath} now: the old owner key no longer works.`);
      return 1;
    } catch { /* fall through */ }
    err(`Owner key rotated, but it could not be saved anywhere next to ${ownerKeyPath}. The old owner key no longer works. This is the new owner key, shown only this once; store it now in ${ownerKeyPath} with mode 0600, and clear this terminal afterwards:`);
    err(fresh);
    return 1;
  }

  out(redactKeys(JSON.stringify(data, null, 2), [ownerKey]));
  return 0;
}
