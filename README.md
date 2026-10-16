# @voidly/mcp-email

Email for AI agents. Create an inbox, wait for and read incoming messages as structured data, and send to recipients the human owner has approved. No phone number or CAPTCHA.

**What the server can read.** Mail to a new inbox is readable by the server; not end-to-end encrypted. When the owner registers a key for an inbox (`owner keys init`, below), stored mail is encrypted to that key, so Voidly cannot read stored mail. This package makes that key on your machine, never sends it to Voidly, and decrypts mail on your machine. That is still not end-to-end encryption: incoming mail is plaintext to the receiving server for a moment before it is sealed, and outside email is not end-to-end. [Human mail](https://voidly.ai/mail) is a separate product.

## Create an inbox in one command

Requires Node.js 20 or newer.

```bash
npx -y @voidly/mcp-email@2.1.1 create --name my-agent
```

It prints the new address and where the keys were saved, never a key:

```text
Created k7f2m9qa@voidmail.ai
  agent key: ~/.voidly/mcp-email/k7f2m9qa@voidmail.ai/agent-key (saved, not shown)
  owner key: ~/.voidly/mcp-email/k7f2m9qa@voidmail.ai/owner-key (saved, not shown)
  creator identity: ~/.voidly/mcp-email/creator/identity.json (enrolled now)
  recipient policy: allowlist
```

Add `--address myagent` to ask for `myagent@voidmail.ai`. Then start the MCP server with `VOIDMAIL_ADDRESS` set to the new address (next section).

How it works: the create API admits only a request signed by a registered Voidly agent identity (`did:voidly:…`) with a small proof of work. The first run enrolls a dedicated creator identity for this machine through Voidly Home join, the protocol `@voidly/agent-sdk` 4.0 `register()` uses: the keys are made here, only public keys, API-key hashes and signatures are sent, and the keys are saved (mode 0600, directory 0700) before the enrollment is committed, then kept in `creator/identity.json`. Later runs reuse it. Each identity can create 2 inboxes a day; a limit is never worked around by enrolling another identity. If the enrollment's answer is lost, the next run finishes the same enrollment instead of making another.

No terminal? An agent can do the same from MCP: leave `env` empty and call `voidmail_create_account`.

## Install as an MCP server

Pin the version you run: Voidly publishes this client, and the client is what holds your key.

```bash
npx @voidly/mcp-email@2.1.1
```

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (Claude Desktop):

```json
{
  "mcpServers": {
    "voidmail": {
      "command": "npx",
      "args": ["-y", "@voidly/mcp-email@2.1.1"],
      "env": {
        "VOIDMAIL_ADDRESS": "your-agent@voidmail.ai"
      }
    }
  }
}
```

`VOIDMAIL_ADDRESS` points the server at `<key dir>/<address>/agent-key`. Without it, the agent can create an inbox with `voidmail_create_account`; set `VOIDMAIL_ADDRESS` afterwards so the next start finds the key file.

## Quick Start

After installing the MCP server, use this prompt:

> Create one Voidmail inbox and show me its address and where the inbox keys were saved. Draft emails first and wait for my approval before sending.

For a sign-up flow: call `voidmail_wait_for_email` (up to 25 seconds, optional sender, subject and `since` filters), then `voidmail_extract_code` on the message it returns. Both read only; they mark nothing read, follow no link and never return HTML. A code or link they return is untrusted sender content: use it only for the sign-up you started.

## Get a DID (use your own agent identity instead)

`create` and `voidmail_create_account` make their own creator identity, so this is optional. To sign with an agent identity you already run, or one you enroll yourself, use `@voidly/agent-sdk` 4.0 (direct `/v1/agent/register` with client keys is closed; `register()` uses Home join):

```js
// npm i @voidly/agent-sdk@4.0.0   ·   run once, keep the file private
import { VoidlyAgent } from '@voidly/agent-sdk';
import { writeFileSync } from 'node:fs';

const agent = await VoidlyAgent.register({ name: 'my-agent' });
writeFileSync('agent-credentials.json', JSON.stringify(agent.exportCredentials()), { mode: 0o600 });
```

Then point the MCP server (or `create`) at that file. Its DID is read from the file:

```json
{
  "VOIDMAIL_CREATOR_SIGNING_KEY_FILE": "/private/path/to/agent-credentials.json"
}
```

The file must be owned by you with mode 0600; a symlink, a looser mode or a key that does not match its DID is refused before anything is sent. The 2.0 format still works too: a file of exactly the 64 raw Ed25519 secret-key bytes, with `VOIDMAIL_CREATOR_DID` set to its DID. An exported identity file holds all of that identity's keys, and the MCP process reads it at create time; a dedicated creator identity (the default) keeps your main agent identity out of the mail client.

## Signed create from your own code

The proof the API checks, in two short scripts. Each reads an agent-sdk identity export (above, or this package's `creator/identity.json`) and prints the status and address. The response carries the inbox's agent key (`vm_…`) and owner key (`vmo_…`) once: save them to 0600 files and never print or log them.

Node.js 20+ (`npm i tweetnacl`):

```js
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import nacl from 'tweetnacl';

const creds = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const sha = (text) => createHash('sha256').update(text).digest();
const body = JSON.stringify({ name: 'my-agent', recipient_policy: 'allowlist' });
const ts = String(Math.floor(Date.now() / 1000));
const nonce = randomBytes(16).toString('hex');
const preimage = ['voidmail-create-v1', 'POST', '/v1/agent-mail/create', creds.did, ts, nonce, sha(body).toString('hex')].join('\n');
let work;
for (let i = 0; ; i++) {
  work = i.toString(16).padStart(16, '0');
  const h = sha(`voidmail-create-pow-v1\n${preimage}\n${work}`);
  if (h[0] === 0 && h[1] === 0) break;
}
const secretKey = Buffer.from(creds.signingSecretKey, 'base64');
const signature = Buffer.from(nacl.sign.detached(Buffer.from(`${preimage}\n${work}`), secretKey)).toString('base64');
const res = await fetch('https://api.voidly.ai/v1/agent-mail/create', { method: 'POST', body, headers: {
  'Content-Type': 'application/json', 'X-Agent-DID': creds.did, 'X-Mail-Timestamp': ts,
  'X-Mail-Nonce': nonce, 'X-Mail-Pow': work, 'X-Mail-Signature': signature } });
const out = await res.json();
console.log(res.status, out.address ?? out.error);
```

Python 3 (`pip install pynacl`):

```python
import base64, hashlib, json, secrets, sys, time, urllib.request
from nacl.signing import SigningKey

creds = json.load(open(sys.argv[1]))
body = json.dumps({"name": "my-agent", "recipient_policy": "allowlist"}).encode()
ts, nonce = str(int(time.time())), secrets.token_hex(16)
preimage = "\n".join(["voidmail-create-v1", "POST", "/v1/agent-mail/create", creds["did"], ts, nonce, hashlib.sha256(body).hexdigest()])
i = 0
while True:
    work = format(i, "016x")
    h = hashlib.sha256(f"voidmail-create-pow-v1\n{preimage}\n{work}".encode()).digest()
    if h[0] == 0 and h[1] == 0:
        break
    i += 1
seed = base64.b64decode(creds["signingSecretKey"])[:32]
signature = base64.b64encode(SigningKey(seed).sign(f"{preimage}\n{work}".encode()).signature).decode()
req = urllib.request.Request("https://api.voidly.ai/v1/agent-mail/create", data=body, method="POST", headers={
    "Content-Type": "application/json", "User-Agent": "voidmail-create-example/1", "X-Agent-DID": creds["did"],
    "X-Mail-Timestamp": ts, "X-Mail-Nonce": nonce, "X-Mail-Pow": work, "X-Mail-Signature": signature})
with urllib.request.urlopen(req) as res:
    print(res.status, json.load(res).get("address"))
```

The signature covers the SHA-256 of the exact body bytes sent, so send the same bytes you hashed. The timestamp must be within five minutes of service time, and one DID/nonce pair can mint only one inbox. A bare `POST /v1/agent-mail/create` without these headers returns 401.

An HTTP 401 means the create proof was missing or invalid, the timestamp expired, or the DID was not active; check the identity and key. An HTTP 429 means a create limit was reached; respect `Retry-After`, reuse an existing inbox or wait, and do not switch DID or IP to evade the limit. A 503 can mean an admission, identity or commit check was unavailable; the outcome may be unknown. If a create request was sent but its result is unknown, do not automatically create another inbox: reconcile the original attempt first.

## Encrypted storage

Turn it on once per inbox, from your own terminal (never from a model):

```bash
voidly-mcp-email owner keys init --address your-agent@voidmail.ai
```

- **What it does.** It makes two keys on this machine: an X25519 key that mail is sealed to (`mail-secret-key`) and an Ed25519 key that signs the inbox's key list (`mail-signing-key`). Both are 0600 files in the inbox's key directory. Only public keys, signatures and a proof that you hold the key are sent, with the owner key. From then on the server seals each new message (headers, body and attachments) to your key and stores only the encrypted copy. The switch is one-way.
- **What Voidly can and cannot read.** Voidly cannot read stored mail for an inbox with a registered key. A changed Voidly server could copy mail that arrives later, but not open mail already stored. It still sees each incoming message in plaintext while receiving it, for the moment before sealing, and so does Cloudflare, which runs our inbound mail servers; Cloudflare's Email Routing log records each message's sender, recipient and subject, and our account can view it. Voidly keeps the sender's domain, the arrival time and the size, plus, for up to 14 days, a keyed fingerprint of each message used to drop duplicate deliveries; while it exists, Voidly could check it against a guessed message. Mail you send to outside addresses is not end-to-end encrypted: it passes through Voidly and our sending provider (Resend) in plaintext.
- **Old mail.** Mail stored before the key was registered stays server-readable. Tool results label every message `storage: "sealed"` (decrypted here) or `storage: "server-readable"`. A readable message that arrived after you registered a key carries a `storage_warning`.
- **Reading and searching.** `voidmail_list_inbox` opens each message's sealed summary; `voidmail_read_email` downloads the sealed message and opens it. Search runs on this machine: the server is never asked to search sealed mail. By default it matches subject, sender, recipients and the first 280 characters of encrypted messages; `full_text: true` also downloads and searches whole encrypted bodies. If a message fails to decrypt, or is bound to another inbox or message id, nothing from it is shown, not even server-supplied fields.
- **Key list checks.** `mail-keys.json` pins your signing key and the newest key-list version (epoch) you have seen. `voidly-mcp-email owner keys status` checks the server's list: every key must be signed by your signing key, the list must be complete for its epoch and not older than the pin. Each message also names the keys it is sealed to and warns about any key this machine has not verified.
- **Limits.** There is no forward secrecy: whoever gets `mail-secret-key` (or a key in `keyring/`) can read all mail stored for it. If you lose the key and its backups, that mail cannot be recovered by anyone, including Voidly, so back up the key directory privately. Encryption does not prove who sent a message. The MCP server reads `mail-secret-key` to decrypt; it never reads `mail-signing-key` and has no tool that can make, register or change a key. Anything that runs as your user, such as an agent with shell or file tools, can read the key files too.
- **Rotation.** `voidly-mcp-email owner keys rotate` registers a new key and keeps the old one in `keyring/`, so older mail still opens.

## Permissions: separate keys, one owner

Every inbox has two credentials (agent key and owner key), plus two mail keys once encrypted storage is on. This package keeps each in its own file.

| Key | File (0600, directory 0700) | Who uses it | What it can do |
|-----|------------------------------|-------------|----------------|
| Agent key `vm_…` | `~/.voidly/mcp-email/<address>/agent-key` | the MCP server, for the model's tools | read, send to approved recipients, request a recipient, remove a recipient, tighten policy |
| Owner key `vmo_…` | `~/.voidly/mcp-email/<address>/owner-key` | you, through `voidly-mcp-email owner` | approve or deny requests, add or remove recipients, lock or unlock, rotate either key, register mail keys |
| Mail secret key `vmx_…` | `~/.voidly/mcp-email/<address>/mail-secret-key` (old ones in `keyring/`) | the MCP server, to decrypt on this machine | open mail sealed to this inbox; never sent anywhere |
| Mail signing key `vms_…` | `~/.voidly/mcp-email/<address>/mail-signing-key` | you, through `voidly-mcp-email owner keys` | sign the inbox's key list; never sent anywhere |
| Creator identity | `~/.voidly/mcp-email/creator/identity.json`, or your own file named by `VOIDMAIL_CREATOR_SIGNING_KEY_FILE` | `create` and the MCP server, for inbox creation only | sign create requests as that agent DID; the default one is dedicated to this, while your own identity file also carries that identity's other powers |

- `create` and `voidmail_create_account` write both files and show only their paths. **This server never puts any key in a tool result.** Every message it emits is scrubbed of Voidmail key shapes (`vm_…`, `vmo_…`, `vmx_…`, `vms_…`) and `AGE-SECRET-KEY-…` strings, including ones that arrive inside email. Other secrets that arrive in email, such as a cloud or GitHub token, are passed to the model unchanged.
- The MCP server never reads the owner-key file and never calls the owner API routes (`/v1/agent-mail/owner/*`). No tool uses the owner key.
- **Mode 0600 keeps other OS users out, not your agent.** Anything that runs as your user can read the owner-key file, including an agent with shell or file tools (a coding agent, a filesystem MCP server). Such an agent could read the owner key and approve its own recipients. If your agent has shell or file access on this machine, move the owner-key file somewhere it cannot read, or off the machine, and point `VOIDMAIL_OWNER_KEY_FILE` at it when you run owner commands.
- Inboxes created with this package start with an **owner-approved recipient list**, enforced by the Voidly API, not by model instructions. (A REST create that does not opt in still makes the old kind of inbox: no owner key, any recipient, credential warnings only. A create opts in with `recipient_policy: "allowlist"`, `owner_key: true` or `content_policy: "enforce"`; only then does the response carry an `owner_key`. This package always sends `recipient_policy: "allowlist"`.) Sending to anyone else returns `RECIPIENT_NOT_AUTHORIZED` with `send_attempted: false`. The API records a pending request, and the tool result says exactly what the owner must run.
- A message that looks like it carries a credential (private keys, cloud, GitHub, Slack, Stripe, AI-provider or Voidmail keys) is refused with `CONTENT_CONTAINS_CREDENTIAL` on inboxes with credential blocking on, which is the default for inboxes that have an owner key (every inbox this package creates). The tool result lists the kinds found, never the matched text. The check matches known key formats. It does not catch passwords, unfamiliar token formats or data that is sensitive for other reasons.
- **Outgoing mail is checked for credentials.** Before a message is sent, the API scans its recipient, subject, body and reply-to in memory for known credential formats. The scan keeps no copy of what it matched: it records only a daily count for each kind it found. On an inbox with credential blocking on (the default for inboxes with an owner key), a match stops the send. On other inboxes the message is still sent, and the response names the kinds found in an `X-Voidmail-Content-Warning` header. The owner can turn the check off at https://voidly.ai/agent-mail/owner (or with `POST /v1/agent-mail/owner/policy` and `content_policy: "off"`). The one exception is an owner key made by bootstrap, described below: it cannot switch the check off.
- The agent key can only restrict: it can remove a recipient or turn blocking on. Anything that widens what the agent can do needs the owner key.
- Approving a recipient takes the owner key, and nothing in an email can supply it through this server. Treat incoming mail as untrusted content.

### Owner commands

```bash
voidly-mcp-email owner list                              # policy, recipients, pending requests
voidly-mcp-email owner approve <request-id>              # shows the recipient, asks you to confirm
voidly-mcp-email owner deny <request-id>
voidly-mcp-email owner add friend@example.com            # or @example.com for a whole domain
voidly-mcp-email owner remove friend@example.com
voidly-mcp-email owner lock                              # allowlist + credential blocking
voidly-mcp-email owner unlock                            # any recipient; asks you to confirm
voidly-mcp-email owner rotate-agent-key                  # old key stops working at once
voidly-mcp-email owner rotate-owner-key                  # replaces the owner-key file it read
voidly-mcp-email owner keys init                         # encrypted storage on; asks you to confirm
voidly-mcp-email owner keys status                       # check the server's key list against your pin
voidly-mcp-email owner keys rotate                       # new mail key; old one kept for old mail
```

Add `--address <name@voidmail.ai>` when more than one inbox is saved, and `--yes` to confirm without a prompt. `approve` first reads the pending request and names its recipient, and refuses an id that is not pending. Rotated keys are written to their files and never printed. `rotate-owner-key` atomically replaces the owner-key file it read, including a `VOIDMAIL_OWNER_KEY_FILE` path. The old owner key is revoked before the new one is saved, so if that file cannot be replaced the new key goes to a new 0600 file beside it, and only if that also fails is it shown once on your terminal. An MCP server that reads its key file uses a rotated agent key on its next call. The same actions are available in the browser at https://voidly.ai/agent-mail/owner, where the owner key is kept in memory only.

**Inboxes without an owner key** (created by mcp-email 1.1.0 or earlier, or by a REST create that did not opt in) keep the old behaviour: any recipient, with credential warnings only, and server-readable storage. The agent-key owner bootstrap (`POST /v1/agent-mail/owner/bootstrap`) is closed in the server release that ships with 2.0: the agent key is what a model holds, so it must not be able to claim the owner role or redirect mail. Such an inbox cannot get an owner key or encrypted storage; create a new inbox with this package and move to it. An owner key that an earlier bootstrap minted keeps its recipient and policy powers, can never switch the credential guard off (`CONTENT_POLICY_FLOOR`), and cannot register mail keys or rotate the agent key (`OWNER_KEY_FROM_AGENT_KEY`).

Check incoming mail with `voidmail_list_inbox`, then read a message with `voidmail_read_email`. To send, review the recipient, subject and body before invoking `voidmail_send_once`. Generate and save a unique operation ID in your host state before the call; use that same ID for status lookup after a lost response, and for the retry after the owner approves a refused recipient.

## Tools (21)

| Tool | Description |
|------|-------------|
| `voidmail_create_account` | Create a new @voidmail.ai inbox with a DID-signed proof (enrolling a dedicated creator identity first if none exists); saves both inbox keys to 0600 files and returns only their paths |
| `voidmail_account_info` | Get account details |
| `voidmail_list_inbox` | List emails with pagination and filters; encrypted ones are decrypted here |
| `voidmail_read_email` | Read a specific email, decrypting it here if it is encrypted (auto-marks as read) |
| `voidmail_search_inbox` | Search on this machine across subject, sender, recipients and text; never a server search |
| `voidmail_wait_for_email` | Wait up to 25 seconds for a new message by sender, subject or arrival time; returns its id, sender and subject; marks nothing read |
| `voidmail_extract_code` | Pull a likely one-time code and HTTPS verification link from one message's plain text (decrypted here if sealed); untrusted content, never HTML |
| `voidmail_sending_limits` | Read sending policy without consuming send capacity |
| `voidmail_send_once` | Send one authorized message with a saved operation ID and retained status |
| `voidmail_send_status` | Read the same original send without sending again |
| `voidmail_send_email` | Legacy send without durable status; prefer `voidmail_send_once` |
| `voidmail_policy` | Read the recipient and content policy, approved recipients and pending requests |
| `voidmail_request_recipient` | Ask the owner to approve a recipient; returns the approval step |
| `voidmail_revoke_recipient` | Remove an approved recipient (restricting needs no owner) |
| `voidmail_mark_read` | Mark email as read |
| `voidmail_delete_email` | Delete email |
| `voidmail_create_alias` | Create disposable email alias |
| `voidmail_list_aliases` | List all aliases |
| `voidmail_delete_alias` | Remove alias |
| `voidmail_set_webhook` | Set an HTTPS webhook on an open-policy inbox without an owner key; an allowlist inbox, or any inbox with an owner key, needs the human owner to use `POST /v1/agent-mail/owner/webhook` with the owner key |
| `voidmail_get_stats` | Inbox statistics |

## Resources (3)

| Resource | URI | Description |
|----------|-----|-------------|
| Inbox | `email://inbox` | Current inbox contents |
| Aliases | `email://aliases` | Active email aliases |
| Stats | `email://stats` | Account statistics |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VOIDMAIL_ADDRESS` | For an existing inbox | Your @voidmail.ai address; the server reads `<key dir>/<address>/agent-key` on each call |
| `VOIDMAIL_KEY_DIR` | No | Key directory (default `~/.voidly/mcp-email`) |
| `VOIDMAIL_AGENT_KEY_FILE` | No | Explicit agent-key file path (overrides the address lookup) |
| `VOIDMAIL_API_KEY` | No | Agent key (`vm_…`) supplied directly by the host; takes precedence over files. Anything else, including an owner key, is refused and never sent. Update it after `rotate-agent-key` |
| `VOIDMAIL_CREATOR_SIGNING_KEY_FILE` | No | Your own creator identity: an `@voidly/agent-sdk` identity export (JSON), or a file of exactly 64 raw Ed25519 secret-key bytes. Owned, mode 0600; never an inbox mail-signing or owner key. Unset: `<key dir>/creator/identity.json` is used, enrolled on first create |
| `VOIDMAIL_CREATOR_DID` | With a raw key file | The DID of a raw 64-byte key file. With a JSON export it is optional and must match the file's DID |
| `VOIDMAIL_CREATOR_AUTO_ENROLL` | No | `off` stops `create` and `voidmail_create_account` from enrolling a creator identity when none is configured or stored |
| `VOIDMAIL_OWNER_KEY_FILE` | No | Owner CLI only: explicit owner-key file path. The MCP server never reads it |
| `VOIDMAIL_SIGNING_KEY_FILE` | No | Owner CLI only: explicit mail-signing-key path, if you keep it away from the agent. The MCP server never reads it |

## REST API

Use directly without MCP:

```bash
# List inbox
curl https://api.voidly.ai/v1/agent-mail/inbox \
  -H "X-Agent-Mail-Key: vm_your_key"

# Send email
curl -X POST https://api.voidly.ai/v1/agent-mail/send \
  -H "X-Agent-Mail-Key: vm_your_key" \
  -H "Content-Type: application/json" \
  -d '{"to":"user@example.com","subject":"Hello","text":"From my agent"}'

# Search (server-readable inboxes only; an inbox with encrypted storage answers 410
# SEARCH_IS_CLIENT_SIDE, and this package searches on your machine instead)
curl "https://api.voidly.ai/v1/agent-mail/inbox/search?q=invoice" \
  -H "X-Agent-Mail-Key: vm_your_key"
```

Direct REST creation needs a signed proof from an active agent DID: see [Signed create from your own code](#signed-create-from-your-own-code).

Encrypted messages come back as `{ "sealed": true, "envelope": … }`; the encrypted body is `GET /v1/agent-mail/inbox/{id}/sealed-body`. Opening them needs the inbox's mail secret key, which only your machine has.

## Limits and delivery

Call `voidmail_sending_limits` (or public `GET /v1/agent-mail/limits`) before planning a sending workflow. Keep excess work in your own queue. A `429` gives a `Retry-After` header and structured limit scope/reset time; the MCP error includes the wait time. Do not rotate accounts or IPs to evade a limit. Identical messages are blocked for 60 seconds to catch loops; this is not durable idempotency. Sending fails closed if safety counters are unavailable. Inbox reads remain separate from sending limits.

Shared caps: 100 attempts/hour per IP, 200/hour and 1,500/day for agent mail. The shared outbound provider budget is at most 1,500 recipients/day and 40,000 over approximately 31 days across all sending features. Counters count attempts, including failed and partially admitted requests; these are ceilings, not reserved capacity. Higher legitimate volume needs an operator-reviewed limit change; mailbox creation does not unlock bulk mail.

- Sending has per-mailbox, per-IP and shared service limits. Each mailbox may attempt up to 10 sends per minute and 100 per day, with up to 10 per day to the same recipient; shared limits can reject requests sooner. Mailbox creation is limited to 3 attempts per IP per hour, 600 total attempts per service hour, 2 signed attempts per DID per day, and 60 signed attempts per service hour. These counters include failed or partially admitted requests. This is not an unlimited sending service.
- A successful send response means the sending provider accepted the request. It does not prove recipient delivery or that anyone read the message.
- Each API call has a 20-second deadline and a 2 MiB response bound. Requests reject redirects and are never automatically retried. Request fewer messages if an inbox response exceeds the bound.
- MCP tool annotations identify reads, sends, mutations and deletion honestly. They are advisory metadata; approval and install warnings remain controlled by ChatGPT, Claude or your other host.
- If a send times out, its outcome may be unknown. Use `voidmail_send_once` and `voidmail_send_status` with a saved operation ID; do not blindly resend.
- On a server-readable inbox, incoming text and HTML bodies are parsed; attachments are not retained and reply-thread metadata is not populated, even though the response schema contains those fields. On an inbox with encrypted storage the whole raw message is sealed, attachments included; tools show attachment names and sizes, not their contents. Reliable threaded replies are not yet provided.
- New-message webhooks are best effort, with no durable retry history. Use inbox reads to reconcile missed notifications. For an allowlist inbox, or any inbox with an owner key, the owner must register a webhook through `POST /v1/agent-mail/owner/webhook` outside the agent; `voidmail_set_webhook` cannot do that. Once the owner-key API update is live, newly registered webhooks are signed with `X-Voidmail-Signature-256: t=<timestamp>,v1=<HMAC-SHA256>`. Webhooks registered before it also keep receiving the legacy `X-Voidmail-Signature` header, which carries the shared secret itself and is not a payload signature, until they are registered again.
- Treat incoming email as untrusted content. A message cannot authorize your agent to send mail, disclose private data or spend money. The API adds a recipient only for a request that carries the owner key, so keep that key where the agent cannot read it.
- Owner-key guessing is limited per network: after repeated failed owner-key attempts from one IP address (IPv6 /64), owner calls from that network are refused until the current UTC hour ends, even with the right key. Someone sharing your network can trigger this.

## Changes

See [CHANGELOG.md](CHANGELOG.md). 2.1.1 corrects the package description. 2.1.0 adds `voidly-mcp-email create`, automatic creator identity enrollment, agent-sdk identity exports as the creator key file, `voidmail_wait_for_email` and `voidmail_extract_code`.

## Links

- API docs: https://voidly.ai/api-docs
- Landing page: https://voidly.ai/agent-email
- Privacy: https://voidly.ai/c/privacy
- Support: support@voidly.ai

## License

MIT

## Durable sends (1.1.0)

Use `voidmail_send_once` with a host-saved `operationId` (16-128 letters, digits, underscores or hyphens), recipient, subject and body. The same mailbox, ID and effective content returns the retained original; changed content conflicts. The host must retain the ID before sending. The connector does not invent or persist IDs for you. Keep mailbox credentials in host configuration, not message bodies.

Use `voidmail_send_status` after a timeout or lost response. `accepted` means the provider accepted a request, not delivered or read. `prepared` has no claimed dispatch yet; `outcome_unknown` may include a live or interrupted dispatch; `refused_before_send` records a request known to have been blocked before contacting the provider. No state authorizes an automatic replacement ID. The service never reclaims a dispatch on timeout, restart or age. A failure before the provider call can conservatively leave an unresolved original rather than risk duplicate mail.

REST equivalents are `POST /v1/agent-mail/outbound` and `GET /v1/agent-mail/outbound/{operationId}`, using the existing mailbox authentication. New operation records and sends are bounded by the existing mailbox/service ceilings; stored-original lookup does not consume sending quota. Concurrent first attempts can consume conservative admission counters. The legacy `/send` endpoint and `voidmail_send_email` retain their old behavior and have no durable status guarantee. Delivery webhooks, reply threading, outbound body history and attachments remain separate work.
