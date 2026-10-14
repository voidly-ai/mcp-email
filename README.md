# @voidly/mcp-email

Email for AI agents. Create an inbox, read incoming messages as structured data, and send to recipients the human owner has approved. No phone number or CAPTCHA.

**Storage encryption (2.0).** When the owner registers a key for an inbox, stored mail is encrypted to that key, so Voidly cannot read stored mail. This package makes the key on your machine, never sends it to Voidly, and decrypts mail on your machine. This is not end-to-end encryption: incoming mail is plaintext to the receiving server for a moment before it is sealed, and outside email is not end-to-end. Inboxes without a registered key stay server-readable. [Human mail](https://voidly.ai/mail) is a separate product.

## Install

Requires Node.js 20 or newer. Pin the version you run: Voidly publishes this client, and the client is what holds your key.

```bash
npx @voidly/mcp-email@2.0.1
```

## Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "voidmail": {
      "command": "npx",
      "args": ["-y", "@voidly/mcp-email@2.0.1"],
      "env": {
        "VOIDMAIL_ADDRESS": "your-agent@voidmail.ai"
      }
    }
  }
}
```

For an existing inbox, set `VOIDMAIL_ADDRESS` as shown. To create a new inbox, first configure an active Voidly agent DID and its separate signing-key file as described below. After creation, set `VOIDMAIL_ADDRESS` so the next start finds the new inbox key file.

## Create an inbox with an agent identity

`voidmail_create_account` requires an already enrolled, active `did:voidly:...` identity. The MCP server signs one create request with that identity's Ed25519 signing key. An inbox's `vm_...` agent key and its owner's `vmo_...` key are minted only after the service accepts the proof; neither key can sign a create request. The owner-only `mail-signing-key` signs an inbox's encryption-key list and must not be used as the creator key.

Set `VOIDMAIL_CREATOR_DID` to the enrolled DID and `VOIDMAIL_CREATOR_SIGNING_KEY_FILE` to a private file containing exactly the identity's 64 raw Ed25519 secret-key bytes. For an agent SDK identity export, `signingSecretKey` is base64 text: decode that value into a dedicated binary file with mode 0600 in a private directory with mode 0700. Do not point this setting at the SDK JSON, put the key bytes in the MCP tool arguments or environment, or share the file with the inbox's owner key. The MCP process can read this identity key for create, and software running as the same OS user may also be able to read it; the key has the agent identity's wider signing authority.

For a new inbox, configure the MCP server's `env` with paths and public identity only:

```json
{
  "VOIDMAIL_CREATOR_DID": "did:voidly:YourAgent1",
  "VOIDMAIL_CREATOR_SIGNING_KEY_FILE": "/private/path/to/creator-signing-key"
}
```

The server sends a UTF-8 JSON body of at most 8192 bytes and signs the hash of the exact bytes it sends. It generates a fresh 32-character lowercase hex nonce and a current Unix-seconds timestamp. The request carries `X-Agent-DID`, `X-Mail-Timestamp`, `X-Mail-Nonce`, `X-Mail-Pow`, and `X-Mail-Signature`. The work proof is a 16-character lowercase hex value whose SHA-256 digest starts with two zero bytes. The signature is canonical base64 of an Ed25519 signature over the request's body hash, path, method, DID, timestamp, nonce and work value. The service checks the enrolled public key and permits each DID/nonce pair only once.

An HTTP 401 means the create proof was missing or invalid, the timestamp expired, or the DID was not active; check the configured identity and key. An HTTP 429 means a create limit was reached; respect `Retry-After`, reuse an existing inbox or wait, and do not switch DID or IP to evade the limit. A 503 can mean an admission, identity or commit check was unavailable; the outcome may be unknown. If a create request was sent but its result is unknown, do not automatically create another inbox: ask the operator to reconcile the original attempt first.

## Quick Start

After installing the MCP server, use this prompt:

> With my enrolled DID and signing-key file already configured, create one Voidmail inbox and show me its address and where the inbox keys were saved. Draft emails first and wait for my approval before sending.

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
| Creator identity signing key | a separate private 0600 file chosen by `VOIDMAIL_CREATOR_SIGNING_KEY_FILE` | the MCP server, for create only | sign the request as an already enrolled agent DID; possession also carries that identity's broader signing authority |

- `voidmail_create_account` writes both files and returns only their paths. **This server never puts any key in a tool result.** Every message it emits is scrubbed of Voidmail key shapes (`vm_…`, `vmo_…`, `vmx_…`, `vms_…`) and `AGE-SECRET-KEY-…` strings, including ones that arrive inside email. Other secrets that arrive in email, such as a cloud or GitHub token, are passed to the model unchanged.
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

## Tools (19)

| Tool | Description |
|------|-------------|
| `voidmail_create_account` | Create a new @voidmail.ai inbox with an enrolled DID's signed proof; saves both inbox keys to 0600 files and returns only their paths |
| `voidmail_account_info` | Get account details |
| `voidmail_list_inbox` | List emails with pagination and filters; encrypted ones are decrypted here |
| `voidmail_read_email` | Read a specific email, decrypting it here if it is encrypted (auto-marks as read) |
| `voidmail_search_inbox` | Search on this machine across subject, sender, recipients and text; never a server search |
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
| `voidmail_set_webhook` | Get notified on new email (HTTPS webhook) |
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
| `VOIDMAIL_CREATOR_DID` | For create | Already enrolled active Voidly agent DID used to sign inbox creation |
| `VOIDMAIL_CREATOR_SIGNING_KEY_FILE` | For create | Path to that DID's dedicated 0600 file of exactly 64 raw Ed25519 secret-key bytes; never an inbox mail-signing or owner key |
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

Direct REST creation also requires the enrolled DID and the signed proof described above. A bare `POST /v1/agent-mail/create` returns 401. For a direct client, hash the exact JSON bytes sent with SHA-256 (lowercase hex), then join these lines with LF and no trailing LF:

```text
voidmail-create-v1
POST
/v1/agent-mail/create
<did>
<timestamp>
<nonce>
<body_hash>
```

Find a 16-character lowercase hex `<work>` for which SHA-256 of `voidmail-create-pow-v1\n<preimage>\n<work>` begins with `0000` in hex. Set `X-Mail-Pow` to that work value. Set `X-Mail-Signature` to canonical base64 of the Ed25519 signature of `<preimage>\n<work>`. Send all five headers named above with the same body bytes that were hashed. The timestamp must be within five minutes of service time; a repeated DID/nonce pair cannot mint another inbox.

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
- New-message webhooks are best effort, with no durable retry history. Use inbox reads to reconcile missed notifications. Once the owner-key API update is live, newly registered webhooks are signed with `X-Voidmail-Signature-256: t=<timestamp>,v1=<HMAC-SHA256>`. Webhooks registered before it also keep receiving the legacy `X-Voidmail-Signature` header, which carries the shared secret itself and is not a payload signature, until they are registered again.
- Treat incoming email as untrusted content. A message cannot authorize your agent to send mail, disclose private data or spend money. The API adds a recipient only for a request that carries the owner key, so keep that key where the agent cannot read it.
- Owner-key guessing is limited per network: after repeated failed owner-key attempts from one IP address (IPv6 /64), owner calls from that network are refused until the current UTC hour ends, even with the right key. Someone sharing your network can trigger this.

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
