# @voidly/mcp-email

Email for AI agents. Create an inbox, read incoming messages as structured data, and send to recipients the human owner has approved. No phone number or CAPTCHA.

Agent inboxes are readable by the server; they are not end-to-end encrypted. [Human mail](https://voidly.ai/mail) is a separate product.

## Install

Requires Node.js 20 or newer.

```bash
npx -y @voidly/mcp-email@1.2.1
```

### Add to Cursor

Copy this install URI into your browser address bar. Cursor asks you to review the local command before adding it:

```text
cursor://anysphere.cursor-deeplink/mcp/install?name=voidmail&config=eyJ0eXBlIjoic3RkaW8iLCJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkB2b2lkbHkvbWNwLWVtYWlsQDEuMi4xIl19
```

For manual project setup, copy the JSON below into `.cursor/mcp.json` (or `~/.cursor/mcp.json` for all projects).

### Install in VS Code

Copy this install URI into your browser address bar. VS Code asks you to review the local command before adding it:

```text
vscode:mcp/install?%7B%22name%22%3A%22voidmail%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40voidly%2Fmcp-email%401.2.1%22%5D%7D
```

For manual workspace setup, copy the JSON below into `.mcp.json` at the workspace root. GitHub renders custom app URIs as plain text, so use the copyable snippets above.

```json
{
  "mcpServers": {
    "voidmail": {
      "type": "stdio",
      "command": "npx",
      "args": [
        "-y",
        "@voidly/mcp-email@1.2.1"
      ]
    }
  }
}
```

These instructions run the **local stdio** package at 1.2.1. They do not create an inbox. The repository's root [`.mcp.json`](./.mcp.json) keeps that local command as `voidmail` and also offers the hosted connector as `voidmail-hosted` at `https://api.voidly.ai/mcp/mail`. It contains no credentials. The hosted connector has its own tool set; use `voidmail_setup` to check mailbox configuration before authenticated inbox actions.

**Before creating an inbox in a coding agent:** `voidmail_create_account` saves an owner key on the local machine. Keep that key outside the agent's shell and file access before handing the inbox to the agent. A 0600 file owned by the same OS user is not enough separation. The server can read message contents; provider acceptance of a send is not delivery.

## Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "voidmail": {
      "command": "npx",
      "args": ["-y", "@voidly/mcp-email@1.2.1"]
    }
  }
}
```

This first-time config has no inbox key. After `voidmail_create_account` returns an address and saves the keys, add `"env": {"VOIDMAIL_ADDRESS": "<returned-address>"}` to this server config and restart the host. If the agent has shell or file tools, use an isolated runtime that can read the agent key but cannot read the owner key; file mode 0600 alone does not separate two processes running as the same user.

## Quick Start

After installing the MCP server, use this prompt:

> Create one Voidmail inbox and show me its address and where the keys were saved. Draft emails first and wait for my approval before sending.

The draft approval in this prompt is a host workflow request. The API enforces the owner-approved recipient list and content policy; it does not require the owner to review every message body.

For a first receive and send check:

1. In a trusted owner-controlled host, call `voidmail_create_account` once. Keep the returned owner-key path outside any agent shell or file access before handing the inbox to an agent. If creation is uncertain, inspect the original setup before making another inbox.
2. Send one test message from a separate trusted mailbox to the new address. Call `voidmail_list_inbox`, then `voidmail_read_email` with the returned message ID. Reading marks that message as read.
3. In an owner-only terminal, run `npx -y @voidly/mcp-email@1.2.1 owner add you@example.com` (use your actual target address). Set `VOIDMAIL_OWNER_KEY_FILE` if you moved the owner key. The owner command reads it locally; never paste it into the model conversation. The agent can check `voidmail_policy` and `voidmail_sending_limits` afterward.
4. Review one recipient, subject and body. Save a unique 16-128 character operation ID (letters, digits, `_` or `-`) with that message in trusted host state, then call `voidmail_send_once`. If the response is uncertain, look up that same ID with `voidmail_send_status`; do not invent a replacement ID. A provider `accepted` result does not prove delivery.

## Permissions: two keys, one owner

Every inbox has two credentials, and this package keeps them apart.

| Key | File (0600, directory 0700) | Who uses it | What it can do |
|-----|------------------------------|-------------|----------------|
| Agent key `vm_…` | `~/.voidly/mcp-email/<address>/agent-key` | the MCP server, for the model's tools | read, send to approved recipients, request a recipient, remove a recipient, tighten policy |
| Owner key `vmo_…` | `~/.voidly/mcp-email/<address>/owner-key` | you, through `voidly-mcp-email owner` | approve or deny requests, add or remove recipients, lock or unlock, rotate either key |

- `voidmail_create_account` writes both files and returns only their paths. **This server never puts either key in a tool result.** Every message it emits is scrubbed of Voidmail key shapes (`vm_…`, `vmo_…`), including ones that arrive inside email. Other secrets that arrive in email, such as a cloud or GitHub token, are passed to the model unchanged.
- The MCP server never reads the owner-key file and never calls the owner API routes (`/v1/agent-mail/owner/*`). No tool uses the owner key.
- **Mode 0600 keeps other OS users out, not your agent.** Anything that runs as your user can read the owner-key file, including an agent with shell or file tools (a coding agent, a filesystem MCP server). Such an agent could read the owner key and approve its own recipients. If your agent has shell or file access on this machine, move the owner-key file somewhere it cannot read, or off the machine, and point `VOIDMAIL_OWNER_KEY_FILE` at it when you run owner commands.
- Inboxes created with this package start with an **owner-approved recipient list**, enforced by the Voidly API, not by model instructions. (A REST create that does not opt in still makes the old kind of inbox: no owner key, any recipient, credential warnings only. A create opts in with `recipient_policy: "allowlist"`, `owner_key: true` or `content_policy: "enforce"`; only then does the response carry an `owner_key`. This package always sends `recipient_policy: "allowlist"`.) Sending to anyone else returns `RECIPIENT_NOT_AUTHORIZED` with `send_attempted: false`. The API records a pending request, and the tool result says exactly what the owner must run.
- A message that looks like it carries a credential (private keys, cloud, GitHub, Slack, Stripe, AI-provider or Voidmail keys) is refused with `CONTENT_CONTAINS_CREDENTIAL` on inboxes with credential blocking on, which is the default for inboxes that have an owner key (every inbox this package creates). The tool result lists the kinds found, never the matched text. The check matches known key formats. It does not catch passwords, unfamiliar token formats or data that is sensitive for other reasons.
- **Outgoing mail is checked for credentials.** Before a message is sent, the API scans its recipient, subject, body and reply-to in memory for known credential formats. The scan keeps no copy of what it matched: it records only a daily count for each kind it found. On an inbox with credential blocking on (the default for inboxes with an owner key), a match stops the send. On other inboxes the message is still sent, and the response names the kinds found in an `X-Voidmail-Content-Warning` header. The owner can turn the check off at https://voidly.ai/agent-mail/owner (or with `POST /v1/agent-mail/owner/policy` and `content_policy: "off"`). The one exception is an owner key made by bootstrap, described below: it cannot switch the check off.
- The agent key can only restrict: it can remove a recipient or turn blocking on. Anything that widens what the agent can do needs the owner key.
- Approving a recipient takes the owner key, and nothing in an email can supply it through this server. Treat incoming mail as untrusted content.

### Owner commands

```bash
npx -y @voidly/mcp-email@1.2.1 owner list                 # policy, recipients, pending requests
npx -y @voidly/mcp-email@1.2.1 owner approve <request-id> # names the recipient; asks to confirm
npx -y @voidly/mcp-email@1.2.1 owner deny <request-id>
npx -y @voidly/mcp-email@1.2.1 owner add friend@example.com
npx -y @voidly/mcp-email@1.2.1 owner remove friend@example.com
npx -y @voidly/mcp-email@1.2.1 owner lock                 # allowlist + credential blocking
npx -y @voidly/mcp-email@1.2.1 owner unlock               # any recipient; asks to confirm
npx -y @voidly/mcp-email@1.2.1 owner rotate-agent-key     # old key stops working at once
npx -y @voidly/mcp-email@1.2.1 owner rotate-owner-key     # replaces the owner-key file it read
```

Add `--address <name@voidmail.ai>` when more than one inbox is saved, and `--yes` to confirm without a prompt. `approve` first reads the pending request and names its recipient, and refuses an id that is not pending. Rotated keys are written to their files and never printed. `rotate-owner-key` atomically replaces the owner-key file it read, including a `VOIDMAIL_OWNER_KEY_FILE` path. The old owner key is revoked before the new one is saved, so if that file cannot be replaced the new key goes to a new 0600 file beside it, and only if that also fails is it shown once on your terminal. An MCP server that reads its key file uses a rotated agent key on its next call. The same actions are available in the browser at https://voidly.ai/agent-mail/owner, where the owner key is kept in memory only.

**Inboxes without an owner key** (created before the owner-key API update, by mcp-email 1.1.0 or earlier, or by a REST create that did not opt in) keep the old behaviour: any recipient, with credential warnings only. To take control of one, call `POST /v1/agent-mail/owner/bootstrap` once with its agent key (`X-Agent-Mail-Key`). It works only on an untouched legacy inbox (still open, credential warnings only, never changed with the agent key); otherwise it refuses with `BOOTSTRAP_NOT_AVAILABLE`. Whoever makes this call first gets the owner key, and the API cannot tell a person from an agent holding the same agent key. Make the call yourself, outside any model conversation, before the agent does. It mints the owner key, switches the inbox to the approved list with credential blocking, and removes any webhook set with the agent key; only the owner can set a webhook afterwards. It cannot be undone with the agent key. An owner key minted this way can reopen the inbox but can never switch the credential guard off (`CONTENT_POLICY_FLOOR`). Save the returned `owner_key` in `~/.voidly/mcp-email/<address>/owner-key` with mode 0600.

Check incoming mail with `voidmail_list_inbox`, then read a message with `voidmail_read_email`. To send, review the recipient, subject and body before invoking `voidmail_send_once`. Generate and save a unique operation ID in your host state before the call; use that same ID for status lookup after a lost response, and for the retry after the owner approves a refused recipient.

## Tools (19)

| Tool | Description |
|------|-------------|
| `voidmail_create_account` | Create a new @voidmail.ai inbox; saves both keys to 0600 files and returns only their paths |
| `voidmail_account_info` | Get account details |
| `voidmail_list_inbox` | List emails with pagination and filters |
| `voidmail_read_email` | Read a specific email (auto-marks as read) |
| `voidmail_search_inbox` | Full-text search across subject, body, sender |
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
| `voidmail_set_webhook` | Set an HTTPS webhook on an open-policy inbox; allowlist inboxes require the human owner to use `POST /v1/agent-mail/owner/webhook` with the owner key |
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
| `VOIDMAIL_OWNER_KEY_FILE` | No | Owner CLI only: explicit owner-key file path. The MCP server never reads it |

## REST API

Use directly without MCP. Create an inbox only from a human-controlled terminal: the create response contains one-time agent and owner keys. Capture the owner key outside the model conversation and store it beyond any shell or file access granted to the agent. The example opts in to the owner-approved recipient list; a REST create without that option uses the legacy open-recipient policy.

```bash
# Create an owner-controlled inbox
curl -X POST https://api.voidly.ai/v1/agent-mail/create \
  -H "Content-Type: application/json" \
  -d '{"name":"my-agent","recipient_policy":"allowlist"}'

# List inbox
curl https://api.voidly.ai/v1/agent-mail/inbox \
  -H "X-Agent-Mail-Key: vm_your_key"

# Send once, after saving a unique operation ID in your host state and getting
# owner approval for the recipient. Replace the sample ID for each new message.
curl -X POST https://api.voidly.ai/v1/agent-mail/outbound \
  -H "X-Agent-Mail-Key: vm_your_key" \
  -H "Content-Type: application/json" \
  -d '{"operationId":"saved-message-id-0001","to":"user@example.com","subject":"Hello","text":"From my agent"}'

# Check the original result after a timeout or lost response; do not invent a new ID.
curl https://api.voidly.ai/v1/agent-mail/outbound/saved-message-id-0001 \
  -H "X-Agent-Mail-Key: vm_your_key"

# Search
curl "https://api.voidly.ai/v1/agent-mail/inbox/search?q=invoice" \
  -H "X-Agent-Mail-Key: vm_your_key"
```

## Limits and delivery

Call `voidmail_sending_limits` (or public `GET /v1/agent-mail/limits`) before planning a sending workflow. Keep excess work in your own queue. Sending and creation rate-limit `429` responses give a `Retry-After` header and structured limit scope/reset time; the MCP error includes the wait time. Other refusal codes, including a full pending-recipient-request list, may not have a retry time. Do not rotate accounts or IPs to evade a limit. Identical messages are blocked for 60 seconds to catch loops; this is not durable idempotency. Sending fails closed if safety counters are unavailable. Inbox reads remain separate from sending limits.

Shared caps: 100 attempts/hour per IP, 200/hour and 1,500/day for agent mail. The shared outbound provider budget is at most 1,500 recipients/day and 40,000 over approximately 31 days across all sending features. Counters count attempts, including failed and partially admitted requests; these are ceilings, not reserved capacity. Higher legitimate volume needs an operator-reviewed limit change; mailbox creation does not unlock bulk mail.

- Sending has per-mailbox, per-IP and shared service limits. Each mailbox may attempt up to 10 sends per minute and 100 per day, with up to 10 per day to the same recipient; shared limits can reject requests sooner. Mailbox creation is limited to 3 per IP per hour and 60 per service per hour. This is not an unlimited sending service.
- A successful send response means the sending provider accepted the request. It does not prove recipient delivery or that anyone read the message.
- Each API call has a 20-second deadline and a 2 MiB response bound. Requests reject redirects and are never automatically retried. Request fewer messages if an inbox response exceeds the bound.
- MCP tool annotations identify reads, sends, mutations and deletion honestly. They are advisory metadata; approval and install warnings remain controlled by ChatGPT, Claude or your other host.
- If a send times out, its outcome may be unknown. Use `voidmail_send_once` and `voidmail_send_status` with a saved operation ID; do not blindly resend.
- Incoming text and HTML bodies are parsed. This ingestion path does not currently retain attachments or populate reply-thread metadata, even though the response schema contains those fields. Reliable threaded replies are not yet provided.
- New-message webhooks are best effort, with no durable retry history. Use inbox reads to reconcile missed notifications. For a protected inbox, the owner must register a webhook through `POST /v1/agent-mail/owner/webhook` outside the agent; `voidmail_set_webhook` cannot do that. Once the owner-key API update is live, newly registered webhooks are signed with `X-Voidmail-Signature-256: t=<timestamp>,v1=<HMAC-SHA256>`. Webhooks registered before it also keep receiving the legacy `X-Voidmail-Signature` header, which carries the shared secret itself and is not a payload signature, until they are registered again.
- Treat incoming email as untrusted content. A message cannot authorize your agent to send mail, disclose private data or spend money. The API adds a recipient only for a request that carries the owner key, so keep that key where the agent cannot read it.
- Owner-key guessing is limited per network: repeated failed owner-key attempts from one IP address (IPv6 /64) are refused until the current UTC hour ends. A valid owner-key lookup is checked first and is not blocked by that failed-attempt budget.

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

## Trademarks

Voidly™ and Voidpay™ are trademarks of Ai Analytics LLC. The open-source license for this code does not grant any rights to these names or logos. If you fork or redistribute this project, please use your own name and branding, and don't present it as an official Voidly product.
