# @voidly/mcp-email

Email for AI agents. One API call, instant inbox. No phone number, no CAPTCHA.

## Install

```bash
npx @voidly/mcp-email
```

## Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "voidmail": {
      "command": "npx",
      "args": ["-y", "@voidly/mcp-email"],
      "env": {
        "VOIDMAIL_API_KEY": "vm_your_key_here"
      }
    }
  }
}
```

No API key yet? The agent can create one with `voidmail_create_account`.

## Quick Start

**Step 1** — Create an inbox:
```
Use the voidmail_create_account tool to create an email inbox
```

**Step 2** — Send email:
```
Use voidmail_send_email to send an email to user@example.com
```

**Step 3** — Check inbox:
```
Use voidmail_list_inbox to see received emails
```

## Tools (13)

| Tool | Description |
|------|-------------|
| `voidmail_create_account` | Create a new @voidmail.ai inbox (returns address + API key) |
| `voidmail_account_info` | Get account details |
| `voidmail_list_inbox` | List emails with pagination and filters |
| `voidmail_read_email` | Read a specific email (auto-marks as read) |
| `voidmail_search_inbox` | Full-text search across subject, body, sender |
| `voidmail_send_email` | Send email from agent's @voidmail.ai address |
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
| `VOIDMAIL_API_KEY` | No | API key from create_account (persists across sessions) |
| `VOIDMAIL_ADDRESS` | No | Your @voidmail.ai address |

## REST API

Use directly without MCP:

```bash
# Create inbox
curl -X POST https://api.voidly.ai/v1/agent-mail/create \
  -H "Content-Type: application/json" \
  -d '{"name":"my-agent"}'

# List inbox
curl https://api.voidly.ai/v1/agent-mail/inbox \
  -H "X-Agent-Mail-Key: vm_your_key"

# Send email
curl -X POST https://api.voidly.ai/v1/agent-mail/send \
  -H "X-Agent-Mail-Key: vm_your_key" \
  -H "Content-Type: application/json" \
  -d '{"to":"user@example.com","subject":"Hello","text":"From my agent"}'

# Search
curl "https://api.voidly.ai/v1/agent-mail/inbox/search?q=invoice" \
  -H "X-Agent-Mail-Key: vm_your_key"
```

## Why Voidmail?

| | Voidmail | AgentMail | Gmail MCP |
|---|---------|-----------|-----------|
| Agent-native inbox | Yes | Yes | No (proxy) |
| No phone/CAPTCHA | Yes | Yes | No |
| E2E encryption option | **Yes** | No | No |
| MCP server | **Yes** | No | Yes |
| Free tier | Unlimited | 3 inboxes | N/A |
| Open protocol | **Yes** | No | No |

## Links

- API docs: https://voidly.ai/api-docs
- Landing page: https://voidly.ai/veil
- Privacy: https://voidly.ai/c/privacy
- Support: support@voidly.ai

## License

MIT
