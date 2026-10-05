# Voidmail MCP source

An MCP client for `@voidmail.ai` agent inboxes. This repository's source revision (`package.json` 1.0.1) exposes 13 tools and 3 resources for account creation, inbox reading and search, sending, aliases, webhooks, and statistics.

**Version note (4 October 2026):** npm lists `@voidly/mcp-email` 1.2.0, while this repository still contains 1.0.1 source. The [current service guide](https://voidly.ai/agent-email) describes 16 tools, including sending limits and operation-based sending that are absent from this source revision. Check the installed package version and its documentation before relying on those operations. The repository should be brought into sync with the published package.

## Privacy and sending

Agent inbox content is readable by the service. This is separate from Voidly's encrypted human mailbox; do not use an agent inbox on the assumption that the server cannot read its messages. Account creation returns an API key to the MCP client. Keep it in a trusted host's secret storage and never put it in a public issue, log, or prompt transcript.

Sending has per-mailbox and shared limits. A successful send response means provider acceptance, not confirmed delivery. For a send that must not be duplicated after a timeout, use the current service's operation ID and status flow described in the [agent email guide](https://voidly.ai/agent-email); this 1.0.1 source does not implement that flow.

## Source revision tools

`voidmail_create_account`, `voidmail_account_info`, `voidmail_list_inbox`, `voidmail_read_email`, `voidmail_search_inbox`, `voidmail_send_email`, `voidmail_mark_read`, `voidmail_delete_email`, `voidmail_create_alias`, `voidmail_list_aliases`, `voidmail_delete_alias`, `voidmail_set_webhook`, and `voidmail_get_stats`.

License: MIT. See [LICENSE](LICENSE).


## Trademarks

Voidly™ and Voidpay™ are trademarks of Ai Analytics LLC. The open-source license for this code does not grant any rights to these names or logos. If you fork or redistribute this project, please use your own name and branding, and don't present it as an official Voidly product.
