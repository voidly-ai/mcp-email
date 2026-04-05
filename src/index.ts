#!/usr/bin/env node
// @voidly/mcp-email — Agent-native encrypted email for AI
// MCP server that gives any AI agent its own @voidmail.ai inbox

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

const API_BASE = 'https://api.voidly.ai';

// ── State ────────────────────────────────────────────────────────────────

let apiKey: string | null = process.env.VOIDMAIL_API_KEY || null;
let address: string | null = process.env.VOIDMAIL_ADDRESS || null;

async function api(path: string, method = 'GET', body?: any): Promise<any> {
  if (!apiKey) throw new Error('Not authenticated. Use voidmail_create_account or set VOIDMAIL_API_KEY env var.');

  const resp = await fetch(`${API_BASE}${path}`, {
    method,
    headers: {
      'X-Agent-Mail-Key': apiKey,
      'Content-Type': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error || `API error: ${resp.status}`);
  return data;
}

// ── Server ───────────────────────────────────────────────────────────────

const server = new McpServer({
  name: 'voidmail',
  version: '1.0.0',
});

// ── Tools ────────────────────────────────────────────────────────────────

server.tool(
  'voidmail_create_account',
  'Create a new @voidmail.ai email inbox for this agent. Returns an email address and API key. No phone number, no CAPTCHA required.',
  { name: z.string().optional().describe('Agent name (optional)'), address: z.string().optional().describe('Preferred email address (optional, random if not specified)') },
  async ({ name, address: addr }) => {
    const resp = await fetch(`${API_BASE}/v1/agent-mail/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: name || 'agent', address: addr }),
    });
    const data = await resp.json() as any;
    if (!resp.ok) return { content: [{ type: 'text' as const, text: `Error: ${data.error}` }] };

    // Auto-authenticate
    apiKey = data.api_key;
    address = data.address;

    return { content: [{ type: 'text' as const, text: JSON.stringify({
      address: data.address,
      api_key: data.api_key,
      note: 'Save this API key — set VOIDMAIL_API_KEY env var to persist across sessions.',
    }, null, 2) }] };
  }
);

server.tool(
  'voidmail_account_info',
  'Get information about the current agent email account.',
  {},
  async () => {
    const data = await api('/v1/agent-mail/account');
    return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  'voidmail_list_inbox',
  'List emails in the agent inbox. Returns structured email data including sender, subject, body, and metadata.',
  {
    limit: z.number().optional().describe('Max emails to return (default 20, max 100)'),
    offset: z.number().optional().describe('Pagination offset'),
    unread: z.boolean().optional().describe('Only return unread emails'),
    category: z.string().optional().describe('Filter by category'),
  },
  async ({ limit, offset, unread, category }) => {
    const params = new URLSearchParams();
    if (limit) params.set('limit', String(limit));
    if (offset) params.set('offset', String(offset));
    if (unread) params.set('unread', 'true');
    if (category) params.set('category', category);
    const data = await api(`/v1/agent-mail/inbox?${params}`);
    return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  'voidmail_read_email',
  'Read a specific email by ID. Returns full email content including body, attachments, and thread info. Auto-marks as read.',
  { email_id: z.string().describe('Email ID to read') },
  async ({ email_id }) => {
    const data = await api(`/v1/agent-mail/inbox/${email_id}`);
    return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  'voidmail_search_inbox',
  'Search emails by keyword across subject, body, and sender. Returns matching emails.',
  {
    query: z.string().describe('Search query'),
    limit: z.number().optional().describe('Max results (default 20)'),
  },
  async ({ query, limit }) => {
    const params = new URLSearchParams({ q: query });
    if (limit) params.set('limit', String(limit));
    const data = await api(`/v1/agent-mail/inbox/search?${params}`);
    return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  'voidmail_send_email',
  'Send an email from the agent\'s @voidmail.ai address.',
  {
    to: z.string().describe('Recipient email address'),
    subject: z.string().describe('Email subject'),
    text: z.string().optional().describe('Plain text body'),
    html: z.string().optional().describe('HTML body (optional)'),
  },
  async ({ to, subject, text, html }) => {
    const data = await api('/v1/agent-mail/send', 'POST', { to, subject, text, html });
    return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  'voidmail_mark_read',
  'Mark an email as read.',
  { email_id: z.string().describe('Email ID to mark as read') },
  async ({ email_id }) => {
    const data = await api(`/v1/agent-mail/inbox/${email_id}/read`, 'POST');
    return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  'voidmail_delete_email',
  'Delete an email from the inbox.',
  { email_id: z.string().describe('Email ID to delete') },
  async ({ email_id }) => {
    const data = await api(`/v1/agent-mail/inbox/${email_id}`, 'DELETE');
    return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  'voidmail_create_alias',
  'Create a disposable email alias that routes to this agent\'s inbox.',
  { name: z.string().optional().describe('Alias name (random if not specified)') },
  async ({ name }) => {
    const data = await api('/v1/agent-mail/aliases', 'POST', { name });
    return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  'voidmail_list_aliases',
  'List all email aliases for this agent.',
  {},
  async () => {
    const data = await api('/v1/agent-mail/aliases');
    return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  'voidmail_delete_alias',
  'Delete an email alias.',
  { alias: z.string().describe('Alias to delete (without @voidmail.ai)') },
  async ({ alias }) => {
    const data = await api(`/v1/agent-mail/aliases/${alias}`, 'DELETE');
    return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  'voidmail_set_webhook',
  'Set a webhook URL to get notified when new email arrives.',
  {
    url: z.string().describe('HTTPS webhook URL'),
    secret: z.string().optional().describe('Webhook signing secret (auto-generated if not provided)'),
  },
  async ({ url, secret }) => {
    const data = await api('/v1/agent-mail/webhooks', 'POST', { url, secret });
    return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
  }
);

server.tool(
  'voidmail_get_stats',
  'Get inbox statistics — total emails, unread count, storage used.',
  {},
  async () => {
    const data = await api('/v1/agent-mail/stats');
    return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
  }
);

// ── Resources ────────────────────────────────────────────────────────────

server.resource(
  'inbox',
  'email://inbox',
  async (uri) => {
    if (!apiKey) return { contents: [{ uri: uri.href, text: 'Not authenticated. Use voidmail_create_account first.', mimeType: 'text/plain' }] };
    const data = await api('/v1/agent-mail/inbox?limit=10');
    return { contents: [{ uri: uri.href, text: JSON.stringify(data, null, 2), mimeType: 'application/json' }] };
  }
);

server.resource(
  'aliases',
  'email://aliases',
  async (uri) => {
    if (!apiKey) return { contents: [{ uri: uri.href, text: 'Not authenticated.', mimeType: 'text/plain' }] };
    const data = await api('/v1/agent-mail/aliases');
    return { contents: [{ uri: uri.href, text: JSON.stringify(data, null, 2), mimeType: 'application/json' }] };
  }
);

server.resource(
  'stats',
  'email://stats',
  async (uri) => {
    if (!apiKey) return { contents: [{ uri: uri.href, text: 'Not authenticated.', mimeType: 'text/plain' }] };
    const data = await api('/v1/agent-mail/stats');
    return { contents: [{ uri: uri.href, text: JSON.stringify(data, null, 2), mimeType: 'application/json' }] };
  }
);

// ── Start ────────────────────────────────────────────────────────────────

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('Voidmail MCP server running — 13 tools, 3 resources');
}

main().catch(console.error);
