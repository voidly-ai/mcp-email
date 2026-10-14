// A synthetic Voidmail API that follows the 2.0 key and sealing contract (src/mailcrypto.ts,
// mirroring worker/src/lib/agentMailKeys.ts and agentMailSeal.ts). Test double only: it seals
// with tweetnacl exactly as the Worker does, checks proof of possession and binding
// signatures, and records every request it sees.
import nacl from 'tweetnacl';
import PostalMime from 'postal-mime';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

export const b64 = bytes => Buffer.from(bytes).toString('base64');
export const unb64 = s => new Uint8Array(Buffer.from(s, 'base64'));
export const keyIdFor = pub => createHash('sha256').update('voidmail-key-id/1\n').update(pub).digest('hex').slice(0, 32);
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const bindingPreimage = f => Buffer.from(['voidmail-key-binding/1', `address=${f.address}`, `epoch=${f.epoch}`, `count=${f.count}`,
  `kind=${f.kind}`, `key_id=${f.key_id}`, `x25519=${f.x25519_public_key}`].join('\n'));

/** Seal raw bytes to the recipients of a key set, exactly as agentMailSeal.sealMessage does. */
export async function seal(raw, { recipients, epoch }, { emailId, address, receivedAt = new Date().toISOString(), bodyRaw = raw }) {
  const parsed = await new PostalMime().parse(raw);
  const base = { v: 1, email_id: emailId, mailbox: address, received_at: receivedAt, raw_sha256: sha256(raw), raw_bytes: raw.length };
  const text = parsed.text ?? '';
  const summary = {
    ...base, from: parsed.from ? { address: parsed.from.address ?? null, name: parsed.from.name ?? null } : null,
    to: (parsed.to ?? []).map(a => ({ address: a.address ?? null, name: a.name ?? null })), cc: [], reply_to: [],
    subject: parsed.subject ?? null, date: parsed.date ?? null, message_id: parsed.messageId ?? null, in_reply_to: null, references: null,
    snippet: text.replace(/\s+/g, ' ').trim().slice(0, 280),
    attachments: (parsed.attachments ?? []).map(a => ({ filename: a.filename, mime_type: a.mimeType, size: a.content.byteLength ?? null, disposition: a.disposition })),
    attachments_total: (parsed.attachments ?? []).length, truncated: false,
  };
  const dek = nacl.randomBytes(32);
  const summaryNonce = nacl.randomBytes(24);
  const summaryCt = nacl.secretbox(new Uint8Array(Buffer.from('voidmail-sealed-summary/1\n' + JSON.stringify(summary))), summaryNonce, dek);
  const header = Buffer.from('voidmail-sealed-payload/1\n' + JSON.stringify({ ...base, delivered_to: address, envelope_from: 'sender@example.com' }) + '\n');
  const bodyNonce = nacl.randomBytes(24);
  const bodyCt = nacl.secretbox(new Uint8Array(Buffer.concat([header, Buffer.from(bodyRaw)])), bodyNonce, dek);
  const stanzas = recipients.map(r => {
    const eph = nacl.box.keyPair(); const nonce = nacl.randomBytes(24);
    const wrapped = nacl.box(dek, nonce, unb64(r.x25519_public_key), eph.secretKey); eph.secretKey.fill(0);
    return { kind: r.kind, key_id: r.key_id, ephemeral_public_key: b64(eph.publicKey), nonce: b64(nonce), wrapped_key: b64(wrapped) };
  });
  dek.fill(0);
  return {
    envelope: { v: 1, alg: 'x25519-xsalsa20poly1305-box+secretbox', email_id: emailId, mailbox: address, epoch, recipients: stanzas,
      summary: { nonce: b64(summaryNonce), ciphertext: b64(summaryCt) },
      body: { nonce: b64(bodyNonce), bytes: bodyCt.byteLength, parts: 1, part_bytes: 786432 } },
    body: bodyCt,
  };
}

export function mime({ from = 'Sender Person <sender@example.com>', to, subject, text, html, attachment } = {}) {
  const boundary = 'b' + randomBytes(6).toString('hex');
  const lines = [`From: ${from}`, `To: ${to}`, `Subject: ${subject}`, 'Date: Wed, 07 Oct 2026 23:00:00 +0000', `Message-ID: <${randomBytes(6).toString('hex')}@example.com>`, 'MIME-Version: 1.0'];
  const parts = [['Content-Type: text/plain; charset=utf-8', '', text ?? ''].join('\r\n')];
  if (html) parts.push(['Content-Type: text/html; charset=utf-8', '', html].join('\r\n'));
  if (attachment) parts.push([`Content-Type: application/octet-stream; name="${attachment.name}"`, `Content-Disposition: attachment; filename="${attachment.name}"`, 'Content-Transfer-Encoding: base64', '', Buffer.from(attachment.content).toString('base64')].join('\r\n'));
  lines.push(`Content-Type: multipart/mixed; boundary="${boundary}"`, '');
  for (const part of parts) lines.push(`--${boundary}`, part);
  lines.push(`--${boundary}--`, '');
  return Buffer.from(lines.join('\r\n'));
}

export function fakeVoidmail({ address, ownerKey, agentKey }) {
  const state = {
    address, storage: 'server_readable', rows: [], challenges: new Map(), emails: [], bodies: new Map(), calls: [],
    hostile: {}, // switches for hostile-server tests
  };
  const json = (data, status = 200) => Response.json(data, { status });
  const ownerOk = init => init.headers?.['X-Agent-Mail-Owner-Key'] === ownerKey;
  const agentOk = init => init.headers?.['X-Agent-Mail-Key'] === agentKey;
  const active = () => state.rows.filter(r => r.retired === false);
  const maxEpoch = () => state.rows.reduce((m, r) => Math.max(m, r.epoch), 0);
  const directory = () => {
    const set = active();
    if (state.hostile.directory) return state.hostile.directory(set);
    return { address, storage: state.storage, epoch: set[0]?.epoch ?? 0, signing_public_key: set[0]?.signing_public_key ?? null,
      recipients: set.map(r => ({ kind: r.kind, key_id: r.key_id, x25519_public_key: r.x25519_public_key, binding_sig: r.binding_sig, count: set.length })), note: 'synthetic' };
  };
  const sealedView = row => ({ id: row.id, sealed: true, seal_version: 1, key_epoch: row.envelope?.epoch ?? null, from_domain: 'example.com', raw_size: row.raw_size,
    is_read: row.is_read, category: null, labels: null, received_at: row.received_at, envelope: row.envelope,
    body_url: state.hostile.bodyUrl ?? `/v1/agent-mail/inbox/${row.id}/sealed-body`, note: 'sealed', ...(row.extra ?? {}) });

  /** Deliver one message: sealed to the active set when the mailbox is sealed, else stored readable. */
  async function deliver(raw, { plaintext = false, receivedAt, extraRecipients = [], id, bodyRaw } = {}) {
    const emailId = id ?? 'sealed_' + randomBytes(16).toString('hex');
    const at = receivedAt ?? new Date().toISOString();
    const set = active();
    if (plaintext || state.storage !== 'sealed') {
      const text = raw.toString('utf8');
      state.emails.unshift({ id: emailId, from_address: 'sender@example.com', from_name: 'Sender Person', to_address: address,
        subject: /^Subject: (.*)$/m.exec(text)?.[1] ?? '', body_text: text.split('\r\n\r\n').slice(1).join('\n'), is_read: 0, received_at: at.replace('T', ' ').slice(0, 19) });
    } else {
      const sealed = await seal(raw, { recipients: [...set, ...extraRecipients], epoch: set[0].epoch }, { emailId, address, receivedAt: at, bodyRaw });
      state.emails.unshift({ id: emailId, sealed: true, is_read: 0, received_at: at, raw_size: raw.length, envelope: sealed.envelope });
      state.bodies.set(emailId, sealed.body);
    }
    return emailId;
  }

  async function handle(url, init = {}) {
    const u = new URL(url); const path = u.pathname; const method = init.method ?? 'GET';
    const body = init.body ? JSON.parse(init.body) : undefined;
    state.calls.push({ url, method, path, headers: { ...(init.headers ?? {}) }, body: init.body ?? null });
    if (u.origin !== 'https://api.voidly.ai') return json({ error: 'wrong host' }, 599);
    if (path.startsWith('/v1/agent-mail/owner/')) {
      if (!ownerOk(init)) return json({ error: 'unauthorized' }, 401);
      if (state.hostile.bootstrappedOwner) return json({ error: 'owner_key_from_agent_key', code: 'OWNER_KEY_FROM_AGENT_KEY' }, 403);
      if (path === '/v1/agent-mail/owner/keys' && method === 'GET') return json(directory());
      if (path === '/v1/agent-mail/owner/keys/challenge' && method === 'POST') {
        const challenges = body.recipients.map(r => {
          const pub = unb64(r.x25519_public_key); const keyId = keyIdFor(pub);
          const challengeId = randomBytes(16).toString('hex'); const answer = randomBytes(32).toString('hex');
          const plaintext = state.hostile.challengePlaintext?.({ challengeId, keyId }) ?? Buffer.from(['voidmail-key-pop/1', `address=${address}`, `challenge_id=${challengeId}`, `key_id=${keyId}`, `answer=${answer}`].join('\n'));
          const eph = nacl.box.keyPair(); const nonce = nacl.randomBytes(24);
          const ciphertext = nacl.box(new Uint8Array(plaintext), nonce, pub, eph.secretKey);
          state.challenges.set(challengeId, { keyId, pub: r.x25519_public_key, answer, used: false });
          return { key_id: keyId, challenge_id: challengeId, expires_at: new Date(Date.now() + 600_000).toISOString(), sealed: { ephemeral_public_key: b64(eph.publicKey), nonce: b64(nonce), ciphertext: b64(ciphertext) } };
        });
        return json({ challenges }, 201);
      }
      if (path === '/v1/agent-mail/owner/keys' && method === 'POST') {
        const keys = Object.keys(body).sort().join(',');
        if (keys !== 'epoch,recipients,signing_public_key' && keys !== 'epoch,recipients,signing_key_change,signing_public_key') return json({ error: 'invalid_request', code: 'INVALID_REQUEST', field: 'keys' }, 400);
        if (body.epoch !== maxEpoch() + 1) return json({ error: 'stale_epoch', code: 'MAIL_KEY_EPOCH_CONFLICT', current_epoch: maxEpoch() }, 409);
        const current = active();
        if (current.length && current[0].signing_public_key !== body.signing_public_key && body.signing_key_change !== true) return json({ error: 'x', code: 'SIGNING_KEY_CHANGE_NOT_CONFIRMED' }, 409);
        const count = body.recipients.length;
        for (const r of body.recipients) {
          if (keyIdFor(unb64(r.x25519_public_key)) !== r.key_id) return json({ error: 'invalid_request', code: 'INVALID_REQUEST', field: 'key_id' }, 400);
          if (!nacl.sign.detached.verify(bindingPreimage({ address, epoch: body.epoch, count, kind: r.kind, key_id: r.key_id, x25519_public_key: r.x25519_public_key }), unb64(r.binding_sig), unb64(body.signing_public_key))) {
            return json({ error: 'invalid_request', code: 'INVALID_REQUEST', field: 'binding_sig' }, 400);
          }
          if (r.challenge_id !== undefined) {
            const ch = state.challenges.get(r.challenge_id);
            const given = Buffer.from(String(r.challenge_answer)); const want = Buffer.from(ch?.answer ?? '');
            if (!ch || ch.used || ch.keyId !== r.key_id || ch.pub !== r.x25519_public_key || given.length !== want.length || !timingSafeEqual(given, want)) {
              return json({ error: 'possession_not_proven', code: 'KEY_POSSESSION_NOT_PROVEN' }, 403);
            }
          } else if (!current.some(c => c.key_id === r.key_id && c.kind === r.kind && c.x25519_public_key === r.x25519_public_key)) {
            return json({ error: 'possession_not_proven', code: 'KEY_POSSESSION_NOT_PROVEN' }, 403);
          }
        }
        if (body.recipients.filter(r => r.kind === 'agent').length !== 1) return json({ error: 'invalid_request', code: 'INVALID_REQUEST', field: 'recipients' }, 400);
        for (const r of body.recipients) if (r.challenge_id) state.challenges.get(r.challenge_id).used = true;
        for (const r of current) r.retired = true;
        for (const r of body.recipients) state.rows.push({ epoch: body.epoch, kind: r.kind, key_id: r.key_id, x25519_public_key: r.x25519_public_key, signing_public_key: body.signing_public_key, binding_sig: r.binding_sig, retired: false });
        state.storage = 'sealed';
        state.hostile.afterRegister?.();
        return json({ ...directory(), changed: true }, 200);
      }
      return json({ error: 'not_found' }, 404);
    }
    if (!agentOk(init) && !path.endsWith('/limits')) return json({ error: 'unauthorized' }, 401);
    if (path === '/v1/agent-mail/keys' && method === 'GET') return json(directory());
    if (path === '/v1/agent-mail/inbox/search') return state.storage === 'sealed' ? json({ error: 'x', code: 'SEARCH_IS_CLIENT_SIDE' }, 410) : json({ results: [], query: u.searchParams.get('q') });
    if (path === '/v1/agent-mail/inbox' && method === 'GET') {
      const limit = Number(u.searchParams.get('limit') ?? 50); const offset = Number(u.searchParams.get('offset') ?? 0);
      return json({ emails: state.emails.slice(offset, offset + limit).map(e => (e.sealed ? sealedView(e) : { ...e })), total: state.emails.length, limit, offset });
    }
    const bodyMatch = /^\/v1\/agent-mail\/inbox\/([A-Za-z0-9_-]{1,128})\/sealed-body$/.exec(path);
    if (bodyMatch && method === 'GET') {
      const bytes = state.bodies.get(bodyMatch[1]);
      if (!bytes) return json({ error: 'Email not found' }, 404);
      const out = state.hostile.body?.(bodyMatch[1], bytes) ?? bytes;
      return new Response(out, { status: 200, headers: { 'Content-Type': 'application/octet-stream' } });
    }
    if (path.startsWith('/v1/agent-mail/inbox/') && method === 'GET') {
      const id = decodeURIComponent(path.split('/')[4]);
      const row = state.emails.find(e => e.id === id);
      if (!row) return json({ error: 'Email not found' }, 404);
      row.is_read = 1;
      return json(row.sealed ? { ...sealedView(row), is_read: 1 } : { ...row, attachments: [] });
    }
    if (path === '/v1/agent-mail/account') return json({ address, recipient_policy: 'allowlist', storage_mode: state.storage });
    return json({ ok: true });
  }

  return { state, handle, deliver };
}
