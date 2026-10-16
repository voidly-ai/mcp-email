// A synthetic Voidly API for creator enrollment and signed inbox creation. Test double only.
// It follows worker/src/routes/agentHomeJoin.ts (challenge → exact message → both signatures →
// identities, replay answered from the receipt) and worker/src/routes/agentMailCreate.ts
// (timestamp, nonce, 16-bit work proof, Ed25519 signature by an ACTIVE identity, 2 per DID per
// day, one use per DID/nonce). Every request is recorded.
import nacl from 'tweetnacl';
import { createHash, randomBytes } from 'node:crypto';

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const HEX64 = /^[0-9a-f]{64}$/;
export const sha256Hex = text => createHash('sha256').update(text).digest('hex');
const b64 = bytes => Buffer.from(bytes).toString('base64');
const unb64 = (value, length) => {
  if (typeof value !== 'string') return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.length === length && bytes.toString('base64') === value ? new Uint8Array(bytes) : null;
};

export function didFrom(publicKey) {
  const prefix = publicKey.subarray(0, 16);
  let n = BigInt('0x' + Buffer.from(prefix).toString('hex'));
  let out = '';
  while (n > 0n) { out = BASE58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of prefix) { if (b !== 0) break; out = '1' + out; }
  return 'did:voidly:' + (out || '1');
}

export function intent(operationId, nonce, issued, expires, root, board) {
  const part = (side, p) => [`${side}-mode:${p.mode}`, `${side}-did:${p.did}`, `${side}-signing-public-key:${p.signing_public_key}`,
    `${side}-encryption-public-key:${p.encryption_public_key}`, `${side}-api-key-hash:${p.api_key_hash}`];
  return ['voidly-agent-home-join-v1', 'action:join', 'audience:https://api.voidly.ai/v1/home/join', `operation-id:${operationId}`,
    ...part('root', root), ...part('board', board), 'public-profile:false', `nonce:${nonce}`,
    `issued-at:${new Date(issued).toISOString()}`, `expires-at:${new Date(expires).toISOString()}`,
    'effect:private-home-only-no-mail-handle-wallet'].join('\n');
}

let mailboxCounter = 0;

export function fakeVoidly({ mint } = {}) {
  const state = {
    calls: [], joins: [], creates: [], identities: new Map(), challenges: new Map(), operations: new Map(),
    nonces: new Set(), perDid: new Map(), hostile: {},
  };
  const json = (data, status = 200, headers = {}) => Response.json(data, { status, headers: { 'Cache-Control': 'no-store', ...headers } });
  const exactKeys = (o, keys) => o && typeof o === 'object' && Object.keys(o).length === keys.length && Object.keys(o).every(k => keys.includes(k));

  function parsePart(raw) {
    if (!exactKeys(raw, ['mode', 'did', 'signing_public_key', 'encryption_public_key', 'api_key_hash']) || raw.mode !== 'create') return 'invalid_identity';
    const signing = unb64(raw.signing_public_key, 32), encryption = unb64(raw.encryption_public_key, 32);
    if (!signing || !encryption || raw.did !== didFrom(signing)) return 'invalid_identity_keys';
    if (!HEX64.test(raw.api_key_hash)) return 'invalid_api_key_hash';
    if (state.identities.has(raw.did)) return 'identity_occupied';
    return null;
  }
  const card = (op) => ({ operation_id: op.operation_id, state: 'working', private: true,
    root: { did: op.root.did, identity: 'ready', credential: 'local_retention_required' },
    board: { did: op.board.did, identity: 'ready', credential: 'local_retention_required' },
    mail: { state: 'held', reason: 'owner_action_required' }, next_actions: ['back_up_local_keys', 'complete_mail_owner_setup'] });

  function join(body) {
    if (body.action === 'challenge') {
      if (!exactKeys(body, ['action', 'operation_id', 'root', 'board', 'public_profile']) || body.public_profile !== false || !HEX64.test(body.operation_id)) return json({ error: 'invalid_join_request' }, 400);
      for (const side of ['root', 'board']) { const bad = parsePart(body[side]); if (bad) return json({ error: bad }, bad === 'identity_occupied' ? 409 : 400); }
      if (body.root.did === body.board.did || body.root.signing_public_key === body.board.signing_public_key || body.root.api_key_hash === body.board.api_key_hash) return json({ error: 'identities_must_be_independent' }, 400);
      const issued = Date.now(); const expires = issued + 60_000; const nonce = randomBytes(32).toString('hex');
      const message = intent(body.operation_id, nonce, issued, expires, body.root, body.board);
      state.challenges.set(nonce, { operation_id: body.operation_id, message, root: body.root, board: body.board, expires, consumed: false });
      let answer = { operation_id: body.operation_id, nonce, message, message_sha256: sha256Hex(message), expires_at: new Date(expires).toISOString(), signing: 'ed25519_exact_utf8_both_keys' };
      if (state.hostile.challenge) answer = state.hostile.challenge(answer, body);
      return json(answer, 202);
    }
    if (body.action === 'commit') {
      if (!exactKeys(body, ['action', 'operation_id', 'nonce', 'message', 'root_signature', 'board_signature'])) return json({ error: 'invalid_commit_request' }, 400);
      const ch = state.challenges.get(body.nonce);
      if (!ch || ch.operation_id !== body.operation_id) return json({ error: 'challenge_mismatch' }, 409);
      if (ch.message !== body.message) return json({ error: 'operation_conflict' }, 409);
      const bytes = Buffer.from(ch.message, 'utf8');
      const rs = unb64(body.root_signature, 64), bs = unb64(body.board_signature, 64);
      if (state.hostile.refuseCommit) return json({ error: state.hostile.refuseCommit }, 401);
      if (!rs || !bs || !nacl.sign.detached.verify(bytes, rs, unb64(ch.root.signing_public_key, 32)) || !nacl.sign.detached.verify(bytes, bs, unb64(ch.board.signing_public_key, 32))) {
        return json({ error: 'owner_signature_required' }, 401);
      }
      const prior = state.operations.get(body.operation_id);
      if (prior) return json(card(prior), 200);
      if (ch.consumed || Date.now() >= ch.expires) return json({ error: 'challenge_expired_or_used' }, 409);
      ch.consumed = true;
      for (const part of [ch.root, ch.board]) state.identities.set(part.did, { signing_public_key: part.signing_public_key, status: 'active', discoverable: 0 });
      const op = { operation_id: body.operation_id, root: ch.root, board: ch.board };
      state.operations.set(body.operation_id, op);
      return json(card(op), 201);
    }
    return json({ error: 'invalid_join_action' }, 400);
  }

  function create(init, raw) {
    const h = init.headers ?? {};
    const did = h['X-Agent-DID'], ts = h['X-Mail-Timestamp'], nonce = h['X-Mail-Nonce'], work = h['X-Mail-Pow'], sig = h['X-Mail-Signature'];
    const record = { did, verified: false, body: raw };
    state.creates.push(record);
    if (!/^did:voidly:[1-9A-HJ-NP-Za-km-z]{1,32}$/.test(did ?? '') || !/^[0-9]{10}$/.test(ts ?? '') || !/^[0-9a-f]{32}$/.test(nonce ?? '')
        || !/^[0-9a-f]{16}$/.test(work ?? '') || !/^[A-Za-z0-9+/]{86}==$/.test(sig ?? '') || Math.abs(Math.floor(Date.now() / 1000) - Number(ts)) > 300) {
      return json({ error: 'mail_create_proof_required' }, 401);
    }
    const preimage = ['voidmail-create-v1', 'POST', '/v1/agent-mail/create', did, ts, nonce, sha256Hex(Buffer.from(raw, 'utf8'))].join('\n');
    const workHash = createHash('sha256').update(['voidmail-create-pow-v1', preimage, work].join('\n')).digest();
    if (workHash[0] !== 0 || workHash[1] !== 0) return json({ error: 'mail_create_invalid_work' }, 401);
    const identity = state.identities.get(did);
    if (!identity || identity.status !== 'active') return json({ error: 'mail_create_invalid_identity' }, 401);
    if (!nacl.sign.detached.verify(Buffer.from([preimage, work].join('\n')), unb64(sig, 64), unb64(identity.signing_public_key, 32))) return json({ error: 'mail_create_invalid_signature' }, 401);
    const used = state.perDid.get(did) ?? 0;
    if (used >= 2) return json({ error: 'MAILBOX_CREATION_RATE_LIMITED', scope: 'mailbox_creation_did' }, 429, { 'Retry-After': '3600' });
    if (state.nonces.has(`${did}:${nonce}`)) return json({ error: 'mail_create_replay' }, 409);
    state.nonces.add(`${did}:${nonce}`); state.perDid.set(did, used + 1);
    record.verified = true;
    const body = JSON.parse(raw);
    const n = ++mailboxCounter;
    const minted = mint?.(body, n) ?? {
      address: `${body.address ?? `fixture${n}x`}@voidmail.ai`, api_key: 'vm_' + randomBytes(32).toString('hex'),
      owner_key: 'vmo_' + Array.from(randomBytes(40), b => '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'[b % 62]).join(''),
      recipient_policy: body.recipient_policy === 'allowlist' ? 'allowlist' : 'open',
    };
    record.minted = minted;
    return json(minted, 201);
  }

  async function handle(url, init = {}) {
    const u = new URL(url);
    state.calls.push({ url, path: u.pathname, method: init.method ?? 'GET', headers: { ...(init.headers ?? {}) }, body: init.body ?? null, redirect: init.redirect });
    if (u.origin !== 'https://api.voidly.ai') return json({ error: 'wrong host' }, 599);
    if (u.pathname === '/v1/home/join' && init.method === 'POST') {
      if (!/^application\/json/.test(init.headers?.['Content-Type'] ?? '')) return json({ error: 'application_json_required' }, 415);
      const body = JSON.parse(init.body);
      state.joins.push({ action: body.action, raw: init.body });
      if (state.hostile.joinStatus) return json({ error: state.hostile.joinStatus.error }, state.hostile.joinStatus.status, state.hostile.joinStatus.headers);
      const response = join(body);
      if (body.action === 'commit' && state.hostile.dropCommit > 0) {
        state.hostile.dropCommit--;
        throw new TypeError('fetch failed'); // the commit landed; its response was lost
      }
      return response;
    }
    if (u.pathname === '/v1/agent-mail/create' && init.method === 'POST') return create(init, init.body);
    return json({ ok: true });
  }

  return { state, handle };
}

/** An agent-sdk exportCredentials()-shaped object for a fresh identity (synthetic keys). */
export function sdkExport() {
  const signing = nacl.sign.keyPair(); const encryption = nacl.box.keyPair();
  return {
    signing,
    json: {
      did: didFrom(signing.publicKey), apiKey: randomBytes(32).toString('hex'),
      signingSecretKey: b64(signing.secretKey), encryptionSecretKey: b64(encryption.secretKey),
      signingPublicKey: b64(signing.publicKey), encryptionPublicKey: b64(encryption.publicKey),
      ratchetSchemaVersion: 2, homeJoinIdentity: true,
    },
  };
}
