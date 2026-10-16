import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import nacl from 'tweetnacl';

const CREATE_PATH = '/v1/agent-mail/create';
const SIGN_CONTEXT = 'voidmail-create-v1';
const POW_CONTEXT = 'voidmail-create-pow-v1';
const DID_RE = /^did:voidly:[1-9A-HJ-NP-Za-km-z]{1,32}$/;

/**
 * Make one proof for the exact JSON string that will be transmitted (worker
 * routes/agentMailCreate.ts). Nothing here goes to an MCP result. The caller owns
 * `signer.secretKey` and zeroes it afterwards.
 */
export function signedCreateRequest(body: string, signer: { did: string; secretKey: Uint8Array }): { body: string; headers: Record<string, string> } {
  if (!signer || !DID_RE.test(signer.did) || !(signer.secretKey instanceof Uint8Array) || signer.secretKey.length !== 64) {
    throw new Error('Signed inbox creation needs an active registered agent identity and its Ed25519 signing key; no create request was sent.');
  }
  if (Buffer.byteLength(body, 'utf8') > 8192) throw new Error('Inbox create details exceed the 8192-byte limit; no create request was sent.');
  let keyPair: nacl.SignKeyPair | undefined;
  try {
    keyPair = nacl.sign.keyPair.fromSeed(signer.secretKey.subarray(0, 32));
    if (!timingSafeEqual(Buffer.from(keyPair.publicKey), Buffer.from(signer.secretKey.subarray(32)))) {
      throw new Error('Creator signing key is not a valid Ed25519 key pair; no create request was sent.');
    }
    const timestamp = String(Math.floor(Date.now() / 1000));
    if (!/^\d{10}$/.test(timestamp)) throw new Error('System clock cannot form a create timestamp; no create request was sent.');
    const nonce = randomBytes(16).toString('hex');
    const bodyHash = createHash('sha256').update(body, 'utf8').digest('hex');
    const preimage = [SIGN_CONTEXT, 'POST', CREATE_PATH, signer.did, timestamp, nonce, bodyHash].join('\n');
    let work: string | null = null;
    for (let i = 0; i < 1 << 22; i++) {
      const candidate = i.toString(16).padStart(16, '0');
      const hash = createHash('sha256').update([POW_CONTEXT, preimage, candidate].join('\n'), 'utf8').digest();
      if (hash[0] === 0 && hash[1] === 0) { work = candidate; break; }
    }
    if (!work) throw new Error('Create proof of work could not be found within the local bound; no create request was sent.');
    const signedMessage = [preimage, work].join('\n');
    const signature = Buffer.from(nacl.sign.detached(Buffer.from(signedMessage, 'utf8'), keyPair.secretKey)).toString('base64');
    return { body, headers: {
      'Content-Type': 'application/json',
      'X-Agent-DID': signer.did,
      'X-Mail-Timestamp': timestamp,
      'X-Mail-Nonce': nonce,
      'X-Mail-Pow': work,
      'X-Mail-Signature': signature,
    } };
  } finally {
    keyPair?.secretKey.fill(0);
  }
}
