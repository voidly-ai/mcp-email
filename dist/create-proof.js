import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { constants, fstatSync, openSync, readFileSync, closeSync } from 'node:fs';
import nacl from 'tweetnacl';
const CREATE_PATH = '/v1/agent-mail/create';
const SIGN_CONTEXT = 'voidmail-create-v1';
const POW_CONTEXT = 'voidmail-create-pow-v1';
const DID_RE = /^did:voidly:[1-9A-HJ-NP-Za-km-z]{1,32}$/;
function readCreatorSigningKey(path) {
    let fd;
    try {
        fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    }
    catch {
        throw new Error('Creator signing key file could not be opened safely; no create request was sent.');
    }
    try {
        const stat = fstatSync(fd);
        if (!stat.isFile() || stat.size !== 64 || (stat.mode & 0o077) !== 0 || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
            throw new Error('Creator signing key file must be an owned regular file with 0600 or stricter permissions and exactly 64 raw Ed25519 secret-key bytes; no create request was sent.');
        }
        const secret = readFileSync(fd);
        if (secret.length !== 64) {
            secret.fill(0);
            throw new Error('Creator signing key file changed while reading; no create request was sent.');
        }
        return secret;
    }
    finally {
        closeSync(fd);
    }
}
/** Make one proof for the exact JSON string that will be transmitted. Nothing here goes to an MCP result. */
export function signedCreateRequest(body, creatorDid, signingKeyFile) {
    if (!creatorDid || !DID_RE.test(creatorDid) || !signingKeyFile) {
        throw new Error('Signed inbox creation needs VOIDMAIL_CREATOR_DID and VOIDMAIL_CREATOR_SIGNING_KEY_FILE for an active registered agent identity; no create request was sent.');
    }
    if (Buffer.byteLength(body, 'utf8') > 8192)
        throw new Error('Inbox create details exceed the 8192-byte limit; no create request was sent.');
    const secret = readCreatorSigningKey(signingKeyFile);
    let keyPair;
    try {
        keyPair = nacl.sign.keyPair.fromSeed(secret.subarray(0, 32));
        if (!timingSafeEqual(Buffer.from(keyPair.publicKey), secret.subarray(32))) {
            throw new Error('Creator signing key file is not a valid Ed25519 key pair; no create request was sent.');
        }
        const timestamp = String(Math.floor(Date.now() / 1000));
        if (!/^\d{10}$/.test(timestamp))
            throw new Error('System clock cannot form a create timestamp; no create request was sent.');
        const nonce = randomBytes(16).toString('hex');
        const bodyHash = createHash('sha256').update(body, 'utf8').digest('hex');
        const preimage = [SIGN_CONTEXT, 'POST', CREATE_PATH, creatorDid, timestamp, nonce, bodyHash].join('\n');
        let work = null;
        for (let i = 0; i < 1 << 22; i++) {
            const candidate = i.toString(16).padStart(16, '0');
            const hash = createHash('sha256').update([POW_CONTEXT, preimage, candidate].join('\n'), 'utf8').digest();
            if (hash[0] === 0 && hash[1] === 0) {
                work = candidate;
                break;
            }
        }
        if (!work)
            throw new Error('Create proof of work could not be found within the local bound; no create request was sent.');
        const signedMessage = [preimage, work].join('\n');
        const signature = Buffer.from(nacl.sign.detached(Buffer.from(signedMessage, 'utf8'), keyPair.secretKey)).toString('base64');
        return { body, headers: {
                'Content-Type': 'application/json',
                'X-Agent-DID': creatorDid,
                'X-Mail-Timestamp': timestamp,
                'X-Mail-Nonce': nonce,
                'X-Mail-Pow': work,
                'X-Mail-Signature': signature,
            } };
    }
    finally {
        secret.fill(0);
        keyPair?.secretKey.fill(0);
    }
}
