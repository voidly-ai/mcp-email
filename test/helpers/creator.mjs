// Fixed, synthetic Ed25519 identity for offline signed-create fixtures only.
import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import nacl from 'tweetnacl';

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const SEED = Uint8Array.from({ length: 32 }, (_, index) => index + 1);

function didFor(publicKey) {
  const prefix = publicKey.subarray(0, 16);
  let value = BigInt('0x' + Buffer.from(prefix).toString('hex'));
  let encoded = '';
  while (value > 0n) {
    encoded = BASE58[Number(value % 58n)] + encoded;
    value /= 58n;
  }
  for (const byte of prefix) {
    if (byte !== 0) break;
    encoded = '1' + encoded;
  }
  return 'did:voidly:' + (encoded || '1');
}

export function creatorOptions(_t) {
  const signingKeyPair = nacl.sign.keyPair.fromSeed(SEED);
  const dir = mkdtempSync(join(tmpdir(), 'voidmail-synthetic-creator-'));
  chmodSync(dir, 0o700);
  const creatorSigningKeyFile = join(dir, 'signing-key');
  writeFileSync(creatorSigningKeyFile, Buffer.from(signingKeyPair.secretKey), { flag: 'wx', mode: 0o600 });
  return { creatorDid: didFor(signingKeyPair.publicKey), creatorSigningKeyFile, signingKeyPair };
}
