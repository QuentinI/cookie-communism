// The exact byte strings that get signed, mirroring crates/proto/src/signing.rs.

import { sha256, sha256Hex, utf8 } from "./encoding.ts";

export async function requestBytes(
  method: string,
  pathAndQuery: string,
  body: Uint8Array<ArrayBuffer>,
  time: number,
  nonce: string,
): Promise<Uint8Array<ArrayBuffer>> {
  return utf8(`cc-req-v1\n${method}\n${pathAndQuery}\n${await sha256Hex(body)}\n${time}\n${nonce}`);
}

export async function envelopeBytes(grantId: string, version: number, ciphertext: Uint8Array<ArrayBuffer>) {
  return utf8(`cc-env-v1\n${grantId}\n${version}\n${await sha256Hex(ciphertext)}`);
}

export async function messageBytes(grantId: string, ciphertext: Uint8Array<ArrayBuffer>) {
  return utf8(`cc-msg-v1\n${grantId}\n${await sha256Hex(ciphertext)}`);
}

export async function pairingRequestBytes(inviteToken: string, ciphertext: Uint8Array<ArrayBuffer>) {
  return utf8(`cc-pairreq-v1\n${inviteToken}\n${await sha256Hex(ciphertext)}`);
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** First 40 bits of SHA-256 over all four keys and the invite token, as `XXXX-XXXX`. */
export async function pairingCode(
  ownerSign: string,
  ownerBox: string,
  consumerSign: string,
  consumerBox: string,
  inviteToken: string,
): Promise<string> {
  const digest = await sha256(
    utf8(`cc-pair-v1\n${ownerSign}\n${ownerBox}\n${consumerSign}\n${consumerBox}\n${inviteToken}`),
  );
  let bits = 0n;
  for (const b of digest.slice(0, 5)) bits = (bits << 8n) | BigInt(b);
  let chars = "";
  for (let i = 7; i >= 0; i--) chars += CROCKFORD[Number((bits >> BigInt(i * 5)) & 31n)];
  return `${chars.slice(0, 4)}-${chars.slice(4)}`;
}
