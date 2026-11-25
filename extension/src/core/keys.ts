// Ed25519 (WebCrypto) and age X25519 (typage), with the same encodings as crates/proto.

import { Decrypter, Encrypter, generateX25519Identity, identityToRecipient } from "age-encryption";
import { b64, randomBytes, unb64 } from "./encoding.ts";

// PKCS#8 wrapping of a raw 32-byte Ed25519 seed (RFC 8410).
const PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/** An Ed25519 private key, stored as the base64 of its 32-byte seed. */
export class SignKey {
  readonly seed: string;
  readonly publicKey: string;
  private readonly key: CryptoKey;

  private constructor(seed: string, publicKey: string, key: CryptoKey) {
    this.seed = seed;
    this.publicKey = publicKey;
    this.key = key;
  }

  static generate(): Promise<SignKey> {
    return SignKey.fromSeed(b64(randomBytes(32)));
  }

  static async fromSeed(seed: string): Promise<SignKey> {
    const raw = unb64(seed);
    if (raw.length !== 32) throw new Error("signing key must be 32 bytes");
    const pkcs8 = new Uint8Array(48);
    pkcs8.set(PKCS8_PREFIX);
    pkcs8.set(raw, 16);
    const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
    const jwk = await crypto.subtle.exportKey("jwk", key);
    if (!jwk.x) throw new Error("WebCrypto did not export the Ed25519 public key");
    return new SignKey(seed, jwk.x, key);
  }

  /** Signs `message`; returns the base64 signature. */
  async sign(message: Uint8Array<ArrayBuffer>): Promise<string> {
    return b64(new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, this.key, message)));
  }
}

export async function verify(publicKey: string, message: Uint8Array<ArrayBuffer>, signature: string): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey("raw", unb64(publicKey), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, unb64(signature), message);
  } catch {
    return false;
  }
}

/** A new age X25519 identity (`AGE-SECRET-KEY-1…`). */
export function generateBoxIdentity(): Promise<string> {
  return generateX25519Identity();
}

export function boxRecipient(identity: string): Promise<string> {
  return identityToRecipient(identity);
}

export async function encryptTo(recipient: string, plaintext: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
  if (!recipient.startsWith("age1")) throw new Error("not an age X25519 recipient");
  const e = new Encrypter();
  e.addRecipient(recipient);
  return (await e.encrypt(plaintext)) as Uint8Array<ArrayBuffer>;
}

export async function decryptWith(identity: string, ciphertext: Uint8Array): Promise<Uint8Array> {
  const d = new Decrypter();
  d.addIdentity(identity);
  return d.decrypt(ciphertext);
}
