// Ed25519 signatures and X25519 HPKE encryption, both on WebCrypto, with the same encodings as
// crates/proto.

import { Aes128Gcm, CipherSuite, DhkemX25519HkdfSha256, HkdfSha256 } from "@hpke/core";
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

// HPKE (RFC 9180), base mode, with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM, all
// on WebCrypto. Must match crates/proto/src/keys.rs. Built on first use, so bundles that never
// encrypt (the popup) leave it out.
let cipherSuite: CipherSuite | undefined;
const hpke = () =>
  (cipherSuite ??= new CipherSuite({ kem: new DhkemX25519HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes128Gcm() }));
/** Length of the encapsulated key that starts every ciphertext. */
const ENC_LEN = 32;

/** What a ciphertext holds, bound into its encryption as HPKE's `info`. */
export type Purpose = "pairing request" | "envelope" | "message";
const info = (purpose: Purpose) => new TextEncoder().encode(`cookie-communism/v1 ${purpose}`);

/** A new X25519 private key, as the base64 of its 32 bytes. */
export async function generateBoxIdentity(): Promise<string> {
  const { privateKey } = await hpke().kem.generateKeyPair();
  return b64(new Uint8Array(await hpke().kem.serializePrivateKey(privateKey)));
}

/** The public key of `identity`, as the base64 of its 32 bytes. */
export async function boxRecipient(identity: string): Promise<string> {
  const key = await hpke().kem.deserializePrivateKey(unb64(identity));
  const { x } = await crypto.subtle.exportKey("jwk", key);
  if (!x) throw new Error("WebCrypto did not export the X25519 public key");
  return x;
}

/** Encrypts to `recipient`: the encapsulated key, then the AEAD ciphertext. */
export async function encryptTo(recipient: string, plaintext: Uint8Array, purpose: Purpose): Promise<Uint8Array<ArrayBuffer>> {
  const recipientPublicKey = await hpke().kem.deserializePublicKey(unb64(recipient));
  const { enc, ct } = await hpke().seal({ recipientPublicKey, info: info(purpose) }, plaintext);
  const out = new Uint8Array(enc.byteLength + ct.byteLength);
  out.set(new Uint8Array(enc));
  out.set(new Uint8Array(ct), enc.byteLength);
  return out;
}

export async function decryptWith(identity: string, ciphertext: Uint8Array, purpose: Purpose): Promise<Uint8Array> {
  if (ciphertext.length < ENC_LEN) throw new Error("ciphertext too short");
  const recipientKey = await hpke().kem.deserializePrivateKey(unb64(identity));
  const pt = await hpke().open(
    { recipientKey, enc: ciphertext.slice(0, ENC_LEN), info: info(purpose) },
    ciphertext.slice(ENC_LEN),
  );
  return new Uint8Array(pt);
}
