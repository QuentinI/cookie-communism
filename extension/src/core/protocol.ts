// Wire types and payload sealing, mirroring crates/proto (payload.rs, api.rs, selector.rs).

import { b64, fromUtf8, unb64, utf8 } from "./encoding.ts";
import { decryptWith, encryptTo, type SignKey, verify } from "./keys.ts";
import { envelopeBytes, messageBytes, pairingRequestBytes } from "./signing.ts";

export interface Invite {
  relay: string;
  owner_sign: string;
  owner_box: string;
  token: string;
}

export function encodeInvite(invite: Invite): string {
  // Field order matches the Rust struct, though decoding does not depend on it.
  const ordered: Invite = {
    relay: invite.relay,
    owner_sign: invite.owner_sign,
    owner_box: invite.owner_box,
    token: invite.token,
  };
  return `cc1:${b64(utf8(JSON.stringify(ordered)))}`;
}

export function decodeInvite(text: string): Invite {
  const body = text.trim();
  if (!body.startsWith("cc1:")) throw new Error("invite must start with cc1:");
  const invite = JSON.parse(fromUtf8(unb64(body.slice(4)))) as Invite;
  return { ...invite, relay: invite.relay.replace(/\/+$/, "") };
}

export type SameSite = "no_restriction" | "lax" | "strict" | "unspecified";

export interface Cookie {
  domain: string;
  host_only: boolean;
  name: string;
  value: string;
  path: string;
  secure: boolean;
  http_only: boolean;
  same_site: SameSite;
  expires: number | null;
  partition_key: string | null;
  changed_at: number;
}

export interface Snapshot {
  owner_label: string;
  taken_at: number;
  selectors: string[];
  cookies: Cookie[];
}

export interface PairingRequest {
  label: string;
  wants: string[];
  consumer_sign: string;
  consumer_box: string;
}

export type ConsumerMessage =
  | { type: "refresh"; selector: string; reason: string }
  | { type: "resolved"; selector: string };

export interface MailboxItem {
  id: number;
  kind: "pairing" | "message";
  sender: string;
  invite_token: string | null;
  grant_id: string | null;
  ciphertext: string;
  signature: string;
  created_at: number;
}

export interface Envelope {
  grant_id: string;
  version: number;
  ciphertext: string;
  signature: string;
}

export interface Selector {
  domain: string;
  name: string | null;
}

export function parseSelector(text: string): Selector {
  const i = text.indexOf(":");
  const rawDomain = i < 0 ? text : text.slice(0, i);
  const name = i < 0 ? null : text.slice(i + 1);
  const domain = rawDomain.trim().replace(/^\.+/, "").toLowerCase();
  if (!domain.includes(".") || !/^[a-z0-9.-]+$/.test(domain)) {
    throw new Error(`invalid selector domain in ${JSON.stringify(text)}`);
  }
  if (name !== null && (name === "" || /[\s;=]/.test(name))) {
    throw new Error(`invalid cookie name in ${JSON.stringify(text)}`);
  }
  return { domain, name };
}

export function selectorToString(s: Selector): string {
  return s.name === null ? s.domain : `${s.domain}:${s.name}`;
}

export function coversDomain(s: Selector, cookieDomain: string): boolean {
  const d = cookieDomain.replace(/^\./, "").toLowerCase();
  return d === s.domain || d.endsWith(`.${s.domain}`);
}

export function selectorMatches(s: Selector, cookie: { domain: string; name: string }): boolean {
  return coversDomain(s, cookie.domain) && (s.name === null || s.name === cookie.name);
}

export async function sealEnvelope(
  grantId: string,
  version: number,
  snapshot: Snapshot,
  consumerBox: string,
  owner: SignKey,
): Promise<Envelope> {
  const ciphertext = await encryptTo(consumerBox, utf8(JSON.stringify(snapshot)));
  return {
    grant_id: grantId,
    version,
    ciphertext: b64(ciphertext),
    signature: await owner.sign(await envelopeBytes(grantId, version, ciphertext)),
  };
}

export async function openEnvelope(env: Envelope, ownerSign: string, consumerBox: string): Promise<Snapshot> {
  const ciphertext = unb64(env.ciphertext);
  if (!(await verify(ownerSign, await envelopeBytes(env.grant_id, env.version, ciphertext), env.signature))) {
    throw new Error("bad envelope signature");
  }
  return JSON.parse(fromUtf8(await decryptWith(consumerBox, ciphertext))) as Snapshot;
}

/** Verifies and decrypts a pairing request (see `MailboxItem::open_pairing` in Rust). */
export async function openPairing(item: MailboxItem, ownerBox: string): Promise<PairingRequest> {
  if (!item.invite_token) throw new Error("pairing item without invite token");
  const ciphertext = unb64(item.ciphertext);
  const request = JSON.parse(fromUtf8(await decryptWith(ownerBox, ciphertext))) as PairingRequest;
  if (request.consumer_sign !== item.sender) throw new Error("pairing request key does not match sender");
  const signed = await pairingRequestBytes(item.invite_token, ciphertext);
  if (!(await verify(request.consumer_sign, signed, item.signature))) {
    throw new Error("bad pairing request signature");
  }
  if (!request.consumer_box.startsWith("age1")) throw new Error("consumer box key is not age X25519");
  request.wants = request.wants.map((w) => selectorToString(parseSelector(w)));
  return request;
}

export async function openMessage(item: MailboxItem, consumerSign: string, ownerBox: string): Promise<ConsumerMessage> {
  if (!item.grant_id) throw new Error("message item without grant ID");
  const ciphertext = unb64(item.ciphertext);
  if (!(await verify(consumerSign, await messageBytes(item.grant_id, ciphertext), item.signature))) {
    throw new Error("bad message signature");
  }
  return JSON.parse(fromUtf8(await decryptWith(ownerBox, ciphertext))) as ConsumerMessage;
}
