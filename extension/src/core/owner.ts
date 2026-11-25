// The owner (extension) side of the protocol, independent of browser APIs so it can be tested
// in Node against the real relay and client. The browser glue is in ../background.ts.

import { nowSecs, randomId, sha256Hex, utf8 } from "./encoding.ts";
import { boxRecipient, generateBoxIdentity, SignKey } from "./keys.ts";
import {
  type ConsumerMessage,
  type Cookie,
  coversDomain,
  encodeInvite,
  type MailboxItem,
  openMessage,
  openPairing,
  parseSelector,
  type SameSite,
  sealEnvelope,
  selectorMatches,
  selectorToString,
  type Snapshot,
} from "./protocol.ts";
import { Relay, RelayError } from "./relay.ts";
import { pairingCode } from "./signing.ts";

/** A cookie as the WebExtension `cookies` API reports it. */
export interface BrowserCookie {
  domain: string;
  hostOnly: boolean;
  name: string;
  value: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
  expirationDate?: number;
  storeId: string;
  partitionKey?: { topLevelSite?: string } | null;
}

export interface Notice {
  id: string;
  title: string;
  message: string;
  /** Opened when the notification is clicked. */
  url?: string;
}

/** What the owner needs from the browser. */
export interface Platform {
  load(): Promise<OwnerState | undefined>;
  save(state: OwnerState): Promise<void>;
  /** Cookies on `domain` and its subdomains, in `storeId` (the default store if null). */
  cookies(domain: string, storeId: string | null): Promise<BrowserCookie[]>;
  notify(notice: Notice): void;
  clearNotice(id: string): void;
}

export interface PendingRequest {
  mailboxId: number;
  token: string;
  label: string;
  wants: string[];
  consumerSign: string;
  consumerBox: string;
  code: string;
  receivedAt: number;
}

export interface Grant {
  id: string;
  label: string;
  consumerSign: string;
  consumerBox: string;
  selectors: string[];
  storeId: string | null;
  version: number;
  lastHash: string | null;
  lastPushAt: number | null;
  createdAt: number;
}

export interface Alert {
  id: string;
  grantId: string;
  selector: string;
  reason: string;
  at: number;
}

export interface OwnerState {
  /** 1 held an age identity; 2 holds a raw X25519 key for HPKE. */
  format: 2;
  label: string;
  relay: string;
  registrationSecret: string | null;
  signSeed: string;
  boxIdentity: string;
  openInvites: { token: string; createdAt: number }[];
  pending: PendingRequest[];
  grants: Grant[];
  /** Per cookie identity: hash of the last value seen and when it changed. */
  seen: Record<string, { hash: string; changedAt: number }>;
  alerts: Alert[];
  /** Per `grantId selector`: when the last expiry reminder was shown. */
  reminded: Record<string, number>;
}

/** What the popup shows; no secrets. */
export interface OwnerStatus {
  label: string;
  relay: string;
  registrationSecretSet: boolean;
  publicKey: string;
  openInvites: number;
  pending: PendingRequest[];
  grants: (Grant & { earliestExpiry: number | null; matching: number })[];
  alerts: Alert[];
}

const INVITE_TTL_SECS = 3600;
const REMINDER_WINDOW_SECS = 3 * 86400;
const REMINDER_INTERVAL_SECS = 86400;

function cookieKey(c: BrowserCookie): string {
  return [c.storeId, c.domain, c.path, c.name, c.partitionKey?.topLevelSite ?? ""].join("\t");
}

function sameSite(value: string): SameSite {
  return value === "no_restriction" || value === "lax" || value === "strict" ? value : "unspecified";
}

/**
 * Narrowing only: an approved selector must be one the consumer asked for, or a single cookie
 * under a domain the consumer asked for.
 */
export function allowedSelector(approved: string, wants: string[]): boolean {
  const s = parseSelector(approved);
  return wants.map(parseSelector).some((w) => w.domain === s.domain && (w.name === null || w.name === s.name));
}

export class Owner {
  private queue: Promise<unknown> = Promise.resolve();
  private readonly platform: Platform;
  private state: OwnerState;
  private readonly key: SignKey;

  private constructor(platform: Platform, state: OwnerState, key: SignKey) {
    this.platform = platform;
    this.state = state;
    this.key = key;
  }

  static async open(platform: Platform, defaults: { label: string; relay?: string }): Promise<Owner> {
    let state = await platform.load();
    if (!state || (state.format as number) !== 2) {
      // A format 1 state's box key and grants were made for age, which consumers no longer
      // read. Keep the settings and the signing key, so the relay still knows this browser.
      state = {
        format: 2,
        label: state?.label ?? defaults.label,
        relay: state?.relay ?? defaults.relay ?? "",
        registrationSecret: state?.registrationSecret ?? null,
        signSeed: state?.signSeed ?? (await SignKey.generate()).seed,
        boxIdentity: await generateBoxIdentity(),
        openInvites: [],
        pending: [],
        grants: [],
        seen: {},
        alerts: [],
        reminded: {},
      };
      await platform.save(state);
    }
    return new Owner(platform, state, await SignKey.fromSeed(state.signSeed));
  }

  /** Runs `fn` after every earlier call has finished, so state updates never interleave. */
  private run<T>(fn: () => Promise<T>): Promise<T> {
    const next = this.queue.then(fn, fn);
    this.queue = next.catch(() => undefined);
    return next;
  }

  private relay(): Relay {
    if (!this.state.relay) throw new Error("set the relay URL first");
    return new Relay(this.state.relay, this.key, this.state.registrationSecret ?? undefined);
  }

  private save(): Promise<void> {
    return this.platform.save(this.state);
  }

  get publicKey(): string {
    return this.key.publicKey;
  }

  configure(settings: { label?: string; relay?: string; registrationSecret?: string | null }): Promise<void> {
    return this.run(async () => {
      if (settings.label !== undefined) this.state.label = settings.label.trim() || this.state.label;
      if (settings.relay !== undefined) {
        const relay = settings.relay.trim().replace(/\/+$/, "");
        if (relay && !/^https?:\/\//.test(relay)) throw new Error("relay URL must start with https://");
        if (relay !== this.state.relay && this.state.grants.length > 0) {
          throw new Error("revoke every grant before changing the relay");
        }
        this.state.relay = relay;
      }
      if (settings.registrationSecret !== undefined) {
        this.state.registrationSecret = settings.registrationSecret || null;
      }
      await this.save();
    });
  }

  /** True while an invite may still bring a pairing request. */
  hasOpenInvites(now = nowSecs()): boolean {
    return this.state.openInvites.some((i) => i.createdAt + INVITE_TTL_SECS > now);
  }

  createInvite(): Promise<string> {
    return this.run(async () => {
      const token = randomId();
      await this.relay().call("POST", "/invites", { token });
      this.state.openInvites.push({ token, createdAt: nowSecs() });
      await this.save();
      return encodeInvite({
        relay: this.state.relay,
        owner_sign: this.key.publicKey,
        owner_box: await boxRecipient(this.state.boxIdentity),
        token,
      });
    });
  }

  /** Fetches and handles mailbox items, waiting up to `waitSecs` for one. */
  pollMailbox(waitSecs = 0): Promise<void> {
    // The long-poll itself runs outside the queue so it does not block other operations.
    const fetched = this.relay().call<{ items: MailboxItem[] }>("GET", `/mailbox?wait=${waitSecs}`);
    return fetched.then((res) => this.run(() => this.handleMailbox(res?.items ?? [])));
  }

  private async handleMailbox(items: MailboxItem[]): Promise<void> {
    const relay = this.relay();
    const ack = (item: MailboxItem) => relay.call("DELETE", `/mailbox/${item.id}`).catch(() => undefined);
    for (const item of items) {
      if (item.kind === "pairing") {
        if (this.state.pending.some((p) => p.mailboxId === item.id)) continue;
        try {
          const request = await openPairing(item, this.state.boxIdentity);
          const token = item.invite_token!;
          const code = await pairingCode(
            this.key.publicKey,
            await boxRecipient(this.state.boxIdentity),
            request.consumer_sign,
            request.consumer_box,
            token,
          );
          this.state.pending.push({
            mailboxId: item.id,
            token,
            label: request.label,
            wants: request.wants,
            consumerSign: request.consumer_sign,
            consumerBox: request.consumer_box,
            code,
            receivedAt: nowSecs(),
          });
          this.state.openInvites = this.state.openInvites.filter((i) => i.token !== token);
          this.platform.notify({
            id: `pairing:${item.id}`,
            title: `Pairing request from ${request.label}`,
            message: `Open cookie-communism and check the code ${code}.`,
          });
        } catch (e) {
          console.warn("discarding invalid pairing request", e);
          await ack(item);
        }
      } else {
        const grant = this.state.grants.find((g) => g.id === item.grant_id);
        try {
          if (grant) await this.handleMessage(grant, await openMessage(item, grant.consumerSign, this.state.boxIdentity));
        } catch (e) {
          console.warn("discarding invalid message", e);
        }
        await ack(item);
      }
    }
    this.state.openInvites = this.state.openInvites.filter((i) => i.createdAt + INVITE_TTL_SECS > nowSecs());
    await this.save();
  }

  private async handleMessage(grant: Grant, message: ConsumerMessage): Promise<void> {
    const selector = parseSelector(message.selector);
    if (message.type === "resolved") {
      this.clearAlerts((a) => a.grantId === grant.id && parseSelector(a.selector).domain === selector.domain);
      return;
    }
    const changed = await this.syncGrant(grant, false);
    if (changed) return;
    const id = `refresh:${grant.id}:${selector.domain}`;
    this.state.alerts = this.state.alerts.filter((a) => a.id !== id);
    this.state.alerts.push({ id, grantId: grant.id, selector: message.selector, reason: message.reason, at: nowSecs() });
    this.platform.notify({
      id,
      title: `Log in to ${selector.domain}`,
      message: `${grant.label}: ${message.reason}`,
      url: `https://${selector.domain}/`,
    });
  }

  private clearAlerts(pred: (a: Alert) => boolean): void {
    for (const a of this.state.alerts.filter(pred)) this.platform.clearNotice(a.id);
    this.state.alerts = this.state.alerts.filter((a) => !pred(a));
  }

  /**
   * Approves a pairing request for `selectors` (the requested ones, or narrower), reading
   * cookies from `storeId`, and sends the first snapshot. Host permissions must already be
   * granted by the caller.
   */
  approve(mailboxId: number, selectors: string[], storeId: string | null = null): Promise<Grant> {
    return this.run(async () => {
      const request = this.state.pending.find((p) => p.mailboxId === mailboxId);
      if (!request) throw new Error("no such pairing request");
      if (selectors.length === 0) throw new Error("approve at least one selector");
      for (const s of selectors) {
        if (!allowedSelector(s, request.wants)) throw new Error(`${s} was not requested`);
      }
      const relay = this.relay();
      const grant: Grant = {
        id: randomId(),
        label: request.label,
        consumerSign: request.consumerSign,
        consumerBox: request.consumerBox,
        selectors: [...new Set(selectors.map((s) => selectorToString(parseSelector(s))))].sort(),
        storeId,
        version: 0,
        lastHash: null,
        lastPushAt: null,
        createdAt: nowSecs(),
      };
      await relay.call("PUT", `/grants/${grant.id}`, { invite_token: request.token });
      await relay.call("DELETE", `/mailbox/${mailboxId}`).catch(() => undefined);
      this.state.pending = this.state.pending.filter((p) => p.mailboxId !== mailboxId);
      this.state.grants.push(grant);
      this.platform.clearNotice(`pairing:${mailboxId}`);
      await this.save();
      await this.syncGrant(grant, true);
      return grant;
    });
  }

  reject(mailboxId: number): Promise<void> {
    return this.run(async () => {
      const request = this.state.pending.find((p) => p.mailboxId === mailboxId);
      if (!request) return;
      const relay = this.relay();
      await relay.call("DELETE", `/invites/${request.token}`).catch(() => undefined);
      await relay.call("DELETE", `/mailbox/${mailboxId}`).catch(() => undefined);
      this.state.pending = this.state.pending.filter((p) => p.mailboxId !== mailboxId);
      this.platform.clearNotice(`pairing:${mailboxId}`);
      await this.save();
    });
  }

  revoke(grantId: string): Promise<void> {
    return this.run(async () => {
      try {
        await this.relay().call("DELETE", `/grants/${grantId}`);
      } catch (e) {
        if (!(e instanceof RelayError && e.status === 404)) throw e;
      }
      this.state.grants = this.state.grants.filter((g) => g.id !== grantId);
      this.clearAlerts((a) => a.grantId === grantId);
      await this.save();
    });
  }

  /** Builds the grant's snapshot, recording when each cookie value was first seen. */
  private async snapshot(grant: Grant): Promise<Snapshot> {
    const selectors = grant.selectors.map(parseSelector);
    const domains = [...new Set(selectors.map((s) => s.domain))];
    const byKey = new Map<string, BrowserCookie>();
    for (const domain of domains) {
      for (const c of await this.platform.cookies(domain, grant.storeId)) {
        if (selectors.some((s) => selectorMatches(s, c))) byKey.set(cookieKey(c), c);
      }
    }
    const now = nowSecs();
    const cookies: Cookie[] = [];
    for (const [key, c] of [...byKey].sort(([a], [b]) => (a < b ? -1 : 1))) {
      const hash = await sha256Hex(utf8(c.value));
      const seen = this.state.seen[key];
      const changedAt = seen && seen.hash === hash ? seen.changedAt : now;
      this.state.seen[key] = { hash, changedAt };
      cookies.push({
        domain: c.domain,
        host_only: c.hostOnly,
        name: c.name,
        value: c.value,
        path: c.path,
        secure: c.secure,
        http_only: c.httpOnly,
        same_site: sameSite(c.sameSite),
        expires: c.expirationDate === undefined ? null : Math.floor(c.expirationDate),
        partition_key: c.partitionKey?.topLevelSite ?? null,
        changed_at: changedAt,
      });
    }
    return { owner_label: this.state.label, taken_at: now, selectors: grant.selectors, cookies };
  }

  /** Uploads the grant's snapshot if it changed (or `force`). Returns whether it changed. */
  private async syncGrant(grant: Grant, force: boolean): Promise<boolean> {
    const snapshot = await this.snapshot(grant);
    const hash = await sha256Hex(
      utf8(JSON.stringify({ label: snapshot.owner_label, selectors: snapshot.selectors, cookies: snapshot.cookies })),
    );
    const changed = hash !== grant.lastHash;
    if (!changed && !force) return false;
    // Versions only need to increase. Basing them on the clock keeps them increasing even if
    // extension storage is restored from an older copy.
    const version = Math.max(grant.version + 1, Date.now());
    const env = await sealEnvelope(grant.id, version, snapshot, grant.consumerBox, this.key);
    try {
      await this.relay().call("PUT", `/grants/${grant.id}/envelope`, env);
    } catch (e) {
      if (e instanceof RelayError && e.status === 404) {
        // Revoked on the relay (for example from another copy of this profile).
        this.state.grants = this.state.grants.filter((g) => g.id !== grant.id);
        await this.save();
        return false;
      }
      throw e;
    }
    grant.version = version;
    grant.lastHash = hash;
    grant.lastPushAt = nowSecs();
    if (changed) {
      const domains = new Set(grant.selectors.map((s) => parseSelector(s).domain));
      this.clearAlerts((a) => a.grantId === grant.id && domains.has(parseSelector(a.selector).domain));
    }
    await this.save();
    return changed;
  }

  /** Re-snapshots every grant whose selectors cover one of `domains` (all grants if omitted). */
  sync(domains?: string[], force = false): Promise<void> {
    return this.run(async () => {
      for (const grant of [...this.state.grants]) {
        const selectors = grant.selectors.map(parseSelector);
        if (domains && !domains.some((d) => selectors.some((s) => coversDomain(s, d)))) continue;
        try {
          await this.syncGrant(grant, force);
        } catch (e) {
          console.warn(`sync of ${grant.label} failed`, e);
        }
      }
    });
  }

  /** Notifies about named cookies that expire within three days, at most once a day each. */
  remind(now = nowSecs()): Promise<void> {
    return this.run(async () => {
      for (const grant of this.state.grants) {
        for (const text of grant.selectors) {
          const selector = parseSelector(text);
          if (selector.name === null) continue;
          const cookies = await this.platform.cookies(selector.domain, grant.storeId);
          const expiries = cookies
            .filter((c) => selectorMatches(selector, c) && c.expirationDate !== undefined)
            .map((c) => c.expirationDate!);
          // The latest one matters: it is what the consumer will use longest.
          const expiry = expiries.length ? Math.max(...expiries) : null;
          const key = `${grant.id} ${text}`;
          if (expiry === null || expiry - now > REMINDER_WINDOW_SECS) continue;
          if ((this.state.reminded[key] ?? 0) + REMINDER_INTERVAL_SECS > now) continue;
          this.state.reminded[key] = now;
          const days = Math.max(0, Math.round((expiry - now) / 86400));
          this.platform.notify({
            id: `expiry:${key}`,
            title: `Log in to ${selector.domain}`,
            message:
              expiry <= now
                ? `${selector.name} has expired; ${grant.label} cannot use it.`
                : `${selector.name} expires in ${days === 0 ? "less than a day" : `${days} days`} (used by ${grant.label}).`,
            url: `https://${selector.domain}/`,
          });
        }
      }
      await this.save();
    });
  }

  dismissAlert(id: string): Promise<void> {
    return this.run(async () => {
      this.clearAlerts((a) => a.id === id);
      await this.save();
    });
  }

  /** Domains this owner reads cookies from, for host permissions. */
  grantedDomains(): string[] {
    return [...new Set(this.state.grants.flatMap((g) => g.selectors.map((s) => parseSelector(s).domain)))];
  }

  /** Whether any grant covers a cookie on `domain`. */
  covers(domain: string): boolean {
    return this.state.grants.some((g) => g.selectors.some((s) => coversDomain(parseSelector(s), domain)));
  }

  status(): Promise<OwnerStatus> {
    return this.run(async () => {
      const now = nowSecs();
      const grants = [];
      for (const g of this.state.grants) {
        let earliest: number | null = null;
        let matching = 0;
        for (const text of g.selectors) {
          const s = parseSelector(text);
          const cookies = (await this.platform.cookies(s.domain, g.storeId)).filter((c) => selectorMatches(s, c));
          matching += cookies.length;
          if (s.name === null) continue;
          for (const c of cookies) {
            if (c.expirationDate !== undefined && c.expirationDate > now) {
              earliest = earliest === null ? c.expirationDate : Math.min(earliest, c.expirationDate);
            }
          }
        }
        grants.push({ ...g, earliestExpiry: earliest, matching });
      }
      return {
        label: this.state.label,
        relay: this.state.relay,
        registrationSecretSet: this.state.registrationSecret !== null,
        publicKey: this.key.publicKey,
        openInvites: this.state.openInvites.length,
        pending: this.state.pending,
        grants,
        alerts: this.state.alerts,
      };
    });
  }
}
