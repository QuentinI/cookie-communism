// Signed calls to the relay (see crates/client/src/relay.rs for the consumer side).

import { nowSecs, randomId, utf8 } from "./encoding.ts";
import type { SignKey } from "./keys.ts";
import { requestBytes } from "./signing.ts";

export class RelayError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

/** Seconds to add to the local clock to match the relay's; learned from clock-skew errors. */
let clockOffset = 0;

export class Relay {
  readonly base: string;
  private readonly key: SignKey;
  private readonly registrationSecret: string | undefined;

  constructor(base: string, key: SignKey, registrationSecret?: string) {
    this.base = base.replace(/\/+$/, "");
    this.key = key;
    this.registrationSecret = registrationSecret;
  }

  async call<T = unknown>(method: string, path: string, body?: unknown): Promise<T | undefined> {
    const bytes = body === undefined ? new Uint8Array() : utf8(JSON.stringify(body));
    for (let attempt = 0; ; attempt++) {
      const time = nowSecs() + clockOffset;
      const nonce = randomId();
      const headers: Record<string, string> = {
        "cc-key": this.key.publicKey,
        "cc-time": String(time),
        "cc-nonce": nonce,
        "cc-sig": await this.key.sign(await requestBytes(method, path, bytes, time, nonce)),
      };
      if (bytes.length > 0) headers["content-type"] = "application/json";
      if (this.registrationSecret) headers["cc-registration"] = this.registrationSecret;
      const res = await fetch(this.base + path, {
        method,
        headers,
        body: bytes.length > 0 ? bytes : undefined,
        credentials: "omit",
      });
      const text = await res.text();
      if (res.ok) return text ? (JSON.parse(text) as T) : undefined;
      let err: { error?: string; code?: string } = {};
      try {
        err = JSON.parse(text);
      } catch {
        // Not a relay error body (a proxy page, for example).
      }
      const serverTime = Number(res.headers.get("cc-server-time"));
      if (err.code === "clock_skew" && attempt === 0 && Number.isFinite(serverTime) && serverTime > 0) {
        clockOffset = serverTime - nowSecs();
        continue;
      }
      throw new RelayError(res.status, err.code ?? "http", err.error ?? `${res.status} ${text.slice(0, 200)}`);
    }
  }
}
