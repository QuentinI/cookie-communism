// The WebExtension API in both browsers. Firefox provides `browser`; Chrome's `chrome` returns
// promises in Manifest V3 for every API used here.

import type Browser from "webextension-polyfill";

export const browser: Browser.Browser =
  (globalThis as { browser?: Browser.Browser }).browser ?? (globalThis as unknown as { chrome: Browser.Browser }).chrome;

/** Host permission patterns covering a domain and its subdomains. */
export function originsFor(domains: string[]): string[] {
  return domains.flatMap((d) => [`*://${d}/*`, `*://*.${d}/*`]);
}

export type Request =
  | { type: "status" }
  | { type: "configure"; label?: string; relay?: string; registrationSecret?: string | null }
  | { type: "createInvite" }
  | { type: "approve"; mailboxId: number; selectors: string[]; storeId: string | null }
  | { type: "reject"; mailboxId: number }
  | { type: "revoke"; grantId: string }
  | { type: "sync" }
  | { type: "dismiss"; alertId: string };

export type Response<T = unknown> = { ok: true; value: T } | { ok: false; error: string };

export async function send<T>(request: Request): Promise<T> {
  const res = (await browser.runtime.sendMessage(request)) as Response<T> | undefined;
  if (!res) throw new Error("no response from the background script");
  if (!res.ok) throw new Error(res.error);
  return res.value;
}
