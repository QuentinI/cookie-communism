// Background script: connects the owner logic to the browser's cookies, storage, alarms and
// notifications. Listeners are registered synchronously at the top level, as Manifest V3
// requires for a service worker (Chrome) or event page (Firefox) to be woken by them.

import type Browser from "webextension-polyfill";
import { browser, originsFor, type Request, type Response } from "./browser.ts";
import { type BrowserCookie, type Notice, Owner, type OwnerState, type Platform } from "./core/owner.ts";

const platform: Platform = {
  async load() {
    const { owner } = await browser.storage.local.get("owner");
    return owner as OwnerState | undefined;
  },
  async save(state) {
    await browser.storage.local.set({ owner: state });
  },
  async cookies(domain, storeId) {
    const details: Browser.Cookies.GetAllDetailsType = { domain };
    if (storeId) details.storeId = storeId;
    try {
      // An empty partition key asks for partitioned (CHIPS) cookies too.
      return (await browser.cookies.getAll({ ...details, partitionKey: {} })) as BrowserCookie[];
    } catch {
      return (await browser.cookies.getAll(details)) as BrowserCookie[];
    }
  },
  notify(notice: Notice) {
    // Firefox for Android has no notifications API; alerts still show in the popup there.
    if (!browser.notifications) return;
    void browser.notifications.create(notice.id, {
      type: "basic",
      title: notice.title,
      message: notice.message,
      iconUrl: browser.runtime.getURL("icon-128.png"),
    });
  },
  clearNotice(id) {
    if (browser.notifications) void browser.notifications.clear(id);
  },
};

function defaultLabel(): string {
  const ua = navigator.userAgent;
  const name = /Firefox\//.test(ua) ? "Firefox" : /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : "Browser";
  const os = /Mac OS X/.test(ua) ? "macOS" : /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${name} on ${os}` : name;
}

let ownerPromise: Promise<Owner> | undefined;
function owner(): Promise<Owner> {
  ownerPromise ??= Owner.open(platform, { label: defaultLabel() });
  return ownerPromise;
}

// --- Mailbox polling ------------------------------------------------------------------------

const MAILBOX_ALARM = "mailbox";
const SYNC_ALARM = "sync";
let fastPolling = false;

async function pollMailbox(wait: number): Promise<void> {
  const o = await owner();
  if (!(await o.status()).relay) return;
  try {
    await o.pollMailbox(wait);
  } catch (e) {
    console.warn("mailbox poll failed", e);
  }
}

/** While an invite is open, long-poll the mailbox continuously so pairing feels immediate. */
async function pollWhileInvitesOpen(): Promise<void> {
  if (fastPolling) return;
  fastPolling = true;
  try {
    const o = await owner();
    while (o.hasOpenInvites()) await pollMailbox(20);
  } finally {
    fastPolling = false;
  }
}

function setupAlarms(): void {
  void browser.alarms.create(MAILBOX_ALARM, { periodInMinutes: 5 });
  void browser.alarms.create(SYNC_ALARM, { periodInMinutes: 180, delayInMinutes: 1 });
}

browser.runtime.onInstalled.addListener(setupAlarms);
browser.runtime.onStartup.addListener(setupAlarms);

browser.alarms.onAlarm.addListener(async (alarm) => {
  const o = await owner();
  if (alarm.name === MAILBOX_ALARM) {
    await pollMailbox(0);
    if (o.hasOpenInvites()) void pollWhileInvitesOpen();
  } else if (alarm.name === SYNC_ALARM) {
    await o.sync();
    await o.remind();
  }
});

// --- Cookie changes -------------------------------------------------------------------------

const changedDomains = new Set<string>();
let debounce: ReturnType<typeof setTimeout> | undefined;

browser.cookies.onChanged.addListener(async ({ cookie }) => {
  const o = await owner();
  if (!o.covers(cookie.domain)) return;
  changedDomains.add(cookie.domain.replace(/^\./, ""));
  clearTimeout(debounce);
  // A login sets many cookies at once; send one snapshot after they settle.
  debounce = setTimeout(() => {
    const domains = [...changedDomains];
    changedDomains.clear();
    void o.sync(domains);
  }, 2000);
});

// --- Notifications --------------------------------------------------------------------------

browser.notifications?.onClicked.addListener(async (id) => {
  void browser.notifications.clear(id);
  if (id.startsWith("pairing:")) {
    await browser.tabs.create({ url: browser.runtime.getURL("popup.html?tab=1") });
    return;
  }
  // refresh:<grant>:<domain> and expiry:<grant> <domain>[:<name>]
  const domain = id.startsWith("refresh:") ? id.split(":")[2] : id.split(" ")[1]?.split(":")[0];
  if (domain) await browser.tabs.create({ url: `https://${domain}/` });
});

// --- Popup requests -------------------------------------------------------------------------

async function handle(request: Request): Promise<unknown> {
  const o = await owner();
  switch (request.type) {
    case "status": {
      const status = await o.status();
      const missing: string[] = [];
      for (const d of o.grantedDomains()) {
        if (!(await browser.permissions.contains({ origins: originsFor([d]) }))) missing.push(d);
      }
      const stores = (await browser.cookies.getAllCookieStores()).map((s) => s.id);
      return { ...status, missingPermissions: missing, stores };
    }
    case "configure":
      return o.configure(request);
    case "createInvite": {
      const invite = await o.createInvite();
      void pollWhileInvitesOpen();
      return invite;
    }
    case "approve":
      return (await o.approve(request.mailboxId, request.selectors, request.storeId)).id;
    case "reject":
      return o.reject(request.mailboxId);
    case "revoke": {
      await o.revoke(request.grantId);
      // Drop host permissions that no remaining grant needs.
      const needed = new Set(originsFor(o.grantedDomains()));
      const { origins = [] } = await browser.permissions.getAll();
      const unused = origins.filter((origin) => !needed.has(origin));
      if (unused.length) await browser.permissions.remove({ origins: unused });
      return;
    }
    case "sync":
      await pollMailbox(0);
      await o.sync(undefined, true);
      return o.remind();
    case "dismiss":
      return o.dismissAlert(request.alertId);
  }
}

browser.runtime.onMessage.addListener(((message: unknown, _sender: unknown, sendResponse: (r: Response) => void) => {
  handle(message as Request).then(
    (value) => sendResponse({ ok: true, value }),
    (e: unknown) => sendResponse({ ok: false, error: e instanceof Error ? e.message : String(e) }),
  );
  // Keeps the channel open for the asynchronous response, in both browsers.
  return true;
}) as unknown as Browser.Runtime.OnMessageListenerCallback);
