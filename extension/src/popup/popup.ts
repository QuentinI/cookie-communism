// Popup (and full-tab) UI, drawn with fdl-css components. Consumer-supplied text (labels,
// selectors, reasons) is untrusted and only ever inserted as text nodes.

import { browser, originsFor, send } from "../browser.ts";
import type { OwnerStatus, PendingRequest } from "../core/owner.ts";
import { parseSelector } from "../core/protocol.ts";

type Status = OwnerStatus & { missingPermissions: string[]; stores: string[] };

const $ = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
// Firefox for Android opens the popup as a full page.
const isAndroid = /Android/.test(navigator.userAgent);
const inTab = new URLSearchParams(location.search).has("tab") || isAndroid;
// Firefox may close the popup when a permission prompt opens, losing the approval; approve in
// a tab there instead.
const isFirefox = typeof (browser.runtime as { getBrowserInfo?: unknown }).getBrowserInfo === "function";
if (inTab) document.body.classList.add("tab");
$("open-tab").hidden = inTab;

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> & { class?: string } = {},
  ...children: (Node | string | null | undefined | false)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  const { class: className, ...rest } = props;
  Object.assign(node, rest);
  if (className) node.className = className;
  for (const c of children) if (c) node.append(c);
  return node;
}

function button(label: string, variant = ""): HTMLButtonElement {
  return el("button", { type: "button", class: `fdl-button ${variant}`.trim() }, label);
}

function ago(unix: number | null): string {
  if (unix === null) return "never";
  return `${human(Date.now() / 1000 - unix)} ago`;
}

function human(secs: number): string {
  const s = Math.abs(secs);
  if (s < 120) return `${Math.round(s)} s`;
  if (s < 7200) return `${Math.round(s / 60)} min`;
  if (s < 172800) return `${Math.round(s / 3600)} h`;
  return `${Math.round(s / 86400)} days`;
}

// --- Status line ----------------------------------------------------------------------------

let error: string | null = null;
let idleStatus = "";

function renderStatus(): void {
  const line = $("status");
  $("status-kind").textContent = error === null ? "" : "Error";
  $("status-text").textContent = error ?? idleStatus;
  line.toggleAttribute("data-error", error !== null);
  if (error === null) line.removeAttribute("data-expanded");
  line.title = error ?? "";
}

function showError(e: unknown): void {
  error = e instanceof Error ? e.message : String(e);
  renderStatus();
}

// A long error is cut to one line; a tap shows all of it.
$("status").addEventListener("click", () => {
  if (error !== null) $("status").toggleAttribute("data-expanded");
});

async function action(target: HTMLButtonElement, fn: () => Promise<unknown>): Promise<void> {
  target.disabled = true;
  error = null;
  renderStatus();
  try {
    await fn();
  } catch (e) {
    showError(e);
  } finally {
    target.disabled = false;
    await refresh();
  }
}

async function copy(target: HTMLButtonElement, text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
  target.textContent = "Copied";
}

async function requestHostPermission(domains: string[]): Promise<void> {
  const granted = await browser.permissions.request({ origins: originsFor(domains) });
  if (!granted) throw new Error(`Cookie access for ${domains.join(", ")} was not granted.`);
}

// --- Pairing requests -----------------------------------------------------------------------

// Panels are kept across refreshes so a selection the user is making is not reset.
const pendingPanels = new Map<number, { panel: HTMLElement; received: HTMLElement; receivedAt: number }>();

function renderPending(status: Status): void {
  const ids = new Set(status.pending.map((p) => p.mailboxId));
  for (const id of pendingPanels.keys()) if (!ids.has(id)) pendingPanels.delete(id);
  for (const p of status.pending) {
    if (!pendingPanels.has(p.mailboxId)) pendingPanels.set(p.mailboxId, pendingPanel(p, status.stores));
    const entry = pendingPanels.get(p.mailboxId)!;
    entry.received.textContent = `Received ${ago(entry.receivedAt)}`;
  }
  $("pending").replaceChildren(...status.pending.map((p) => pendingPanels.get(p.mailboxId)!.panel));
}

function pendingPanel(p: PendingRequest, stores: string[]) {
  const checks = p.wants.map((w) => {
    const input = el("input", { type: "checkbox", checked: true, value: w });
    const broad = parseSelector(w).name === null;
    const item = el(
      "li",
      { class: "fdl-row" },
      el("label", { class: "fdl-check" }, input, el("code", {}, w)),
      broad && el("span", { class: "fdl-badge fdl-badge--warning" }, "Whole domain"),
    );
    return { input, item };
  });
  const anyBroad = p.wants.some((w) => parseSelector(w).name === null);
  const storeSelect = el("select", { class: "fdl-select", id: `store-${p.mailboxId}` }, ...stores.map((s) => el("option", { value: s }, s)));
  const reviewInTab = isFirefox && !inTab;
  const approve = button(reviewInTab ? "Review in tab" : "Approve", "fdl-button--primary");
  const reject = button("Reject");
  approve.addEventListener("click", () => {
    if (reviewInTab) {
      void browser.tabs.create({ url: browser.runtime.getURL("popup.html?tab=1") });
      window.close();
      return;
    }
    void action(approve, async () => {
      const selectors = checks.filter((c) => c.input.checked).map((c) => c.input.value);
      if (selectors.length === 0) throw new Error("Select at least one cookie to share.");
      // Requested first, while the click still counts as a user gesture.
      await requestHostPermission([...new Set(selectors.map((s) => parseSelector(s).domain))]);
      const storeId = stores.length > 1 ? storeSelect.value : null;
      await send({ type: "approve", mailboxId: p.mailboxId, selectors, storeId });
    });
  });
  reject.addEventListener("click", () => void action(reject, () => send({ type: "reject", mailboxId: p.mailboxId })));

  const received = el("span", { class: "fdl-muted" });
  const panel = el(
    "section",
    { class: "fdl-panel" },
    el("div", { class: "fdl-panel__head" }, el("h2", {}, `${p.label} asks for cookies`), received),
    el(
      "div",
      { class: "fdl-panel__body settings" },
      el(
        "div",
        { class: "fdl-field" },
        el("span", { class: "fdl-field__label" }, "Pairing code"),
        el("span", { class: "pair-code" }, p.code),
        el("span", { class: "fdl-field__help" }, "Approve only if the consumer shows the same code."),
      ),
      el(
        "div",
        { class: "fdl-field" },
        el("span", { class: "fdl-field__label" }, "Cookies to share"),
        el("ul", { class: "checks" }, ...checks.map((c) => c.item)),
        el(
          "span",
          { class: "fdl-field__help" },
          anyBroad
            ? "A whole-domain selector shares every cookie on the domain, including ones the site may rotate on use."
            : "",
        ),
      ),
      stores.length > 1 &&
        el(
          "div",
          { class: "fdl-field" },
          el("label", { htmlFor: storeSelect.id }, "Cookie store"),
          storeSelect,
          el("span", { class: "fdl-field__help" }, "The container or profile whose cookies are shared."),
        ),
    ),
    el("div", { class: "fdl-panel__foot" }, reject, approve),
  );
  return { panel, received, receivedAt: p.receivedAt };
}

// --- Consumers ------------------------------------------------------------------------------

function renderGrants(status: Status): void {
  const list = $("grants");
  list.removeAttribute("aria-busy");
  const empty = status.grants.length === 0;
  list.hidden = empty;
  $("no-grants").hidden = !empty;
  $("add").hidden = empty;
  const now = Date.now() / 1000;
  list.replaceChildren(
    ...status.grants.map((g) => {
      const revoke = button("Revoke", "fdl-button--small");
      revoke.addEventListener("click", () => {
        const ok = confirm(
          `Revoke ${g.label}? It stops receiving cookies, but keeps the ones it already has until they expire or you log out.`,
        );
        if (ok) void action(revoke, () => send({ type: "revoke", grantId: g.id }));
      });
      const facts = [`Last pushed ${ago(g.lastPushAt)}.`];
      if (g.earliestExpiry !== null) facts.push(`First cookie expires in ${human(g.earliestExpiry - now)}.`);
      if (g.storeId) facts.push(`Cookie store ${g.storeId}.`);
      return el(
        "li",
        {},
        el(
          "div",
          { class: "grant" },
          el("span", { class: "grant__name" }, g.label),
          el("div", { class: "selectors" }, ...g.selectors.map((s) => el("code", {}, s))),
          el("p", { class: "fdl-muted" }, facts.join(" ")),
          g.matching === 0 &&
            el(
              "div",
              { class: "fdl-row" },
              el("span", { class: "fdl-badge fdl-badge--warning" }, "No cookies"),
              el("span", { class: "fdl-muted" }, "Log in to the site in this browser."),
            ),
        ),
        revoke,
      );
    }),
  );
}

// --- Alerts ---------------------------------------------------------------------------------

function renderAlerts(status: Status): void {
  $("alerts").replaceChildren(
    ...status.alerts.map((a) => {
      const domain = parseSelector(a.selector).domain;
      const open = button(`Open ${domain}`);
      open.addEventListener("click", () => void browser.tabs.create({ url: `https://${domain}/` }));
      const dismiss = button("Dismiss");
      dismiss.addEventListener("click", () => void action(dismiss, () => send({ type: "dismiss", alertId: a.id })));
      const grant = status.grants.find((g) => g.id === a.grantId);
      return el(
        "div",
        { class: "fdl-notice fdl-notice--warning" },
        el("span", { class: "fdl-notice__kind" }, "Warning"),
        el(
          "div",
          { class: "notice-body" },
          el("p", {}, `Log in to ${domain}. ${grant?.label ?? "A consumer"} reports: ${a.reason}`),
          el("div", { class: "actions" }, dismiss, open),
        ),
      );
    }),
  );
}

// --- Page -----------------------------------------------------------------------------------

let current: Status | undefined;

function relayHost(relay: string): string {
  try {
    return new URL(relay).host;
  } catch {
    return relay;
  }
}

async function refresh(): Promise<void> {
  try {
    const status = await send<Status>({ type: "status" });
    const first = current === undefined;
    current = status;
    const connected = Boolean(status.relay);

    idleStatus = connected
      ? `Sharing as ${status.label} through ${relayHost(status.relay)}.`
      : "Not connected to a relay.";
    renderStatus();
    $("setup").hidden = connected;
    $("settings-summary").textContent = status.label;
    $("public-key").textContent = status.publicKey;
    $("permissions").hidden = status.missingPermissions.length === 0;
    $("missing-domains").textContent = status.missingPermissions.join(", ");
    // An invite is single use; hide it once its pairing request has arrived or it expired.
    if (status.openInvites === 0) $("invite-box").hidden = true;

    // One primary action per view: the pairing approval when one waits, otherwise the next step.
    const waiting = status.pending.length > 0;
    for (const id of ["add", "add-first"]) {
      const b = $<HTMLButtonElement>(id);
      b.disabled = !connected;
      b.classList.toggle("fdl-button--primary", connected && !waiting);
    }
    $("save-settings").classList.toggle("fdl-button--primary", !connected);

    if (first) {
      $<HTMLInputElement>("set-label").value = status.label;
      $<HTMLInputElement>("set-relay").value = status.relay;
      if (!connected) $<HTMLDetailsElement>("settings").open = true;
    }
    renderAlerts(status);
    renderPending(status);
    renderGrants(status);
  } catch (e) {
    showError(e);
  }
}

$("open-tab").addEventListener("click", () => {
  void browser.tabs.create({ url: browser.runtime.getURL("popup.html?tab=1") });
  window.close();
});

for (const id of ["add", "add-first"]) {
  $<HTMLButtonElement>(id).addEventListener("click", (ev) =>
    void action(ev.currentTarget as HTMLButtonElement, async () => {
      const invite = await send<string>({ type: "createInvite" });
      $("invite").textContent = invite;
      $("copy-invite").textContent = "Copy";
      $("invite-box").hidden = false;
    }),
  );
}

$<HTMLButtonElement>("copy-invite").addEventListener("click", (ev) =>
  void copy(ev.currentTarget as HTMLButtonElement, $("invite").textContent ?? ""),
);

$<HTMLButtonElement>("copy-key").addEventListener("click", (ev) =>
  void copy(ev.currentTarget as HTMLButtonElement, $("public-key").textContent ?? ""),
);

$<HTMLButtonElement>("sync").addEventListener("click", (ev) =>
  void action(ev.currentTarget as HTMLButtonElement, () => send({ type: "sync" })),
);

$<HTMLButtonElement>("grant-missing").addEventListener("click", (ev) =>
  void action(ev.currentTarget as HTMLButtonElement, () => requestHostPermission(current?.missingPermissions ?? [])),
);

$<HTMLFormElement>("settings-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const secret = $<HTMLInputElement>("set-secret").value;
  void action($<HTMLButtonElement>("save-settings"), () =>
    send({
      type: "configure",
      label: $<HTMLInputElement>("set-label").value,
      relay: $<HTMLInputElement>("set-relay").value,
      ...(secret ? { registrationSecret: secret } : {}),
    }),
  );
});

void refresh();
// Pairing requests arrive while the invite is shown; keep the view current.
setInterval(() => void refresh(), 2000);
