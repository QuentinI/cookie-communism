// Smoke test of the built Chrome extension in a real Chromium, against the real relay and
// `ccom`: configure, invite, pair through the UI, and follow a cookie change made by a site.
//
// Run with `npm run test:browser` after `npm run build`. Needs Chromium (not branded Chrome,
// which ignores --load-extension); set CHROMIUM to its executable if it is not at the macOS
// default. Not part of `npm test` because it needs a browser.

import assert from "node:assert/strict";
import { type ChildProcess, execFile, execFileSync, spawn } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer } from "node:http";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { promisify } from "node:util";

import { chromium } from "playwright-core";

const root = new URL("../../", import.meta.url).pathname;
const bin = (name: string) => join(root, "target", "debug", name);
const run = promisify(execFile);
const chromiumPath = process.env.CHROMIUM ?? "/Applications/Chromium.app/Contents/MacOS/Chromium";

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, "127.0.0.1", () => {
      const { port } = s.address() as { port: number };
      s.close(() => resolve(port));
    });
  });
}

const until = async <T>(what: string, fn: () => Promise<T | undefined | false>, ms = 15000): Promise<T> => {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn().catch(() => undefined);
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 200));
  }
};

let dir: string;
let relay: ChildProcess;
let relayUrl: string;
let site: ReturnType<typeof createHttpServer>;
let siteUrl: string;

before(async () => {
  execFileSync("cargo", ["build", "-q", "-p", "cookie-communism-relay", "-p", "ccom"], { cwd: root, stdio: "inherit" });
  dir = mkdtempSync(join(tmpdir(), "cc-browser-"));
  const port = await freePort();
  relayUrl = `http://127.0.0.1:${port}`;
  relay = spawn(bin("cookie-communism-relay"), ["--listen", `127.0.0.1:${port}`, "--database", join(dir, "relay.sqlite")], {
    stdio: "ignore",
  });
  await until("relay", async () => (await fetch(`${relayUrl}/health`)).ok);

  // A "site" that logs the user in by setting a cookie.
  site = createHttpServer((req, res) => {
    const url = new URL(req.url!, "http://x");
    // Only /login sets the cookie; the browser also requests /favicon.ico.
    if (url.pathname !== "/login") {
      res.statusCode = 404;
      res.end();
      return;
    }
    const v = url.searchParams.get("v") ?? "1";
    res.setHeader("set-cookie", `sid=session-${v}; Path=/; Max-Age=86400; HttpOnly`);
    res.end(`logged in (${v})`);
  });
  const sitePort = await freePort();
  await new Promise<void>((r) => site.listen(sitePort, "127.0.0.1", r));
  siteUrl = `http://127.0.0.1:${sitePort}`;
});

after(() => {
  relay?.kill();
  site?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

test("Chrome extension pairs through its UI and pushes cookie changes", async () => {
  // The test build grants the site's host permission up front, since a test cannot click the
  // browser's permission prompt; the approval flow still calls permissions.request.
  const ext = join(dir, "ext");
  cpSync(join(root, "extension", "dist", "chrome"), ext, { recursive: true });
  const manifest = JSON.parse(readFileSync(join(ext, "manifest.json"), "utf8"));
  manifest.host_permissions = ["*://127.0.0.1/*", "*://*.127.0.0.1/*"];
  writeFileSync(join(ext, "manifest.json"), JSON.stringify(manifest));

  const context = await chromium.launchPersistentContext(join(dir, "profile"), {
    executablePath: chromiumPath,
    headless: true,
    // Playwright disables extensions by default.
    ignoreDefaultArgs: ["--disable-extensions"],
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  try {
    const worker = context.serviceWorkers()[0] ?? (await context.waitForEvent("serviceworker", { timeout: 15000 }));
    const extId = new URL(worker.url()).host;
    worker.on("console", (m) => console.log(`[background] ${m.type()}: ${m.text()}`));
    const ui = await context.newPage();
    ui.on("console", (m) => console.log(`[ui] ${m.type()}: ${m.text()}`));
    ui.on("pageerror", (e) => console.log(`[ui] error: ${e.message}`));
    await ui.goto(`chrome-extension://${extId}/popup.html?tab=1`);

    await ui.fill("#set-label", "Chromium test");
    await ui.fill("#set-relay", relayUrl);
    await ui.click("#save-settings");
    await until("relay saved", async () => !(await ui.isDisabled("#add-first")));

    await ui.click("#add-first");
    const invite = await until("invite", async () => (await ui.textContent("#invite")) || undefined);
    assert.match(invite, /^cc1:/);

    const page = await context.newPage();
    await page.goto(`${siteUrl}/login?v=1`);

    const state = join(dir, "consumer.json");
    const pairing = spawn(bin("ccom"), ["--state", state, "pair", invite, "--label", "smoke", "--want", "127.0.0.1:sid"], {
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    pairing.stderr!.on("data", (d) => (stderr += d));
    const exited = new Promise<number>((r) => pairing.on("exit", (c) => r(c ?? -1)));
    after(() => pairing.kill());
    const code = await until("pairing code", async () => /Pairing code: (\S+)/.exec(stderr)?.[1]);

    await ui.waitForSelector(".pair-code", { timeout: 30000 }).catch(async (e) => {
      console.log("UI:", await ui.textContent("body"));
      throw e;
    });
    assert.equal(await ui.textContent(".pair-code"), code);
    await ui.screenshot({ path: join(root, "extension", "dist", "smoke-pending.png") });
    await ui.click("#pending button:text('Approve')");
    const timeout = new Promise<number>((_, reject) => setTimeout(() => reject(new Error(`ccom pair did not finish: ${stderr}`)), 20000));
    assert.equal(await Promise.race([exited, timeout]), 0, stderr);

    const get = async () => (await run(bin("ccom"), ["--state", state, "get"])).stdout;
    assert.match(await get(), /^#HttpOnly_127\.0\.0\.1\tFALSE\t\/\tFALSE\t\d+\tsid\tsession-1$/m);

    // The site sets a new cookie; the extension notices and pushes it.
    await page.goto(`${siteUrl}/login?v=2`);
    await until(
      "new cookie at the consumer",
      async () => {
        await run(bin("ccom"), ["--state", state, "sync"]);
        return /\tsid\tsession-2$/m.test(await get());
      },
      20000,
    ).catch(async (e) => {
      const owner = await worker.evaluate(async () => {
        const { owner } = await (globalThis as any).chrome.storage.local.get("owner");
        return { grants: owner.grants, seen: owner.seen };
      });
      console.log("extension grants:", JSON.stringify(owner, null, 1));
      console.log("browser cookies:", JSON.stringify(await context.cookies()));
      console.log("consumer:", await get());
      throw e;
    });

    await ui.waitForSelector("#grants li .grant");
    await ui.screenshot({ path: join(root, "extension", "dist", "smoke-grants.png") });
    assert.match((await ui.textContent("#grants"))!, /smoke.*127\.0\.0\.1:sid.*Last pushed/s);
  } finally {
    await context.close();
  }
});
