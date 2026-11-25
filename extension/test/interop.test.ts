// The extension's owner logic (TypeScript) against the real relay binary and the real `ccom`
// consumer CLI (Rust): pairing, snapshots, refresh requests, resolution and revocation.

import assert from "node:assert/strict";
import { type ChildProcess, execFile, execFileSync, spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { promisify } from "node:util";

import { type BrowserCookie, type Notice, Owner, type OwnerState, type Platform } from "../src/core/owner.ts";

const root = new URL("../../", import.meta.url).pathname;
const bin = (name: string) => join(root, "target", "debug", name);
const run = promisify(execFile);

class FakeBrowser implements Platform {
  state: OwnerState | undefined;
  jar: BrowserCookie[] = [];
  notices = new Map<string, Notice>();
  async load() {
    return this.state && structuredClone(this.state);
  }
  async save(s: OwnerState) {
    this.state = structuredClone(s);
  }
  async cookies(domain: string) {
    return this.jar.filter((c) => {
      const d = c.domain.replace(/^\./, "");
      return d === domain || d.endsWith(`.${domain}`);
    });
  }
  notify(n: Notice) {
    this.notices.set(n.id, n);
  }
  clearNotice(id: string) {
    this.notices.delete(id);
  }
  setSid(value: string, expiresIn = 14 * 86400) {
    this.jar = [
      {
        domain: ".example.com",
        hostOnly: false,
        name: "sid",
        value,
        path: "/",
        secure: true,
        httpOnly: true,
        sameSite: "lax",
        expirationDate: Date.now() / 1000 + expiresIn,
        storeId: "0",
      },
      {
        domain: "www.example.com",
        hostOnly: true,
        name: "unrelated",
        value: "x",
        path: "/",
        secure: false,
        httpOnly: false,
        sameSite: "unspecified",
        storeId: "0",
      },
    ];
  }
}

let dir: string;
let relay: ChildProcess;
let relayUrl: string;

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer().listen(0, "127.0.0.1", () => {
      const { port } = s.address() as { port: number };
      s.close(() => resolve(port));
    });
  });
}

before(async () => {
  execFileSync("cargo", ["build", "-q", "-p", "cookie-communism-relay", "-p", "ccom"], { cwd: root, stdio: "inherit" });
  dir = mkdtempSync(join(tmpdir(), "cc-interop-"));
  const port = await freePort();
  relayUrl = `http://127.0.0.1:${port}`;
  relay = spawn(bin("cookie-communism-relay"), ["--listen", `127.0.0.1:${port}`, "--database", join(dir, "relay.sqlite")], {
    stdio: ["ignore", "ignore", "inherit"],
  });
  for (let i = 0; i < 100; i++) {
    try {
      if ((await fetch(`${relayUrl}/health`)).ok) return;
    } catch {
      // Not listening yet.
    }
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("relay did not start");
});

after(() => {
  relay?.kill();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

const ccom = (...args: string[]) => run(bin("ccom"), ["--state", join(dir, "consumer.json"), ...args]);

test("TypeScript owner and Rust consumer, end to end", async () => {
  const browser = new FakeBrowser();
  browser.setSid("first");
  const owner = await Owner.open(browser, { label: "Glide" });
  await owner.configure({ relay: relayUrl });

  // Pairing, with both sides showing the same code.
  const invite = await owner.createInvite();
  const pairing = spawn(
    bin("ccom"),
    ["--state", join(dir, "consumer.json"), "pair", invite, "--label", "esselunga-mcp", "--want", "example.com:sid"],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  let stderr = "";
  pairing.stderr!.on("data", (d) => (stderr += d));
  const exited = new Promise<number>((resolve) => pairing.on("exit", (code) => resolve(code ?? -1)));
  while (!/Pairing code: (\S+)/.test(stderr)) await new Promise((r) => setTimeout(r, 50));
  const consumerCode = /Pairing code: (\S+)/.exec(stderr)![1];

  await owner.pollMailbox(10);
  const status = await owner.status();
  assert.equal(status.pending.length, 1);
  const request = status.pending[0];
  assert.equal(request.code, consumerCode);
  assert.equal(request.label, "esselunga-mcp");
  assert.deepEqual(request.wants, ["example.com:sid"]);
  assert.ok(browser.notices.has(`pairing:${request.mailboxId}`));
  await assert.rejects(owner.approve(request.mailboxId, ["example.com"]), /not requested/);
  await owner.approve(request.mailboxId, ["example.com:sid"]);
  assert.equal(await exited, 0, stderr);

  let jar = (await ccom("get")).stdout;
  assert.match(jar, /^#HttpOnly_\.example\.com\tTRUE\t\/\tTRUE\t\d+\tsid\tfirst$/m);
  assert.doesNotMatch(jar, /unrelated/);
  assert.match((await ccom("status")).stdout, /example\.com \[example\.com:sid\] policy longest: from Glide/);

  // A new login in the browser reaches the consumer.
  browser.setSid("second");
  await owner.sync(["www.example.com"]);
  await ccom("sync");
  assert.match((await ccom("get")).stdout, /\tsid\tsecond$/m);

  // Nothing changes: no new envelope is uploaded.
  const version = browser.state!.grants[0].version;
  await owner.sync();
  assert.equal(browser.state!.grants[0].version, version);

  // The consumer reports a failure; the browser has nothing newer, so it asks the user to log in.
  const failed = await ccom("fail", "example.com:sid", "--reason", "SSO hop returned 401");
  assert.match(failed.stdout, /UNAVAILABLE/);
  await owner.pollMailbox(0);
  const alerts = (await owner.status()).alerts;
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].reason, "SSO hop returned 401");
  const notice = browser.notices.get(alerts[0].id)!;
  assert.equal(notice.title, "Log in to example.com");
  assert.equal(notice.url, "https://example.com/");

  // The user logs in: the new cookie clears the alert, and the consumer uses it again.
  browser.setSid("third");
  await owner.sync(["example.com"]);
  assert.equal((await owner.status()).alerts.length, 0);
  assert.equal(browser.notices.size, 0);
  await ccom("sync");
  assert.match((await ccom("get")).stdout, /\tsid\tthird$/m);
  await owner.pollMailbox(0); // consumes the `resolved` message

  // Expiry reminders.
  browser.setSid("third", 3600);
  await owner.remind();
  assert.ok([...browser.notices.values()].some((n) => /expires in less than a day/.test(n.message)));

  // Revocation.
  await owner.revoke(browser.state!.grants[0].id);
  assert.match((await ccom("sync")).stderr, /Glide revoked access/);
  assert.equal((await ccom("get")).stdout.split("\n").filter((l) => l && !l.startsWith("# ")).length, 0);
});
