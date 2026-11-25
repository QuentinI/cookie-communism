// Builds dist/firefox and dist/chrome (and a .zip of each) from one source tree.

import { execFileSync } from "node:child_process";
import { copyFileSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { build } from "esbuild";

const pkg = JSON.parse(readFileSync("package.json", "utf8"));

const FDL_CSS = "vendor/fdl/packages/css";
if (!existsSync(`${FDL_CSS}/fdl.css`)) {
  throw new Error(`${FDL_CSS} is missing: run \`git submodule update --init\``);
}

const base = {
  manifest_version: 3,
  name: "cookie-communism",
  version: pkg.version,
  description: "Share selected cookies with your automations, end-to-end encrypted through a relay.",
  permissions: ["cookies", "alarms", "storage", "notifications"],
  optional_host_permissions: ["*://*/*"],
  action: { default_popup: "popup.html", default_icon: { 128: "icon-128.png" } },
  icons: { 128: "icon-128.png" },
};

const targets = {
  firefox: {
    ...base,
    background: { scripts: ["background.js"] },
    browser_specific_settings: {
      gecko: {
        id: "cookie-communism@cookie-communism",
        strict_min_version: "140.0",
        // Cookies leave the browser (encrypted, to consumers the user approves).
        data_collection_permissions: { required: ["authenticationInfo"] },
        // Signed builds are distributed as GitHub releases; Firefox checks this for new versions.
        update_url: "https://github.com/QuentinI/cookie-communism/releases/latest/download/updates.json",
      },
      // Firefox for Android supports data_collection_permissions from 142.
      gecko_android: { strict_min_version: "142.0" },
    },
  },
  chrome: {
    ...base,
    background: { service_worker: "background.js" },
    minimum_chrome_version: "137",
  },
};

for (const [target, manifest] of Object.entries(targets)) {
  const out = `dist/${target}`;
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  await build({
    entryPoints: { background: "src/background.ts", popup: "src/popup/popup.ts" },
    outdir: out,
    bundle: true,
    format: "iife",
    target: target === "firefox" ? "firefox140" : "chrome137",
    legalComments: "none",
    logLevel: "warning",
  });
  copyFileSync("src/popup/popup.html", `${out}/popup.html`);
  copyFileSync("src/popup/popup.css", `${out}/popup.css`);
  // fdl-css (the FDL submodule's web package) expects its fonts/ next to fdl.css.
  cpSync(`${FDL_CSS}/tokens.css`, `${out}/tokens.css`);
  cpSync(`${FDL_CSS}/fdl.css`, `${out}/fdl.css`);
  cpSync(`${FDL_CSS}/fonts`, `${out}/fonts`, { recursive: true });
  copyFileSync("assets/icon-128.png", `${out}/icon-128.png`);
  writeFileSync(`${out}/manifest.json`, JSON.stringify(manifest, null, 2) + "\n");
  rmSync(`dist/${target}.zip`, { force: true });
  execFileSync("zip", ["-qr", `../${target}.zip`, "."], { cwd: out });
  console.log(`built ${out} and dist/${target}.zip`);
}
