# cookie-communism

Keep your automations' cookies fresh without exporting `cookies.txt` by hand.

A browser extension holds your real logins. After you approve a consumer once, it pushes the
cookies that consumer asked for, end-to-end encrypted, through a relay you host. The relay only
sees ciphertext; a pairing code you compare on both sides keeps it from slipping in its own
consumer. Consumers can pair with several browsers and choose between them by policy.

- Design: [docs/DESIGN.md](docs/DESIGN.md)

| Part | What it is |
|---|---|
| `extension/` | WebExtension for Firefox 140+, Firefox for Android 142+ and Chrome 137+ |
| `crates/relay` | `cookie-communism-relay`: HTTP relay, one binary with SQLite |
| `crates/client` | `cookie-communism`: Rust library for consumers, with a reqwest cookie store |
| `crates/cli` | `ccom`: consumer CLI that keeps a Netscape `cookies.txt` current |
| `crates/proto` | Wire protocol shared by all of the above |

## Setup

### 1. Relay

```sh
cargo build --release -p cookie-communism-relay
./target/release/cookie-communism-relay \
  --listen 127.0.0.1:8787 --database /var/lib/cookie-communism/relay.sqlite \
  --registration-secret "$(openssl rand -hex 16)"
```

Put it behind a TLS proxy (Caddy, nginx). Restrict who can use it with `--registration-secret`
(each browser enters it once) or `--allow-owner <public key>` (shown in the extension's
settings). Without either, anyone can create an account on it.

### 2. Extension

```sh
git submodule update --init   # FDL, the UI design language
cd extension && npm install && npm run build
```

This produces `dist/firefox.zip` and `dist/chrome.zip`. Firefox only installs signed extensions
permanently: sign the zip as unlisted on addons.mozilla.org, or load `dist/firefox` temporarily
from `about:debugging`. In Chrome, load `dist/chrome` unpacked from `chrome://extensions` in
developer mode.

In the extension's settings, enter the relay URL (and registration secret) and a name for this
browser.

### 3. Consumer

In the extension, click **Add consumer** and copy the invite. Then:

```sh
cargo build --release -p ccom
ccom pair 'cc1:…' --label esselunga-mcp --want 'esselunga.it:rmbme-sso-x'
```

`ccom` prints a pairing code. Check that the extension shows the same code, then approve. Repeat
with an invite from another browser to add it as a second source.

Keep a cookie file current:

```sh
ccom watch --out ~/.config/esselunga-mcp/cookies.txt
```

Run it under launchd or systemd. Other commands: `ccom status`, `ccom owners`, `ccom get [--json]`,
`ccom sync`, `ccom fail SELECTOR` (report that cookies stopped working), `ccom policy …`
(`longest`, the default; `freshest`; `sticky`; `pinned`), `ccom forget OWNER`. The state file
defaults to the OS config directory; `--state` or `CCOM_STATE` selects another.

### Embedding

```rust
let client = cookie_communism::Client::open("state.json")?;
let http = reqwest::Client::builder().cookie_provider(client.cookie_store()).build()?;
// On a 401 from the site:
client.report_failure("example.com:session", "401 from /api").await?;
```

See `crates/client/src/lib.rs` and design §5.

## Security notes

- A grant is access to your account for as long as the cookies live. Revoking it stops updates;
  the consumer keeps what it already has until it expires or you log out on the site.
- Prefer named selectors (`domain:cookie`) over whole domains.
- The consumer's state file holds its private keys and cookies; it is written with mode 0600.

## Development

```sh
just test     # Rust tests, cross-language vectors, TS owner ↔ Rust relay and ccom
just lint     # clippy, rustfmt, tsc
just smoke    # drive the built Chrome extension in Chromium, and web-ext lint the Firefox build
just vectors  # regenerate testdata/vectors/proto.json
```

The extension's UI follows [FDL](https://forgejo.faptek.party/quentin/fdl), a git submodule at
`extension/vendor/fdl`: clone with `--recursive`, or run `git submodule update --init`.

`just smoke` needs Chromium (branded Chrome ignores `--load-extension`); set `CHROMIUM` if it is
not at `/Applications/Chromium.app`.
