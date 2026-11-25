# cookie-communism: design

Automations that act on a website as the user need that user's cookies. Today the user exports
`cookies.txt` by hand and repeats it whenever the cookies expire. cookie-communism moves that job
to the browser: a WebExtension holds the user's real logins and, after a one-time approval per
consumer, pushes selected cookies, end-to-end encrypted, through a relay server to the automation.

The relay is not trusted. It stores ciphertext and routes messages. A compromised relay can deny
service and learn metadata (which keys talk to each other, when, blob sizes). It cannot read
cookies, get its own consumer approved, or roll a consumer back to older cookies.

## 1. Goals

- **No manual export.** Cookies reach the consumer when the browser changes them.
- **Any site.** Nothing in the extension, relay or client knows about a particular site.
- **Embeddable client.** An automation links the client library and gets a live cookie jar.
  Automations that cannot link it use the CLI, which keeps a Netscape `cookies.txt` up to date.
- **Least privilege.** A consumer gets the cookies it asked for and the user approved, nothing
  else, and the user sees what each consumer has.
- **Firefox and Chrome** from one extension codebase.

Non-goals: logging in on the user's behalf (passwords, captchas, 2FA), syncing cookies back from
consumers to the browser, sharing between different people.

## 2. What "fresh" can mean

The extension forwards what the browser has; it does not create credentials. How much that
automates depends on the site:

| Site behaviour | Result |
|---|---|
| Sliding session: normal browsing extends or reissues the cookie | Fully automatic. The user's ordinary use keeps the consumer working. |
| Session that slides only when a page is visited | Automatic with a per-grant **keepalive** URL (§6). |
| Fixed-lifetime cookie, reissued only by a password login | The user still logs in when it expires. The extension reminds them ahead of time, and the new cookie reaches the consumer seconds after the login. |
| Cookies bound to IP, user agent or TLS fingerprint | Copied cookies fail on the consumer. Out of scope. |
| Rotating refresh token, invalidated on use | Browser and consumer log each other out. The approval screen warns about this. |

### Example: Esselunga (fixed lifetime)

[esselunga-mcp](../../esselunga-mcp) needs one cookie, `rmbme-sso-x` on `.esselunga.it`. It has a
fixed 14-day lifetime and the SSO hop does not extend it (esselunga-mcp `docs/API.md` §3.3.1).
Checked on 2026-11-12 in a logged-in Glide (Firefox) profile:

- The persistent Esselunga cookies are `rmbme-sso-x` (expires 2026-11-26 09:36, so issued by this
  morning's login), `trusted_token`, `gescliweb.sso.is-logged-user` and consent cookies.
- The browser also holds an `account.esselunga.it` session (`ESSELUNGA_GCWI_JSESSIONID`, session
  cookie). Replaying the browser's session cookies **without** `rmbme-sso-x` through
  `/commerce/login/spesaonline` ends on `applicationCheck`, which issues a new anonymous
  `ESSELUNGA_GCWI_JSESSIONID` and serves the login page (`Login | Esselunga`,
  `initDataLayer4NotLogged`). No `rmbme-sso-x` is set.

So nothing in the browser outlives `rmbme-sso-x`, and Esselunga falls in the fixed-lifetime row:
one login every 14 days, with no export and no file copying.

## 3. Actors and keys

| Actor | Holds | Keys |
|---|---|---|
| **Owner**: the extension in a browser profile | The real logins | `owner_sign` (Ed25519), `owner_box` (X25519) |
| **Consumer**: an automation, through the client library or CLI | A local jar | `consumer_sign` (Ed25519), `consumer_box` (X25519) |
| **Relay**: an HTTP server | Ciphertext and mailboxes | none |

An owner's identity on the relay is its `owner_sign` public key. There are no passwords; every
call is signed. One extension install (one browser profile) is one owner. A consumer can pair
with several owners and chooses between them by policy (§4.7).

## 4. Flows

### 4.1 Pairing

1. In the extension, the user clicks "Add consumer". The extension registers a single-use
   **invite** on the relay and shows an invite string: `cc1:` followed by the base64 of
   `{"relay", "owner_sign", "owner_box", "token"}` as JSON.
   This is what the user gives the automation. It allows posting **one** pairing request and
   nothing else, and expires after an hour.
2. The consumer generates its keypairs and posts a request, encrypted to `owner_box`:
   `{label, wants, consumer_sign pub, consumer_box pub}`, and signed with `consumer_sign`. `wants`
   is a list of cookie selectors (§4.2). The consumer shows a **pairing code**, a short hash of both parties' public keys and
   the invite token, e.g. `KTR4-9WQX`.
3. The extension shows the request: label, selectors and the same pairing code. The user checks
   the codes match and approves, optionally removing selectors. (It cannot show which cookies a
   selector matches yet: reading them needs the host permission that approval grants.)
4. The extension asks for the host permissions the grant needs (§6), records the **grant**, and
   sends the first snapshot.

The pairing code is what lets the relay be untrusted. A relay that saw the invite token could
post its own request with its own keys. Encrypting the request to `owner_box` hides its contents
but does not prevent that, because `owner_box` is public. The user comparing codes does.

### 4.2 Selectors

A selector is `domain[:name]`:

- `example.com:session_id` — that cookie name, on `example.com` and its subdomains;
- `example.com` — every cookie on `example.com` and its subdomains.

Name selectors are preferred: they limit what leaks and make the rotating-token warning
unnecessary. Consumers that do not know which cookies matter can ask for the domain, and the
approval screen marks those grants as broad.

### 4.3 Sync (owner → consumer)

The extension keeps, per grant, a hash of the last snapshot sent. It rebuilds the snapshot on:

- `cookies.onChanged` for a cookie matching the grant, debounced ~2 s (a login sets many cookies);
- an `alarms` tick every few hours, as a backstop for missed events;
- a consumer `refresh` message (§4.4).

If the snapshot changed, it uploads an **envelope**:

```
envelope  = { grant_id, version, ciphertext, signature }
  version    strictly increasing per grant
  ciphertext age, encrypted to consumer_box
  signature  Ed25519 by owner_sign over (grant_id, version, ciphertext)
plaintext = { owner_label, taken_at,
              cookies: [{domain, host_only, name, value, path, secure,
                         http_only, same_site, expires, partition_key, changed_at}] }
```

`owner_label` is the name the user gave the browser in the extension ("Glide, laptop").
`changed_at` is when the extension first saw this value of the cookie. The `cookies` API exposes
no creation time, so the extension records it from `cookies.onChanged` and keeps it across
snapshots; cookies that existed before the grant get the time of the first snapshot.

The relay keeps only the latest envelope per grant. The consumer long-polls for it, verifies the
signature against `owner_sign` from the invite, rejects any `version` not greater than the last
one it accepted, and decrypts.

Snapshots carry the browser's full cookie state for the grant, so the consumer replaces its copy
of those cookies rather than merging.

### 4.4 Consumer → owner messages

Signed and encrypted to `owner_box`, delivered through the owner's mailbox:

- **`refresh {selector, reason}`**: "the cookies I have stopped working". The extension
  re-snapshots. If nothing changed, it notifies the user to log in to the site, naming the
  consumer and reason. With several owners, which owners receive it depends on the policy
  (§4.7).
- **`resolved {selector}`**: the selector works again (another owner supplied cookies). The
  extension clears its login notification for it.

### 4.5 Expiry reminders

The extension knows every granted cookie's expiry. When a cookie that a grant names explicitly
will expire within a configurable window (default 3 days), it notifies the user once a day with
a button that opens the site. Domain-wide grants are not tracked this way, since they usually
include short-lived cookies; they rely on `refresh` messages instead.

### 4.6 Revocation

Revoking deletes the grant and its envelope on the relay; the relay then refuses the consumer's
key. The consumer keeps the cookies it already received until they expire, and only logging out
on the site (if the site ends sessions server-side) invalidates them. The revoke screen says so.

### 4.7 Several owners

A consumer pairs once per browser profile; each pairing adds an owner to the same client state.
The owners do not know about each other. Choosing between them is the client's job, configured
by a **policy** per selector (with a default for all selectors).

**The unit of choice is the selector.** All cookies for a selector come from one owner at a
time; the client never mixes a session cookie from one browser with a CSRF cookie from another.
Selectors on the same domain are grouped and always share an owner.

A source (an owner's snapshot for a selector) is **usable** when it contains at least one
matching cookie, none of the cookies the selector names has expired, and the application has not
reported it broken (`report_failure`) since its last change. A new snapshot that changes the
cookies clears the broken mark.

| Policy | Chooses | Switches when |
|---|---|---|
| `longest` (default) | The usable source whose **earliest key-cookie expiry** is latest; ties go to `freshest` | Any snapshot makes another source outlive the current one |
| `freshest` | The usable source with the latest `changed_at` among its cookies; ties go to the latest `expires` | Any snapshot makes another source fresher |
| `sticky { prefer: [owners] }` | The current source while usable; otherwise the first usable owner in `prefer`, then `longest` among the rest | The current source stops being usable |
| `pinned { owner }` | That owner only | Never. If it is not usable, the selector has no cookies and the client says why |

`longest` is the default because, for most sites, "logged in most recently" and "expires last"
are the same thing, and expiry is measured better:

- `expires` comes from the site's own server, so values from different browsers are on the same
  clock. `changed_at` comes from each browser's clock, and only from when the extension noticed
  the change.
- `expires` reflects what the site intends: a cookie set by an older, longer "remember me" login
  correctly beats a newer short session.

**Key cookies.** For a name selector, the key cookies are the ones it names, and a source's
expiry is the earliest of theirs (one short-lived cookie limits the whole set). For a domain
selector, the policy can name them (`longest { by: [names] }`); without `by`, comparing every
cookie on the domain would be dominated by short-lived tracking cookies, so `longest` falls back
to `freshest`. Session cookies (no `expires`) end when the browser closes, at an unknown time;
they count as expiring before any dated cookie, so `longest` prefers persistent logins, and ties
among them go to `freshest`.

`longest` does not see server-side invalidation: a session the site ended early keeps its long
cookie expiry. `report_failure` covers that by making the source unusable until it changes.

`sticky` with an empty `prefer` is "keep whatever works". `freshest` compares `changed_at` values
from different machines, so clock skew between browsers of more than a few seconds can pick the
wrong one; since switches are only a problem when the old source still works, this is acceptable.

On a switch, the client **drops the local layer** for that selector's domains (cookies the site
set during the consumer's own requests, §5.2), because they belong to the previous source's
session. The switch is reported through `watch()` and logged with both owner labels.

When the application reports a failure and another owner takes over, only the broken owner gets
a `refresh` message (§4.4): the application works again, and only that browser needs a look. When
no owner is usable afterwards, `refresh` goes to:

- `longest` and `freshest`: every owner with a grant covering the selector. Whichever browser
  the user logs in with becomes the chosen source.
- `sticky`: the owners in `prefer` that are not usable, in order, or every owner if `prefer` is
  empty.
- `pinned`: the pinned owner only.

An extension clears its own login reminder when it pushes changed cookies for the grant. The
others cannot see that, so when the group becomes usable again the client sends `resolved` to
every owner it asked.

Policies assume every owner is logged in to **the same account** on the site. The client cannot
check that in general. `ccom pair` warns when a new browser is asked for a domain that another
paired browser already supplies.

## 5. Client library

The client is a Rust crate, `cookie-communism`, with the CLI as a thin wrapper. It is the only
client; applications in other languages use the CLI's `cookies.txt` or `ccom get --json`.

### 5.1 State

One state file (mode 0600) per consumer, at a path the embedding application chooses. It holds
the consumer keys, and per owner: label, public keys, relay URL, grant ID, last accepted version
and the last snapshot. It also holds the policies, the current source per selector group, and the
broken marks. Caching snapshots there lets an application start while the relay is down.

The consumer uses the same keypair with every owner. The relay can therefore link a consumer's
grants across owners, which it could also do from polling patterns.

### 5.2 API sketch

```rust
// Pairing. The application shows `code` to the user however it talks to them
// (stderr, an MCP tool result, a UI) and waits. Pairing again with another
// browser's invite adds an owner to the same state.
let pending = Client::pair(state_path, &invite, "esselunga-mcp", &["esselunga.it:rmbme-sso-x"]).await?;
println!("pairing code: {}", pending.code());
let client: Client = pending.approved().await?;

// Later runs.
let client = Client::open(state_path)?;
client.set_policy(Policy::Sticky { prefer: vec![] })?;                      // default for all selectors
client.set_policy_for("esselunga.it:rmbme-sso-x", Policy::Longest { by: vec![] })?;  // per selector

client.owners() -> Vec<OwnerInfo>                // label, relay, approved selectors, last snapshot
client.status() -> Vec<GroupStatus>              // per group: policy, current owner or why none, expiry
client.jar() -> Jar                              // current choice per group, from the local state
client.sync().await -> Result<Vec<Event>>        // one fetch from every owner
client.poll(wait).await -> Result<Vec<Event>>    // long-poll up to `wait`
client.watch() -> impl Stream<Item = Result<Event>>  // Updated, Switched, Unavailable, Revoked

// The application's cookies stopped working: marks the current source broken,
// re-chooses under the policy, and sends `refresh` as §4.7 describes.
client.report_failure("esselunga.it:rmbme-sso-x", "SSO login returned 401").await?;

// Integration with reqwest: a CookieStore that serves the synced cookies and
// keeps cookies the site sets during this process's own requests in a local layer.
let store = client.cookie_store();         // Arc<impl reqwest::cookie::CookieStore>
let http = reqwest::Client::builder().cookie_provider(store).build()?;
```

`cookie_store()` merges two layers: the synced snapshot, and cookies set by responses to the
consumer's own requests (session cookies minted from a long-lived one, for example). When a new
snapshot arrives, cookies from the snapshot replace same-named local ones; when the source
switches, the local layer for those domains is dropped (§4.7). Nothing in the local layer is sent
back to an owner.

### 5.3 CLI

The binary is `ccom` (`cc` is the C compiler on most systems).

```sh
ccom pair <invite> --label NAME --want 'example.com:session' [--want …]   # prints code, waits; repeat per browser
ccom owners                           # paired browsers and what they cover
ccom status                           # per group: policy, current browser or why none, expiry
ccom policy [--selector S] longest [--by NAME…] | freshest | sticky [--prefer OWNER…] | pinned OWNER | clear
ccom sync  [--out cookies.txt]        # one fetch; writes a Netscape jar atomically (temp + rename, 0600)
ccom watch [--out cookies.txt]        # long-poll forever; for launchd/systemd
ccom get [--json]                     # print the current jar
ccom fail SELECTOR [--reason TEXT]    # report_failure from a script
ccom forget OWNER                     # drop a browser locally
```

`--state` (or `CCOM_STATE`; default: the OS config dir) selects the state file, so one machine
can hold several consumers.

### 5.4 Example: esselunga-mcp

- **Without code changes:** `ccom watch --out "$ESSELUNGA_COOKIES"` under launchd. esselunga-mcp
  re-reads the file on every login attempt.
- **Embedded:** esselunga-mcp replaces its cookie-file reading with `Client::cookies()` and calls
  `report_failure` when the SSO hop fails. Its expiry notice can then say "log in to Esselunga in
  your browser" instead of "re-export cookies.txt".
- **Policy:** the default, `longest`. `rmbme-sso-x` has a fixed 14-day lifetime from login, so the
  one that expires last is the most recent login, whichever browser it happened in.

## 6. Extension

- **One codebase, Manifest V3**, for Firefox 140+ and Firefox for Android 142+ (background
  event page) and Chrome 137+ (service worker). Firefox's `browser` and Chrome's promise-returning `chrome` are used directly,
  without a polyfill. All state is in `storage.local`; `cookies.onChanged` and `alarms` wake the
  background script.
- **Permissions:** `cookies`, `alarms`, `storage`, `notifications`, and **optional host
  permissions** requested per grant at approval time (`*://example.com/*`, `*://*.example.com/*`),
  not for all sites at install time. Revoking the last grant for a domain drops its permission.
  The relay needs no host permission: it allows CORS from any origin, which is safe because it
  authenticates by signature, never by cookies.
- **Protocol core** (`extension/src/core/`) has no browser dependencies, so Node tests run it
  against the real relay and `ccom`.
- **Cookie access:** `cookies.getAll({domain})` returns `HttpOnly` cookies for permitted hosts.
  Each grant records a `storeId`: Firefox containers and private windows, or Chrome's
  incognito store. Partitioned (CHIPS) cookies are included with their `partitionKey`.
- **Mailbox:** the extension cannot receive pushes. While an invite is open it long-polls the
  relay continuously (20 s per request); otherwise it polls every 5 minutes on an alarm.
- **UI:** a popup (also openable as a tab) listing grants (label, selectors, last push, earliest
  named-cookie expiry), pending requests with the approval screen (§4.1), login alerts and
  settings; notifications for expiry (§4.5), `refresh` messages (§4.4) and new pairing requests.
  Firefox can close a popup when a permission prompt opens, so there approval happens in a tab.
  Firefox for Android has no notifications API: alerts and pairing requests show only in the
  popup, which Android opens as a full page.
- **Snapshot versions** are `max(previous + 1, now in ms)`, so they keep increasing even if
  extension storage is restored from an older copy.
- **Not built yet:** the per-grant keepalive URL (§2), for sites whose session only slides on a
  page view.
- **Key storage:** private keys in `storage.local`. That is not encrypted at rest, but anything
  able to read it can also read the browser's cookie store, which is what is being protected.
- **Distribution:** self-signed unlisted on AMO for Firefox; developer-mode load or self-hosted
  CRX for Chrome. A cookie-exporting extension would face heavy store review, so public listing
  is not a goal.

## 7. Relay

A single Rust binary with SQLite, run on the user's server behind TLS.

| Call | Caller | Does |
|---|---|---|
| `POST /invites` | owner | Register an invite token (TTL 1 h, single use) |
| `DELETE /invites/{token}` | owner | Reject the pairing request made with it |
| `POST /invites/{token}/request` | invite holder | Post one signed, encrypted pairing request; burns the token |
| `GET /pairing/{token}?wait=` | that consumer | Long-poll for approval: the grant ID once created, or rejected |
| `GET /mailbox?wait=` | owner | Pending requests and consumer messages, long-polled |
| `DELETE /mailbox/{id}` | owner | Acknowledge an item |
| `PUT /grants/{id}` | owner | Create a grant for the consumer that used an invite |
| `PUT /grants/{id}/envelope` | owner | Upload an envelope (signature checked, version must increase) |
| `DELETE /grants/{id}` | owner | Revoke |
| `POST /envelopes?wait=` | consumer | For all its grants at once (body `{"after": {grant_id: version}}`): every newer envelope, plus grants that are gone; long-polled |
| `POST /grants/{id}/messages` | consumer | Signed, encrypted message to the owner |
| `GET /health` | anyone | Liveness |

- **Authentication:** each call carries `cc-key`, `cc-time`, `cc-nonce` and `cc-sig`, an Ed25519
  signature over method, path and query, body hash, time and nonce. Times outside ±5 min are
  rejected (the response's `cc-server-time` lets clients correct their clock), and recently seen
  signatures are kept to reject replays. The nonce keeps two identical requests in the same
  second from looking like a replay. The relay checks the key is the grant's owner or consumer.
- **Registration:** an owner exists once it creates its first invite. To stop strangers using the
  relay, the operator can set an allow-list of owner keys, or a shared registration secret.
- **Limits:** envelope ≤ 64 KiB, mailbox ≤ 100 messages per owner, per-key rate limits.
- **What it sees:** public keys, grant IDs, timing and sizes. Labels, selectors and cookies are
  only inside ciphertext.

## 8. Crypto

- **Encryption: [age](https://age-encryption.org) X25519 recipients**, via
  [typage](https://github.com/FiloSottile/typage) in the extension and the `age` crate in Rust. A
  consumer key is an ordinary age identity, so payloads can be inspected with `rage -d` when
  debugging.
- **Signatures: Ed25519**, via WebCrypto and `ed25519-dalek`. age
  does not authenticate the sender, so envelopes and messages are signed.
- **Pairing code:** the first 40 bits of
  `SHA-256("cc-pair-v1" ‖ owner_sign ‖ owner_box ‖ consumer_sign ‖ consumer_box ‖ invite_token)`,
  in Crockford base32 as `XXXX-XXXX`. A relay forging a request has one guess per invite, and the
  invite is single-use.

## 9. Repository layout

```
Cargo workspace
  crates/proto        wire types, signing/verification, age wrapping, pairing code
  crates/client       the embeddable library (`cookie-communism`), policies, reqwest CookieStore;
                      tests/e2e.rs runs it against an in-process relay
  crates/cli          `ccom`
  crates/relay        axum + SQLite
  testdata/vectors/   JSON fixtures generated from proto, checked by the extension's tests
extension/            TypeScript, MV3, typage + WebCrypto, esbuild; builds Firefox and Chrome zips
  src/core/           protocol and owner logic, no browser APIs
  test/               vectors, TS owner ↔ Rust relay and `ccom`, and a Chromium smoke test
```

## 10. Risks

- **Blast radius.** A grant is account access for as long as the cookies live. Mitigations: name
  selectors by default, the pairing code, visible "last pushed" per grant, and revocation.
- **Rotating tokens and session binding** (§2). Not detectable in general. They show up as
  repeated `refresh` messages that a new login does not fix; the extension does not yet call
  that out.
- **Owners on different accounts.** With several owners, a policy can switch the consumer to a
  browser logged in as someone else. The client cannot detect that in general (§4.7); `pinned`
  is the answer when it matters.
- **Clock skew** between consumer and relay breaks request signing. The relay returns its time on
  a skew error, and the client adjusts.

## 11. Decisions

- Browsers: Firefox (desktop and Android) and Chrome, one codebase.
- Relay: self-hosted Rust binary.
- Clients: Rust library and CLI only.
- Several owners per consumer, with a client-side policy per selector, `longest` by default
  (§4.7).
