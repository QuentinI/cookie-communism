# Loads .env (gitignored), for example WEB_EXT_API_KEY and WEB_EXT_API_SECRET for `just sign`.
set dotenv-load := true

# GitHub repository that carries releases (a mirror of the Forgejo one).
github := "QuentinI/cookie-communism"

# Run every test that does not need a browser.
test:
    cargo test --workspace
    cd extension && npm test

# Lint Rust and type-check the extension.
lint:
    cargo clippy --workspace --all-targets
    cargo fmt --all --check
    cd extension && npx tsc --noEmit

# Build the relay, the CLI and both extension packages.
build:
    cargo build --release -p cookie-communism-relay -p ccom
    cd extension && npm run build

# Drive the built Chrome extension in Chromium (set CHROMIUM if it is not in /Applications).
smoke: build
    cd extension && npm run test:browser && npx web-ext lint --self-hosted --source-dir dist/firefox

# Regenerate the cross-language test vectors.
vectors:
    CC_WRITE_VECTORS=1 cargo test -p cookie-communism-proto --test vectors

# Takes the API key from https://addons.mozilla.org/developers/addon/api/key/ in WEB_EXT_API_KEY
# and WEB_EXT_API_SECRET, from the environment or .env. Each upload needs a new version in
# extension/package.json.
# Sign the Firefox build on addons.mozilla.org as unlisted; the .xpi lands in extension/dist/signed/.
sign: build
    rm -f extension/dist/source.zip
    # The bundle is esbuild output, so AMO gets the readable source alongside it.
    { git ls-files README.md LICENSE extension | grep -vx extension/vendor/fdl; \
      git -C extension/vendor/fdl ls-files LICENSE packages/css | sed 's|^|extension/vendor/fdl/|'; } \
      | zip -q extension/dist/source.zip -@
    cd extension && npx web-ext sign --channel unlisted --source-dir dist/firefox \
      --upload-source-code dist/source.zip --artifacts-dir dist/signed

# Expects the signed .xpi for the current extension/package.json version from `just sign`. The tag
# is pushed to both remotes before the release exists: GitHub mirrors Forgejo, and a tag missing
# from Forgejo would be removed from GitHub on the next sync.
# Publish the signed extension as a GitHub release, with updates.json for Firefox's updates.
release:
    #!/usr/bin/env bash
    set -euo pipefail
    cd extension
    version=$(node -p 'require("./package.json").version')
    name="cookie-communism-$version.xpi"
    signed=(dist/signed/*-"$version".xpi)
    [ -f "${signed[0]}" ] || { echo "no signed .xpi for $version; run just sign" >&2; exit 1; }
    rm -rf dist/release && mkdir -p dist/release
    cp "${signed[0]}" "dist/release/$name"
    node -e '
      const { createHash } = require("node:crypto");
      const { readFileSync } = require("node:fs");
      const [version, name] = process.argv.slice(1);
      const hash = createHash("sha256").update(readFileSync(`dist/release/${name}`)).digest("hex");
      const link = `https://github.com/{{github}}/releases/download/v${version}/${name}`;
      const updates = { addons: { "cookie-communism@cookie-communism": {
        updates: [{ version, update_link: link, update_hash: `sha256:${hash}` }] } } };
      console.log(JSON.stringify(updates, null, 2));
    ' "$version" "$name" > dist/release/updates.json
    git tag -a "v$version" -m "v$version"
    git push origin "v$version"
    git push "git@github.com:{{github}}.git" "v$version"
    gh release create "v$version" --repo {{github}} --verify-tag --title "v$version" \
      --notes "Signed Firefox build (desktop and Android). Install the .xpi from about:addons → Install Add-on From File." \
      "dist/release/$name" dist/release/updates.json
