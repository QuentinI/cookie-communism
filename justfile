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
    cd extension && npm run test:browser && npx web-ext lint --source-dir dist/firefox

# Regenerate the cross-language test vectors.
vectors:
    CC_WRITE_VECTORS=1 cargo test -p cookie-communism-proto --test vectors

# Takes the API key from https://addons.mozilla.org/developers/addon/api/key/ in WEB_EXT_API_KEY
# and WEB_EXT_API_SECRET. Each upload needs a new version in extension/package.json.
# Sign the Firefox build on addons.mozilla.org as unlisted; the .xpi lands in extension/dist/signed/.
sign: build
    rm -f extension/dist/source.zip
    # The bundle is esbuild output, so AMO gets the readable source alongside it.
    { git ls-files README.md LICENSE extension | grep -vx extension/vendor/fdl; \
      git -C extension/vendor/fdl ls-files LICENSE packages/css | sed 's|^|extension/vendor/fdl/|'; } \
      | zip -q extension/dist/source.zip -@
    cd extension && npx web-ext sign --channel unlisted --source-dir dist/firefox \
      --upload-source-code dist/source.zip --artifacts-dir dist/signed
