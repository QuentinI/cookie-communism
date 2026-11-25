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
