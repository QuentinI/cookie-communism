//! Wire protocol shared by the relay, the client and (through test vectors) the extension.
//!
//! Every signed byte string is built by one function in [`signing`], so the extension's
//! TypeScript implementation has a single place to mirror.

pub mod api;
pub mod keys;
pub mod payload;
pub mod selector;
pub mod signing;

pub use keys::{BoxIdentity, BoxRecipient, PublicKey, SignKey};
pub use payload::{ConsumerMessage, Cookie, Invite, PairingRequest, SameSite, Snapshot};
pub use selector::Selector;

use base64::Engine;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid encoding: {0}")]
    Encoding(String),
    #[error("bad signature")]
    BadSignature,
    #[error("encryption failed: {0}")]
    Encrypt(String),
    #[error("decryption failed: {0}")]
    Decrypt(String),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Unpadded URL-safe base64, used for every binary value on the wire.
pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64(text: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|e| Error::Encoding(format!("base64: {e}")))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `n` random bytes from the OS.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS random number generator unavailable");
    out
}

/// A random identifier: 16 bytes, base64.
pub fn random_id() -> String {
    b64(&random_bytes::<16>())
}
