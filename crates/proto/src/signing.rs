//! The exact byte strings that get signed, and the pairing code.
//!
//! Each string starts with a version tag, so a signature made for one purpose cannot be
//! replayed as another. Fields are joined with `\n`; none of them can contain a newline
//! (methods, paths, base64, decimal numbers, hex digests, grant IDs).

use crate::sha256_hex;

/// Signed by the caller of every relay request. The nonce makes two identical requests in
/// the same second distinguishable from a replay.
pub fn request(method: &str, path_and_query: &str, body: &[u8], time: i64, nonce: &str) -> Vec<u8> {
    format!(
        "cc-req-v1\n{method}\n{path_and_query}\n{}\n{time}\n{nonce}",
        sha256_hex(body)
    )
    .into_bytes()
}

/// Signed by the owner over each envelope it uploads.
pub fn envelope(grant_id: &str, version: u64, ciphertext: &[u8]) -> Vec<u8> {
    format!(
        "cc-env-v1\n{grant_id}\n{version}\n{}",
        sha256_hex(ciphertext)
    )
    .into_bytes()
}

/// Signed by the consumer over each message it sends to an owner.
pub fn message(grant_id: &str, ciphertext: &[u8]) -> Vec<u8> {
    format!("cc-msg-v1\n{grant_id}\n{}", sha256_hex(ciphertext)).into_bytes()
}

/// Signed by the consumer over its encrypted pairing request.
pub fn pairing_request(invite_token: &str, ciphertext: &[u8]) -> Vec<u8> {
    format!("cc-pairreq-v1\n{invite_token}\n{}", sha256_hex(ciphertext)).into_bytes()
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The code both sides show during pairing: the first 40 bits of a SHA-256 over all four
/// public keys and the invite token, in Crockford base32 as `XXXX-XXXX`.
pub fn pairing_code(
    owner_sign: &str,
    owner_box: &str,
    consumer_sign: &str,
    consumer_box: &str,
    invite_token: &str,
) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(
        format!(
            "cc-pair-v1\n{owner_sign}\n{owner_box}\n{consumer_sign}\n{consumer_box}\n{invite_token}"
        )
        .as_bytes(),
    );
    let bits = digest[..5]
        .iter()
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    let chars: String = (0..8)
        .rev()
        .map(|i| CROCKFORD[((bits >> (i * 5)) & 31) as usize] as char)
        .collect();
    format!("{}-{}", &chars[..4], &chars[4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_code_shape() {
        let code = pairing_code("a", "b", "c", "d", "e");
        assert_eq!(code.len(), 9);
        assert_eq!(&code[4..5], "-");
        assert_ne!(code, pairing_code("a", "b", "c", "d", "f"));
    }
}
