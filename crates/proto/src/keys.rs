//! Ed25519 signing keys and age X25519 encryption keys.

use std::str::FromStr;

use age::secrecy::ExposeSecret;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

use crate::{Error, Result, b64, random_bytes, unb64};

/// An Ed25519 private key. Serialised as the base64 of its 32-byte seed.
#[derive(Clone)]
pub struct SignKey(SigningKey);

impl SignKey {
    pub fn generate() -> Self {
        Self::from_seed(random_bytes::<32>())
    }

    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    pub fn from_b64(text: &str) -> Result<Self> {
        let seed: [u8; 32] = unb64(text)?
            .try_into()
            .map_err(|_| Error::Encoding("signing key must be 32 bytes".into()))?;
        Ok(Self::from_seed(seed))
    }

    pub fn to_b64(&self) -> String {
        b64(&self.0.to_bytes())
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }

    /// Signs `message`; returns the base64 signature.
    pub fn sign(&self, message: &[u8]) -> String {
        b64(&self.0.sign(message).to_bytes())
    }
}

impl std::fmt::Debug for SignKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SignKey({})", self.public())
    }
}

/// An Ed25519 public key. Serialised as the base64 of its 32 bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(VerifyingKey);

impl PublicKey {
    pub fn from_b64(text: &str) -> Result<Self> {
        let bytes: [u8; 32] = unb64(text)?
            .try_into()
            .map_err(|_| Error::Encoding("public key must be 32 bytes".into()))?;
        VerifyingKey::from_bytes(&bytes)
            .map(Self)
            .map_err(|_| Error::Encoding("not an Ed25519 public key".into()))
    }

    pub fn to_b64(&self) -> String {
        b64(self.0.as_bytes())
    }

    pub fn verify(&self, message: &[u8], signature_b64: &str) -> Result<()> {
        let bytes: [u8; 64] = unb64(signature_b64)?
            .try_into()
            .map_err(|_| Error::BadSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&bytes);
        self.0
            .verify_strict(message, &signature)
            .map_err(|_| Error::BadSignature)
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_b64())
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({self})")
    }
}

/// An age X25519 identity (`AGE-SECRET-KEY-1…`).
#[derive(Clone)]
pub struct BoxIdentity(age::x25519::Identity);

impl BoxIdentity {
    pub fn generate() -> Self {
        Self(age::x25519::Identity::generate())
    }

    pub fn parse(text: &str) -> Result<Self> {
        age::x25519::Identity::from_str(text)
            .map(Self)
            .map_err(|e| Error::Encoding(format!("age identity: {e}")))
    }

    pub fn to_secret_string(&self) -> String {
        self.0.to_string().expose_secret().to_string()
    }

    pub fn recipient(&self) -> BoxRecipient {
        BoxRecipient(self.0.to_public())
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        age::decrypt(&self.0, ciphertext).map_err(|e| Error::Decrypt(e.to_string()))
    }
}

impl std::fmt::Debug for BoxIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BoxIdentity({})", self.recipient())
    }
}

/// An age X25519 recipient (`age1…`).
#[derive(Clone)]
pub struct BoxRecipient(age::x25519::Recipient);

impl BoxRecipient {
    pub fn parse(text: &str) -> Result<Self> {
        age::x25519::Recipient::from_str(text)
            .map(Self)
            .map_err(|e| Error::Encoding(format!("age recipient: {e}")))
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        age::encrypt(&self.0, plaintext).map_err(|e| Error::Encrypt(e.to_string()))
    }
}

impl std::fmt::Display for BoxRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Debug for BoxRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BoxRecipient({self})")
    }
}
