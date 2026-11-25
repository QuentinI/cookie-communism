//! Ed25519 signing keys, and X25519 keys for HPKE encryption.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hpke::{Deserializable, Serializable};

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

/// What a ciphertext holds, bound into its encryption as HPKE's `info` so that one of one kind
/// can't be opened as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    PairingRequest,
    Envelope,
    Message,
}

impl Purpose {
    fn info(self) -> &'static [u8] {
        match self {
            Self::PairingRequest => b"cookie-communism/v1 pairing request",
            Self::Envelope => b"cookie-communism/v1 envelope",
            Self::Message => b"cookie-communism/v1 message",
        }
    }
}

// HPKE (RFC 9180), base mode, with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM.
type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type Aead = hpke::aead::AesGcm128;
type PrivateKey = <Kem as hpke::Kem>::PrivateKey;
type EncappedKey = <Kem as hpke::Kem>::EncappedKey;
/// Length of the encapsulated key that starts every ciphertext.
const ENC_LEN: usize = 32;

/// An HPKE X25519 private key. Serialised as the base64 of its 32 bytes.
#[derive(Clone)]
pub struct BoxIdentity(PrivateKey);

impl BoxIdentity {
    pub fn generate() -> Self {
        Self(<Kem as hpke::Kem>::gen_keypair().0)
    }

    pub fn parse(text: &str) -> Result<Self> {
        PrivateKey::from_bytes(&unb64(text)?)
            .map(Self)
            .map_err(|_| Error::Encoding("not an X25519 private key".into()))
    }

    pub fn to_secret_string(&self) -> String {
        b64(&self.0.to_bytes())
    }

    pub fn recipient(&self) -> BoxRecipient {
        BoxRecipient(<Kem as hpke::Kem>::sk_to_pk(&self.0))
    }

    /// Opens a ciphertext made by [`BoxRecipient::encrypt`] for the same purpose.
    pub fn decrypt(&self, ciphertext: &[u8], purpose: Purpose) -> Result<Vec<u8>> {
        if ciphertext.len() < ENC_LEN {
            return Err(Error::Decrypt("ciphertext too short".into()));
        }
        let (enc, sealed) = ciphertext.split_at(ENC_LEN);
        let enc = EncappedKey::from_bytes(enc).map_err(|e| Error::Decrypt(format!("{e:?}")))?;
        hpke::single_shot_open::<Aead, Kdf, Kem>(
            &hpke::OpModeR::Base,
            &self.0,
            &enc,
            purpose.info(),
            sealed,
            b"",
        )
        .map_err(|e| Error::Decrypt(format!("{e:?}")))
    }
}

impl std::fmt::Debug for BoxIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BoxIdentity({})", self.recipient())
    }
}

/// An HPKE X25519 public key. Serialised as the base64 of its 32 bytes.
#[derive(Clone)]
pub struct BoxRecipient(<Kem as hpke::Kem>::PublicKey);

impl BoxRecipient {
    pub fn parse(text: &str) -> Result<Self> {
        <Kem as hpke::Kem>::PublicKey::from_bytes(&unb64(text)?)
            .map(Self)
            .map_err(|_| Error::Encoding("not an X25519 public key".into()))
    }

    /// Encrypts to this key: the encapsulated key, then the AEAD ciphertext.
    pub fn encrypt(&self, plaintext: &[u8], purpose: Purpose) -> Result<Vec<u8>> {
        let (enc, sealed) = hpke::single_shot_seal::<Aead, Kdf, Kem>(
            &hpke::OpModeS::Base,
            &self.0,
            purpose.info(),
            plaintext,
            b"",
        )
        .map_err(|e| Error::Encrypt(format!("{e:?}")))?;
        let mut out = enc.to_bytes().to_vec();
        out.extend_from_slice(&sealed);
        Ok(out)
    }
}

impl std::fmt::Display for BoxRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&b64(&self.0.to_bytes()))
    }
}

impl std::fmt::Debug for BoxRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BoxRecipient({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_purpose_binding() {
        let identity = BoxIdentity::generate();
        let reparsed = BoxIdentity::parse(&identity.to_secret_string()).unwrap();
        let recipient = BoxRecipient::parse(&reparsed.recipient().to_string()).unwrap();

        let ciphertext = recipient.encrypt(b"cookies", Purpose::Envelope).unwrap();
        assert_eq!(
            identity.decrypt(&ciphertext, Purpose::Envelope).unwrap(),
            b"cookies"
        );
        assert!(identity.decrypt(&ciphertext, Purpose::Message).is_err());
        assert!(
            BoxIdentity::generate()
                .decrypt(&ciphertext, Purpose::Envelope)
                .is_err()
        );

        let mut tampered = ciphertext.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(identity.decrypt(&tampered, Purpose::Envelope).is_err());
    }
}
