//! Relay HTTP request and response bodies, and request authentication headers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    BoxIdentity, BoxRecipient, ConsumerMessage, Error, PairingRequest, PublicKey, Purpose, Result,
    SignKey, Snapshot, b64, signing, unb64,
};

/// The caller's Ed25519 public key.
pub const HEADER_KEY: &str = "cc-key";
/// Unix seconds when the request was signed.
pub const HEADER_TIME: &str = "cc-time";
/// Random value, base64, unique per request.
pub const HEADER_NONCE: &str = "cc-nonce";
/// Signature over [`signing::request`].
pub const HEADER_SIG: &str = "cc-sig";
/// Shared registration secret, required when a relay restricts new owners.
pub const HEADER_REGISTRATION: &str = "cc-registration";
/// Sent by the relay on every response: its clock, in Unix seconds.
pub const HEADER_SERVER_TIME: &str = "cc-server-time";

/// Requests whose signed time is further than this from the relay's clock are rejected.
pub const MAX_CLOCK_SKEW_SECS: i64 = 300;
/// Longest long-poll the relay honours.
pub const MAX_WAIT_SECS: u64 = 60;
pub const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

/// Error body for every non-2xx response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
    pub code: ErrorCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthenticated,
    ClockSkew,
    Forbidden,
    NotFound,
    Conflict,
    TooLarge,
    RateLimited,
    Internal,
}

/// `POST /invites` (owner).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateInvite {
    pub token: String,
}

/// `POST /invites/{token}/request` (consumer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostPairingRequest {
    /// HPKE ciphertext of a [`PairingRequest`], base64.
    pub ciphertext: String,
    /// By the consumer, over [`signing::pairing_request`].
    pub signature: String,
}

impl PostPairingRequest {
    pub fn seal(
        request: &PairingRequest,
        invite_token: &str,
        owner_box: &BoxRecipient,
        consumer: &SignKey,
    ) -> Result<Self> {
        let ciphertext =
            owner_box.encrypt(&serde_json::to_vec(request)?, Purpose::PairingRequest)?;
        Ok(Self {
            signature: consumer.sign(&signing::pairing_request(invite_token, &ciphertext)),
            ciphertext: b64(&ciphertext),
        })
    }
}

/// `GET /mailbox` (owner).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mailbox {
    pub items: Vec<MailboxItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MailboxItem {
    pub id: i64,
    pub kind: MailboxKind,
    /// The consumer's public key.
    pub sender: String,
    /// Set for `pairing`.
    pub invite_token: Option<String>,
    /// Set for `message`.
    pub grant_id: Option<String>,
    pub ciphertext: String,
    pub signature: String,
    /// Unix seconds.
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailboxKind {
    Pairing,
    Message,
}

impl MailboxItem {
    /// Verifies and decrypts a pairing request. Checks that the request was signed by the key
    /// it names, and that the relay delivered it from that key.
    pub fn open_pairing(&self, owner_box: &BoxIdentity) -> Result<PairingRequest> {
        let token = self
            .invite_token
            .as_deref()
            .ok_or_else(|| Error::Encoding("pairing item without invite token".into()))?;
        let ciphertext = unb64(&self.ciphertext)?;
        let request: PairingRequest =
            serde_json::from_slice(&owner_box.decrypt(&ciphertext, Purpose::PairingRequest)?)?;
        if request.consumer_sign != self.sender {
            return Err(Error::BadSignature);
        }
        PublicKey::from_b64(&request.consumer_sign)?.verify(
            &signing::pairing_request(token, &ciphertext),
            &self.signature,
        )?;
        Ok(request)
    }

    /// Verifies and decrypts a consumer message against the grant's consumer key.
    pub fn open_message(
        &self,
        consumer: &PublicKey,
        owner_box: &BoxIdentity,
    ) -> Result<ConsumerMessage> {
        let grant_id = self
            .grant_id
            .as_deref()
            .ok_or_else(|| Error::Encoding("message item without grant ID".into()))?;
        let ciphertext = unb64(&self.ciphertext)?;
        consumer.verify(&signing::message(grant_id, &ciphertext), &self.signature)?;
        Ok(serde_json::from_slice(
            &owner_box.decrypt(&ciphertext, Purpose::Message)?,
        )?)
    }
}

/// `PUT /grants/{id}` (owner): approve the consumer that used `invite_token`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateGrant {
    pub invite_token: String,
}

/// `GET /pairing/{token}` (consumer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PairingStatus {
    Pending,
    Approved { grant_id: String },
    Rejected,
}

/// `PUT /grants/{id}/envelope` (owner), and an item of [`EnvelopePollResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub grant_id: String,
    pub version: u64,
    /// HPKE ciphertext of a [`Snapshot`], base64.
    pub ciphertext: String,
    /// By the owner, over [`signing::envelope`].
    pub signature: String,
}

impl Envelope {
    pub fn seal(
        grant_id: &str,
        version: u64,
        snapshot: &Snapshot,
        consumer_box: &BoxRecipient,
        owner: &SignKey,
    ) -> Result<Self> {
        let ciphertext = consumer_box.encrypt(&serde_json::to_vec(snapshot)?, Purpose::Envelope)?;
        Ok(Self {
            grant_id: grant_id.to_string(),
            version,
            signature: owner.sign(&signing::envelope(grant_id, version, &ciphertext)),
            ciphertext: b64(&ciphertext),
        })
    }

    pub fn open(&self, owner: &PublicKey, consumer_box: &BoxIdentity) -> Result<Snapshot> {
        let ciphertext = unb64(&self.ciphertext)?;
        owner.verify(
            &signing::envelope(&self.grant_id, self.version, &ciphertext),
            &self.signature,
        )?;
        Ok(serde_json::from_slice(
            &consumer_box.decrypt(&ciphertext, Purpose::Envelope)?,
        )?)
    }
}

/// `POST /envelopes` (consumer): for each grant, the last version the consumer has.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvelopePoll {
    pub after: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnvelopePollResult {
    /// Envelopes newer than requested.
    pub envelopes: Vec<Envelope>,
    /// Grants that no longer exist (revoked), or that this consumer is not party to.
    pub gone: Vec<String>,
}

/// `POST /grants/{id}/messages` (consumer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostMessage {
    pub ciphertext: String,
    /// By the consumer, over [`signing::message`].
    pub signature: String,
}

impl PostMessage {
    pub fn seal(
        grant_id: &str,
        message: &ConsumerMessage,
        owner_box: &BoxRecipient,
        consumer: &SignKey,
    ) -> Result<Self> {
        let ciphertext = owner_box.encrypt(&serde_json::to_vec(message)?, Purpose::Message)?;
        Ok(Self {
            signature: consumer.sign(&signing::message(grant_id, &ciphertext)),
            ciphertext: b64(&ciphertext),
        })
    }
}

/// Authentication headers for a request: `(name, value)` pairs.
pub fn auth_headers(
    key: &SignKey,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    time: i64,
) -> [(&'static str, String); 4] {
    let nonce = crate::random_id();
    [
        (HEADER_KEY, key.public().to_b64()),
        (HEADER_TIME, time.to_string()),
        (
            HEADER_SIG,
            key.sign(&signing::request(
                method,
                path_and_query,
                body,
                time,
                &nonce,
            )),
        ),
        (HEADER_NONCE, nonce),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cookie, SameSite, Selector};

    fn snapshot() -> Snapshot {
        Snapshot {
            owner_label: "Firefox".into(),
            taken_at: 1_800_000_000,
            selectors: vec![Selector::parse("example.com:sid").unwrap()],
            cookies: vec![Cookie {
                domain: ".example.com".into(),
                host_only: false,
                name: "sid".into(),
                value: "v".into(),
                path: "/".into(),
                secure: true,
                http_only: true,
                same_site: SameSite::Lax,
                expires: Some(1_900_000_000),
                partition_key: None,
                changed_at: 1_799_999_000,
            }],
        }
    }

    #[test]
    fn envelope_round_trip_and_tamper() {
        let owner = SignKey::generate();
        let consumer = BoxIdentity::generate();
        let env = Envelope::seal("g1", 3, &snapshot(), &consumer.recipient(), &owner).unwrap();
        assert_eq!(env.open(&owner.public(), &consumer).unwrap(), snapshot());

        let mut replayed = env.clone();
        replayed.version = 4;
        assert!(matches!(
            replayed.open(&owner.public(), &consumer),
            Err(Error::BadSignature)
        ));
        let mut moved = env;
        moved.grant_id = "g2".into();
        assert!(moved.open(&owner.public(), &consumer).is_err());
    }

    #[test]
    fn pairing_request_must_be_signed_by_named_key() {
        let owner_box = BoxIdentity::generate();
        let consumer = SignKey::generate();
        let request = PairingRequest {
            label: "x".into(),
            wants: vec![],
            consumer_sign: consumer.public().to_b64(),
            consumer_box: BoxIdentity::generate().recipient().to_string(),
        };
        let post =
            PostPairingRequest::seal(&request, "tok", &owner_box.recipient(), &consumer).unwrap();
        let mut item = MailboxItem {
            id: 1,
            kind: MailboxKind::Pairing,
            sender: consumer.public().to_b64(),
            invite_token: Some("tok".into()),
            grant_id: None,
            ciphertext: post.ciphertext,
            signature: post.signature,
            created_at: 0,
        };
        assert_eq!(item.open_pairing(&owner_box).unwrap(), request);
        item.sender = SignKey::generate().public().to_b64();
        assert!(item.open_pairing(&owner_box).is_err());
    }
}
