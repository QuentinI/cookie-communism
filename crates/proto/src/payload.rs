//! Plaintext payloads. The relay only ever sees them encrypted.

use serde::{Deserialize, Serialize};

use crate::{Error, Result, Selector, b64, unb64};

/// What the user gives a consumer to start pairing: `cc1:` followed by the base64 of this
/// struct as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    /// Base URL of the relay, without a trailing slash.
    pub relay: String,
    pub owner_sign: String,
    pub owner_box: String,
    pub token: String,
}

impl Invite {
    const PREFIX: &str = "cc1:";

    pub fn encode(&self) -> String {
        format!(
            "{}{}",
            Self::PREFIX,
            b64(&serde_json::to_vec(self).expect("invite serialises"))
        )
    }

    pub fn decode(text: &str) -> Result<Self> {
        let body = text
            .trim()
            .strip_prefix(Self::PREFIX)
            .ok_or_else(|| Error::Encoding("invite must start with cc1:".into()))?;
        let mut invite: Self = serde_json::from_slice(&unb64(body)?)?;
        invite.relay = invite.relay.trim_end_matches('/').to_string();
        Ok(invite)
    }
}

/// Sent by a consumer, encrypted to the owner, to ask for a grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingRequest {
    pub label: String,
    pub wants: Vec<Selector>,
    pub consumer_sign: String,
    pub consumer_box: String,
}

/// The browser's cookies for one grant, as sent to its consumer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The name the user gave this browser in the extension.
    pub owner_label: String,
    /// Unix seconds.
    pub taken_at: i64,
    /// The selectors the user approved for this grant.
    pub selectors: Vec<Selector>,
    pub cookies: Vec<Cookie>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cookie {
    /// As the browser reports it: a leading dot for domain cookies.
    pub domain: String,
    pub host_only: bool,
    pub name: String,
    pub value: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSite,
    /// Unix seconds; `None` for a session cookie.
    pub expires: Option<i64>,
    pub partition_key: Option<String>,
    /// Unix seconds: when the extension first saw this value.
    pub changed_at: i64,
}

impl Cookie {
    /// The domain without a leading dot.
    pub fn host(&self) -> &str {
        self.domain.trim_start_matches('.')
    }

    pub fn is_expired(&self, now: i64) -> bool {
        self.expires.is_some_and(|e| e <= now)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SameSite {
    NoRestriction,
    Lax,
    Strict,
    Unspecified,
}

/// Sent by a consumer to an owner, encrypted to the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConsumerMessage {
    /// The cookies for `selector` stopped working.
    Refresh { selector: Selector, reason: String },
    /// `selector` works again; a pending login reminder can be dismissed.
    Resolved { selector: Selector },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_round_trip() {
        let invite = Invite {
            relay: "https://relay.example".into(),
            owner_sign: "s".into(),
            owner_box: "b".into(),
            token: "t".into(),
        };
        let text = invite.encode();
        assert!(text.starts_with("cc1:"));
        assert_eq!(Invite::decode(&text).unwrap(), invite);
    }
}
