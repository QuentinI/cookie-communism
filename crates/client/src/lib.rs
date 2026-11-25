//! Consumer side of cookie-communism: pair with browser extensions, receive their cookies
//! end-to-end encrypted through a relay, and choose between browsers by policy.
//!
//! ```no_run
//! # async fn demo() -> cookie_communism::Result<()> {
//! use cookie_communism::Client;
//!
//! let pending = Client::pair("state.json", "cc1:…", "my-bot", &["example.com:session"]).await?;
//! eprintln!("pairing code: {}", pending.code());
//! let client = pending.approved().await?;
//!
//! let http = reqwest::Client::builder().cookie_provider(client.cookie_store()).build().unwrap();
//! # Ok(()) }
//! ```
//!
//! One state file must be used by one process at a time.

mod client;
mod jar;
pub mod policy;
mod relay;
mod state;

pub use client::{Client, Event, GroupStatus, OwnerInfo, OwnerRef, PendingPairing};
pub use cookie_communism_proto::{Cookie, Selector, Snapshot};
pub use jar::{Jar, SharedJar};
pub use policy::Policy;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("state file: {0}")]
    State(String),
    #[error("relay: {0}")]
    Relay(String),
    #[error("relay refused the request ({code:?}): {message}")]
    Rejected {
        code: cookie_communism_proto::api::ErrorCode,
        message: String,
    },
    #[error(transparent)]
    Protocol(#[from] cookie_communism_proto::Error),
    #[error("the browser rejected the pairing request")]
    PairingRejected,
    #[error("already paired with this browser as {0:?}")]
    AlreadyPaired(String),
    #[error("no approved selector on {0}")]
    UnknownSelector(String),
    #[error("no paired browser named {0:?}")]
    UnknownOwner(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
}
