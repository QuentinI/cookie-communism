//! Signed HTTP calls to a relay.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use cookie_communism_proto::SignKey;
use cookie_communism_proto::api::{self, ErrorBody, ErrorCode};
use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Error, Result, now};

/// Seconds to add to the local clock to match the relay's; learned from clock-skew errors.
static CLOCK_OFFSET: AtomicI64 = AtomicI64::new(0);

#[derive(Clone)]
pub(crate) struct Relay {
    http: reqwest::Client,
    base: String,
    key: SignKey,
}

impl Relay {
    pub fn new(http: reqwest::Client, base: &str, key: SignKey) -> Self {
        Self {
            http,
            base: base.trim_end_matches('/').to_string(),
            key,
        }
    }

    /// Sends a signed request. `wait` is the long-poll duration the relay may hold it for.
    pub async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
        wait: Option<Duration>,
    ) -> Result<Option<T>> {
        let body = match body {
            Some(b) => serde_json::to_vec(b).expect("request serialises"),
            None => Vec::new(),
        };
        let path = match wait {
            Some(w) => format!("{path}?wait={}", w.as_secs().min(api::MAX_WAIT_SECS)),
            None => path.to_string(),
        };
        let mut retried = false;
        loop {
            let time = now() + CLOCK_OFFSET.load(Ordering::Relaxed);
            let mut req = self
                .http
                .request(method.clone(), format!("{}{path}", self.base))
                .timeout(wait.unwrap_or_default() + Duration::from_secs(20));
            for (name, value) in api::auth_headers(&self.key, method.as_str(), &path, &body, time) {
                req = req.header(name, value);
            }
            if !body.is_empty() {
                req = req
                    .header("content-type", "application/json")
                    .body(body.clone());
            }
            let res = req
                .send()
                .await
                .map_err(|e| Error::Relay(format!("{}: {e}", self.base)))?;
            let status = res.status();
            let server_time: Option<i64> = res
                .headers()
                .get(api::HEADER_SERVER_TIME)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok());
            let bytes = res.bytes().await.map_err(|e| Error::Relay(e.to_string()))?;
            if status.is_success() {
                if bytes.is_empty() || status == reqwest::StatusCode::NO_CONTENT {
                    return Ok(None);
                }
                return serde_json::from_slice(&bytes)
                    .map(Some)
                    .map_err(|e| Error::Relay(format!("unexpected response: {e}")));
            }
            let err: Option<ErrorBody> = serde_json::from_slice(&bytes).ok();
            if let (
                Some(ErrorBody {
                    code: ErrorCode::ClockSkew,
                    ..
                }),
                Some(server),
                false,
            ) = (&err, server_time, retried)
            {
                CLOCK_OFFSET.store(server - now(), Ordering::Relaxed);
                tracing::warn!(
                    "local clock is {}s off the relay's; adjusting",
                    now() - server
                );
                retried = true;
                continue;
            }
            return Err(match err {
                Some(e) => Error::Rejected {
                    code: e.code,
                    message: e.error,
                },
                None => Error::Relay(format!("{} {}", status, String::from_utf8_lossy(&bytes))),
            });
        }
    }
}
