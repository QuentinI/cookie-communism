//! Request signature verification, replay protection and per-key rate limiting.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{FromRequest, Request};
use cookie_communism_proto::api::{
    ErrorCode, HEADER_KEY, HEADER_NONCE, HEADER_REGISTRATION, HEADER_SIG, HEADER_TIME,
    MAX_CLOCK_SKEW_SECS,
};
use cookie_communism_proto::{PublicKey, signing};

use crate::{AppError, AppState, now};

#[derive(Default)]
pub struct AuthState {
    /// Signatures seen recently, with the time after which they can be forgotten.
    seen: Mutex<HashMap<String, i64>>,
    /// Per key: (start of the current minute window, requests in it).
    rate: Mutex<HashMap<String, (i64, u32)>>,
}

impl AuthState {
    pub fn prune(&self, now: i64) {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, until| *until > now);
        self.rate
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, (start, _)| *start + 60 > now);
    }
}

/// A request whose signature checked out. Holds the caller's key and the raw body.
pub struct Authed {
    pub key: PublicKey,
    pub body: Bytes,
    pub registration: Option<String>,
}

impl Authed {
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T, AppError> {
        serde_json::from_slice(&self.body)
            .map_err(|e| AppError::bad_request(format!("invalid body: {e}")))
    }
}

fn header<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

fn unauthenticated(m: &str) -> AppError {
    AppError::new(ErrorCode::Unauthenticated, m)
}

impl FromRequest<Arc<AppState>> for Authed {
    type Rejection = AppError;

    async fn from_request(req: Request, state: &Arc<AppState>) -> Result<Self, AppError> {
        let key = header(&req, HEADER_KEY).ok_or_else(|| unauthenticated("missing cc-key"))?;
        let key = PublicKey::from_b64(key).map_err(|_| unauthenticated("invalid cc-key"))?;
        let time: i64 = header(&req, HEADER_TIME)
            .and_then(|t| t.parse().ok())
            .ok_or_else(|| unauthenticated("missing or invalid cc-time"))?;
        let sig = header(&req, HEADER_SIG)
            .ok_or_else(|| unauthenticated("missing cc-sig"))?
            .to_string();
        let nonce = header(&req, HEADER_NONCE)
            .filter(|n| (16..=64).contains(&n.len()))
            .ok_or_else(|| unauthenticated("missing or invalid cc-nonce"))?
            .to_string();
        let registration = header(&req, HEADER_REGISTRATION).map(str::to_string);

        let now = now();
        if (time - now).abs() > MAX_CLOCK_SKEW_SECS {
            return Err(AppError::new(
                ErrorCode::ClockSkew,
                "request time too far from server time",
            ));
        }

        let method = req.method().as_str().to_string();
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| req.uri().path().to_string());
        let body = Bytes::from_request(req, state)
            .await
            .map_err(|_| AppError::new(ErrorCode::TooLarge, "body too large"))?;

        key.verify(&signing::request(&method, &path, &body, time, &nonce), &sig)
            .map_err(|_| unauthenticated("bad signature"))?;

        {
            let mut seen = state.auth.seen.lock().unwrap_or_else(|e| e.into_inner());
            if seen.insert(sig, time + MAX_CLOCK_SKEW_SECS + 1).is_some() {
                return Err(unauthenticated("replayed request"));
            }
        }

        let limit = state.config.rate_limit_per_minute;
        if limit > 0 {
            let mut rate = state.auth.rate.lock().unwrap_or_else(|e| e.into_inner());
            let entry = rate.entry(key.to_b64()).or_insert((now, 0));
            if now - entry.0 >= 60 {
                *entry = (now, 0);
            }
            entry.1 += 1;
            if entry.1 > limit {
                return Err(AppError::new(ErrorCode::RateLimited, "too many requests"));
            }
        }

        Ok(Self {
            key,
            body,
            registration,
        })
    }
}
