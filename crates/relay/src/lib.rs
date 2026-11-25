//! The relay: stores ciphertext and routes messages between owners and consumers.
//!
//! It is not trusted with cookie contents. It does check signatures and grant membership, so
//! that strangers cannot fill mailboxes or read envelopes meant for someone else.

mod auth;
mod db;
mod error;
mod routes;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cookie_communism_proto::PublicKey;

pub use error::AppError;

#[derive(Debug, Clone, Default)]
pub struct Config {
    /// SQLite path; `None` keeps everything in memory (tests).
    pub database: Option<PathBuf>,
    /// If non-empty, only these owner keys may create invites.
    pub allowed_owners: HashSet<String>,
    /// If set, a new owner's first invite must carry this in `cc-registration`.
    pub registration_secret: Option<String>,
    /// Requests per key per minute.
    pub rate_limit_per_minute: u32,
}

pub struct AppState {
    config: Config,
    db: Mutex<rusqlite::Connection>,
    /// Bumped on every write that a long-poll might be waiting for.
    changes: tokio::sync::watch::Sender<u64>,
    auth: auth::AuthState,
}

impl AppState {
    pub fn new(config: Config) -> Result<Arc<Self>, rusqlite::Error> {
        let conn = match &config.database {
            Some(path) => rusqlite::Connection::open(path)?,
            None => rusqlite::Connection::open_in_memory()?,
        };
        db::migrate(&conn)?;
        Ok(Arc::new(Self {
            config,
            db: Mutex::new(conn),
            changes: tokio::sync::watch::channel(0).0,
            auth: auth::AuthState::default(),
        }))
    }

    fn with_db<T>(
        &self,
        f: impl FnOnce(&rusqlite::Connection) -> rusqlite::Result<T>,
    ) -> Result<T, AppError> {
        let conn = self.db.lock().unwrap_or_else(|e| e.into_inner());
        f(&conn).map_err(AppError::from)
    }

    fn notify(&self) {
        self.changes.send_modify(|v| *v = v.wrapping_add(1));
    }

    fn owner_allowed(&self, key: &PublicKey, registration: Option<&str>) -> Result<bool, AppError> {
        let key_b64 = key.to_b64();
        if self.with_db(|c| db::owner_exists(c, &key_b64))? {
            return Ok(true);
        }
        if !self.config.allowed_owners.is_empty() && !self.config.allowed_owners.contains(&key_b64)
        {
            return Ok(false);
        }
        if let Some(secret) = &self.config.registration_secret
            && registration != Some(secret.as_str())
        {
            return Ok(false);
        }
        Ok(true)
    }

    /// Deletes expired invites and stale replay-cache entries.
    pub fn cleanup(&self) {
        let now = now();
        if let Err(e) = self.with_db(|c| db::cleanup(c, now)) {
            tracing::warn!("cleanup failed: {}", e.message);
        }
        self.auth.prune(now);
    }
}

pub fn router(state: Arc<AppState>) -> axum::Router {
    routes::router(state)
}

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs() as i64
}
