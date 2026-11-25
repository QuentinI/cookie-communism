//! SQLite schema and queries. All functions take a locked connection.

use cookie_communism_proto::api::{Envelope, MailboxItem, MailboxKind};
use rusqlite::{Connection, OptionalExtension, Result, params};

/// How long an invite can be used to post a pairing request.
pub const INVITE_TTL_SECS: i64 = 3600;
/// How long an invite row (and so the consumer's pairing status) is kept after it expires.
const INVITE_RETENTION_SECS: i64 = 86_400;
pub const MAILBOX_LIMIT: i64 = 100;

pub fn migrate(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS owners (
             key        TEXT PRIMARY KEY,
             created_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS invites (
             token      TEXT PRIMARY KEY,
             owner      TEXT NOT NULL REFERENCES owners(key),
             expires_at INTEGER NOT NULL,
             status     TEXT NOT NULL CHECK (status IN ('open', 'requested', 'approved', 'rejected')),
             consumer   TEXT,
             grant_id   TEXT
         );
         CREATE TABLE IF NOT EXISTS grants (
             id         TEXT PRIMARY KEY,
             owner      TEXT NOT NULL REFERENCES owners(key),
             consumer   TEXT NOT NULL,
             created_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS grants_consumer ON grants(consumer);
         CREATE TABLE IF NOT EXISTS envelopes (
             grant_id   TEXT PRIMARY KEY REFERENCES grants(id) ON DELETE CASCADE,
             version    INTEGER NOT NULL,
             ciphertext TEXT NOT NULL,
             signature  TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS mailbox (
             id           INTEGER PRIMARY KEY AUTOINCREMENT,
             owner        TEXT NOT NULL REFERENCES owners(key),
             kind         TEXT NOT NULL CHECK (kind IN ('pairing', 'message')),
             sender       TEXT NOT NULL,
             invite_token TEXT,
             grant_id     TEXT REFERENCES grants(id) ON DELETE CASCADE,
             ciphertext   TEXT NOT NULL,
             signature    TEXT NOT NULL,
             created_at   INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS mailbox_owner ON mailbox(owner, id);",
    )
}

pub fn owner_exists(conn: &Connection, key: &str) -> Result<bool> {
    conn.query_row("SELECT 1 FROM owners WHERE key = ?1", [key], |_| Ok(()))
        .optional()
        .map(|r| r.is_some())
}

pub fn ensure_owner(conn: &Connection, key: &str, now: i64) -> Result<()> {
    conn.execute(
        "INSERT OR IGNORE INTO owners (key, created_at) VALUES (?1, ?2)",
        params![key, now],
    )
    .map(drop)
}

pub fn create_invite(conn: &Connection, token: &str, owner: &str, now: i64) -> Result<bool> {
    let n = conn.execute(
        "INSERT OR IGNORE INTO invites (token, owner, expires_at, status) VALUES (?1, ?2, ?3, 'open')",
        params![token, owner, now + INVITE_TTL_SECS],
    )?;
    Ok(n == 1)
}

pub struct Invite {
    pub owner: String,
    pub expires_at: i64,
    pub status: String,
    pub consumer: Option<String>,
    pub grant_id: Option<String>,
}

pub fn invite(conn: &Connection, token: &str) -> Result<Option<Invite>> {
    conn.query_row(
        "SELECT owner, expires_at, status, consumer, grant_id FROM invites WHERE token = ?1",
        [token],
        |r| {
            Ok(Invite {
                owner: r.get(0)?,
                expires_at: r.get(1)?,
                status: r.get(2)?,
                consumer: r.get(3)?,
                grant_id: r.get(4)?,
            })
        },
    )
    .optional()
}

/// Moves an open, unexpired invite to `requested` and files the request. Returns false if the
/// invite was not open.
pub fn post_pairing_request(
    conn: &Connection,
    token: &str,
    consumer: &str,
    ciphertext: &str,
    signature: &str,
    now: i64,
) -> Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let n = tx.execute(
        "UPDATE invites SET status = 'requested', consumer = ?2
         WHERE token = ?1 AND status = 'open' AND expires_at > ?3",
        params![token, consumer, now],
    )?;
    if n == 0 {
        return Ok(false);
    }
    tx.execute(
        "INSERT INTO mailbox (owner, kind, sender, invite_token, ciphertext, signature, created_at)
         SELECT owner, 'pairing', ?2, ?1, ?3, ?4, ?5 FROM invites WHERE token = ?1",
        params![token, consumer, ciphertext, signature, now],
    )?;
    tx.commit()?;
    Ok(true)
}

pub fn set_invite_status(
    conn: &Connection,
    token: &str,
    status: &str,
    grant_id: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE invites SET status = ?2, grant_id = ?3 WHERE token = ?1",
        params![token, status, grant_id],
    )
    .map(drop)
}

pub struct Grant {
    pub owner: String,
    pub consumer: String,
}

pub fn grant(conn: &Connection, id: &str) -> Result<Option<Grant>> {
    conn.query_row(
        "SELECT owner, consumer FROM grants WHERE id = ?1",
        [id],
        |r| {
            Ok(Grant {
                owner: r.get(0)?,
                consumer: r.get(1)?,
            })
        },
    )
    .optional()
}

pub fn create_grant(
    conn: &Connection,
    id: &str,
    owner: &str,
    consumer: &str,
    now: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO grants (id, owner, consumer, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![id, owner, consumer, now],
    )
    .map(drop)
}

pub fn delete_grant(conn: &Connection, id: &str) -> Result<()> {
    conn.execute("DELETE FROM grants WHERE id = ?1", [id])
        .map(drop)
}

pub fn envelope_version(conn: &Connection, grant_id: &str) -> Result<Option<u64>> {
    conn.query_row(
        "SELECT version FROM envelopes WHERE grant_id = ?1",
        [grant_id],
        |r| r.get::<_, i64>(0).map(|v| v as u64),
    )
    .optional()
}

pub fn put_envelope(conn: &Connection, env: &Envelope) -> Result<()> {
    conn.execute(
        "INSERT INTO envelopes (grant_id, version, ciphertext, signature) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (grant_id) DO UPDATE SET
             version = excluded.version, ciphertext = excluded.ciphertext, signature = excluded.signature",
        params![env.grant_id, env.version as i64, env.ciphertext, env.signature],
    )
    .map(drop)
}

pub fn envelope(conn: &Connection, grant_id: &str) -> Result<Option<Envelope>> {
    conn.query_row(
        "SELECT version, ciphertext, signature FROM envelopes WHERE grant_id = ?1",
        [grant_id],
        |r| {
            Ok(Envelope {
                grant_id: grant_id.to_string(),
                version: r.get::<_, i64>(0)? as u64,
                ciphertext: r.get(1)?,
                signature: r.get(2)?,
            })
        },
    )
    .optional()
}

pub fn mailbox_count(conn: &Connection, owner: &str) -> Result<i64> {
    conn.query_row(
        "SELECT count(*) FROM mailbox WHERE owner = ?1",
        [owner],
        |r| r.get(0),
    )
}

pub fn post_message(
    conn: &Connection,
    owner: &str,
    sender: &str,
    grant_id: &str,
    ciphertext: &str,
    signature: &str,
    now: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO mailbox (owner, kind, sender, grant_id, ciphertext, signature, created_at)
         VALUES (?1, 'message', ?2, ?3, ?4, ?5, ?6)",
        params![owner, sender, grant_id, ciphertext, signature, now],
    )
    .map(drop)
}

pub fn mailbox(conn: &Connection, owner: &str) -> Result<Vec<MailboxItem>> {
    let mut stmt = conn.prepare(
        "SELECT id, kind, sender, invite_token, grant_id, ciphertext, signature, created_at
         FROM mailbox WHERE owner = ?1 ORDER BY id",
    )?;
    stmt.query_map([owner], |r| {
        Ok(MailboxItem {
            id: r.get(0)?,
            kind: if r.get::<_, String>(1)? == "pairing" {
                MailboxKind::Pairing
            } else {
                MailboxKind::Message
            },
            sender: r.get(2)?,
            invite_token: r.get(3)?,
            grant_id: r.get(4)?,
            ciphertext: r.get(5)?,
            signature: r.get(6)?,
            created_at: r.get(7)?,
        })
    })?
    .collect()
}

pub fn delete_mailbox_item(conn: &Connection, owner: &str, id: i64) -> Result<bool> {
    conn.execute(
        "DELETE FROM mailbox WHERE owner = ?1 AND id = ?2",
        params![owner, id],
    )
    .map(|n| n == 1)
}

pub fn cleanup(conn: &Connection, now: i64) -> Result<()> {
    conn.execute(
        "DELETE FROM invites WHERE expires_at + ?1 < ?2",
        params![INVITE_RETENTION_SECS, now],
    )?;
    // Pairing requests for invites that are gone can no longer be approved.
    conn.execute(
        "DELETE FROM mailbox WHERE kind = 'pairing'
         AND invite_token NOT IN (SELECT token FROM invites WHERE status = 'requested')",
        [],
    )
    .map(drop)
}
