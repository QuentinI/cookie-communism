use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use cookie_communism_proto::api::{
    CreateGrant, CreateInvite, Envelope, EnvelopePoll, EnvelopePollResult, ErrorCode,
    HEADER_SERVER_TIME, MAX_ENVELOPE_BYTES, MAX_WAIT_SECS, Mailbox, PairingStatus, PostMessage,
    PostPairingRequest,
};
use cookie_communism_proto::{PublicKey, signing, unb64};
use serde::Deserialize;

use crate::auth::Authed;
use crate::{AppError, AppState, db, now};

type AppResult<T> = Result<T, AppError>;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/invites", post(create_invite))
        .route("/invites/{token}", delete(reject_invite))
        .route("/invites/{token}/request", post(post_pairing_request))
        .route("/pairing/{token}", get(pairing_status))
        .route("/mailbox", get(get_mailbox))
        .route("/mailbox/{id}", delete(delete_mailbox_item))
        .route("/grants/{id}", put(create_grant).delete(revoke_grant))
        .route("/grants/{id}/envelope", put(put_envelope))
        .route("/grants/{id}/messages", post(post_message))
        .route("/envelopes", post(poll_envelopes))
        .layer(DefaultBodyLimit::max(2 * MAX_ENVELOPE_BYTES))
        .layer(axum::middleware::map_response(add_server_time))
        .layer(cors())
        .with_state(state)
}

/// Any origin may call the relay: requests are authenticated by signature, never by ambient
/// credentials, so CORS adds no protection, and allowing it spares the extension a host
/// permission for the relay.
fn cors() -> tower_http::cors::CorsLayer {
    use axum::http::{HeaderName, Method};
    use cookie_communism_proto::api::{
        HEADER_KEY, HEADER_NONCE, HEADER_REGISTRATION, HEADER_SIG, HEADER_TIME,
    };
    tower_http::cors::CorsLayer::new()
        .allow_origin(tower_http::cors::Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers(
            [
                HEADER_KEY,
                HEADER_TIME,
                HEADER_NONCE,
                HEADER_SIG,
                HEADER_REGISTRATION,
                "content-type",
            ]
            .map(HeaderName::from_static),
        )
        .expose_headers([HeaderName::from_static(HEADER_SERVER_TIME)])
        .max_age(Duration::from_secs(86400))
}

async fn add_server_time(mut res: Response) -> Response {
    res.headers_mut()
        .insert(HEADER_SERVER_TIME, HeaderValue::from(now()));
    res
}

#[derive(Deserialize)]
struct WaitQuery {
    #[serde(default)]
    wait: u64,
}

/// Runs `check` until it returns `Some`, re-running it after every relay write, for up to
/// `wait` seconds. Returns `None` on timeout.
async fn long_poll<T>(
    state: &AppState,
    wait: u64,
    mut check: impl FnMut() -> AppResult<Option<T>>,
) -> AppResult<Option<T>> {
    let mut rx = state.changes.subscribe();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(wait.min(MAX_WAIT_SECS));
    loop {
        rx.borrow_and_update();
        if let Some(v) = check()? {
            return Ok(Some(v));
        }
        match tokio::time::timeout_at(deadline, rx.changed()).await {
            Ok(Ok(())) => continue,
            _ => return Ok(None),
        }
    }
}

fn valid_id(id: &str) -> AppResult<()> {
    let ok = (8..=64).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if ok {
        Ok(())
    } else {
        Err(AppError::bad_request("invalid identifier"))
    }
}

async fn create_invite(State(state): State<Arc<AppState>>, req: Authed) -> AppResult<StatusCode> {
    let body: CreateInvite = req.json()?;
    valid_id(&body.token)?;
    if !state.owner_allowed(&req.key, req.registration.as_deref())? {
        return Err(AppError::forbidden("this relay does not accept this owner"));
    }
    let owner = req.key.to_b64();
    let now = now();
    let created = state.with_db(|c| {
        db::ensure_owner(c, &owner, now)?;
        db::create_invite(c, &body.token, &owner, now)
    })?;
    if !created {
        return Err(AppError::conflict("invite token already used"));
    }
    Ok(StatusCode::CREATED)
}

async fn reject_invite(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    req: Authed,
) -> AppResult<StatusCode> {
    let owner = req.key.to_b64();
    let invite = state
        .with_db(|c| db::invite(c, &token))?
        .filter(|i| i.owner == owner)
        .ok_or_else(|| AppError::not_found("no such invite"))?;
    if invite.status == "approved" {
        return Err(AppError::conflict("invite already approved"));
    }
    state.with_db(|c| db::set_invite_status(c, &token, "rejected", None))?;
    state.notify();
    Ok(StatusCode::NO_CONTENT)
}

async fn post_pairing_request(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    req: Authed,
) -> AppResult<StatusCode> {
    let body: PostPairingRequest = req.json()?;
    let ciphertext =
        unb64(&body.ciphertext).map_err(|_| AppError::bad_request("invalid ciphertext"))?;
    if ciphertext.len() > MAX_ENVELOPE_BYTES {
        return Err(AppError::new(ErrorCode::TooLarge, "request too large"));
    }
    req.key
        .verify(
            &signing::pairing_request(&token, &ciphertext),
            &body.signature,
        )
        .map_err(|_| AppError::bad_request("bad request signature"))?;
    let consumer = req.key.to_b64();
    let posted = state.with_db(|c| {
        db::post_pairing_request(
            c,
            &token,
            &consumer,
            &body.ciphertext,
            &body.signature,
            now(),
        )
    })?;
    if !posted {
        return Err(AppError::not_found(
            "invite is unknown, expired or already used",
        ));
    }
    state.notify();
    Ok(StatusCode::CREATED)
}

async fn pairing_status(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    Query(q): Query<WaitQuery>,
    req: Authed,
) -> AppResult<Json<PairingStatus>> {
    let consumer = req.key.to_b64();
    let check = || -> AppResult<Option<PairingStatus>> {
        let invite = state
            .with_db(|c| db::invite(c, &token))?
            .filter(|i| i.consumer.as_deref() == Some(consumer.as_str()))
            .ok_or_else(|| AppError::not_found("no pairing request from this key"))?;
        Ok(match invite.status.as_str() {
            "approved" => Some(PairingStatus::Approved {
                grant_id: invite.grant_id.unwrap_or_default(),
            }),
            "rejected" => Some(PairingStatus::Rejected),
            _ => None,
        })
    };
    Ok(Json(
        long_poll(&state, q.wait, check)
            .await?
            .unwrap_or(PairingStatus::Pending),
    ))
}

async fn get_mailbox(
    State(state): State<Arc<AppState>>,
    Query(q): Query<WaitQuery>,
    req: Authed,
) -> AppResult<Json<Mailbox>> {
    let owner = req.key.to_b64();
    let items = long_poll(&state, q.wait, || {
        let items = state.with_db(|c| db::mailbox(c, &owner))?;
        Ok((!items.is_empty()).then_some(items))
    })
    .await?
    .unwrap_or_default();
    Ok(Json(Mailbox { items }))
}

async fn delete_mailbox_item(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    req: Authed,
) -> AppResult<StatusCode> {
    let owner = req.key.to_b64();
    if state.with_db(|c| db::delete_mailbox_item(c, &owner, id))? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::not_found("no such mailbox item"))
    }
}

async fn create_grant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: Authed,
) -> AppResult<StatusCode> {
    valid_id(&id)?;
    let body: CreateGrant = req.json()?;
    let owner = req.key.to_b64();
    let invite = state
        .with_db(|c| db::invite(c, &body.invite_token))?
        .filter(|i| i.owner == owner)
        .ok_or_else(|| AppError::not_found("no such invite"))?;
    match (invite.status.as_str(), invite.grant_id.as_deref()) {
        ("approved", Some(g)) if g == id => return Ok(StatusCode::OK),
        ("requested", _) => {}
        _ => return Err(AppError::conflict("invite has no pending request")),
    }
    let consumer = invite
        .consumer
        .ok_or_else(|| AppError::conflict("invite has no pending request"))?;
    if invite.expires_at + db::INVITE_TTL_SECS < now() {
        return Err(AppError::conflict("pairing request expired"));
    }
    if state.with_db(|c| db::grant(c, &id))?.is_some() {
        return Err(AppError::conflict("grant ID already exists"));
    }
    state.with_db(|c| {
        db::create_grant(c, &id, &owner, &consumer, now())?;
        db::set_invite_status(c, &body.invite_token, "approved", Some(&id))
    })?;
    state.notify();
    Ok(StatusCode::CREATED)
}

/// Loads a grant and checks the caller is its owner.
fn owned_grant(state: &AppState, id: &str, key: &PublicKey) -> AppResult<db::Grant> {
    let owner = key.to_b64();
    state
        .with_db(|c| db::grant(c, id))?
        .filter(|g| g.owner == owner)
        .ok_or_else(|| AppError::not_found("no such grant"))
}

async fn revoke_grant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: Authed,
) -> AppResult<StatusCode> {
    owned_grant(&state, &id, &req.key)?;
    state.with_db(|c| db::delete_grant(c, &id))?;
    state.notify();
    Ok(StatusCode::NO_CONTENT)
}

async fn put_envelope(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: Authed,
) -> AppResult<StatusCode> {
    owned_grant(&state, &id, &req.key)?;
    let env: Envelope = req.json()?;
    if env.grant_id != id {
        return Err(AppError::bad_request("grant_id does not match the path"));
    }
    let ciphertext =
        unb64(&env.ciphertext).map_err(|_| AppError::bad_request("invalid ciphertext"))?;
    if ciphertext.len() > MAX_ENVELOPE_BYTES {
        return Err(AppError::new(ErrorCode::TooLarge, "envelope too large"));
    }
    req.key
        .verify(
            &signing::envelope(&id, env.version, &ciphertext),
            &env.signature,
        )
        .map_err(|_| AppError::bad_request("bad envelope signature"))?;
    if state
        .with_db(|c| db::envelope_version(c, &id))?
        .is_some_and(|v| v >= env.version)
    {
        return Err(AppError::conflict("version must increase"));
    }
    state.with_db(|c| db::put_envelope(c, &env))?;
    state.notify();
    Ok(StatusCode::NO_CONTENT)
}

async fn post_message(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    req: Authed,
) -> AppResult<StatusCode> {
    let consumer = req.key.to_b64();
    let grant = state
        .with_db(|c| db::grant(c, &id))?
        .filter(|g| g.consumer == consumer)
        .ok_or_else(|| AppError::not_found("no such grant"))?;
    let body: PostMessage = req.json()?;
    let ciphertext =
        unb64(&body.ciphertext).map_err(|_| AppError::bad_request("invalid ciphertext"))?;
    if ciphertext.len() > 8 * 1024 {
        return Err(AppError::new(ErrorCode::TooLarge, "message too large"));
    }
    req.key
        .verify(&signing::message(&id, &ciphertext), &body.signature)
        .map_err(|_| AppError::bad_request("bad message signature"))?;
    if state.with_db(|c| db::mailbox_count(c, &grant.owner))? >= db::MAILBOX_LIMIT {
        return Err(AppError::new(
            ErrorCode::RateLimited,
            "owner mailbox is full",
        ));
    }
    state.with_db(|c| {
        db::post_message(
            c,
            &grant.owner,
            &consumer,
            &id,
            &body.ciphertext,
            &body.signature,
            now(),
        )
    })?;
    state.notify();
    Ok(StatusCode::CREATED)
}

async fn poll_envelopes(
    State(state): State<Arc<AppState>>,
    Query(q): Query<WaitQuery>,
    req: Authed,
) -> AppResult<Json<EnvelopePollResult>> {
    let poll: EnvelopePoll = req.json()?;
    if poll.after.len() > 64 {
        return Err(AppError::bad_request("too many grants in one poll"));
    }
    let consumer = req.key.to_b64();
    let check = || -> AppResult<Option<EnvelopePollResult>> {
        let mut result = EnvelopePollResult::default();
        state.with_db(|c| {
            for (grant_id, after) in &poll.after {
                match db::grant(c, grant_id)? {
                    Some(g) if g.consumer == consumer => {
                        if let Some(env) = db::envelope(c, grant_id)?
                            && env.version > *after
                        {
                            result.envelopes.push(env);
                        }
                    }
                    _ => result.gone.push(grant_id.clone()),
                }
            }
            Ok(())
        })?;
        Ok((!result.envelopes.is_empty() || !result.gone.is_empty()).then_some(result))
    };
    Ok(Json(
        long_poll(&state, q.wait, check).await?.unwrap_or_default(),
    ))
}
