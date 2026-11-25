use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use cookie_communism_proto::api::{
    EnvelopePoll, EnvelopePollResult, ErrorCode, PairingStatus, PostMessage, PostPairingRequest,
};
use cookie_communism_proto::{
    BoxRecipient, ConsumerMessage, Invite, PairingRequest, PublicKey, Selector, signing,
};
use futures_util::Stream;
use reqwest::Method;
use rustls_platform_verifier::BuilderVerifierExt;

use crate::jar::{Jar, SharedJar};
use crate::policy::{self, Choice, Policy};
use crate::relay::Relay;
use crate::state::{Current, OwnerState, State};
use crate::{Error, Result, now};

/// A paired browser, as shown to the application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRef {
    pub id: String,
    pub label: String,
}

impl std::fmt::Display for OwnerRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The current owner sent changed cookies for a group.
    Updated { group: String, owner: OwnerRef },
    /// A group's cookies now come from another owner.
    Switched {
        group: String,
        from: Option<OwnerRef>,
        to: OwnerRef,
    },
    /// No owner can supply a group any more.
    Unavailable { group: String, reason: String },
    /// An owner revoked this consumer's grant.
    Revoked { owner: OwnerRef },
}

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::Updated { group, owner } => write!(f, "{group}: updated by {owner}"),
            Event::Switched {
                group,
                from: Some(from),
                to,
            } => {
                write!(f, "{group}: switched from {from} to {to}")
            }
            Event::Switched {
                group,
                from: None,
                to,
            } => write!(f, "{group}: now from {to}"),
            Event::Unavailable { group, reason } => write!(f, "{group}: unavailable ({reason})"),
            Event::Revoked { owner } => write!(f, "{owner} revoked access"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OwnerInfo {
    pub owner: OwnerRef,
    pub relay: String,
    pub selectors: Vec<Selector>,
    /// Unix seconds of the latest snapshot.
    pub snapshot_taken_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct GroupStatus {
    pub domain: String,
    pub selectors: Vec<Selector>,
    pub policy: Policy,
    pub owner: Option<OwnerRef>,
    /// Set when `owner` is `None`.
    pub unavailable: Option<String>,
    /// Earliest expiry among the chosen cookies, Unix seconds.
    pub expires: Option<i64>,
}

/// A consumer paired with one or more browsers.
pub struct Client {
    path: PathBuf,
    state: Mutex<State>,
    http: reqwest::Client,
    jar: Arc<SharedJar>,
}

/// A pairing request posted to the relay, waiting for the user to approve it in the browser.
pub struct PendingPairing {
    path: PathBuf,
    state: State,
    invite: Invite,
    code: String,
    overlaps: Vec<String>,
    http: reqwest::Client,
}

impl PendingPairing {
    /// The code the user compares with the one the extension shows.
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Labels of already paired browsers that supply a domain this pairing asks for. Policies
    /// assume every browser is logged in to the same account on a site.
    pub fn overlaps(&self) -> &[String] {
        &self.overlaps
    }

    /// Waits until the user approves (or rejects) the request, then fetches the first snapshot.
    pub async fn approved(mut self) -> Result<Client> {
        let relay = Relay::new(
            self.http.clone(),
            &self.invite.relay,
            self.state.sign_key()?,
        );
        let path = format!("/pairing/{}", self.invite.token);
        let grant_id = loop {
            let status: Option<PairingStatus> = relay
                .call(
                    Method::GET,
                    &path,
                    None::<&()>,
                    Some(Duration::from_secs(60)),
                )
                .await?;
            match status {
                Some(PairingStatus::Approved { grant_id }) => break grant_id,
                Some(PairingStatus::Rejected) => return Err(Error::PairingRejected),
                _ => continue,
            }
        };
        self.state.owners.push(OwnerState {
            grant_id: grant_id.clone(),
            relay: self.invite.relay.clone(),
            owner_sign: self.invite.owner_sign.clone(),
            owner_box: self.invite.owner_box.clone(),
            label: "browser".into(),
            version: 0,
            snapshot: None,
            broken: BTreeMap::new(),
        });
        self.state.save(&self.path)?;
        let client = Client::from_state(self.path, self.state, self.http);
        // The extension uploads the first snapshot right after approving.
        for _ in 0..3 {
            client.poll(Duration::from_secs(20)).await?;
            if client
                .lock()
                .owners
                .iter()
                .any(|o| o.grant_id == grant_id && o.snapshot.is_some())
            {
                break;
            }
        }
        Ok(client)
    }
}

impl Client {
    /// Posts a pairing request for `wants` (selectors like `example.com:session`) using an
    /// invite from the extension. Pairing again with another browser's invite adds that browser
    /// to the same state file.
    pub async fn pair(
        state_path: impl AsRef<Path>,
        invite: &str,
        label: &str,
        wants: &[impl AsRef<str>],
    ) -> Result<PendingPairing> {
        let path = state_path.as_ref().to_path_buf();
        let invite = Invite::decode(invite)?;
        PublicKey::from_b64(&invite.owner_sign)?;
        let owner_box = BoxRecipient::parse(&invite.owner_box)?;
        let state = State::load_or_new(&path)?;
        if let Some(o) = state
            .owners
            .iter()
            .find(|o| o.owner_sign == invite.owner_sign)
        {
            return Err(Error::AlreadyPaired(o.label.clone()));
        }
        let wants = wants
            .iter()
            .map(|w| Selector::parse(w.as_ref()))
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let overlaps = state
            .owners
            .iter()
            .filter(|o| {
                o.snapshot.as_ref().is_some_and(|s| {
                    s.selectors
                        .iter()
                        .any(|have| wants.iter().any(|w| w.domain == have.domain))
                })
            })
            .map(|o| o.label.clone())
            .collect();
        let key = state.sign_key()?;
        let consumer_sign = key.public().to_b64();
        let consumer_box = state.box_identity()?.recipient().to_string();
        let request = PairingRequest {
            label: label.to_string(),
            wants,
            consumer_sign: consumer_sign.clone(),
            consumer_box: consumer_box.clone(),
        };
        let body = PostPairingRequest::seal(&request, &invite.token, &owner_box, &key)?;
        let http = http_client();
        Relay::new(http.clone(), &invite.relay, key)
            .call::<serde_json::Value>(
                Method::POST,
                &format!("/invites/{}/request", invite.token),
                Some(&body),
                None,
            )
            .await?;
        let code = signing::pairing_code(
            &invite.owner_sign,
            &invite.owner_box,
            &consumer_sign,
            &consumer_box,
            &invite.token,
        );
        Ok(PendingPairing {
            path,
            state,
            invite,
            code,
            overlaps,
            http,
        })
    }

    pub fn open(state_path: impl AsRef<Path>) -> Result<Self> {
        let path = state_path.as_ref().to_path_buf();
        let state = State::load(&path)?;
        Ok(Self::from_state(path, state, http_client()))
    }

    fn from_state(path: PathBuf, state: State, http: reqwest::Client) -> Self {
        let jar = Arc::new(SharedJar::new(&chosen_jar(&state)));
        Self {
            path,
            state: Mutex::new(state),
            http,
            jar,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The policy for groups without a selector-specific one.
    pub fn set_policy(&self, policy: Policy) -> Result<Vec<Event>> {
        self.mutate(|s| s.default_policy = policy)
    }

    /// Sets (or with `None`, clears) the policy for one selector. A policy for a bare domain
    /// (`example.com`) applies to every selector on it.
    pub fn set_policy_for(&self, selector: &str, policy: Option<Policy>) -> Result<Vec<Event>> {
        let selector = Selector::parse(selector)?;
        self.mutate(|s| match policy {
            Some(p) => drop(s.policies.insert(selector, p)),
            None => drop(s.policies.remove(&selector)),
        })
    }

    /// Forgets a browser locally. The grant stays on the relay until the browser revokes it.
    pub fn remove_owner(&self, owner: &str) -> Result<Vec<Event>> {
        let mut state = self.lock();
        let before = state.owners.len();
        state
            .owners
            .retain(|o| o.grant_id != owner && o.label != owner);
        if state.owners.len() == before {
            return Err(Error::UnknownOwner(owner.to_string()));
        }
        drop(state);
        self.mutate(|_| ())
    }

    fn mutate(&self, f: impl FnOnce(&mut State)) -> Result<Vec<Event>> {
        let mut state = self.lock();
        f(&mut state);
        // `resolved` messages need the network; leave pending refreshes for the next poll.
        let (events, _) = recompute(&mut state, now(), false);
        state.save(&self.path)?;
        self.apply_events(&state, &events);
        Ok(events)
    }

    pub fn owners(&self) -> Vec<OwnerInfo> {
        self.lock()
            .owners
            .iter()
            .map(|o| OwnerInfo {
                owner: OwnerRef {
                    id: o.grant_id.clone(),
                    label: o.label.clone(),
                },
                relay: o.relay.clone(),
                selectors: o
                    .snapshot
                    .as_ref()
                    .map(|s| s.selectors.clone())
                    .unwrap_or_default(),
                snapshot_taken_at: o.snapshot.as_ref().map(|s| s.taken_at),
            })
            .collect()
    }

    pub fn status(&self) -> Vec<GroupStatus> {
        let state = self.lock();
        let now = now();
        state
            .groups()
            .into_iter()
            .map(|g| {
                let policy = state.policy_for(&g).clone();
                let current = state.current.get(&g.domain).map(|c| c.owner.as_str());
                let (owner, unavailable) =
                    match policy::choose(&policy, &g, &state.sources(&g), current, now) {
                        Choice::Owner(id) => (Some(owner_ref(&state, &id)), None),
                        Choice::None(why) => (None, Some(why)),
                    };
                let expires = owner.as_ref().and_then(|o| {
                    let snap = state
                        .owners
                        .iter()
                        .find(|x| x.grant_id == o.id)?
                        .snapshot
                        .as_ref()?;
                    g.cookies(snap).iter().filter_map(|c| c.expires).min()
                });
                GroupStatus {
                    domain: g.domain.clone(),
                    selectors: g.selectors.iter().cloned().collect(),
                    policy,
                    owner,
                    unavailable,
                    expires,
                }
            })
            .collect()
    }

    /// The cookies currently chosen for every group.
    pub fn jar(&self) -> Jar {
        chosen_jar(&self.lock())
    }

    /// A reqwest cookie store that follows the chosen cookies as they change.
    pub fn cookie_store(&self) -> Arc<SharedJar> {
        self.jar.clone()
    }

    /// Fetches new snapshots from every relay without waiting.
    pub async fn sync(&self) -> Result<Vec<Event>> {
        self.poll(Duration::ZERO).await
    }

    /// Fetches new snapshots, waiting up to `wait` for one to arrive.
    pub async fn poll(&self, wait: Duration) -> Result<Vec<Event>> {
        let (key, polls) = {
            let state = self.lock();
            let mut polls: BTreeMap<String, EnvelopePoll> = BTreeMap::new();
            for o in &state.owners {
                polls
                    .entry(o.relay.clone())
                    .or_default()
                    .after
                    .insert(o.grant_id.clone(), o.version);
            }
            (state.sign_key()?, polls)
        };
        if polls.is_empty() {
            tokio::time::sleep(wait).await;
            return Ok(Vec::new());
        }
        let calls = polls.into_iter().map(|(base, poll)| {
            let relay = Relay::new(self.http.clone(), &base, key.clone());
            Box::pin(async move {
                relay
                    .call::<EnvelopePollResult>(Method::POST, "/envelopes", Some(&poll), Some(wait))
                    .await
            })
        });
        // With several relays, take whichever answers first; the others are asked again on the
        // next poll, and relays keep the latest envelope, so nothing is lost.
        let (result, _, _) = futures_util::future::select_all(calls).await;
        let result = result?.unwrap_or_default();
        self.process(result).await
    }

    async fn process(&self, result: EnvelopePollResult) -> Result<Vec<Event>> {
        let (events, messages) = {
            let mut state = self.lock();
            let identity = state.box_identity()?;
            let mut events = Vec::new();
            for env in &result.envelopes {
                let Some(owner) = state.owner_mut(&env.grant_id) else {
                    continue;
                };
                if env.version <= owner.version {
                    continue;
                }
                let opened =
                    PublicKey::from_b64(&owner.owner_sign).and_then(|k| env.open(&k, &identity));
                // A bad envelope still advances the version, so a relay serving it cannot make
                // the consumer spin; the previous snapshot stays in use.
                owner.version = env.version;
                match opened {
                    Ok(snapshot) => {
                        owner.label = snapshot.owner_label.clone();
                        owner.snapshot = Some(snapshot);
                    }
                    Err(e) => tracing::error!(
                        "discarding envelope {} v{} from {}: {e}",
                        env.grant_id,
                        env.version,
                        owner.label
                    ),
                }
            }
            for gone in &result.gone {
                if let Some(pos) = state.owners.iter().position(|o| &o.grant_id == gone) {
                    let o = state.owners.remove(pos);
                    events.push(Event::Revoked {
                        owner: OwnerRef {
                            id: o.grant_id,
                            label: o.label,
                        },
                    });
                }
            }
            let (more, messages) = recompute(&mut state, now(), true);
            events.extend(more);
            state.save(&self.path)?;
            self.apply_events(&state, &events);
            (events, messages)
        };
        self.send_messages(messages).await;
        Ok(events)
    }

    /// Reports that the cookies for `selector` stopped working. The current owner is marked
    /// broken until its cookies change, the policy picks another owner if one is usable, and
    /// browsers are asked to refresh (design §4.7).
    pub async fn report_failure(&self, selector: &str, reason: &str) -> Result<Vec<Event>> {
        let selector = Selector::parse(selector)?;
        let (events, messages) = {
            let mut state = self.lock();
            let now = now();
            let group = state
                .group_for(&selector)
                .ok_or_else(|| Error::UnknownSelector(selector.to_string()))?;
            let broken_owner = state.current.get(&group.domain).map(|c| c.owner.clone());
            if let Some(id) = &broken_owner
                && let Some(owner) = state.owner_mut(id)
                && let Some(snapshot) = &owner.snapshot
            {
                let fp = group.fingerprint(snapshot);
                owner.broken.insert(group.domain.clone(), fp);
            }
            let (events, mut messages) = recompute(&mut state, now, true);
            let refresh = ConsumerMessage::Refresh {
                selector: selector.clone(),
                reason: reason.to_string(),
            };
            if state.current.contains_key(&group.domain) {
                // Another browser took over; only the broken one needs to look at its cookies.
                messages.extend(broken_owner.map(|id| (id, refresh)));
            } else {
                let targets = policy::refresh_targets(
                    state.policy_for(&group),
                    &group,
                    &state.sources(&group),
                    now,
                );
                state
                    .pending_refresh
                    .entry(group.domain.clone())
                    .or_default()
                    .extend(targets.iter().cloned());
                messages.extend(targets.into_iter().map(|id| (id, refresh.clone())));
            }
            state.save(&self.path)?;
            self.apply_events(&state, &events);
            (events, messages)
        };
        self.send_messages(messages).await;
        Ok(events)
    }

    /// Long-polls forever, yielding events as snapshots arrive. Errors are yielded too; after
    /// one, the next poll waits with exponential backoff (up to 5 minutes).
    pub fn watch(&self) -> impl Stream<Item = Result<Event>> + '_ {
        struct W {
            queue: VecDeque<Result<Event>>,
            failures: u32,
        }
        futures_util::stream::unfold(
            W {
                queue: VecDeque::new(),
                failures: 0,
            },
            move |mut w| async move {
                loop {
                    if let Some(item) = w.queue.pop_front() {
                        return Some((item, w));
                    }
                    if w.failures > 0 {
                        let secs = 5u64.saturating_mul(1 << w.failures.min(6)).min(300);
                        tokio::time::sleep(Duration::from_secs(secs)).await;
                    }
                    match self.poll(Duration::from_secs(60)).await {
                        Ok(events) => {
                            w.failures = 0;
                            w.queue.extend(events.into_iter().map(Ok));
                        }
                        Err(e) => {
                            w.failures += 1;
                            w.queue.push_back(Err(e));
                        }
                    }
                }
            },
        )
    }

    fn apply_events(&self, state: &State, events: &[Event]) {
        if events.is_empty() {
            return;
        }
        for event in events {
            match event {
                Event::Switched { group, .. } | Event::Unavailable { group, .. } => {
                    self.jar.drop_local(group, None)
                }
                Event::Updated { group, owner } => {
                    let names: BTreeSet<String> = state
                        .owners
                        .iter()
                        .find(|o| o.grant_id == owner.id)
                        .and_then(|o| o.snapshot.as_ref())
                        .map(|s| {
                            s.cookies
                                .iter()
                                .filter(|c| {
                                    c.host() == group || c.host().ends_with(&format!(".{group}"))
                                })
                                .map(|c| c.name.clone())
                                .collect()
                        })
                        .unwrap_or_default();
                    self.jar.drop_local(group, Some(&names));
                }
                Event::Revoked { .. } => {}
            }
        }
        self.jar.replace_synced(&chosen_jar(state));
    }

    async fn send_messages(&self, messages: Vec<(String, ConsumerMessage)>) {
        for (grant_id, message) in messages {
            let target = {
                let state = self.lock();
                let key = match state.sign_key() {
                    Ok(k) => k,
                    Err(e) => return tracing::error!("{e}"),
                };
                state
                    .owners
                    .iter()
                    .find(|o| o.grant_id == grant_id)
                    .map(|o| (o.relay.clone(), o.owner_box.clone(), o.label.clone(), key))
            };
            let Some((relay, owner_box, label, key)) = target else {
                continue;
            };
            let sealed = BoxRecipient::parse(&owner_box)
                .and_then(|r| PostMessage::seal(&grant_id, &message, &r, &key));
            let result = match sealed {
                Ok(body) => Relay::new(self.http.clone(), &relay, key)
                    .call::<serde_json::Value>(
                        Method::POST,
                        &format!("/grants/{grant_id}/messages"),
                        Some(&body),
                        None,
                    )
                    .await
                    .map(drop),
                Err(e) => Err(e.into()),
            };
            match result {
                Ok(()) => tracing::info!("sent {message:?} to {label}"),
                Err(Error::Rejected {
                    code: ErrorCode::RateLimited,
                    ..
                }) => {
                    tracing::warn!("{label}'s mailbox is full; not sent: {message:?}")
                }
                Err(e) => tracing::warn!("could not message {label}: {e}"),
            }
        }
    }
}

fn http_client() -> reqwest::Client {
    // rustls with ring and the OS's certificate verifier, handed to reqwest directly rather than
    // installed as the process-wide default, which an embedding application may set itself.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .and_then(|b| b.with_platform_verifier())
        .expect("TLS configuration builds")
        .with_no_client_auth();
    reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .user_agent(concat!("cookie-communism/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .build()
        .expect("HTTP client builds")
}

fn owner_ref(state: &State, id: &str) -> OwnerRef {
    let label = state
        .owners
        .iter()
        .find(|o| o.grant_id == id)
        .map(|o| o.label.clone())
        .unwrap_or_else(|| id.to_string());
    OwnerRef {
        id: id.to_string(),
        label,
    }
}

fn chosen_jar(state: &State) -> Jar {
    let mut cookies = Vec::new();
    for group in state.groups() {
        let Some(current) = state.current.get(&group.domain) else {
            continue;
        };
        let Some(snapshot) = state
            .owners
            .iter()
            .find(|o| o.grant_id == current.owner)
            .and_then(|o| o.snapshot.as_ref())
        else {
            continue;
        };
        cookies.extend(group.cookies(snapshot).into_iter().cloned());
    }
    Jar { cookies }
}

/// Re-evaluates every group's owner. Returns the resulting events and, if `resolve`, the
/// `resolved` messages owed to browsers that were asked to refresh.
fn recompute(
    state: &mut State,
    now: i64,
    resolve: bool,
) -> (Vec<Event>, Vec<(String, ConsumerMessage)>) {
    let mut events = Vec::new();
    let mut messages = Vec::new();
    let groups = state.groups();
    for group in &groups {
        let policy = state.policy_for(group).clone();
        let previous = state.current.get(&group.domain).cloned();
        let choice = policy::choose(
            &policy,
            group,
            &state.sources(group),
            previous.as_ref().map(|c| c.owner.as_str()),
            now,
        );
        match choice {
            Choice::Owner(id) => {
                let fingerprint = snapshot_of(state, &id)
                    .map(|s| group.fingerprint(s))
                    .unwrap_or_default();
                let to = owner_ref(state, &id);
                match &previous {
                    Some(p) if p.owner == id => {
                        if p.fingerprint != fingerprint {
                            events.push(Event::Updated {
                                group: group.domain.clone(),
                                owner: to,
                            });
                        }
                    }
                    _ => events.push(Event::Switched {
                        group: group.domain.clone(),
                        from: previous.as_ref().map(|p| owner_ref(state, &p.owner)),
                        to,
                    }),
                }
                state.current.insert(
                    group.domain.clone(),
                    Current {
                        owner: id,
                        fingerprint,
                    },
                );
                if resolve && let Some(asked) = state.pending_refresh.remove(&group.domain) {
                    let selector = Selector {
                        domain: group.domain.clone(),
                        name: None,
                    };
                    messages.extend(asked.into_iter().map(|o| {
                        (
                            o,
                            ConsumerMessage::Resolved {
                                selector: selector.clone(),
                            },
                        )
                    }));
                }
            }
            Choice::None(reason) => {
                if state.current.remove(&group.domain).is_some() {
                    events.push(Event::Unavailable {
                        group: group.domain.clone(),
                        reason,
                    });
                }
            }
        }
    }
    let live: BTreeSet<&str> = groups.iter().map(|g| g.domain.as_str()).collect();
    let stale: Vec<String> = state
        .current
        .keys()
        .filter(|d| !live.contains(d.as_str()))
        .cloned()
        .collect();
    for domain in stale {
        state.current.remove(&domain);
        events.push(Event::Unavailable {
            group: domain,
            reason: "no paired browser covers it".into(),
        });
    }
    (events, messages)
}

fn snapshot_of<'a>(state: &'a State, id: &str) -> Option<&'a cookie_communism_proto::Snapshot> {
    state
        .owners
        .iter()
        .find(|o| o.grant_id == id)?
        .snapshot
        .as_ref()
}
