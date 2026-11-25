//! End to end: a real relay in-process, the real client, and a test owner that speaks the
//! extension's side of the protocol.

use std::time::Duration;

use cookie_communism::{Client, Event, Policy};
use cookie_communism_proto::api::{self, Envelope, Mailbox, MailboxItem, MailboxKind};
use cookie_communism_proto::{
    BoxIdentity, BoxRecipient, ConsumerMessage, Cookie, Invite, SameSite, Selector, SignKey,
    Snapshot, signing,
};
use reqwest::Method;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn start_relay() -> String {
    let state = cookie_communism_relay::AppState::new(Default::default()).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, cookie_communism_relay::router(state))
            .await
            .unwrap();
    });
    format!("http://{addr}")
}

/// The extension's side of the protocol, for tests.
struct TestOwner {
    relay: String,
    label: String,
    sign: SignKey,
    boxid: BoxIdentity,
    http: reqwest::Client,
}

impl TestOwner {
    fn new(relay: &str, label: &str) -> Self {
        Self {
            relay: relay.into(),
            label: label.into(),
            sign: SignKey::generate(),
            boxid: BoxIdentity::generate(),
            http: reqwest::Client::new(),
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> reqwest::Response {
        let body = body
            .map(|b| serde_json::to_vec(&b).unwrap())
            .unwrap_or_default();
        let mut req = self
            .http
            .request(method.clone(), format!("{}{path}", self.relay));
        for (k, v) in api::auth_headers(&self.sign, method.as_str(), path, &body, now()) {
            req = req.header(k, v);
        }
        req.header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap()
    }

    async fn invite(&self) -> (String, String) {
        let token = cookie_communism_proto::random_id();
        let res = self
            .call(
                Method::POST,
                "/invites",
                Some(serde_json::json!({ "token": token })),
            )
            .await;
        assert_eq!(res.status(), 201, "{}", res.text().await.unwrap());
        let invite = Invite {
            relay: self.relay.clone(),
            owner_sign: self.sign.public().to_b64(),
            owner_box: self.boxid.recipient().to_string(),
            token: token.clone(),
        };
        (invite.encode(), token)
    }

    async fn mailbox(&self, wait: u64) -> Vec<MailboxItem> {
        let res = self
            .call(Method::GET, &format!("/mailbox?wait={wait}"), None)
            .await;
        res.json::<Mailbox>().await.unwrap().items
    }

    async fn ack(&self, item: &MailboxItem) {
        let res = self
            .call(Method::DELETE, &format!("/mailbox/{}", item.id), None)
            .await;
        assert_eq!(res.status(), 204);
    }

    /// Approves the next pairing request; returns (grant ID, consumer box, pairing code).
    async fn approve_next(&self) -> (String, BoxRecipient, String) {
        let item = self
            .mailbox(10)
            .await
            .into_iter()
            .find(|i| i.kind == MailboxKind::Pairing)
            .expect("a pairing request");
        let request = item.open_pairing(&self.boxid).unwrap();
        let token = item.invite_token.clone().unwrap();
        let code = signing::pairing_code(
            &self.sign.public().to_b64(),
            &self.boxid.recipient().to_string(),
            &request.consumer_sign,
            &request.consumer_box,
            &token,
        );
        let grant_id = cookie_communism_proto::random_id();
        let res = self
            .call(
                Method::PUT,
                &format!("/grants/{grant_id}"),
                Some(serde_json::json!({ "invite_token": token })),
            )
            .await;
        assert_eq!(res.status(), 201, "{}", res.text().await.unwrap());
        self.ack(&item).await;
        (
            grant_id,
            BoxRecipient::parse(&request.consumer_box).unwrap(),
            code,
        )
    }

    async fn push(
        &self,
        grant_id: &str,
        version: u64,
        to: &BoxRecipient,
        selectors: &[&str],
        cookies: Vec<Cookie>,
    ) {
        let snapshot = Snapshot {
            owner_label: self.label.clone(),
            taken_at: now(),
            selectors: selectors
                .iter()
                .map(|s| Selector::parse(s).unwrap())
                .collect(),
            cookies,
        };
        let env = Envelope::seal(grant_id, version, &snapshot, to, &self.sign).unwrap();
        let res = self
            .call(
                Method::PUT,
                &format!("/grants/{grant_id}/envelope"),
                Some(serde_json::to_value(&env).unwrap()),
            )
            .await;
        assert_eq!(res.status(), 204, "{}", res.text().await.unwrap());
    }

    async fn messages(&self, grant_id: &str, consumer: &str) -> Vec<ConsumerMessage> {
        let consumer = cookie_communism_proto::PublicKey::from_b64(consumer).unwrap();
        let mut out = Vec::new();
        for item in self.mailbox(0).await {
            if item.kind == MailboxKind::Message && item.grant_id.as_deref() == Some(grant_id) {
                out.push(item.open_message(&consumer, &self.boxid).unwrap());
                self.ack(&item).await;
            }
        }
        out
    }
}

fn cookie(name: &str, value: &str, expires_in: i64, changed_ago: i64) -> Cookie {
    Cookie {
        domain: ".example.com".into(),
        host_only: false,
        name: name.into(),
        value: value.into(),
        path: "/".into(),
        secure: true,
        http_only: true,
        same_site: SameSite::Lax,
        expires: Some(now() + expires_in),
        partition_key: None,
        changed_at: now() - changed_ago,
    }
}

/// Pairs `client_path` with `owner`, pushing `cookies` as the first snapshot.
async fn pair(
    owner: &TestOwner,
    path: &std::path::Path,
    cookies: Vec<Cookie>,
) -> (Client, String, BoxRecipient) {
    let (invite, _) = owner.invite().await;
    let pending = Client::pair(path, &invite, "test-bot", &["example.com:sid"])
        .await
        .unwrap();
    // A second browser for the same domain is flagged.
    let already: Vec<String> = Client::open(path)
        .map(|c| c.owners().into_iter().map(|o| o.owner.label).collect())
        .unwrap_or_default();
    assert_eq!(pending.overlaps(), already.as_slice());
    let consumer_code = pending.code().to_string();
    let waiter = tokio::spawn(pending.approved());
    let (grant, consumer_box, owner_code) = owner.approve_next().await;
    assert_eq!(
        owner_code, consumer_code,
        "both sides must show the same pairing code"
    );
    owner
        .push(&grant, 1, &consumer_box, &["example.com:sid"], cookies)
        .await;
    let client = waiter.await.unwrap().unwrap();
    (client, grant, consumer_box)
}

fn consumer_key(path: &std::path::Path) -> String {
    let state: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    SignKey::from_b64(state["consumer_sign"].as_str().unwrap())
        .unwrap()
        .public()
        .to_b64()
}

#[tokio::test]
async fn pair_sync_and_cookie_store() {
    let relay = start_relay().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let owner = TestOwner::new(&relay, "Firefox");

    let (client, grant, consumer_box) =
        pair(&owner, &path, vec![cookie("sid", "one", 3600, 10)]).await;
    assert_eq!(client.jar().cookies[0].value, "one");
    assert!(client.jar().to_netscape().contains("\tsid\tone\n"));
    assert_eq!(client.owners()[0].owner.label, "Firefox");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // The reqwest store serves the synced cookie, and follows updates.
    use reqwest::cookie::CookieStore;
    let store = client.cookie_store();
    let url = url::Url::parse("https://www.example.com/").unwrap();
    assert_eq!(store.cookies(&url).unwrap(), "sid=one");

    let poll = tokio::spawn(async move {
        let events = client.poll(Duration::from_secs(10)).await.unwrap();
        (client, events)
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    owner
        .push(
            &grant,
            2,
            &consumer_box,
            &["example.com:sid"],
            vec![cookie("sid", "two", 3600, 0)],
        )
        .await;
    let (client, events) = poll.await.unwrap();
    assert!(
        matches!(&events[..], [Event::Updated { group, .. }] if group == "example.com"),
        "{events:?}"
    );
    assert_eq!(store.cookies(&url).unwrap(), "sid=two");

    // State survives a restart.
    drop(client);
    let reopened = Client::open(&path).unwrap();
    assert_eq!(reopened.jar().cookies[0].value, "two");

    // Pairing again with the same browser is refused.
    let (invite, _) = owner.invite().await;
    assert!(matches!(
        Client::pair(&path, &invite, "x", &["example.com:sid"]).await,
        Err(cookie_communism::Error::AlreadyPaired(_))
    ));
}

#[tokio::test]
async fn several_owners_policies_failure_and_revocation() {
    let relay = start_relay().await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let a = TestOwner::new(&relay, "Glide");
    let b = TestOwner::new(&relay, "Chrome");

    // A logged in long ago with a long expiry; B more recently with a shorter one.
    let (client, grant_a, _) = pair(&a, &path, vec![cookie("sid", "a", 30 * 86400, 86400)]).await;
    drop(client);
    let (client, grant_b, box_b) = pair(&b, &path, vec![cookie("sid", "b", 86400, 60)]).await;
    let consumer = consumer_key(&path);

    // Default `longest`: A, even though B is fresher.
    assert_eq!(client.jar().cookies[0].value, "a");
    let events = client.set_policy(Policy::Freshest).unwrap();
    assert!(
        matches!(&events[..], [Event::Switched { to, .. }] if to.label == "Chrome"),
        "{events:?}"
    );
    assert_eq!(client.jar().cookies[0].value, "b");
    client
        .set_policy_for(
            "example.com:sid",
            Some(Policy::Pinned {
                owner: "Glide".into(),
            }),
        )
        .unwrap();
    assert_eq!(client.jar().cookies[0].value, "a");
    client.set_policy_for("example.com:sid", None).unwrap();
    client.set_policy(Policy::default()).unwrap();
    assert_eq!(client.status()[0].owner.as_ref().unwrap().label, "Glide");

    // A's cookie stops working: fail over to B, and only A is asked to refresh.
    let events = client
        .report_failure("example.com:sid", "401 from /api")
        .await
        .unwrap();
    assert!(
        matches!(&events[..], [Event::Switched { to, .. }] if to.label == "Chrome"),
        "{events:?}"
    );
    assert!(matches!(
        &a.messages(&grant_a, &consumer).await[..],
        [ConsumerMessage::Refresh { .. }]
    ));
    assert!(b.messages(&grant_b, &consumer).await.is_empty());

    // B fails too: nothing usable; both browsers are asked to refresh.
    let events = client
        .report_failure("example.com:sid", "401 again")
        .await
        .unwrap();
    assert!(
        matches!(&events[..], [Event::Unavailable { .. }]),
        "{events:?}"
    );
    assert!(client.jar().cookies.is_empty());
    assert!(matches!(
        &a.messages(&grant_a, &consumer).await[..],
        [ConsumerMessage::Refresh { .. }]
    ));
    assert!(matches!(
        &b.messages(&grant_b, &consumer).await[..],
        [ConsumerMessage::Refresh { .. }]
    ));

    // The user logs in again in B: B is chosen, and both get `resolved`.
    b.push(
        &grant_b,
        2,
        &box_b,
        &["example.com:sid"],
        vec![cookie("sid", "b2", 86400, 0)],
    )
    .await;
    let events = client.sync().await.unwrap();
    assert!(
        matches!(&events[..], [Event::Switched { to, .. }] if to.label == "Chrome"),
        "{events:?}"
    );
    assert_eq!(client.jar().cookies[0].value, "b2");
    assert!(matches!(
        &a.messages(&grant_a, &consumer).await[..],
        [ConsumerMessage::Resolved { .. }]
    ));
    assert!(matches!(
        &b.messages(&grant_b, &consumer).await[..],
        [ConsumerMessage::Resolved { .. }]
    ));

    // B revokes: the consumer forgets it; A is still marked broken, so nothing is usable.
    let res = b
        .call(Method::DELETE, &format!("/grants/{grant_b}"), None)
        .await;
    assert_eq!(res.status(), 204);
    let events = client.sync().await.unwrap();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Revoked { owner } if owner.label == "Chrome")),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::Unavailable { .. })),
        "{events:?}"
    );
    assert_eq!(client.owners().len(), 1);
}

#[tokio::test]
async fn relay_enforces_authentication_and_membership() {
    let relay = start_relay().await;
    let owner = TestOwner::new(&relay, "Firefox");
    let http = reqwest::Client::new();

    // Browsers may call the relay cross-origin with the signature headers.
    let res = http
        .request(Method::OPTIONS, format!("{relay}/mailbox"))
        .header("origin", "moz-extension://abc")
        .header("access-control-request-method", "GET")
        .header(
            "access-control-request-headers",
            "cc-key,cc-time,cc-nonce,cc-sig",
        )
        .send()
        .await
        .unwrap();
    assert!(res.status().is_success());
    assert_eq!(res.headers()["access-control-allow-origin"], "*");

    // Unsigned and replayed requests.
    let res = http.get(format!("{relay}/mailbox")).send().await.unwrap();
    assert_eq!(res.status(), 401);
    let headers = api::auth_headers(&owner.sign, "GET", "/mailbox", b"", now());
    let send = || {
        let mut req = http.get(format!("{relay}/mailbox"));
        for (k, v) in &headers {
            req = req.header(*k, v);
        }
        req.send()
    };
    assert_eq!(send().await.unwrap().status(), 200);
    assert_eq!(send().await.unwrap().status(), 401);

    // An invite can be used once.
    let (invite, token) = owner.invite().await;
    let dir = tempfile::tempdir().unwrap();
    let _pending = Client::pair(dir.path().join("1.json"), &invite, "x", &["example.com"])
        .await
        .unwrap();
    assert!(
        Client::pair(dir.path().join("2.json"), &invite, "x", &["example.com"])
            .await
            .is_err()
    );

    // Another owner cannot approve it.
    let intruder = TestOwner::new(&relay, "Intruder");
    intruder.invite().await;
    let res = intruder
        .call(
            Method::PUT,
            "/grants/AAAAAAAAAAAAAAAAAAAAAA",
            Some(serde_json::json!({ "invite_token": token })),
        )
        .await;
    assert_eq!(res.status(), 404);

    // Envelopes with a bad signature, or a non-increasing version, are refused.
    let (grant, consumer_box, _) = owner.approve_next().await;
    owner
        .push(&grant, 5, &consumer_box, &["example.com"], vec![])
        .await;
    let snapshot = Snapshot {
        owner_label: "x".into(),
        taken_at: 0,
        selectors: vec![],
        cookies: vec![],
    };
    let stale = Envelope::seal(&grant, 5, &snapshot, &consumer_box, &owner.sign).unwrap();
    let res = owner
        .call(
            Method::PUT,
            &format!("/grants/{grant}/envelope"),
            Some(serde_json::to_value(&stale).unwrap()),
        )
        .await;
    assert_eq!(res.status(), 409);
    let mut forged = Envelope::seal(&grant, 6, &snapshot, &consumer_box, &intruder.sign).unwrap();
    forged.grant_id = grant.clone();
    let res = owner
        .call(
            Method::PUT,
            &format!("/grants/{grant}/envelope"),
            Some(serde_json::to_value(&forged).unwrap()),
        )
        .await;
    assert_eq!(res.status(), 400);

    // A stranger polling the grant is told it is gone.
    let res = intruder
        .call(
            Method::POST,
            "/envelopes",
            Some(serde_json::json!({ "after": { grant.clone(): 0 } })),
        )
        .await;
    let body: api::EnvelopePollResult = res.json().await.unwrap();
    assert!(body.envelopes.is_empty());
    assert_eq!(body.gone, vec![grant]);
}
