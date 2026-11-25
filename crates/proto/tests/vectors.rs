//! Cross-language test vectors in `testdata/vectors/proto.json`.
//!
//! The extension's tests (extension/test/vectors.test.ts) check its TypeScript implementation
//! against the same file. Run with `CC_WRITE_VECTORS=1` to regenerate it; otherwise this test
//! checks that the file still matches this implementation.

use std::path::PathBuf;

use cookie_communism_proto::api::Envelope;
use cookie_communism_proto::{
    BoxIdentity, Cookie, Invite, SameSite, Selector, SignKey, Snapshot, signing,
};
use serde_json::{Value, json};

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/proto.json")
}

fn snapshot() -> Snapshot {
    Snapshot {
        owner_label: "Glide — laptop".into(),
        taken_at: 1_800_000_000,
        selectors: vec![Selector::parse("example.com:sid").unwrap()],
        cookies: vec![Cookie {
            domain: ".example.com".into(),
            host_only: false,
            name: "sid".into(),
            value: "s3cr3t=;%".into(),
            path: "/".into(),
            secure: true,
            http_only: true,
            same_site: SameSite::NoRestriction,
            expires: Some(1_801_209_600),
            partition_key: None,
            changed_at: 1_799_999_000,
        }],
    }
}

fn generate() -> Value {
    let owner = SignKey::from_seed([7; 32]);
    let consumer = SignKey::from_seed([9; 32]);
    let consumer_box = BoxIdentity::generate();
    let owner_box = BoxIdentity::generate();
    let body = br#"{"token":"abc"}"#;
    let envelope = Envelope::seal(
        "grant-id-0001",
        42,
        &snapshot(),
        &consumer_box.recipient(),
        &owner,
    )
    .unwrap();
    let invite = Invite {
        relay: "https://relay.example".into(),
        owner_sign: owner.public().to_b64(),
        owner_box: owner_box.recipient().to_string(),
        token: "dG9rZW4tdG9rZW4tdG9rZW4".into(),
    };
    json!({
        "owner_seed": owner.to_b64(),
        "owner_public": owner.public().to_b64(),
        "consumer_seed": consumer.to_b64(),
        "consumer_public": consumer.public().to_b64(),
        "owner_box_identity": owner_box.to_secret_string(),
        "owner_box": owner_box.recipient().to_string(),
        "consumer_box_identity": consumer_box.to_secret_string(),
        "consumer_box": consumer_box.recipient().to_string(),
        "request": {
            "method": "POST",
            "path": "/invites?wait=5",
            "body": String::from_utf8(body.to_vec()).unwrap(),
            "time": 1_800_000_123,
            "nonce": "bm9uY2Utbm9uY2Utbm9uY2U",
        },
        "envelope": envelope,
        "snapshot": snapshot(),
        "invite": invite,
        "selectors": [
            {"text": ".Example.COM:sid", "canonical": "example.com:sid", "matches": [".example.com", "www.example.com"], "rejects": ["badexample.com"]},
            {"text": "example.com", "canonical": "example.com", "matches": ["example.com"], "rejects": ["example.org"]},
        ],
        "invalid_selectors": ["localhost", "example.com:", "example.com:a b", "exa mple.com"],
    })
}

/// Fills in the values that are deterministic functions of the inputs.
fn derive(v: &mut Value) {
    let s = |v: &Value, k: &str| v[k].as_str().unwrap().to_string();
    let owner = SignKey::from_b64(&s(v, "owner_seed")).unwrap();
    let consumer = SignKey::from_b64(&s(v, "consumer_seed")).unwrap();
    let r = v["request"].clone();
    let request_bytes = signing::request(
        &s(&r, "method"),
        &s(&r, "path"),
        s(&r, "body").as_bytes(),
        r["time"].as_i64().unwrap(),
        &s(&r, "nonce"),
    );
    v["request"]["signed_text"] = json!(String::from_utf8(request_bytes.clone()).unwrap());
    v["request"]["signature"] = json!(owner.sign(&request_bytes));
    v["message_signature"] =
        json!(consumer.sign(&signing::message("grant-id-0001", b"ciphertext")));
    v["pairing_code"] = json!(signing::pairing_code(
        &s(v, "owner_public"),
        &s(v, "owner_box"),
        &s(v, "consumer_public"),
        &s(v, "consumer_box"),
        v["invite"]["token"].as_str().unwrap(),
    ));
    let invite: Invite = serde_json::from_value(v["invite"].clone()).unwrap();
    v["invite_encoded"] = json!(invite.encode());
}

#[test]
fn vectors() {
    let file = path();
    if std::env::var_os("CC_WRITE_VECTORS").is_some() || !file.exists() {
        let mut v = generate();
        derive(&mut v);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    }
    let stored: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();

    let mut expected = stored.clone();
    derive(&mut expected);
    assert_eq!(
        stored, expected,
        "deterministic vectors changed; regenerate with CC_WRITE_VECTORS=1"
    );

    let owner = SignKey::from_b64(stored["owner_seed"].as_str().unwrap()).unwrap();
    assert_eq!(owner.public().to_b64(), stored["owner_public"]);
    let consumer_box =
        BoxIdentity::parse(stored["consumer_box_identity"].as_str().unwrap()).unwrap();
    assert_eq!(consumer_box.recipient().to_string(), stored["consumer_box"]);
    let envelope: Envelope = serde_json::from_value(stored["envelope"].clone()).unwrap();
    let opened = envelope.open(&owner.public(), &consumer_box).unwrap();
    assert_eq!(
        opened,
        serde_json::from_value::<Snapshot>(stored["snapshot"].clone()).unwrap()
    );
    assert_eq!(
        Invite::decode(stored["invite_encoded"].as_str().unwrap()).unwrap(),
        serde_json::from_value::<Invite>(stored["invite"].clone()).unwrap()
    );
    for case in stored["selectors"].as_array().unwrap() {
        let sel = Selector::parse(case["text"].as_str().unwrap()).unwrap();
        assert_eq!(sel.to_string(), case["canonical"]);
        for d in case["matches"].as_array().unwrap() {
            assert!(sel.covers_domain(d.as_str().unwrap()));
        }
        for d in case["rejects"].as_array().unwrap() {
            assert!(!sel.covers_domain(d.as_str().unwrap()));
        }
    }
    for bad in stored["invalid_selectors"].as_array().unwrap() {
        assert!(Selector::parse(bad.as_str().unwrap()).is_err(), "{bad}");
    }
}
