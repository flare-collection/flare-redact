//! Behaviour the conformance corpus does not pin down, plus known-answer tests
//! for the hand-written HMAC-SHA256.

use flare_redact::crypto::{hmac_sha256, sha256};
use flare_redact::{load_pack, Error, Mode, Options, PlaceholderStyle, Policy, Term, Vault};
use serde_json::json;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn sha256_matches_fips_180_4_examples() {
    assert_eq!(
        hex(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex(&sha256(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn hmac_sha256_matches_rfc_4231_vectors() {
    // Test case 1.
    assert_eq!(
        hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
    // Test case 2.
    assert_eq!(
        hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    // Test case 6: a key longer than the block size is hashed first.
    assert_eq!(
        hex(&hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    );
}

#[test]
fn redacts_strings() {
    let policy = Policy::compile(Options::new()).unwrap();
    assert_eq!(policy.redact_str("contact ada@example.com").unwrap(), "contact a***@***");
    assert_eq!(policy.redact_str("AKIAIOSFODNN7EXAMPLE").unwrap(), "AKIA***");
    assert_eq!(policy.redact_str("nothing here").unwrap(), "nothing here");
    assert_eq!(policy.redact_str("password=hunter2000").unwrap(), "password=***");
}

#[test]
fn redacts_structures_and_leaves_scalars_alone() {
    let policy = Policy::compile(Options::new()).unwrap();
    let safe = policy
        .redact(&json!({"password": "hunter2", "count": 7, "ok": true, "user": {"email": "ada@example.com"}}))
        .unwrap();
    assert_eq!(safe["password"], "***");
    assert_eq!(safe["count"], 7);
    assert_eq!(safe["ok"], true);
    assert_eq!(safe["user"]["email"], "a***@***");
}

#[test]
fn modes() {
    let label = Policy::compile(Options::new().mode(Mode::Label)).unwrap();
    assert_eq!(label.redact_str("ada@example.com").unwrap(), "[REDACTED:email]");

    let hashed = Policy::compile(Options::new().mode(Mode::Hash).transform_secret("k")).unwrap();
    let first = hashed.redact_str("ada@example.com").unwrap();
    assert_eq!(first, hashed.redact_str("ada@example.com").unwrap(), "hash mode is deterministic");
    assert!(first.starts_with("email_"));

    match Policy::compile(Options::new().mode(Mode::Hash)) {
        Err(Error::MissingSecret) => {}
        other => panic!("a keyed mode without a secret must fail, got {other:?}"),
    }
}

#[test]
fn surrogate_card_still_passes_luhn() {
    let policy = Policy::compile(Options::new().mode(Mode::Surrogate).transform_secret("k")).unwrap();
    let out = policy.redact_str("4111 1111 1111 1111").unwrap();
    assert_ne!(out, "4111 1111 1111 1111");
    assert!(flare_redact::checksums::luhn(&out, 13, 19), "surrogate {out:?} fails Luhn");
}

#[test]
fn selection_and_terms() {
    let only = Policy::compile(Options::new().only(["email"])).unwrap();
    assert_eq!(
        only.redact_str("ada@example.com AKIAIOSFODNN7EXAMPLE").unwrap(),
        "a***@*** AKIAIOSFODNN7EXAMPLE"
    );

    let terms = Policy::compile(Options::new().terms([Term::replaced_with("Bluebird", "[PROJECT]")])).unwrap();
    assert_eq!(
        terms.redact_str("Bluebirds follow Bluebird").unwrap(),
        "Bluebirds follow [PROJECT]",
        "a term must not match inside a longer word"
    );
}

#[test]
fn limits_fail_closed() {
    let mut options = Options::new();
    options.max_input_length = 8;
    let policy = Policy::compile(options).unwrap();
    match policy.redact_str(&"x".repeat(64)) {
        Err(Error::Limit(_)) => {}
        other => panic!("oversized input must fail closed, got {other:?}"),
    }
}

#[test]
fn scan_reports_locations_and_paths() {
    let policy = Policy::compile(Options::new()).unwrap();
    let findings = policy.scan(&json!({"note": "line one\nwrite to ada@example.com"})).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].path.as_deref(), Some("note"));
    assert_eq!(findings[0].line, Some(2));
    assert_eq!(findings[0].column, Some(10));
    assert!(findings[0].value.is_none(), "values are omitted unless requested");
}

#[test]
fn vault_round_trip() {
    let mut vault = Vault::new(Options::new()).unwrap().style(PlaceholderStyle::Readable);
    let redacted = vault.redact_str("mail ada@example.com and ada@example.com").unwrap();
    assert_eq!(redacted, "mail [EMAIL_1] and [EMAIL_1]");
    assert_eq!(vault.restore_str(&redacted), "mail ada@example.com and ada@example.com");
    assert_eq!(vault.len(), 1);
}

#[test]
fn stream_restores_across_chunks() {
    let mut vault = Vault::new(Options::new()).unwrap().style(PlaceholderStyle::Readable);
    vault.redact_str("ada@example.com").unwrap();
    let mut restorer = vault.stream();
    let mut out = restorer.push("reply to [EMA");
    out.push_str(&restorer.push("IL_1] soon"));
    out.push_str(&restorer.flush());
    assert_eq!(out, "reply to ada@example.com soon");
}

#[test]
fn opaque_placeholders_do_not_repeat() {
    let mut first = Vault::new(Options::new()).unwrap();
    let mut second = Vault::new(Options::new()).unwrap();
    let a = first.redact_str("ada@example.com").unwrap();
    let b = second.redact_str("ada@example.com").unwrap();
    assert_ne!(a, b);
    assert!(a.starts_with("[FR_EMAIL_"));
}

#[test]
fn packs_reject_non_portable_patterns() {
    let template = |pattern: &str| {
        format!(
            r#"{{"spec":"FRS-1","id":"t","version":"1","detectors":[{{"id":"a","label":"A","why":"w.","pattern":{},"mask":{{"type":"fixed","text":"*"}},"default":true,"risk":"low","confidence":0.5}}]}}"#,
            serde_json::to_string(pattern).unwrap()
        )
    };
    for pattern in [r"TICKET-(?!0)[0-9]{4}", r"\bTICKET-[0-9]{4}", r"TICKET-\d+", r"^TICKET-[0-9]{4}", "[0-9]*"] {
        assert!(load_pack(&template(pattern)).is_err(), "pattern {pattern:?} should not load");
    }
    assert!(load_pack(r#"{"spec":"FRS-2","id":"t","version":"1","detectors":[]}"#).is_err());
}

#[test]
fn packs_reject_unknown_validators() {
    let document = r#"{"spec":"FRS-1","id":"t","version":"1","detectors":[
        {"id":"a","label":"A","why":"w.","pattern":"TICKET-[0-9]{4}",
         "validators":[{"name":"not_a_real_checksum"}],
         "mask":{"type":"fixed","text":"*"},"default":true,"risk":"low","confidence":0.5}]}"#;
    assert!(load_pack(document).is_err());
}
