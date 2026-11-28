//! A value under a sensitive key is masked whatever its type (SPEC §9):
//! numbers and every string or number inside an object or array at any depth.
//! Booleans and null are kept.

use flare_redact::{Mode, Options, PlaceholderStyle, Policy, Vault};
use serde_json::json;

#[test]
fn numbers_and_containers_under_a_sensitive_key_are_masked() {
    let policy = Policy::compile(Options::new()).unwrap();
    let safe = policy
        .redact(&json!({
            "cvv": 123,
            "amount": 1000,
            "cookie": {"name": "connect.sid", "value": "s%3A_SID_abc"},
            "password": ["hunter2", ["letmein", 7.5]],
            "credentials": {"hash": "$argon2id$v=19$abc", "params": {"cost": 12}, "rotated": true},
            "hasPassword": true,
            "token": null
        }))
        .unwrap();
    assert_eq!(
        safe,
        json!({
            "cvv": "***",
            "amount": 1000,
            "cookie": {"name": "***", "value": "***"},
            "password": ["***", ["***", "***"]],
            "credentials": {"hash": "***", "params": {"cost": "***"}, "rotated": true},
            "hasPassword": true,
            "token": null
        })
    );
}

#[test]
fn a_number_is_replaced_as_its_decimal_text() {
    let hashed = Policy::compile(Options::new().mode(Mode::Hash).transform_secret("k")).unwrap();
    assert_eq!(hashed.redact(&json!({"pin": 1234})).unwrap(), hashed.redact(&json!({"pin": "1234"})).unwrap());
    assert_eq!(hashed.redact(&json!({"pin": 1.5})).unwrap(), hashed.redact(&json!({"pin": "1.5"})).unwrap());
    let allowed = Policy::compile(Options::new().allow(["1234"])).unwrap();
    assert_eq!(allowed.redact(&json!({"pin": 1234})).unwrap(), json!({"pin": 1234}));
}

#[test]
fn scan_reports_every_value_under_a_sensitive_key() {
    let policy = Policy::compile(Options::new().include_values(true)).unwrap();
    let findings = policy.scan(&json!({"cvv": 123, "cookie": {"name": "sid", "secure": true}, "ok": 1})).unwrap();
    let got: Vec<_> = findings
        .iter()
        .map(|f| (f.detector.as_str(), f.path.as_deref().unwrap_or(""), f.value.as_deref().unwrap_or("")))
        .collect();
    assert_eq!(got, vec![("sensitive_key", "cookie.name", "sid"), ("sensitive_key", "cvv", "123")]);
}

#[test]
fn a_vault_mints_and_restores_sensitive_values() {
    let mut vault = Vault::new(Options::new()).unwrap().style(PlaceholderStyle::Readable);
    let out = vault.redact(&json!({"otp": 482913, "cookie": {"value": "abc"}})).unwrap();
    assert_eq!(out, json!({"otp": "[SENSITIVE_KEY_2]", "cookie": {"value": "[SENSITIVE_KEY_1]"}}));
    assert_eq!(vault.restore(&out), json!({"otp": "482913", "cookie": {"value": "abc"}}));
}
