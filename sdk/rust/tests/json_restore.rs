//! Restoring into JSON text: tool-call arguments and JSON-mode output stay
//! valid JSON with the same structure, whatever the restored value contains.

use flare_redact::{
    escape_entries_for_json, is_json_document, Options, PlaceholderStyle, Restorer, Session, StreamRestorer, Term,
    Vault,
};
use serde_json::{json, Value};

/// A quote, a backslash and control characters.
const AWKWARD: &str = "Q\"uo\\te\nline\ttab\u{1}end";
/// Credentials holding a quoted fragment; a default detector captures it whole.
const QUOTED_URL: &str = r#"https://user:pa","extra":true,"note":"x@example.com/pay"#;

fn awkward_options() -> Options {
    Options::new().terms([Term::new(AWKWARD)])
}

fn awkward_vault() -> (Vault, String) {
    let mut vault = Vault::new(awkward_options()).expect("vault");
    let redacted = vault.redact_str(&format!("say {AWKWARD}")).expect("redact");
    let placeholder = redacted.trim_start_matches("say ").to_string();
    assert!(placeholder.starts_with("[FR_CUSTOM_TERM_"), "{redacted}");
    (vault, placeholder)
}

fn parse(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|error| panic!("not valid JSON: {error}\n{text}"))
}

#[test]
fn restore_escapes_originals_inside_json_documents() {
    let (vault, placeholder) = awkward_vault();
    let args = json!({ "n": 1, "text": placeholder.as_str() }).to_string();
    let want = json!({ "n": 1, "text": AWKWARD });

    assert_eq!(parse(&vault.restore_str(&args)), want);
    let restored = vault.restore(&json!({ "args": args.as_str() }));
    assert_eq!(parse(restored["args"].as_str().expect("string")), want);
    let document = format!("\n [\"{placeholder}\"]");
    assert_eq!(parse(&Restorer::json_aware(&vault.entries()).restore(&document)), json!([AWKWARD]));
    assert_eq!(Restorer::new(&vault.entries()).restore(&document), format!("\n [\"{AWKWARD}\"]"));
}

#[test]
fn restore_leaves_other_strings_verbatim() {
    let (vault, placeholder) = awkward_vault();
    let cases = [
        (format!("say {placeholder}"), format!("say {AWKWARD}")),
        (format!("{{ not json {placeholder}"), format!("{{ not json {AWKWARD}")),
        (format!("\"{placeholder}\""), format!("\"{AWKWARD}\"")),
    ];
    for (input, want) in cases {
        assert_eq!(vault.restore_str(&input), want);
    }
    assert_eq!(
        vault.restore(&json!({ "input": { "text": placeholder.as_str() } })),
        json!({ "input": { "text": AWKWARD } })
    );
}

#[test]
fn a_restored_value_keeps_the_structure_of_json_text() {
    let mut vault = Vault::new(Options::new()).expect("vault");
    let redacted = vault.redact_str(&format!("call back {QUOTED_URL}")).expect("redact");
    let start = redacted.find("[FR_").expect("a placeholder");
    let end = start + redacted[start..].find(']').expect("placeholder end") + 1;
    let placeholder = &redacted[start..end];
    let args = format!(r#"{{"amount":10,"callback":"{placeholder}"}}"#);
    let parsed = parse(&vault.restore_str(&args));
    assert_eq!(parsed["amount"], json!(10));
    assert_eq!(parsed.as_object().expect("object").len(), 2);
    assert!(QUOTED_URL.starts_with(parsed["callback"].as_str().expect("string")));
}

#[test]
fn json_stream_restorer_escapes_across_chunk_splits() {
    let (vault, placeholder) = awkward_vault();
    let text = json!({ "note": placeholder.as_str() }).to_string();
    let at = text.find(placeholder.as_str()).expect("placeholder") + 6;
    for mut restorer in [vault.stream_json(), StreamRestorer::json(&vault.entries())] {
        let mut out = restorer.push(&text[..at]);
        out.push_str(&restorer.push(&text[at..]));
        out.push_str(&restorer.flush());
        assert_eq!(parse(&out), json!({ "note": AWKWARD }));
    }
    let mut plain = vault.stream();
    let mut out = plain.push(&format!("<{placeholder}>"));
    out.push_str(&plain.flush());
    assert_eq!(out, format!("<{AWKWARD}>"));
}

#[test]
fn a_session_restores_and_streams_by_the_same_rule() {
    let mut session = Session::new(awkward_options(), PlaceholderStyle::Opaque).expect("session");
    let placeholder = session.redact_str(AWKWARD).expect("redact");
    let document = json!([placeholder.as_str()]).to_string();
    assert_eq!(parse(&session.restore_str(&document)), json!([AWKWARD]));
    let mut stream = session.stream_json();
    let mut out = stream.push(&document);
    out.push_str(&stream.flush());
    assert_eq!(parse(&out), json!([AWKWARD]));
}

#[test]
fn escape_entries_for_json_matches_json_string_contents() {
    let entries = [("[A_1]".to_string(), "a\"b\\c\nd\u{1f}\u{2028}é".to_string())];
    let escaped = escape_entries_for_json(&entries);
    assert_eq!(escaped, vec![("[A_1]".to_string(), "a\\\"b\\\\c\\nd\\u001f\u{2028}é".to_string())]);
}

#[test]
fn is_json_document_accepts_objects_and_arrays_only() {
    assert!(is_json_document(" \n{\"a\": [1]}\t"));
    assert!(is_json_document("[]"));
    for text in ["\"text\"", "42", "{ not json", "[NaN]", "\u{a0}{}", ""] {
        assert!(!is_json_document(text), "{text:?}");
    }
}
