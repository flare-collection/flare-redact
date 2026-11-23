//! A Fluent Bit WASM filter that redacts secrets and personal data from every
//! record before it leaves the node, built on the flare-redact Rust engine.
//!
//! ```text
//! [FILTER]
//!     Name             wasm
//!     Match            *
//!     WASM_Path        /etc/fluent-bit/flare-redact.wasm
//!     Function_Name    flare_redact
//!     Accessible_Paths /etc/flare-redact
//!     WASM_Stack_Size  2M
//!     WASM_Heap_Size   8M
//! ```
//!
//! Fluent Bit gives a WASM filter an 8 KB stack and heap by default. The stack
//! must be larger to compile the detectors, and the heap holds each record
//! while it is redacted, so it bounds the largest record.
//!
//! Three functions are exported, so a policy can be picked without any file:
//!
//! - `flare_redact`: the default detectors (secrets, emails, cards, IBANs, ...)
//! - `flare_redact_pii`: the defaults plus the `pii` group (phone numbers, ...)
//! - `flare_redact_label`: the defaults, written as `[REDACTED:email]`
//!
//! For anything else, put a `flare-redact.json` in `/etc/flare-redact` and keep
//! that directory in `Accessible_Paths` (`.` works too, for the working
//! directory):
//!
//! ```json
//! { "enable": ["pii"], "disable": ["ipv4"], "allow": ["ops@example.com"], "terms": ["Project Falcon"] }
//! ```
//!
//! The filter fails closed: when the file is invalid, or a record cannot be
//! redacted, the record is replaced by `{"flare_redact_error": "..."}` rather
//! than passed on as it was.

use std::cell::{Cell, RefCell};

use flare_redact::{Mode, Options, Policy, Term};
use serde::Deserialize;

/// The optional `flare-redact.json`. Every field is optional.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Use exactly these detector ids or tags.
    pub only: Vec<String>,
    /// Turn on detectors that are off by default, by id or tag.
    pub enable: Vec<String>,
    /// Turn off detectors by id or tag.
    pub disable: Vec<String>,
    /// `mask` (default), `label`, `hash`, `pseudonym` or `surrogate`.
    pub mode: Option<String>,
    /// A fixed replacement for every finding.
    pub mask: Option<String>,
    /// Values that are never redacted.
    pub allow: Vec<String>,
    /// Your own words to always catch.
    pub terms: Vec<String>,
    /// The key for `hash`, `pseudonym` and `surrogate`.
    pub transform_secret: Option<String>,
    /// Drop findings scored below this, 0 to 1.
    pub min_confidence: f64,
}

/// Which exported function is running.
#[derive(Debug, Clone, Copy)]
pub enum Variant {
    /// `flare_redact`
    Default,
    /// `flare_redact_pii`
    Pii,
    /// `flare_redact_label`
    Label,
}

fn parse_mode(mode: &str) -> Result<Mode, String> {
    match mode {
        "mask" => Ok(Mode::Mask),
        "label" => Ok(Mode::Label),
        "hash" => Ok(Mode::Hash),
        "pseudonym" => Ok(Mode::Pseudonym),
        "surrogate" => Ok(Mode::Surrogate),
        other => Err(format!("unknown mode {other:?}")),
    }
}

/// Compile the policy for a variant from an optional config file's text.
pub fn compile(variant: Variant, config: Option<&str>) -> Result<Policy, String> {
    let config: Config = match config {
        Some(text) => serde_json::from_str(text).map_err(|e| format!("invalid flare-redact.json: {e}"))?,
        None => Config::default(),
    };
    let mut options = Options::new();
    options.only = config.only;
    options.enable = config.enable;
    options.disable = config.disable;
    options.allow = config.allow;
    options.terms = config.terms.into_iter().map(Term::new).collect();
    options.mask = config.mask;
    options.min_confidence = config.min_confidence;
    if let Some(secret) = config.transform_secret {
        options.transform_secret = secret;
    }
    if let Some(mode) = config.mode.as_deref() {
        options.mode = parse_mode(mode)?;
    }
    match variant {
        Variant::Default => {}
        Variant::Pii => options.enable.push("pii".to_string()),
        Variant::Label => {
            if config.mode.is_none() {
                options.mode = Mode::Label;
            }
        }
    }
    Policy::compile(options).map_err(|e| e.to_string())
}

/// The record that replaces one that could not be redacted.
fn error_record(message: &str) -> String {
    serde_json::json!({ "flare_redact_error": message }).to_string()
}

/// Redact one record given as JSON text, returning JSON text.
pub fn filter_record(policy: &Result<Policy, String>, record: &[u8]) -> String {
    let policy = match policy {
        Ok(policy) => policy,
        Err(message) => return error_record(message),
    };
    let value: serde_json::Value = match serde_json::from_slice(record) {
        Ok(value) => value,
        Err(e) => return error_record(&format!("the record is not JSON: {e}")),
    };
    match policy.redact(&value) {
        Ok(redacted) => redacted.to_string(),
        Err(e) => error_record(&e.to_string()),
    }
}

const CONFIG_PATHS: [&str; 2] = ["flare-redact.json", "/etc/flare-redact/flare-redact.json"];

fn read_config() -> Option<String> {
    CONFIG_PATHS.iter().find_map(|path| std::fs::read_to_string(path).ok())
}

thread_local! {
    /// The compiled policy per exported function. A `Cell` rather than a
    /// `OnceLock`: if the runtime traps while the policy is being compiled
    /// (a stack too small), nothing is left half-initialised, and the next
    /// record simply tries again.
    static POLICIES: [Cell<Option<&'static Result<Policy, String>>>; 3] =
        const { [Cell::new(None), Cell::new(None), Cell::new(None)] };
}

fn policy(variant: Variant) -> &'static Result<Policy, String> {
    POLICIES.with(|cells| {
        let cell = &cells[variant as usize];
        if let Some(compiled) = cell.get() {
            return compiled;
        }
        let compiled = compile(variant, read_config().as_deref());
        if let Err(message) = &compiled {
            eprintln!("[flare-redact] {message}; every record is replaced until this is fixed");
        }
        // Compiled once per function for the life of the filter.
        let compiled: &'static Result<Policy, String> = Box::leak(Box::new(compiled));
        cell.set(Some(compiled));
        compiled
    })
}

thread_local! {
    /// The returned string. Fluent Bit copies it as soon as the call returns,
    /// so one buffer is reused for every record.
    static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn respond(text: String) -> *const u8 {
    OUT.with(|out| {
        let mut out = out.borrow_mut();
        out.clear();
        out.extend_from_slice(text.as_bytes());
        out.push(0);
        out.as_ptr()
    })
}

fn run(variant: Variant, record: *const u8, record_len: u32) -> *const u8 {
    let bytes: &[u8] = if record.is_null() || record_len == 0 {
        &[]
    } else {
        // SAFETY: Fluent Bit passes a buffer of `record_len` bytes that it
        // owns for the duration of this call.
        unsafe { std::slice::from_raw_parts(record, record_len as usize) }
    };
    respond(filter_record(policy(variant), bytes))
}

/// The Fluent Bit filter entry point with the default detectors.
#[no_mangle]
pub extern "C" fn flare_redact(
    _tag: *const u8,
    _tag_len: u32,
    _time_sec: u32,
    _time_nsec: u32,
    record: *const u8,
    record_len: u32,
) -> *const u8 {
    run(Variant::Default, record, record_len)
}

/// The Fluent Bit filter entry point with the `pii` group on.
#[no_mangle]
pub extern "C" fn flare_redact_pii(
    _tag: *const u8,
    _tag_len: u32,
    _time_sec: u32,
    _time_nsec: u32,
    record: *const u8,
    record_len: u32,
) -> *const u8 {
    run(Variant::Pii, record, record_len)
}

/// The Fluent Bit filter entry point that writes `[REDACTED:<detector>]`.
#[no_mangle]
pub extern "C" fn flare_redact_label(
    _tag: *const u8,
    _tag_len: u32,
    _time_sec: u32,
    _time_nsec: u32,
    record: *const u8,
    record_len: u32,
) -> *const u8 {
    run(Variant::Label, record, record_len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    const TOKEN: &str = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";

    fn call(f: extern "C" fn(*const u8, u32, u32, u32, *const u8, u32) -> *const u8, record: &str) -> String {
        let tag = b"app.log";
        let out = f(tag.as_ptr(), tag.len() as u32, 0, 0, record.as_ptr(), record.len() as u32);
        // SAFETY: the filter returns a NUL-terminated buffer it owns.
        unsafe { CStr::from_ptr(out as *const std::ffi::c_char) }.to_str().unwrap().to_string()
    }

    #[test]
    fn exported_functions_redact_records() {
        let record = format!(
            r#"{{"log":"login ada@example.com key {TOKEN} call +44 20 7946 0958","password":"hunter2hunter2","level":"info","n":3}}"#
        );
        let out: serde_json::Value = serde_json::from_str(&call(flare_redact, &record)).unwrap();
        let log = out["log"].as_str().unwrap();
        assert!(!log.contains("ada@example.com") && !log.contains(TOKEN), "{log}");
        assert!(log.contains("+44 20 7946 0958"), "phone numbers are off by default: {log}");
        assert_eq!(out["password"], "***");
        assert_eq!(out["level"], "info");
        assert_eq!(out["n"], 3);

        let pii: serde_json::Value = serde_json::from_str(&call(flare_redact_pii, &record)).unwrap();
        assert!(!pii["log"].as_str().unwrap().contains("7946 0958"));

        let label: serde_json::Value = serde_json::from_str(&call(flare_redact_label, &record)).unwrap();
        assert!(label["log"].as_str().unwrap().contains("[REDACTED:email]"));
    }

    #[test]
    fn clean_records_and_bad_input() {
        assert_eq!(call(flare_redact, r#"{"log":"all good","n":1}"#), r#"{"log":"all good","n":1}"#);
        let bad: serde_json::Value = serde_json::from_str(&call(flare_redact, "not json")).unwrap();
        assert!(bad["flare_redact_error"].as_str().unwrap().contains("not JSON"));
        let empty: serde_json::Value = serde_json::from_str(&call(flare_redact, "")).unwrap();
        assert!(empty.get("flare_redact_error").is_some());
    }

    #[test]
    fn config_file_options() {
        let policy = compile(
            Variant::Default,
            Some(r#"{"enable":["pii"],"allow":["ops@example.com"],"terms":["Project Falcon"],"mode":"label"}"#),
        );
        let out = filter_record(&policy, br#"{"log":"ops@example.com, ada@example.com, Project Falcon, +44 20 7946 0958"}"#);
        let log = serde_json::from_str::<serde_json::Value>(&out).unwrap()["log"].as_str().unwrap().to_string();
        assert!(log.starts_with("ops@example.com, [REDACTED:email], "), "{log}");
        assert!(!log.contains("Project Falcon") && !log.contains("7946 0958"), "{log}");
    }

    #[test]
    fn invalid_config_fails_closed() {
        for text in [r#"{"mode":"shout"}"#, r#"{"enabel":["pii"]}"#, "{", r#"{"mode":"hash"}"#] {
            let policy = compile(Variant::Default, Some(text));
            let out = filter_record(&policy, br#"{"log":"ada@example.com"}"#);
            assert!(!out.contains("ada@example.com"), "{text}: {out}");
            assert!(out.contains("flare_redact_error"), "{text}: {out}");
        }
    }
}
