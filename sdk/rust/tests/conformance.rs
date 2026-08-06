//! The Rust engine must agree with the JavaScript, Python and Go engines, case
//! for case. See `spec/SPEC.md` §13 — this file is the Rust half of that promise.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use flare_redact::{Finding, Mode, Options, PlaceholderStyle, Policy, Term, Vault};
use serde_json::{json, Map, Value};

fn spec_path(parts: &[&str]) -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("..");
    path.push("..");
    path.push("spec");
    for part in parts {
        path.push(part);
    }
    path
}

fn read_json(parts: &[&str]) -> Value {
    let path = spec_path(parts);
    let text = fs::read_to_string(&path).unwrap_or_else(|error| panic!("cannot read {path:?}: {error}"));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("cannot parse {path:?}: {error}"))
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(|v| v.as_array())
        .map(|items| items.iter().filter_map(|item| item.as_str().map(str::to_string)).collect())
        .unwrap_or_default()
}

/// Build options from the JSON wire format the corpus and the gateway share.
fn options_from_wire(wire: &Value) -> Options {
    let mut options = Options::new();
    options.only = strings(wire.get("only"));
    options.enable = strings(wire.get("enable"));
    options.disable = strings(wire.get("disable"));
    options.allow = strings(wire.get("allow"));

    if let Some(mode) = wire.get("mode").and_then(|v| v.as_str()) {
        options.mode = match mode {
            "label" => Mode::Label,
            "hash" => Mode::Hash,
            "pseudonym" | "fpe" => Mode::Pseudonym,
            "surrogate" => Mode::Surrogate,
            _ => Mode::Mask,
        };
    }
    if let Some(mask) = wire.get("mask").and_then(|v| v.as_str()) {
        options.mask = Some(mask.to_string());
    }
    if let Some(secret) = wire.get("transformSecret").and_then(|v| v.as_str()) {
        options.transform_secret = secret.to_string();
    }
    match wire.get("redactKeys") {
        Some(Value::Bool(false)) => options.disable_key_redaction = true,
        Some(Value::Array(_)) => options.key_names = strings(wire.get("redactKeys")),
        _ => {}
    }
    match wire.get("terms") {
        Some(Value::Array(items)) => {
            options.terms = items
                .iter()
                .filter_map(|item| match item {
                    Value::String(term) => Some(Term::new(term.clone())),
                    Value::Object(entry) => entry.get("term").and_then(|v| v.as_str()).map(|term| Term {
                        term: term.to_string(),
                        replace: entry
                            .get("replace")
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string(),
                    }),
                    _ => None,
                })
                .collect();
        }
        Some(Value::Object(entries)) => {
            // A {term: replacement} object. BTreeMap iteration is sorted, so the
            // alternation is built in the same order on every run.
            options.terms = entries
                .iter()
                .map(|(term, replacement)| Term {
                    term: term.clone(),
                    replace: replacement.as_str().unwrap_or_default().to_string(),
                })
                .collect();
        }
        _ => {}
    }
    if let Some(flag) = wire.get("termsCaseSensitive").and_then(|v| v.as_bool()) {
        options.terms_case_sensitive = flag;
    }
    if let Some(minimum) = wire.get("minConfidence").and_then(|v| v.as_f64()) {
        options.min_confidence = minimum;
    }
    if let Some(flag) = wire.get("refineConfidence").and_then(|v| v.as_bool()) {
        options.refine_confidence = flag;
    }
    if let Some(flag) = wire.get("includeValues").and_then(|v| v.as_bool()) {
        options.include_values = flag;
    }
    if let Some(limits) = wire.get("limits") {
        if let Some(value) = limits.get("maxInputLength").and_then(|v| v.as_u64()) {
            options.max_input_length = value as usize;
        }
        if let Some(value) = limits.get("maxFindings").and_then(|v| v.as_u64()) {
            options.max_findings = value as usize;
        }
    }
    options
}

fn round6(value: f64) -> f64 {
    (value * 1e6).round() / 1e6
}

fn normalise_finding(finding: &Finding) -> Value {
    let mut out = Map::new();
    out.insert("detector".into(), json!(finding.detector));
    out.insert("risk".into(), json!(finding.risk));
    out.insert("confidence".into(), json!(round6(finding.confidence)));
    if let Some(start) = finding.start {
        out.insert("start".into(), json!(start));
    }
    if let Some(end) = finding.end {
        out.insert("end".into(), json!(end));
    }
    if let Some(line) = finding.line {
        out.insert("line".into(), json!(line));
    }
    if let Some(column) = finding.column {
        out.insert("column".into(), json!(column));
    }
    if let Some(path) = &finding.path {
        out.insert("path".into(), json!(path));
    }
    if let Some(value) = &finding.value {
        out.insert("value".into(), json!(value));
    }
    Value::Object(out)
}

fn run_case(case: &Value) -> Value {
    let wire = case.get("options").cloned().unwrap_or(Value::Null);
    let options = options_from_wire(&wire);
    let input = case.get("input").expect("case has an input");
    let checks: Vec<String> = case
        .get("checks")
        .and_then(|v| v.as_array())
        .map(|items| items.iter().filter_map(|c| c.as_str().map(str::to_string)).collect())
        .unwrap_or_else(|| vec!["redact".into(), "scan".into()]);

    let mut result = Map::new();

    if checks.iter().any(|check| check == "redact") {
        let policy = Policy::compile(options.clone()).expect("compile");
        result.insert("redact".into(), policy.redact(input).expect("redact"));
    }
    if checks.iter().any(|check| check == "scan") {
        let policy = Policy::compile(options.clone()).expect("compile");
        let findings: Vec<Value> = policy.scan(input).expect("scan").iter().map(normalise_finding).collect();
        result.insert("findings".into(), Value::Array(findings));
    }
    if checks.iter().any(|check| check == "vault") {
        let style = match case.get("vault").and_then(|v| v.get("placeholderStyle")).and_then(|v| v.as_str()) {
            Some("readable") => PlaceholderStyle::Readable,
            _ => PlaceholderStyle::Opaque,
        };
        let mut vault = Vault::new(options.clone()).expect("vault").style(style);
        let redacted = vault.redact(input).expect("vault redact");
        let restored = vault.restore(&redacted);
        let entries: Vec<Value> = vault
            .entries()
            .into_iter()
            .map(|(placeholder, original)| json!([placeholder, original]))
            .collect();
        let mut vault_result = Map::new();
        vault_result.insert("redacted".into(), redacted);
        vault_result.insert("restored".into(), restored);
        vault_result.insert("entries".into(), Value::Array(entries));
        result.insert("vault".into(), Value::Object(vault_result));
    }

    Value::Object(result)
}

#[test]
fn conformance_corpus() {
    let corpus = read_json(&["conformance", "cases.json"]);
    let expected = read_json(&["conformance", "expected.json"]);
    let cases = corpus["cases"].as_array().expect("cases is an array");
    let expectations = expected.as_object().expect("expected.json is an object");

    assert_eq!(
        cases.len(),
        expectations.len(),
        "cases.json and expected.json disagree; regenerate with npm run spec:conformance"
    );

    let mut failures: BTreeMap<String, (String, String)> = BTreeMap::new();
    for case in cases {
        let name = case["name"].as_str().expect("case has a name").to_string();
        let want = expectations.get(&name).unwrap_or_else(|| panic!("no expectation for {name}"));
        let got = run_case(case);
        if &got != want {
            failures.insert(
                name,
                (
                    serde_json::to_string_pretty(&got).unwrap_or_default(),
                    serde_json::to_string_pretty(want).unwrap_or_default(),
                ),
            );
        }
    }

    if !failures.is_empty() {
        let report = failures
            .iter()
            .map(|(name, (got, want))| format!("{name}\n  got:  {got}\n  want: {want}"))
            .collect::<Vec<_>>()
            .join("\n\n");
        panic!("{} conformance failure(s)\n\n{report}", failures.len());
    }
}

#[test]
fn vendored_pack_matches_the_specification() {
    let canonical = read_json(&["detectors.json"]);
    let vendored: Value =
        serde_json::from_str(flare_redact::CORE_PACK_JSON).expect("the embedded pack parses");
    assert_eq!(
        canonical, vendored,
        "the vendored pack has drifted from spec/detectors.json; run `npm run spec:sync`"
    );
}
