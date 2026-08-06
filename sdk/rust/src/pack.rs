//! FRS-1 detector packs.
//!
//! A pack is data: patterns written in a restricted, engine-neutral subset plus
//! named validators and mask strategies. Loading one compiles it into detectors
//! this engine can run — and refuses anything it cannot run exactly as
//! `spec/SPEC.md` describes. An unknown validator or a lookahead in a pattern is
//! a load error, never a silently weakened check, because failing open is how a
//! redactor leaks.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;
use serde::Deserialize;

use crate::checksums;
use crate::ml::ConfidenceModel;
use crate::Error;

/// The FRS-1 revision this engine implements.
pub const SPEC_REVISION: &str = "FRS-1";

/// The bundled core pack, as shipped.
pub const CORE_PACK_JSON: &str = include_str!("detectors.json");

/// Privacy impact of a detector, used to resolve overlapping matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// Little consequence on its own.
    Low,
    /// Reveals infrastructure or aids correlation.
    Medium,
    /// Personal data.
    High,
    /// A live credential or a national identifier.
    Critical,
}

impl Risk {
    fn parse(value: &str) -> Option<Risk> {
        Some(match value {
            "low" => Risk::Low,
            "medium" => Risk::Medium,
            "high" => Risk::High,
            "critical" => Risk::Critical,
            _ => return None,
        })
    }

    /// The wire name, as it appears in a pack and in findings.
    pub fn as_str(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
            Risk::Critical => "critical",
        }
    }

    pub(crate) fn weight(self) -> f64 {
        match self {
            Risk::Low => 1.0,
            Risk::Medium => 1e3,
            Risk::High => 1e6,
            Risk::Critical => 1e9,
        }
    }
}

/// An ASCII character class used for boundary tests. Every FRS-1 boundary class
/// is ASCII, so a byte lookup is both sufficient and exact: the bytes of a
/// multi-byte character are all ≥ 0x80 and can never be members.
#[derive(Debug, Clone)]
pub struct CharClass([bool; 128]);

impl CharClass {
    fn new(members: &str) -> Self {
        let mut table = [false; 128];
        for byte in members.bytes() {
            table[byte as usize] = true;
        }
        CharClass(table)
    }

    pub(crate) fn contains(&self, byte: u8) -> bool {
        (byte as usize) < 128 && self.0[byte as usize]
    }
}

fn boundary_classes() -> &'static HashMap<&'static str, CharClass> {
    static CLASSES: OnceLock<HashMap<&'static str, CharClass>> = OnceLock::new();
    CLASSES.get_or_init(|| {
        const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
        const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const DIGITS: &str = "0123456789";
        let alnum = format!("{LOWER}{UPPER}{DIGITS}");
        HashMap::from([
            ("word", CharClass::new(&format!("{alnum}_"))),
            ("alnum", CharClass::new(&alnum)),
            ("digit", CharClass::new(DIGITS)),
            ("hex", CharClass::new(&format!("{DIGITS}abcdefABCDEF"))),
            ("base64", CharClass::new(&format!("{alnum}+/="))),
            ("base64url", CharClass::new(&format!("{alnum}_+/=-"))),
            ("word_dash", CharClass::new(&format!("{alnum}_-"))),
        ])
    })
}

/// How a matched value is replaced in `mask` mode.
#[derive(Debug, Clone)]
pub(crate) enum Mask {
    Fixed(String),
    KeepPrefix(usize),
    KeepLast(usize),
    KeepThroughSeparator { separator: String, count: usize },
    Replace { pattern: Regex, replacement: String },
    /// Per-term replacements for the caller-supplied terms detector.
    Terms { replacements: HashMap<String, String>, case_sensitive: bool },
}

impl Mask {
    pub(crate) fn apply(&self, value: &str) -> String {
        match self {
            Mask::Fixed(text) => text.clone(),
            Mask::KeepPrefix(n) => {
                let chars: Vec<char> = value.chars().collect();
                if chars.len() <= *n {
                    "***".to_string()
                } else {
                    let head: String = chars[..*n].iter().collect();
                    format!("{head}***")
                }
            }
            Mask::KeepLast(n) => {
                let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
                let tail: String = if digits.len() > *n {
                    digits[digits.len() - n..].to_string()
                } else {
                    digits.clone()
                };
                let groups = if digits.len() > *n { (digits.len() - n + 3) / 4 } else { 0 };
                format!("{}{}", "**** ".repeat(groups), tail).trim().to_string()
            }
            Mask::KeepThroughSeparator { separator, count } => {
                let mut index = None;
                let mut from = 0usize;
                for _ in 0..*count {
                    match value[from..].find(separator.as_str()) {
                        Some(offset) => {
                            let found = from + offset;
                            index = Some(found);
                            from = found + separator.len();
                        }
                        None => return "***".to_string(),
                    }
                }
                match index {
                    Some(found) => format!("{}***", &value[..found + separator.len()]),
                    None => "***".to_string(),
                }
            }
            Mask::Replace { pattern, replacement } => match pattern.captures(value) {
                Some(captures) => expand_replacement(replacement, &captures),
                None => value.to_string(),
            },
            Mask::Terms { replacements, case_sensitive } => {
                let key = if *case_sensitive { value.to_string() } else { value.to_lowercase() };
                replacements.get(&key).cloned().unwrap_or_else(|| "***".to_string())
            }
        }
    }
}

/// Substitute `$1`–`$9` (and `$$`) in a mask replacement template. The regex
/// crate's own `$name` expansion differs, so this is done by hand to keep pack
/// templates identical across engines.
fn expand_replacement(template: &str, captures: &regex::Captures<'_>) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes: Vec<char> = template.chars().collect();
    let mut index = 0;
    while index < bytes.len() {
        let ch = bytes[index];
        if ch == '$' && index + 1 < bytes.len() {
            let next = bytes[index + 1];
            if next == '$' {
                out.push('$');
                index += 2;
                continue;
            }
            if let Some(group) = next.to_digit(10).filter(|d| *d > 0) {
                if let Some(matched) = captures.get(group as usize) {
                    out.push_str(matched.as_str());
                }
                index += 2;
                continue;
            }
        }
        out.push(ch);
        index += 1;
    }
    out
}

pub(crate) enum Validator {
    NormalizedMatch { strip: Option<Regex>, pattern: Regex },
    Luhn { min: usize, max: usize },
    Entropy { min: f64 },
    Named(fn(&str) -> bool),
}

impl Validator {
    pub(crate) fn accepts(&self, value: &str) -> bool {
        match self {
            Validator::NormalizedMatch { strip, pattern } => {
                let candidate = match strip {
                    Some(strip) => strip.replace_all(value, "").into_owned(),
                    None => value.to_string(),
                };
                pattern.is_match(&candidate)
            }
            Validator::Luhn { min, max } => checksums::luhn(value, *min, *max),
            Validator::Entropy { min } => checksums::shannon_entropy(value) >= *min,
            Validator::Named(check) => check(value),
        }
    }
}

/// One compiled rule: what it matches, how it is validated, how it is replaced.
pub struct Detector {
    /// Stable identifier, used in findings and in `label` mode.
    pub id: String,
    /// Human-readable name.
    pub label: String,
    /// One sentence a reader can act on: what an attacker gains.
    pub why: String,
    /// Privacy impact.
    pub risk: Risk,
    /// Base confidence before contextual adjustment.
    pub confidence: f64,
    /// Explicit overlap priority; higher wins.
    pub priority: i64,
    /// Whether the detector runs unless disabled.
    pub default_on: bool,
    /// Selectable groups for `enable` / `disable` / `only`.
    pub tags: Vec<String>,
    /// Whether the learned classifier may adjust this detector's confidence.
    pub refine: bool,

    pub(crate) prefilter: Vec<String>,
    pub(crate) regex: Regex,
    pub(crate) capture: usize,
    pub(crate) before: Option<CharClass>,
    pub(crate) after: Option<CharClass>,
    pub(crate) unicode_boundary: bool,
    pub(crate) reject: Vec<Regex>,
    pub(crate) validators: Vec<Validator>,
    pub(crate) mask: Mask,
    pub(crate) context_positive: Option<Regex>,
    pub(crate) context_negative: Option<Regex>,
    pub(crate) context_window: usize,
}

impl Detector {
    /// Whether `selector` names this detector or one of its tags.
    pub fn matches_selector(&self, selector: &str) -> bool {
        self.id == selector || self.tags.iter().any(|tag| tag == selector)
    }
}

impl std::fmt::Debug for Detector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detector")
            .field("id", &self.id)
            .field("risk", &self.risk)
            .field("default_on", &self.default_on)
            .finish()
    }
}

/// A loaded, compiled detector pack.
pub struct Pack {
    /// Pack identifier, e.g. `flare-redact/core`.
    pub id: String,
    /// Pack version.
    pub version: String,
    /// Human-readable title.
    pub title: String,
    /// Detectors, in evaluation order.
    pub detectors: Vec<Detector>,
    /// Weights for the learned confidence classifier, if the pack carries them.
    pub model: Option<ConfidenceModel>,
}

impl Pack {
    /// Look up a detector by id.
    pub fn detector(&self, id: &str) -> Option<&Detector> {
        self.detectors.iter().find(|detector| detector.id == id)
    }
}

impl std::fmt::Debug for Pack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pack")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("detectors", &self.detectors.len())
            .field("model", &self.model.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PackDocument {
    spec: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default, rename = "confidenceModel")]
    confidence_model: Option<ModelDocument>,
    #[serde(default)]
    detectors: Vec<DetectorDocument>,
}

#[derive(Deserialize)]
struct ModelDocument {
    version: i64,
    features: Vec<String>,
    weights: Vec<f64>,
    bias: f64,
}

#[derive(Deserialize)]
struct BoundaryDocument {
    #[serde(default)]
    before: Option<String>,
    #[serde(default)]
    after: Option<String>,
}

#[derive(Deserialize)]
struct ContextDocument {
    #[serde(default)]
    positive: Option<String>,
    #[serde(default)]
    negative: Option<String>,
    #[serde(default)]
    window: Option<usize>,
}

#[derive(Deserialize)]
struct DetectorDocument {
    id: String,
    label: String,
    why: String,
    pattern: String,
    #[serde(default)]
    flags: String,
    #[serde(default)]
    capture: usize,
    #[serde(default)]
    boundary: Option<BoundaryDocument>,
    #[serde(default)]
    reject: Vec<String>,
    #[serde(default)]
    validators: Vec<serde_json::Value>,
    mask: serde_json::Value,
    #[serde(default)]
    default: bool,
    #[serde(default)]
    tags: Vec<String>,
    risk: String,
    #[serde(default)]
    priority: i64,
    confidence: f64,
    #[serde(default)]
    refine: bool,
    #[serde(default)]
    prefilter: Vec<String>,
    #[serde(default)]
    context: Option<ContextDocument>,
}

const TOKEN_ANY: &str = "(?s:.)";
const TOKEN_LETTER: &str = r"\p{L}";

fn expand_tokens(pattern: &str) -> String {
    pattern.replace("{{ANY}}", TOKEN_ANY).replace("{{L}}", TOKEN_LETTER)
}

const FORBIDDEN_ESCAPES: &str = "bBdDwWsSpP123456789AZzGkK";

/// Reject constructs whose meaning differs between the FRS-1 target engines.
fn assert_portable(pattern: &str, context: &str) -> Result<(), Error> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut index = 0usize;
    let mut in_class = false;
    while index < chars.len() {
        let ch = chars[index];
        if ch == '\\' {
            let Some(next) = chars.get(index + 1) else {
                return Err(Error::Pack(format!("{context}: pattern ends with a dangling backslash")));
            };
            if FORBIDDEN_ESCAPES.contains(*next) {
                return Err(Error::Pack(format!(
                    "{context}: '\\{next}' is not portable across FRS-1 engines; \
                     write the character class out, or use {{{{ANY}}}} / {{{{L}}}}"
                )));
            }
            index += 2;
            continue;
        }
        if in_class {
            if ch == ']' {
                in_class = false;
            }
            index += 1;
            continue;
        }
        if ch == '[' {
            index += 1;
            if chars.get(index) == Some(&'^') {
                index += 1;
            }
            if chars.get(index) == Some(&']') {
                index += 1;
            }
            in_class = true;
            continue;
        }
        if ch == '(' && chars.get(index + 1) == Some(&'?') {
            if chars.get(index + 2) != Some(&':') {
                return Err(Error::Pack(format!(
                    "{context}: only '(...)' and '(?:...)' groups are portable across FRS-1 engines"
                )));
            }
            index += 3;
            continue;
        }
        if ch == '^' || ch == '$' {
            return Err(Error::Pack(format!(
                "{context}: anchors are not allowed inside a detector pattern"
            )));
        }
        index += 1;
    }
    if in_class {
        return Err(Error::Pack(format!("{context}: unterminated character class")));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum Anchor {
    None,
    Prefix,
    Full,
}

fn compile(pattern: &str, flags: &str, context: &str, portable: bool, anchor: Anchor) -> Result<Regex, Error> {
    if portable {
        assert_portable(pattern, context)?;
    }
    let expanded = expand_tokens(pattern);
    let body = match anchor {
        Anchor::None => expanded,
        Anchor::Prefix => format!("^(?:{expanded})"),
        Anchor::Full => format!("^(?:{expanded})$"),
    };
    let source = if flags.contains('i') { format!("(?i){body}") } else { body };
    Regex::new(&source).map_err(|error| Error::Pack(format!("{context}: invalid pattern ({error})")))
}

fn json_str(value: &serde_json::Value, field: &str) -> Option<String> {
    value.get(field).and_then(|v| v.as_str()).map(str::to_string)
}

fn json_usize(value: &serde_json::Value, field: &str, fallback: usize) -> usize {
    value.get(field).and_then(|v| v.as_u64()).map(|n| n as usize).unwrap_or(fallback)
}

fn build_mask(spec: &serde_json::Value, context: &str) -> Result<Mask, Error> {
    let kind = json_str(spec, "type").unwrap_or_default();
    Ok(match kind.as_str() {
        "fixed" => Mask::Fixed(json_str(spec, "text").unwrap_or_else(|| "***".into())),
        "keepPrefix" => Mask::KeepPrefix(json_usize(spec, "n", 0)),
        "keepLast" => Mask::KeepLast(json_usize(spec, "n", 0)),
        "keepThroughSeparator" => Mask::KeepThroughSeparator {
            separator: json_str(spec, "separator").unwrap_or_else(|| "_".into()),
            count: json_usize(spec, "count", 1),
        },
        "replace" => Mask::Replace {
            pattern: compile(
                &json_str(spec, "pattern").unwrap_or_default(),
                &json_str(spec, "flags").unwrap_or_default(),
                &format!("{context} mask"),
                false,
                Anchor::Full,
            )?,
            replacement: json_str(spec, "replacement").unwrap_or_default(),
        },
        other => return Err(Error::Pack(format!("{context}: unknown mask type {other:?}"))),
    })
}

fn build_validator(spec: &serde_json::Value, context: &str) -> Result<Validator, Error> {
    let name = json_str(spec, "name").unwrap_or_default();
    Ok(match name.as_str() {
        "normalized_match" => Validator::NormalizedMatch {
            strip: match json_str(spec, "strip") {
                Some(strip) => Some(compile(&strip, "", &format!("{context} validator strip"), false, Anchor::None)?),
                None => None,
            },
            pattern: compile(
                &json_str(spec, "pattern").unwrap_or_default(),
                "",
                &format!("{context} validator"),
                false,
                Anchor::Full,
            )?,
        },
        "luhn" => Validator::Luhn {
            min: json_usize(spec, "minDigits", 2),
            max: json_usize(spec, "maxDigits", 0),
        },
        "entropy" => Validator::Entropy {
            min: spec.get("min").and_then(|v| v.as_f64()).unwrap_or(0.0),
        },
        other => match checksums::named(other) {
            Some(check) => Validator::Named(check),
            None => {
                return Err(Error::Pack(format!(
                    "{context}: unknown validator {other:?}; refusing to load a pack whose \
                     checks this engine cannot perform"
                )))
            }
        },
    })
}

fn boundary_for(name: &Option<String>, context: &str) -> Result<Option<CharClass>, Error> {
    let Some(name) = name else { return Ok(None) };
    match boundary_classes().get(name.as_str()) {
        Some(class) => Ok(Some(class.clone())),
        None => Err(Error::Pack(format!("{context}: unknown boundary class {name:?}"))),
    }
}

fn compile_detector(document: DetectorDocument) -> Result<Detector, Error> {
    let context = format!("detector {:?}", document.id);
    let Some(risk) = Risk::parse(&document.risk) else {
        return Err(Error::Pack(format!("{context}: risk must be low, medium, high or critical")));
    };
    if !(0.0..=1.0).contains(&document.confidence) {
        return Err(Error::Pack(format!("{context}: confidence must be between 0 and 1")));
    }
    if !document.flags.is_empty() && document.flags != "i" {
        return Err(Error::Pack(format!("{context}: only the 'i' flag is portable")));
    }

    let regex = compile(&document.pattern, &document.flags, &context, true, Anchor::None)?;
    if regex.is_match("") {
        return Err(Error::Pack(format!("{context}: pattern matches the empty string")));
    }
    if document.capture > regex.captures_len().saturating_sub(1) {
        return Err(Error::Pack(format!(
            "{context}: capture group {} does not exist",
            document.capture
        )));
    }

    let (before, after) = match &document.boundary {
        Some(boundary) => (
            boundary_for(&boundary.before, &context)?,
            boundary_for(&boundary.after, &context)?,
        ),
        None => (None, None),
    };

    let mut reject = Vec::with_capacity(document.reject.len());
    for pattern in &document.reject {
        reject.push(compile(pattern, &document.flags, &format!("{context} reject"), false, Anchor::Prefix)?);
    }

    let mut validators = Vec::with_capacity(document.validators.len());
    for spec in &document.validators {
        validators.push(build_validator(spec, &context)?);
    }

    let (context_positive, context_negative, context_window) = match &document.context {
        Some(document_context) => (
            match &document_context.positive {
                Some(pattern) => Some(compile(pattern, "i", &format!("{context} context"), false, Anchor::None)?),
                None => None,
            },
            match &document_context.negative {
                Some(pattern) => Some(compile(pattern, "i", &format!("{context} context"), false, Anchor::None)?),
                None => None,
            },
            document_context.window.unwrap_or(80),
        ),
        None => (None, None, 80),
    };

    Ok(Detector {
        id: document.id,
        label: document.label,
        why: document.why,
        risk,
        confidence: document.confidence,
        priority: document.priority,
        default_on: document.default,
        tags: document.tags,
        refine: document.refine,
        prefilter: document.prefilter.iter().map(|literal| literal.to_lowercase()).collect(),
        regex,
        capture: document.capture,
        before,
        after,
        unicode_boundary: false,
        reject,
        validators,
        mask: build_mask(&document.mask, &context)?,
        context_positive,
        context_negative,
        context_window,
    })
}

/// Compile an FRS-1 pack document.
pub fn load_pack(json: &str) -> Result<Pack, Error> {
    let document: PackDocument = serde_json::from_str(json)?;
    if document.spec != SPEC_REVISION {
        return Err(Error::Pack(format!(
            "unsupported pack revision {:?}; this engine implements {SPEC_REVISION}",
            document.spec
        )));
    }
    if document.detectors.is_empty() {
        return Err(Error::Pack("a pack must declare at least one detector".into()));
    }

    let title = document.title.clone().unwrap_or_else(|| document.id.clone());
    let mut detectors = Vec::with_capacity(document.detectors.len());
    let mut seen = std::collections::HashSet::new();
    for detector_document in document.detectors {
        let detector = compile_detector(detector_document)?;
        if !seen.insert(detector.id.clone()) {
            return Err(Error::Pack(format!("duplicate detector id {:?}", detector.id)));
        }
        detectors.push(detector);
    }

    let model = match document.confidence_model {
        Some(model) => Some(
            ConfidenceModel::new(model.version, &model.features, model.weights, model.bias)
                .map_err(Error::Pack)?,
        ),
        None => None,
    };

    Ok(Pack { id: document.id, version: document.version, title, detectors, model })
}

/// The bundled `flare-redact/core` pack, compiled once per process.
pub fn core_pack() -> Result<std::sync::Arc<Pack>, Error> {
    static CORE: OnceLock<Result<std::sync::Arc<Pack>, String>> = OnceLock::new();
    match CORE.get_or_init(|| {
        load_pack(CORE_PACK_JSON)
            .map(std::sync::Arc::new)
            .map_err(|error| error.to_string())
    }) {
        Ok(pack) => Ok(std::sync::Arc::clone(pack)),
        Err(message) => Err(Error::Pack(message.clone())),
    }
}

pub(crate) fn make_terms_detector(
    terms: &[crate::Term],
    case_sensitive: bool,
) -> Result<Option<Detector>, Error> {
    let mut ordered: Vec<&crate::Term> = terms.iter().filter(|term| !term.term.is_empty()).collect();
    if ordered.is_empty() {
        return Ok(None);
    }
    // Longest first, so "api_key" wins over any prefix of it.
    ordered.sort_by_key(|term| std::cmp::Reverse(term.term.len()));

    let alternation = ordered
        .iter()
        .map(|term| regex::escape(&term.term))
        .collect::<Vec<_>>()
        .join("|");
    let source = if case_sensitive {
        format!("(?:{alternation})")
    } else {
        format!("(?i)(?:{alternation})")
    };
    let regex = Regex::new(&source).map_err(|error| Error::Pack(format!("invalid term list: {error}")))?;

    let mut replacements: HashMap<String, String> = HashMap::new();
    for term in &ordered {
        let key = if case_sensitive { term.term.clone() } else { term.term.to_lowercase() };
        let replacement = if term.replace.is_empty() { "***".to_string() } else { term.replace.clone() };
        replacements.insert(key, replacement);
    }

    Ok(Some(Detector {
        id: "custom_term".into(),
        label: "Custom term".into(),
        why: "A term you configured as sensitive.".into(),
        risk: Risk::High,
        confidence: 0.92,
        priority: 0,
        default_on: true,
        tags: vec!["custom".into()],
        refine: false,
        prefilter: Vec::new(),
        regex,
        capture: 0,
        before: None,
        after: None,
        unicode_boundary: true,
        reject: Vec::new(),
        validators: Vec::new(),
        mask: Mask::Terms { replacements, case_sensitive },
        context_positive: None,
        context_negative: None,
        context_window: 80,
    }))
}
