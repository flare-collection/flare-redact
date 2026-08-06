//! The learned secret-confidence classifier.
//!
//! Pattern-only detection over-fires on high-entropy text: a git SHA, a UUID, a
//! content digest and an API key all look alike to a character-class matcher.
//! This is a 14-feature logistic regression that scores how likely a match is a
//! real secret, so `refine_confidence` can push benign look-alikes below a
//! threshold instead of masking them.
//!
//! The weights ship inside the detector pack, which keeps scoring dependency
//! free, synchronous and identical across languages.

use regex::Regex;
use std::sync::OnceLock;

use crate::checksums::shannon_entropy;

/// Feature names in the exact order [`extract_features`] returns them. A pack
/// whose model declares a different layout is rejected at load time.
pub const FEATURES: [&str; 14] = [
    "log2Len", "entropy", "fracLower", "fracUpper", "fracDigit", "fracSymbol",
    "fracHex", "vowelFrac", "classTransitionRate", "hasMixedClasses",
    "maxRunFrac", "structuredHexId", "ctxSecret", "ctxBenign",
];

/// Logistic-regression weights loaded from a detector pack.
#[derive(Debug, Clone)]
pub struct ConfidenceModel {
    /// Model revision, carried through from the pack.
    pub version: i64,
    /// Weight per feature, aligned with [`FEATURES`].
    pub weights: Vec<f64>,
    /// Intercept.
    pub bias: f64,
}

impl ConfidenceModel {
    /// Validate that a pack's model matches this engine's feature layout.
    pub fn new(version: i64, features: &[String], weights: Vec<f64>, bias: f64) -> Result<Self, String> {
        if features.len() != FEATURES.len() || weights.len() != features.len() {
            return Err(format!(
                "confidence model declares {} features and {} weights; this engine implements {}",
                features.len(),
                weights.len(),
                FEATURES.len()
            ));
        }
        for (index, name) in features.iter().enumerate() {
            if name != FEATURES[index] {
                return Err(format!(
                    "confidence model feature {index} is {name:?}, expected {:?}",
                    FEATURES[index]
                ));
            }
        }
        Ok(Self { version, weights, bias })
    }
}

fn secret_context() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(secret|api[_-]?key|apikey|token|password|passwd|pwd|auth|authorization|bearer|access[_-]?key|private[_-]?key|client[_-]?secret|credential|signing[_-]?key)\b",
        )
        .expect("static pattern")
    })
}

fn benign_context() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)\b(uuid|guid|sha1|sha256|sha512|md5|hash|digest|etag|checksum|commit|revision|request[_-]?id|trace[_-]?id|correlation[_-]?id|span[_-]?id|object[_-]?id|content[_-]?id|version|colou?r|slug|filename)\b",
        )
        .expect("static pattern")
    })
}

fn structured_hex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{24}|[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$",
        )
        .expect("static pattern")
    })
}

/// Cheap character-level features for `value`, informed by nearby `context`.
pub fn extract_features(value: &str, context: &str) -> Vec<f64> {
    let chars: Vec<char> = value.chars().collect();
    let length = if chars.is_empty() { 1 } else { chars.len() };

    let (mut lower, mut upper, mut digit, mut symbol) = (0usize, 0usize, 0usize, 0usize);
    let (mut hexish, mut vowel, mut letters) = (0usize, 0usize, 0usize);
    let (mut transitions, mut run, mut max_run) = (0usize, 1usize, 1usize);
    let mut previous_class: i32 = -1;

    for ch in &chars {
        match ch {
            'a'..='z' => {
                lower += 1;
                letters += 1;
            }
            'A'..='Z' => {
                upper += 1;
                letters += 1;
            }
            '0'..='9' => digit += 1,
            _ => symbol += 1,
        }
        if ch.is_ascii_hexdigit() {
            hexish += 1;
        }
        if matches!(ch, 'a' | 'e' | 'i' | 'o' | 'u' | 'A' | 'E' | 'I' | 'O' | 'U') {
            vowel += 1;
        }
        let class = match ch {
            '0'..='9' => 1,
            'a'..='z' | 'A'..='Z' => 0,
            _ => 2,
        };
        if previous_class == -1 {
            previous_class = class;
        } else {
            if class != previous_class {
                transitions += 1;
                run = 1;
            } else {
                run += 1;
            }
            if run > max_run {
                max_run = run;
            }
            previous_class = class;
        }
    }

    let total = length as f64;
    let boolean = |ok: bool| if ok { 1.0 } else { 0.0 };

    vec![
        total.log2(),
        shannon_entropy(value),
        lower as f64 / total,
        upper as f64 / total,
        digit as f64 / total,
        symbol as f64 / total,
        hexish as f64 / total,
        if letters > 0 { vowel as f64 / letters as f64 } else { 0.0 },
        if length > 1 { transitions as f64 / (length - 1) as f64 } else { 0.0 },
        boolean(lower > 0 && upper > 0 && digit > 0),
        max_run as f64 / total,
        boolean(structured_hex().is_match(value)),
        boolean(secret_context().is_match(context)),
        boolean(benign_context().is_match(context)),
    ]
}

fn sigmoid(z: f64) -> f64 {
    if z >= 0.0 {
        1.0 / (1.0 + (-z).exp())
    } else {
        let e = z.exp();
        e / (1.0 + e)
    }
}

/// Probability in `[0, 1]` that `value` is a real secret rather than a benign
/// high-entropy look-alike.
pub fn secret_probability(value: &str, context: &str, model: &ConfidenceModel) -> f64 {
    let features = extract_features(value, context);
    let mut z = model.bias;
    for (weight, feature) in model.weights.iter().zip(features.iter()) {
        z += weight * feature;
    }
    sigmoid(z)
}
