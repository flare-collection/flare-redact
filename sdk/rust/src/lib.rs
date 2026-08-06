//! Hide secrets and PII before they reach a log, a model, or a vendor.
//!
//! `flare-redact` implements the FRS-1 detector specification — the same one the
//! JavaScript, Python and Go engines implement — so a policy written once
//! behaves identically everywhere in a polyglot system. The shared conformance
//! corpus is run by every engine's test suite; a change that makes them disagree
//! fails CI.
//!
//! ```
//! use flare_redact::{Options, Policy};
//!
//! let policy = Policy::compile(Options::new().enable(["pii"]))?;
//! assert_eq!(policy.redact_str("contact ada@example.com")?, "contact a***@***");
//! # Ok::<(), flare_redact::Error>(())
//! ```
//!
//! Compile once and reuse the policy: it resolves the detector list, the
//! replacement function and the key tests a single time, and reusing it is what
//! guarantees your logs, your HTTP layer and your prompts agree on what
//! "sensitive" means.
//!
//! # Structured values
//!
//! [`Policy::redact`] walks a [`serde_json::Value`], so anything that serialises
//! can be redacted:
//!
//! ```
//! use flare_redact::{Options, Policy};
//! use serde_json::json;
//!
//! let policy = Policy::compile(Options::new())?;
//! let safe = policy.redact(&json!({"password": "hunter2", "count": 7}))?;
//! assert_eq!(safe["password"], "***");
//! assert_eq!(safe["count"], 7);
//! # Ok::<(), flare_redact::Error>(())
//! ```
//!
//! # Reversible redaction
//!
//! A [`Vault`] swaps each secret for a stable placeholder and remembers the
//! mapping, so a prompt can be sent to a model and the model's answer restored.
//! A [`Session`] keeps one vault across the turns of a conversation, and
//! [`StreamRestorer`] handles a placeholder split across streamed chunks.
//!
//! # Failure behaviour
//!
//! Limits fail closed. Oversized input returns [`Error::Limit`] rather than
//! partially redacted text, because a caller cannot tell partially redacted
//! output from clean output. A detector pack that uses a construct this engine
//! cannot execute exactly — a lookahead, a checksum it does not implement —
//! fails to load rather than loading with the check quietly skipped.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use std::sync::Arc;

pub mod checksums;
pub mod crypto;
mod engine;
mod keywords;
pub mod ml;
mod pack;
mod transforms;
mod value;
mod vault;

pub use engine::{Policy, DEFAULT_MAX_FINDINGS, DEFAULT_MAX_INPUT_LENGTH};
pub use keywords::secret_keywords;
pub use pack::{core_pack, load_pack, Detector, Pack, Risk, CORE_PACK_JSON, SPEC_REVISION};
pub use transforms::{pseudonymize, surrogate};
pub use value::Summary;
pub use vault::{PlaceholderStyle, Restorer, Session, StreamRestorer, Vault};

/// Everything that can go wrong. Each variant names a decision the caller can
/// act on, rather than collapsing into a single opaque string.
#[derive(Debug)]
pub enum Error {
    /// A detector pack is malformed, or uses a construct this engine cannot
    /// execute exactly as the specification describes.
    Pack(String),
    /// A configured limit was exceeded. Nothing was redacted.
    Limit(String),
    /// A keyed transform was requested without a `transform_secret`.
    MissingSecret,
    /// JSON could not be parsed or produced.
    Json(serde_json::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Pack(message) => write!(f, "flare-redact: {message}"),
            Error::Limit(message) => write!(f, "flare-redact: {message}"),
            Error::MissingSecret => write!(
                f,
                "flare-redact: a non-empty transform_secret is required for keyed transforms"
            ),
            Error::Json(error) => write!(f, "flare-redact: {error}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Json(error) => Some(error),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::Json(error)
    }
}

/// How a matched value is replaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// The detector's own mask, e.g. `a***@***`. The default.
    #[default]
    Mask,
    /// `[REDACTED:<detector id>]`, when you want to see *what* was removed.
    Label,
    /// `<detector id>_<HMAC fingerprint>`, for correlating without storing.
    Hash,
    /// A keyed, shape-preserving pseudonym. Not encryption, not reversible.
    Pseudonym,
    /// A type-consistent synthetic value: a card stays a valid card.
    Surrogate,
}

/// A caller-supplied word to always catch, with an optional replacement.
#[derive(Debug, Clone, Default)]
pub struct Term {
    /// The literal to match, on Unicode word boundaries.
    pub term: String,
    /// What to put in its place. Empty means `***`.
    pub replace: String,
}

impl Term {
    /// A term masked with `***`.
    pub fn new(term: impl Into<String>) -> Term {
        Term { term: term.into(), replace: String::new() }
    }

    /// A term with a specific replacement.
    pub fn replaced_with(term: impl Into<String>, replacement: impl Into<String>) -> Term {
        Term { term: term.into(), replace: replacement.into() }
    }
}

/// One thing the scanner would redact, and why.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// The detector that fired.
    pub detector: String,
    /// Human-readable detector name.
    pub label: String,
    /// One sentence on what an attacker gains.
    pub why: String,
    /// Privacy impact: `low`, `medium`, `high` or `critical`.
    pub risk: String,
    /// Confidence in `[0, 1]` after contextual adjustment.
    pub confidence: f64,
    /// Character offset of the match, when it came from a span of text.
    pub start: Option<usize>,
    /// Character offset just past the match.
    pub end: Option<usize>,
    /// One-based line within the scanned string.
    pub line: Option<usize>,
    /// One-based character column within the line.
    pub column: Option<usize>,
    /// Location inside a structured value, e.g. `user.contact.email`.
    pub path: Option<String>,
    /// The matched value. Populated only when `include_values` is set.
    pub value: Option<String>,
}

/// Everything that shapes a redaction.
///
/// The default is a working configuration: default detectors, mask mode, key
/// redaction on. The builder methods are chainable.
///
/// ```
/// use flare_redact::{Mode, Options};
///
/// let options = Options::new()
///     .enable(["pii", "tr"])
///     .disable(["ipv4"])
///     .mode(Mode::Label)
///     .min_confidence(0.7);
/// ```
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Use exactly these detector ids or tags, ignoring defaults.
    pub only: Vec<String>,
    /// Turn on non-default detectors by id or tag.
    pub enable: Vec<String>,
    /// Turn off detectors by id or tag.
    pub disable: Vec<String>,
    /// Replacement strategy.
    pub mode: Mode,
    /// A fixed replacement string, which wins over `mode`.
    pub mask: Option<String>,
    /// Key for the hash, pseudonym and surrogate modes.
    pub transform_secret: String,
    /// Turn off the "sensitive by field name" rule.
    pub disable_key_redaction: bool,
    /// Replace the built-in sensitive-name test with an exact list.
    pub key_names: Vec<String>,
    /// Values that are never redacted.
    pub allow: Vec<String>,
    /// Your own words to always catch.
    pub terms: Vec<Term>,
    /// Match `terms` exactly as written.
    pub terms_case_sensitive: bool,
    /// Drop findings scored below this.
    pub min_confidence: f64,
    /// Let the learned classifier adjust generic detectors' confidence.
    pub refine_confidence: bool,
    /// Include raw matched values in findings. Unsafe for logs.
    pub include_values: bool,
    /// Cap on the bytes of a single scanned string. 0 uses the default.
    pub max_input_length: usize,
    /// Cap on findings per scanned string. 0 uses the default.
    pub max_findings: usize,
    /// An alternative detector pack. Defaults to the bundled core pack.
    pub pack: Option<Arc<Pack>>,
}

fn to_strings<I, S>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    values.into_iter().map(Into::into).collect()
}

impl Options {
    /// Default options: the default detector set, mask mode, key redaction on.
    pub fn new() -> Options {
        Options::default()
    }

    /// Use exactly these detector ids or tags.
    pub fn only<I, S>(mut self, selectors: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.only = to_strings(selectors);
        self
    }

    /// Turn on non-default detectors.
    pub fn enable<I, S>(mut self, selectors: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.enable = to_strings(selectors);
        self
    }

    /// Turn off detectors.
    pub fn disable<I, S>(mut self, selectors: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.disable = to_strings(selectors);
        self
    }

    /// Choose the replacement strategy.
    pub fn mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Replace every match with a fixed string.
    pub fn mask(mut self, mask: impl Into<String>) -> Self {
        self.mask = Some(mask.into());
        self
    }

    /// Set the key for the hash, pseudonym and surrogate modes.
    pub fn transform_secret(mut self, secret: impl Into<String>) -> Self {
        self.transform_secret = secret.into();
        self
    }

    /// Values that are never redacted.
    pub fn allow<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allow = to_strings(values);
        self
    }

    /// Your own words to always catch.
    pub fn terms<I: IntoIterator<Item = Term>>(mut self, terms: I) -> Self {
        self.terms = terms.into_iter().collect();
        self
    }

    /// Drop findings scored below this confidence.
    pub fn min_confidence(mut self, minimum: f64) -> Self {
        self.min_confidence = minimum;
        self
    }

    /// Let the learned classifier refine confidence for generic detectors.
    pub fn refine_confidence(mut self, refine: bool) -> Self {
        self.refine_confidence = refine;
        self
    }

    /// Include raw matched values in findings.
    pub fn include_values(mut self, include: bool) -> Self {
        self.include_values = include;
        self
    }

    /// Use an alternative detector pack.
    pub fn pack(mut self, pack: Arc<Pack>) -> Self {
        self.pack = Some(pack);
        self
    }
}

/// Redact a single string. Compiles a policy and throws it away — fine for a
/// script, wasteful in a request path, where [`Policy::compile`] belongs.
pub fn redact_str(text: &str, options: Options) -> Result<String, Error> {
    Policy::compile(options)?.redact_str(text)
}

/// Redact any JSON value with the given options.
pub fn redact(value: &serde_json::Value, options: Options) -> Result<serde_json::Value, Error> {
    Policy::compile(options)?.redact(value)
}

/// List what would be redacted, with the given options.
pub fn scan(value: &serde_json::Value, options: Options) -> Result<Vec<Finding>, Error> {
    Policy::compile(options)?.scan(value)
}
