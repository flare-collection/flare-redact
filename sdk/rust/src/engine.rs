//! The FRS-1 scan and redact engine.
//!
//! Everything this crate does reduces to one function: given a string, produce
//! the set of spans that must not survive, then rewrite the string once.
//!
//! Two decisions are worth knowing about. Overlap resolution is maximum-weight
//! interval scheduling rather than first-match, so a value that is both an
//! OpenRouter key and a high-entropy string is masked the same way regardless of
//! what else is on the line. And limits fail closed: oversized input is an error
//! rather than partially redacted text, because a caller cannot tell partially
//! redacted output from clean output.

use std::collections::HashSet;
use std::sync::Arc;

use crate::keywords::is_sensitive_key_name;
use crate::ml::secret_probability;
use crate::pack::{core_pack, make_terms_detector, Detector, Pack};
use crate::transforms::{pseudonymize, surrogate};
use crate::{Error, Finding, Mode, Options};

/// Maximum bytes in a single scanned string, unless overridden.
pub const DEFAULT_MAX_INPUT_LENGTH: usize = 16 * 1024 * 1024;
/// Maximum findings per scanned string, unless overridden.
pub const DEFAULT_MAX_FINDINGS: usize = 50_000;

/// How far the learned model may move a base confidence score, up or down.
const REFINE_STRENGTH: f64 = 0.4;

/// Invisible characters an attacker can splice through a secret to defeat a
/// naive matcher. Stripped before matching; see [`normalised_view`].
const ZERO_WIDTH: [char; 5] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}', '\u{FEFF}'];

pub(crate) struct Hit<'a> {
    pub(crate) detector: &'a Detector,
    /// Byte offsets into the original string.
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) value: String,
    pub(crate) confidence: f64,
    pub(crate) weight: f64,
}

/// One compiled set of options, reusable everywhere.
///
/// Building a policy resolves the detector list, the replacement function and
/// the key and allow tests once. Reuse it: one policy shared across your logger,
/// your HTTP layer and your prompt path is what makes "sensitive" mean the same
/// thing in all three.
pub struct Policy {
    options: Options,
    pack: Arc<Pack>,
    terms: Option<Detector>,
    selected: Vec<usize>,
    has_prefilter: bool,
    allow: HashSet<String>,
    key_names: Option<HashSet<String>>,
    max_input_length: usize,
    max_findings: usize,
}

impl Policy {
    /// Compile options into a reusable policy.
    pub fn compile(options: Options) -> Result<Policy, Error> {
        let pack = match &options.pack {
            Some(pack) => Arc::clone(pack),
            None => core_pack()?,
        };

        let mut selected = Vec::new();
        for (index, detector) in pack.detectors.iter().enumerate() {
            let chosen = if !options.only.is_empty() {
                options.only.iter().any(|selector| detector.matches_selector(selector))
            } else {
                (detector.default_on
                    || options.enable.iter().any(|selector| detector.matches_selector(selector)))
                    && !options.disable.iter().any(|selector| detector.matches_selector(selector))
            };
            if chosen {
                selected.push(index);
            }
        }

        let terms = make_terms_detector(&options.terms, options.terms_case_sensitive)?;

        // Reject an unusable mode at compile time rather than on the first value.
        match options.mode {
            Mode::Hash | Mode::Pseudonym | Mode::Surrogate if options.transform_secret.is_empty() => {
                return Err(Error::MissingSecret)
            }
            _ => {}
        }

        let has_prefilter = terms.as_ref().is_some_and(|t| !t.prefilter.is_empty())
            || selected.iter().any(|index| !pack.detectors[*index].prefilter.is_empty());

        Ok(Policy {
            allow: options.allow.iter().cloned().collect(),
            key_names: if options.key_names.is_empty() {
                None
            } else {
                Some(options.key_names.iter().map(|name| name.to_lowercase()).collect())
            },
            max_input_length: if options.max_input_length > 0 {
                options.max_input_length
            } else {
                DEFAULT_MAX_INPUT_LENGTH
            },
            max_findings: if options.max_findings > 0 { options.max_findings } else { DEFAULT_MAX_FINDINGS },
            options,
            pack,
            terms,
            selected,
            has_prefilter,
        })
    }

    pub(crate) fn options(&self) -> &Options {
        &self.options
    }

    /// The detectors this policy runs, in evaluation order.
    pub fn detectors(&self) -> Vec<&Detector> {
        let mut out: Vec<&Detector> = Vec::with_capacity(self.selected.len() + 1);
        if let Some(terms) = &self.terms {
            out.push(terms);
        }
        for index in &self.selected {
            out.push(&self.pack.detectors[*index]);
        }
        out
    }

    pub(crate) fn allows(&self, value: &str) -> bool {
        self.allow.contains(value)
    }

    pub(crate) fn is_sensitive_key(&self, name: &str) -> bool {
        if self.options.disable_key_redaction {
            return false;
        }
        match &self.key_names {
            Some(names) => names.contains(&name.to_lowercase()),
            None => is_sensitive_key_name(name),
        }
    }

    /// Replace a matched value according to the configured mode.
    pub(crate) fn replace(&self, value: &str, detector: &Detector) -> String {
        if let Some(mask) = &self.options.mask {
            return mask.clone();
        }
        match self.options.mode {
            Mode::Mask => detector.mask.apply(value),
            Mode::Label => format!("[REDACTED:{}]", detector.id),
            Mode::Hash => format!(
                "{}_{}",
                detector.id,
                crate::crypto::hmac_fingerprint(&self.options.transform_secret, value, 16)
            ),
            Mode::Pseudonym => pseudonymize(value, &self.options.transform_secret),
            Mode::Surrogate => surrogate(value, &detector.id, &self.options.transform_secret),
        }
    }

    /// The replacement for a value found under a sensitive field name.
    pub(crate) fn replace_field(&self, value: &str) -> String {
        if let Some(mask) = &self.options.mask {
            return mask.clone();
        }
        match self.options.mode {
            Mode::Mask => "***".to_string(),
            Mode::Label => "[REDACTED:sensitive_key]".to_string(),
            Mode::Hash => format!(
                "sensitive_key_{}",
                crate::crypto::hmac_fingerprint(&self.options.transform_secret, value, 16)
            ),
            Mode::Pseudonym => pseudonymize(value, &self.options.transform_secret),
            Mode::Surrogate => surrogate(value, "sensitive_key", &self.options.transform_secret),
        }
    }

    fn score_confidence(&self, detector: &Detector, text: &str, start: usize, end: usize) -> f64 {
        let mut score = detector.confidence;
        if detector.context_positive.is_some() || detector.context_negative.is_some() {
            let window = slice_around(text, start, end, detector.context_window);
            if let Some(positive) = &detector.context_positive {
                if positive.is_match(window) {
                    score += 0.06;
                }
            }
            if let Some(negative) = &detector.context_negative {
                if negative.is_match(window) {
                    score -= 0.25;
                }
            }
        }
        if self.options.refine_confidence && detector.refine {
            if let Some(model) = &self.pack.model {
                let window = slice_around(text, start, end, 64);
                score += (secret_probability(&text[start..end], window, model) - 0.5) * REFINE_STRENGTH;
            }
        }
        score.clamp(0.0, 1.0)
    }

    pub(crate) fn scan_hits<'a>(&'a self, text: &str) -> Result<Vec<Hit<'a>>, Error> {
        if text.len() > self.max_input_length {
            return Err(Error::Limit(format!(
                "input length {} exceeds the configured limit of {}",
                text.len(),
                self.max_input_length
            )));
        }

        let (normalised, source) = normalised_view(text);
        let subject: &str = normalised.as_ref();
        let lowered = if self.has_prefilter { Some(subject.to_lowercase()) } else { None };

        let detectors = self.detectors();
        let mut hits: Vec<Hit<'a>> = Vec::new();
        for detector in detectors {
            if !detector.prefilter.is_empty() {
                let lowered = lowered.as_deref().unwrap_or("");
                if !detector.prefilter.iter().any(|literal| lowered.contains(literal.as_str())) {
                    continue;
                }
            }

            for captures in detector.regex.captures_iter(subject) {
                let Some(matched) = captures.get(detector.capture) else { continue };
                let (ns, ne) = (matched.start(), matched.end());
                if ne <= ns {
                    continue;
                }
                if !boundary_ok(detector, subject, ns, ne) {
                    continue;
                }
                let normalised_value = &subject[ns..ne];
                if detector.reject.iter().any(|pattern| pattern.is_match(normalised_value)) {
                    continue;
                }
                if !detector.validators.iter().all(|validator| validator.accepts(normalised_value)) {
                    continue;
                }

                let (start, end) = match &source {
                    Some(map) => (map[ns], map[ne - 1] + 1),
                    None => (ns, ne),
                };
                let value = &text[start..end];
                if self.allows(value) || (value != normalised_value && self.allows(normalised_value)) {
                    continue;
                }

                let confidence = self.score_confidence(detector, text, start, end);
                if confidence < self.options.min_confidence {
                    continue;
                }

                hits.push(Hit {
                    detector,
                    start,
                    end,
                    value: value.to_string(),
                    confidence,
                    weight: detector.risk.weight()
                        + 10.0 * detector.priority as f64
                        + confidence
                        + (end - start) as f64 / 1_000_000.0,
                });
                if hits.len() > self.max_findings {
                    return Err(Error::Limit(format!(
                        "finding count exceeds the configured limit of {}",
                        self.max_findings
                    )));
                }
            }
        }

        if hits.len() < 2 {
            return Ok(hits);
        }
        Ok(select_non_overlapping(hits))
    }

    /// Redact one string in a single pass. Replacements are never rescanned, so
    /// a mask can never itself be masked.
    pub fn redact_str(&self, text: &str) -> Result<String, Error> {
        let hits = self.scan_hits(text)?;
        if hits.is_empty() {
            return Ok(text.to_string());
        }
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        for hit in &hits {
            out.push_str(&text[cursor..hit.start]);
            out.push_str(&self.replace(&hit.value, hit.detector));
            cursor = hit.end;
        }
        out.push_str(&text[cursor..]);
        Ok(out)
    }

    /// List what would be redacted in one string, and why.
    pub fn scan_str(&self, text: &str) -> Result<Vec<Finding>, Error> {
        let hits = self.scan_hits(text)?;
        let mut findings = Vec::with_capacity(hits.len());
        for hit in hits {
            let (line, column) = locate(text, hit.start);
            findings.push(Finding {
                detector: hit.detector.id.clone(),
                label: hit.detector.label.clone(),
                why: hit.detector.why.clone(),
                risk: hit.detector.risk.as_str().to_string(),
                confidence: hit.confidence,
                start: Some(text[..hit.start].chars().count()),
                end: Some(text[..hit.end].chars().count()),
                line: Some(line),
                column: Some(column),
                path: None,
                value: if self.options.include_values { Some(hit.value.clone()) } else { None },
            });
        }
        Ok(findings)
    }
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("pack", &self.pack.id)
            .field("detectors", &(self.selected.len() + usize::from(self.terms.is_some())))
            .field("mode", &self.options.mode)
            .finish()
    }
}

fn boundary_ok(detector: &Detector, subject: &str, start: usize, end: usize) -> bool {
    if detector.unicode_boundary {
        if start > 0 {
            if let Some(previous) = subject[..start].chars().next_back() {
                if previous == '_' || previous.is_alphabetic() || previous.is_numeric() {
                    return false;
                }
            }
        }
        if end < subject.len() {
            if let Some(next) = subject[end..].chars().next() {
                if next == '_' || next.is_alphabetic() || next.is_numeric() {
                    return false;
                }
            }
        }
        return true;
    }
    let bytes = subject.as_bytes();
    if let Some(before) = &detector.before {
        if start > 0 && before.contains(bytes[start - 1]) {
            return false;
        }
    }
    if let Some(after) = &detector.after {
        if end < bytes.len() && after.contains(bytes[end]) {
            return false;
        }
    }
    true
}

/// Strip zero-width characters, keeping a map from each byte of the stripped
/// text back to its byte offset in the original.
fn normalised_view(text: &str) -> (std::borrow::Cow<'_, str>, Option<Vec<usize>>) {
    if !text.chars().any(|ch| ZERO_WIDTH.contains(&ch)) {
        return (std::borrow::Cow::Borrowed(text), None);
    }
    let mut stripped = String::with_capacity(text.len());
    let mut source = Vec::with_capacity(text.len() + 1);
    for (offset, ch) in text.char_indices() {
        if ZERO_WIDTH.contains(&ch) {
            continue;
        }
        stripped.push(ch);
        for byte in 0..ch.len_utf8() {
            source.push(offset + byte);
        }
    }
    source.push(text.len());
    (std::borrow::Cow::Owned(stripped), Some(source))
}

/// A window of `radius` bytes either side of a span, snapped to char boundaries.
fn slice_around(text: &str, start: usize, end: usize, radius: usize) -> &str {
    let mut low = start.saturating_sub(radius);
    while low > 0 && !text.is_char_boundary(low) {
        low -= 1;
    }
    let mut high = (end + radius).min(text.len());
    while high < text.len() && !text.is_char_boundary(high) {
        high += 1;
    }
    &text[low..high]
}

/// One-based line and column, counted in characters.
fn locate(text: &str, offset: usize) -> (usize, usize) {
    let head = &text[..offset];
    let line = 1 + head.matches('\n').count();
    let line_start = head.rfind('\n').map(|index| index + 1).unwrap_or(0);
    (line, text[line_start..offset].chars().count() + 1)
}

/// Keep the maximum-weight set of non-overlapping spans. First-match-wins would
/// make masking depend on detector order, so the same secret could be masked
/// differently depending on what else was nearby.
fn select_non_overlapping<'a>(hits: Vec<Hit<'a>>) -> Vec<Hit<'a>> {
    let mut ordered = hits;
    ordered.sort_by(|a, b| a.end.cmp(&b.end).then(a.start.cmp(&b.start)));

    let count = ordered.len();
    let mut previous = vec![-1i64; count];
    for index in 0..count {
        let (mut low, mut high, mut found) = (0i64, index as i64 - 1, -1i64);
        while low <= high {
            let mid = (low + high) / 2;
            if ordered[mid as usize].end <= ordered[index].start {
                found = mid;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
        previous[index] = found;
    }

    let mut best = vec![0f64; count + 1];
    for index in 1..=count {
        let include = ordered[index - 1].weight + best[(previous[index - 1] + 1) as usize];
        best[index] = best[index - 1].max(include);
    }

    let mut keep = vec![false; count];
    let mut index = count;
    while index > 0 {
        let include = ordered[index - 1].weight + best[(previous[index - 1] + 1) as usize];
        if include > best[index - 1] {
            keep[index - 1] = true;
            index = (previous[index - 1] + 1) as usize;
        } else {
            index -= 1;
        }
    }

    let mut selected: Vec<Hit<'a>> = ordered
        .into_iter()
        .zip(keep)
        .filter_map(|(hit, kept)| if kept { Some(hit) } else { None })
        .collect();
    selected.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)));
    selected
}
