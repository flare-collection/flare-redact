//! Structured redaction over [`serde_json::Value`].
//!
//! `serde_json`'s default `Map` is a `BTreeMap`, so object entries are visited
//! in sorted key order. That matters: finding order and vault placeholder
//! numbering are observable, and the other FRS-1 engines impose the same order.
//!
//! Everything under a sensitive key is masked whatever its type (SPEC §9):
//! strings, numbers (as their decimal text) and every string or number inside
//! an object or array at any depth. Booleans and null are kept, because they
//! are flags, not secrets.

use serde_json::{Map, Number, Value};

use crate::engine::Policy;
use crate::{Error, Finding};

/// Bound on structural recursion. `serde_json::Value` is acyclic, so this only
/// ever fires on pathologically nested input — which is exactly when a redactor
/// should refuse rather than blow the stack.
const MAX_DEPTH: usize = 512;

/// The text a number is replaced as under a sensitive key: an integer's digits,
/// and any other number as the JavaScript engine writes it.
pub(crate) fn number_text(number: &Number) -> String {
    if let Some(integer) = number.as_i64() {
        return integer.to_string();
    }
    if let Some(integer) = number.as_u64() {
        return integer.to_string();
    }
    match number.as_f64() {
        Some(float) => js_float(float),
        None => number.to_string(),
    }
}

/// A floating point number as ECMAScript's `Number::toString` writes it, so
/// every engine hashes and mints the same text: the shortest digits that
/// round-trip, in full from 1e-6 up to 1e21 and in exponent form outside.
pub(crate) fn js_float(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    if value == 0.0 {
        return "0".into();
    }
    let sign = if value < 0.0 { "-" } else { "" };
    // `{:e}` writes the shortest round-trip digits, as in 1.2345e20.
    let formatted = format!("{:e}", value.abs());
    let (mantissa, exponent) = formatted.split_once('e').unwrap_or((formatted.as_str(), "0"));
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let n = exponent.parse::<i32>().unwrap_or(0) + 1;
    let k = digits.len() as i32;
    if k <= n && n <= 21 {
        format!("{sign}{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        let (whole, fraction) = digits.split_at(n as usize);
        format!("{sign}{whole}.{fraction}")
    } else if -6 < n && n <= 0 {
        format!("{sign}0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let (first, rest) = digits.split_at(1);
        let rest = if rest.is_empty() { String::new() } else { format!(".{rest}") };
        let power = n - 1;
        let power_sign = if power >= 0 { '+' } else { '-' };
        format!("{sign}{first}{rest}e{power_sign}{}", power.abs())
    }
}

impl Policy {
    /// Redact every string reachable from `value`, preserving its shape.
    pub fn redact(&self, value: &Value) -> Result<Value, Error> {
        self.redact_at(value, 0, false)
    }

    /// `hot` is true under a sensitive key, where every string and number is
    /// replaced whole instead of being pattern matched.
    fn redact_at(&self, value: &Value, depth: usize, hot: bool) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Limit(format!("value nests deeper than {MAX_DEPTH} levels")));
        }
        Ok(match value {
            Value::String(text) if hot && !self.allows(text) => Value::String(self.replace_field(text)),
            Value::String(text) => Value::String(self.redact_str(text)?),
            Value::Number(number) if hot => {
                let text = number_text(number);
                match self.allows(&text) {
                    true => value.clone(),
                    false => Value::String(self.replace_field(&text)),
                }
            }
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.redact_at(item, depth + 1, hot)?);
                }
                Value::Array(out)
            }
            Value::Object(entries) => {
                let mut out = Map::new();
                for (key, entry) in entries {
                    let replaced = self.redact_at(entry, depth + 1, hot || self.is_sensitive_key(key))?;
                    out.insert(key.clone(), replaced);
                }
                Value::Object(out)
            }
            // Other numbers, booleans and null are returned unchanged: a
            // redactor that stringifies a number changes the meaning of the
            // document, so it does so only where the number is the secret.
            other => other.clone(),
        })
    }

    /// List what would be redacted anywhere in `value`, with paths.
    pub fn scan(&self, value: &Value) -> Result<Vec<Finding>, Error> {
        let mut findings = Vec::new();
        self.scan_at(value, "", 0, None, &mut findings)?;
        Ok(findings)
    }

    /// `under` is the sensitive key the value sits beneath, if any.
    fn scan_at<'a>(
        &self,
        value: &'a Value,
        path: &str,
        depth: usize,
        under: Option<&'a str>,
        out: &mut Vec<Finding>,
    ) -> Result<(), Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Limit(format!("value nests deeper than {MAX_DEPTH} levels")));
        }
        match value {
            Value::String(text) => {
                if let Some(key) = under {
                    if !self.allows(text) {
                        out.push(self.key_finding(key, text, path));
                        return Ok(());
                    }
                }
                for mut finding in self.scan_str(text)? {
                    finding.path = if path.is_empty() { None } else { Some(path.to_string()) };
                    out.push(finding);
                }
            }
            Value::Number(number) => {
                if let Some(key) = under {
                    let text = number_text(number);
                    if !self.allows(&text) {
                        out.push(self.key_finding(key, &text, path));
                    }
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    self.scan_at(item, &format!("{path}[{index}]"), depth + 1, under, out)?;
                }
            }
            Value::Object(entries) => {
                for (key, entry) in entries {
                    let child = if path.is_empty() { key.clone() } else { format!("{path}.{key}") };
                    let under = under.or_else(|| self.is_sensitive_key(key).then_some(key.as_str()));
                    self.scan_at(entry, &child, depth + 1, under, out)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn key_finding(&self, key: &str, text: &str, path: &str) -> Finding {
        Finding {
            detector: "sensitive_key".into(),
            label: "Sensitive field".into(),
            why: format!("Value stored under a sensitive field name (\"{key}\")."),
            risk: "critical".into(),
            confidence: 0.98,
            start: None,
            end: None,
            line: None,
            column: None,
            path: if path.is_empty() { None } else { Some(path.to_string()) },
            value: if self.options().include_values { Some(text.to_string()) } else { None },
        }
    }

    /// Whether nothing in `value` would be redacted.
    pub fn is_clean(&self, value: &Value) -> Result<bool, Error> {
        Ok(self.scan(value)?.is_empty())
    }

    /// Counts by detector and by risk. Contains no matched values, so it is safe
    /// to log.
    pub fn summarise(&self, value: &Value) -> Result<Summary, Error> {
        let findings = self.scan(value)?;
        let mut summary = Summary {
            total: findings.len(),
            by_detector: std::collections::BTreeMap::new(),
            by_risk: std::collections::BTreeMap::new(),
        };
        for finding in &findings {
            *summary.by_detector.entry(finding.detector.clone()).or_insert(0) += 1;
            *summary.by_risk.entry(finding.risk.clone()).or_insert(0) += 1;
        }
        Ok(summary)
    }

    /// Redact a JSON document and return a JSON document.
    pub fn redact_json(&self, document: &str) -> Result<String, Error> {
        let value: Value = serde_json::from_str(document)?;
        Ok(serde_json::to_string(&self.redact(&value)?)?)
    }
}

/// Counts of findings, without disclosing any of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Total findings.
    pub total: usize,
    /// Findings per detector id.
    pub by_detector: std::collections::BTreeMap<String, usize>,
    /// Findings per risk level.
    pub by_risk: std::collections::BTreeMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::js_float;

    #[test]
    fn float_text_matches_ecmascript() {
        let cases = [
            (1.5, "1.5"),
            (0.1, "0.1"),
            (1e-7, "1e-7"),
            (1.2e-5, "0.000012"),
            (1e21, "1e+21"),
            (1.5e21, "1.5e+21"),
            (1e16, "10000000000000000"),
            (100.0, "100"),
            (123456789012345680000.0, "123456789012345680000"),
            (0.1 + 0.2, "0.30000000000000004"),
            (5e-324, "5e-324"),
            (-42.25, "-42.25"),
            (-0.0, "0"),
            (f64::NAN, "NaN"),
            (f64::NEG_INFINITY, "-Infinity"),
        ];
        for (value, text) in cases {
            assert_eq!(js_float(value), text, "{value:?}");
        }
    }
}
