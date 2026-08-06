//! Structured redaction over [`serde_json::Value`].
//!
//! `serde_json`'s default `Map` is a `BTreeMap`, so object entries are visited
//! in sorted key order. That matters: finding order and vault placeholder
//! numbering are observable, and the other FRS-1 engines impose the same order.

use serde_json::{Map, Value};

use crate::engine::Policy;
use crate::{Error, Finding};

/// Bound on structural recursion. `serde_json::Value` is acyclic, so this only
/// ever fires on pathologically nested input — which is exactly when a redactor
/// should refuse rather than blow the stack.
const MAX_DEPTH: usize = 512;

impl Policy {
    /// Redact every string reachable from `value`, preserving its shape.
    pub fn redact(&self, value: &Value) -> Result<Value, Error> {
        self.redact_at(value, 0)
    }

    fn redact_at(&self, value: &Value, depth: usize) -> Result<Value, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Limit(format!("value nests deeper than {MAX_DEPTH} levels")));
        }
        Ok(match value {
            Value::String(text) => Value::String(self.redact_str(text)?),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.redact_at(item, depth + 1)?);
                }
                Value::Array(out)
            }
            Value::Object(entries) => {
                let mut out = Map::new();
                for (key, entry) in entries {
                    let replaced = match entry {
                        Value::String(text) if self.is_sensitive_key(key) && !self.allows(text) => {
                            Value::String(self.replace_field(text))
                        }
                        other => self.redact_at(other, depth + 1)?,
                    };
                    out.insert(key.clone(), replaced);
                }
                Value::Object(out)
            }
            // Numbers, booleans and null are returned unchanged: a redactor that
            // stringifies a number changes the meaning of the document.
            other => other.clone(),
        })
    }

    /// List what would be redacted anywhere in `value`, with paths.
    pub fn scan(&self, value: &Value) -> Result<Vec<Finding>, Error> {
        let mut findings = Vec::new();
        self.scan_at(value, "", 0, &mut findings)?;
        Ok(findings)
    }

    fn scan_at(&self, value: &Value, path: &str, depth: usize, out: &mut Vec<Finding>) -> Result<(), Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Limit(format!("value nests deeper than {MAX_DEPTH} levels")));
        }
        match value {
            Value::String(text) => {
                for mut finding in self.scan_str(text)? {
                    finding.path = if path.is_empty() { None } else { Some(path.to_string()) };
                    out.push(finding);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    self.scan_at(item, &format!("{path}[{index}]"), depth + 1, out)?;
                }
            }
            Value::Object(entries) => {
                for (key, entry) in entries {
                    let child = if path.is_empty() { key.clone() } else { format!("{path}.{key}") };
                    if let Value::String(text) = entry {
                        if self.is_sensitive_key(key) && !self.allows(text) {
                            out.push(Finding {
                                detector: "sensitive_key".into(),
                                label: "Sensitive field".into(),
                                why: format!("Value stored under a sensitive field name (\"{key}\")."),
                                risk: "critical".into(),
                                confidence: 0.98,
                                start: None,
                                end: None,
                                line: None,
                                column: None,
                                path: Some(child),
                                value: if self.options().include_values { Some(text.clone()) } else { None },
                            });
                            continue;
                        }
                    }
                    self.scan_at(entry, &child, depth + 1, out)?;
                }
            }
            _ => {}
        }
        Ok(())
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
