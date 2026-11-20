//! Reversible redaction: vaults, sessions and stream restoration.
//!
//! Masking is one-way, which is right for logs and wrong for a model call. A
//! vault swaps each secret for a stable placeholder and remembers the mapping,
//! so you can send the redacted text to a model and put the originals back into
//! its answer. The model never sees the data; your user still gets the right
//! reply.

use std::collections::HashMap;

use regex::Regex;
use serde_json::{Map, Value};

use crate::engine::Policy;
use crate::{Error, Options};

/// The shape of minted placeholders.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PlaceholderStyle {
    /// `[FR_EMAIL_<random hex>]`. Carries no counter, so the redacted text does
    /// not disclose how many distinct values a conversation involved.
    #[default]
    Opaque,
    /// `[EMAIL_1]`. Predictable, so local debugging only.
    Readable,
}

/// A caller-supplied placeholder generator: detector id and occurrence index in,
/// placeholder out.
type PlaceholderFn = Box<dyn Fn(&str, usize) -> String + Send + Sync>;

/// A reversible redactor.
///
/// The same value always maps to the same placeholder within one vault, so
/// references survive a round trip: "email the address in message 1" still
/// resolves after redaction.
pub struct Vault {
    policy: Policy,
    style: PlaceholderStyle,
    custom: Option<PlaceholderFn>,
    by_value: HashMap<String, String>,
    by_placeholder: HashMap<String, String>,
    order: Vec<String>,
    counts: HashMap<String, usize>,
}

/// Best-effort opaque token.
///
/// `std` ships no random number generator, and pulling one in for placeholder
/// minting would double this crate's dependency list. `RandomState` is seeded
/// from the operating system at process start, which makes tokens unique and
/// unpredictable in practice — but it is not a CSPRNG. If your threat model
/// needs one, supply [`Vault::with_placeholder`].
fn opaque_token(counter: usize) -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let state = RandomState::new();
    let mut first = state.build_hasher();
    first.write_usize(counter);
    let high = first.finish();
    let mut second = state.build_hasher();
    second.write_u64(high);
    second.write_usize(counter.wrapping_add(0x9e37_79b9));
    let low = second.finish();
    format!("{high:016x}{:08x}", low as u32)
}

impl Vault {
    /// Compile options into a reversible redactor.
    pub fn new(options: Options) -> Result<Vault, Error> {
        Ok(Vault::with_policy(Policy::compile(options)?))
    }

    /// Reuse an already-compiled policy.
    pub fn with_policy(policy: Policy) -> Vault {
        Vault {
            policy,
            style: PlaceholderStyle::Opaque,
            custom: None,
            by_value: HashMap::new(),
            by_placeholder: HashMap::new(),
            order: Vec::new(),
            counts: HashMap::new(),
        }
    }

    /// Choose the placeholder style.
    pub fn style(mut self, style: PlaceholderStyle) -> Self {
        self.style = style;
        self
    }

    /// Mint placeholders with your own generator. It must never return the same
    /// token for two different values.
    pub fn with_placeholder<F>(mut self, generator: F) -> Self
    where
        F: Fn(&str, usize) -> String + Send + Sync + 'static,
    {
        self.custom = Some(Box::new(generator));
        self
    }

    fn format(&self, detector_id: &str, index: usize) -> String {
        if let Some(custom) = &self.custom {
            return custom(detector_id, index);
        }
        match self.style {
            PlaceholderStyle::Readable => format!("[{}_{index}]", detector_id.to_uppercase()),
            PlaceholderStyle::Opaque => {
                format!("[FR_{}_{}]", detector_id.to_uppercase(), opaque_token(index))
            }
        }
    }

    fn mint(&mut self, value: &str, detector_id: &str) -> Result<String, Error> {
        if let Some(existing) = self.by_value.get(value) {
            return Ok(existing.clone());
        }
        let index = {
            let counter = self.counts.entry(detector_id.to_string()).or_insert(0);
            *counter += 1;
            *counter
        };
        let placeholder = self.format(detector_id, index);
        if let Some(collision) = self.by_placeholder.get(&placeholder) {
            if collision != value {
                return Err(Error::Pack(format!(
                    "placeholder generator produced a duplicate token for {detector_id}"
                )));
            }
        }
        self.by_value.insert(value.to_string(), placeholder.clone());
        self.by_placeholder.insert(placeholder.clone(), value.to_string());
        self.order.push(placeholder.clone());
        Ok(placeholder)
    }

    /// Replace every secret in `text` with a stable placeholder.
    pub fn redact_str(&mut self, text: &str) -> Result<String, Error> {
        let plan: Vec<(usize, usize, String, String)> = self
            .policy
            .scan_hits(text)?
            .iter()
            .map(|hit| (hit.start, hit.end, hit.value.clone(), hit.detector.id.clone()))
            .collect();
        if plan.is_empty() {
            return Ok(text.to_string());
        }
        // A value captured from JSON text is stored decoded, so restoring it into
        // JSON escapes it exactly once and restoring it into prose gives the value.
        let json_text = is_json_document(text);
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0usize;
        for (start, end, value, detector_id) in plan {
            out.push_str(&text[cursor..start]);
            let value = match json_text {
                true => decode_json_string_content(&value).unwrap_or(value),
                false => value,
            };
            out.push_str(&self.mint(&value, &detector_id)?);
            cursor = end;
        }
        out.push_str(&text[cursor..]);
        Ok(out)
    }

    /// Replace every secret reachable from `value` with a stable placeholder.
    pub fn redact(&mut self, value: &Value) -> Result<Value, Error> {
        Ok(match value {
            Value::String(text) => Value::String(self.redact_str(text)?),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.redact(item)?);
                }
                Value::Array(out)
            }
            Value::Object(entries) => {
                let mut out = Map::new();
                for (key, entry) in entries {
                    let replaced = match entry {
                        Value::String(text)
                            if self.policy.is_sensitive_key(key) && !self.policy.allows(text) =>
                        {
                            Value::String(self.mint(text, "sensitive_key")?)
                        }
                        other => self.redact(other)?,
                    };
                    out.insert(key.clone(), replaced);
                }
                Value::Object(out)
            }
            other => other.clone(),
        })
    }

    /// Placeholder → original pairs, in the order they were minted.
    pub fn entries(&self) -> Vec<(String, String)> {
        self.order
            .iter()
            .map(|placeholder| (placeholder.clone(), self.by_placeholder[placeholder].clone()))
            .collect()
    }

    /// How many distinct values have been masked.
    pub fn len(&self) -> usize {
        self.by_placeholder.len()
    }

    /// Whether nothing has been masked yet.
    pub fn is_empty(&self) -> bool {
        self.by_placeholder.is_empty()
    }

    /// Put the originals back into `text`. When `text` is a JSON object or
    /// array, the originals go in JSON-escaped (see [`Restorer::json_aware`]).
    pub fn restore_str(&self, text: &str) -> String {
        Restorer::json_aware(&self.entries()).restore(text)
    }

    /// Put the originals back into any JSON value. A string that is a JSON
    /// object or array gets the originals JSON-escaped.
    pub fn restore(&self, value: &Value) -> Value {
        let restorer = Restorer::json_aware(&self.entries());
        restore_value(value, &restorer)
    }

    /// A restorer for streamed output, safe across chunk boundaries.
    pub fn stream(&self) -> StreamRestorer {
        StreamRestorer::new(&self.entries())
    }

    /// A stream restorer for text that is JSON, such as tool-call arguments
    /// (see [`StreamRestorer::json`]).
    pub fn stream_json(&self) -> StreamRestorer {
        StreamRestorer::json(&self.entries())
    }
}

/// `value` as it must appear inside a JSON string literal (FRS-1 §11): quote,
/// backslash and control characters escaped, nothing else.
fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => {
                let code = u32::from(c);
                out.push_str(&format!("\\u{code:04x}"));
            }
            c => out.push(c),
        }
    }
    out
}

/// Placeholder → original pairs with each original escaped for the inside of a
/// JSON string literal.
///
/// A placeholder can only sit inside a string in valid JSON, so an original
/// spliced in this form keeps the JSON valid, and quotes, backslashes or
/// control characters in it cannot end the string and add or replace fields.
pub fn escape_entries_for_json(entries: &[(String, String)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(placeholder, original)| (placeholder.clone(), json_escape(original)))
        .collect()
}

fn hex4(text: &str, at: usize) -> Option<u32> {
    let digits = text.get(at..at + 4)?;
    match digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        true => u32::from_str_radix(digits, 16).ok(),
        false => None,
    }
}

/// `text` read as the content of a JSON string literal, or `None` when it is
/// not valid content: an unescaped quote or control character, an unknown or
/// cut-off escape, or a `\u` escape that leaves a lone surrogate (FRS-1 §11).
pub(crate) fn decode_json_string_content(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    let mut run = 0usize;
    while i < bytes.len() {
        let byte = bytes[i];
        if byte == b'"' || byte < 0x20 {
            return None;
        }
        if byte != b'\\' {
            i += 1;
            continue;
        }
        out.push_str(&text[run..i]);
        let simple = match bytes.get(i + 1) {
            Some(b'"') => Some('"'),
            Some(b'\\') => Some('\\'),
            Some(b'/') => Some('/'),
            Some(b'b') => Some('\u{8}'),
            Some(b'f') => Some('\u{c}'),
            Some(b'n') => Some('\n'),
            Some(b'r') => Some('\r'),
            Some(b't') => Some('\t'),
            Some(b'u') => None,
            _ => return None,
        };
        if let Some(simple) = simple {
            out.push(simple);
            i += 2;
            run = i;
            continue;
        }
        let unit = hex4(text, i + 2)?;
        i += 6;
        let code = match unit {
            0xdc00..=0xdfff => return None,
            0xd800..=0xdbff => {
                if text.get(i..i + 2) != Some("\\u") {
                    return None;
                }
                let low = hex4(text, i + 2)?;
                if !(0xdc00..=0xdfff).contains(&low) {
                    return None;
                }
                i += 6;
                0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00)
            }
            _ => unit,
        };
        out.push(char::from_u32(code)?);
        run = i;
    }
    out.push_str(&text[run..]);
    Some(out)
}

/// Whether `text` is a complete JSON object or array.
pub fn is_json_document(text: &str) -> bool {
    let trimmed = text.trim_start_matches([' ', '\t', '\n', '\r']);
    (trimmed.starts_with('{') || trimmed.starts_with('['))
        && serde_json::from_str::<serde::de::IgnoredAny>(text).is_ok()
}

fn restore_value(value: &Value, restorer: &Restorer) -> Value {
    match value {
        Value::String(text) => Value::String(restorer.restore(text)),
        Value::Array(items) => Value::Array(items.iter().map(|item| restore_value(item, restorer)).collect()),
        Value::Object(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, entry)| (key.clone(), restore_value(entry, restorer)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// A single-pass placeholder → original replacer.
///
/// Longer placeholders are matched first, so a token that is a prefix of another
/// cannot clobber its peer and restore the wrong secret.
pub struct Restorer {
    pattern: Option<Regex>,
    lookup: HashMap<String, String>,
    /// Set by [`Restorer::json_aware`]: the same pairs with JSON-escaped originals.
    escaped: Option<Box<Restorer>>,
}

impl Restorer {
    /// Build a restorer from placeholder → original pairs.
    pub fn new(entries: &[(String, String)]) -> Restorer {
        if entries.is_empty() {
            return Restorer { pattern: None, lookup: HashMap::new(), escaped: None };
        }
        let mut ordered: Vec<&(String, String)> = entries.iter().collect();
        ordered.sort_by_key(|entry| std::cmp::Reverse(entry.0.len()));
        let alternation = ordered
            .iter()
            .map(|(placeholder, _)| regex::escape(placeholder))
            .collect::<Vec<_>>()
            .join("|");
        Restorer {
            pattern: Regex::new(&alternation).ok(),
            lookup: entries.iter().cloned().collect(),
            escaped: None,
        }
    }

    /// Like [`Restorer::new`], except that a string which is a JSON object or
    /// array (tool-call arguments, JSON-mode output) gets the originals
    /// JSON-escaped, so it is still valid JSON with the same structure after
    /// the restore. Any other string gets the originals verbatim.
    pub fn json_aware(entries: &[(String, String)]) -> Restorer {
        let mut restorer = Restorer::new(entries);
        if !entries.is_empty() {
            restorer.escaped = Some(Box::new(Restorer::new(&escape_entries_for_json(entries))));
        }
        restorer
    }

    /// Replace every known placeholder in `text`.
    pub fn restore(&self, text: &str) -> String {
        let restored = self.replace(text);
        match &self.escaped {
            Some(escaped) if restored != text && is_json_document(text) => escaped.replace(text),
            _ => restored,
        }
    }

    fn replace(&self, text: &str) -> String {
        let Some(pattern) = &self.pattern else { return text.to_string() };
        pattern
            .replace_all(text, |captures: &regex::Captures<'_>| {
                let matched = captures.get(0).map(|m| m.as_str()).unwrap_or_default();
                self.lookup.get(matched).cloned().unwrap_or_else(|| matched.to_string())
            })
            .into_owned()
    }
}

/// Restores placeholders in a stream, even when one is split across chunks.
///
/// The restorer holds back the longest suffix of what it has buffered that could
/// still turn out to be the start of a placeholder. Everything before that is
/// safe to emit immediately, so a token streamed as `[FR_EMA` + `IL_ab…]` is
/// still restored exactly once.
pub struct StreamRestorer {
    restorer: Restorer,
    placeholders: Vec<String>,
    buffer: String,
}

impl StreamRestorer {
    /// A stream restorer for text that is JSON (tool-call arguments, partial
    /// tool input, JSON-mode output): the originals go in JSON-escaped, so the
    /// assembled text stays valid JSON and a restored value cannot add or
    /// replace fields in it.
    pub fn json(entries: &[(String, String)]) -> StreamRestorer {
        StreamRestorer::new(&escape_entries_for_json(entries))
    }

    /// Build a stream restorer from placeholder → original pairs.
    pub fn new(entries: &[(String, String)]) -> StreamRestorer {
        StreamRestorer {
            restorer: Restorer::new(entries),
            placeholders: entries.iter().map(|(placeholder, _)| placeholder.clone()).collect(),
            buffer: String::new(),
        }
    }

    fn pending_prefix_length(&self) -> usize {
        let mut keep = 0usize;
        for placeholder in &self.placeholders {
            let limit = self.buffer.len().min(placeholder.len().saturating_sub(1));
            let mut length = limit;
            while length > keep {
                if placeholder.is_char_boundary(length)
                    && self.buffer.is_char_boundary(self.buffer.len() - length)
                    && self.buffer.ends_with(&placeholder[..length])
                {
                    keep = length;
                    break;
                }
                length -= 1;
            }
        }
        keep
    }

    /// Feed a chunk; get back the text that is safe to display now.
    pub fn push(&mut self, chunk: &str) -> String {
        self.buffer.push_str(chunk);
        let keep = self.pending_prefix_length();
        let cut = self.buffer.len() - keep;
        let emitted = self.buffer[..cut].to_string();
        self.buffer = self.buffer[cut..].to_string();
        self.restorer.restore(&emitted)
    }

    /// Emit whatever is still held back once the stream ends.
    pub fn flush(&mut self) -> String {
        let out = self.restorer.restore(&self.buffer);
        self.buffer.clear();
        out
    }
}

/// A conversation-scoped vault.
///
/// One session keeps one vault, so the same value maps to the same placeholder
/// across every turn: mask the user's message on the way in, restore the model's
/// answer on the way out.
pub struct Session {
    options: Options,
    style: PlaceholderStyle,
    vault: Vault,
}

impl Session {
    /// Open a conversation-scoped vault.
    pub fn new(options: Options, style: PlaceholderStyle) -> Result<Session, Error> {
        let vault = Vault::new(options.clone())?.style(style);
        Ok(Session { options, style, vault })
    }

    /// The underlying placeholder ↔ original map.
    pub fn vault(&self) -> &Vault {
        &self.vault
    }

    /// Mask a message before it reaches the model.
    pub fn redact(&mut self, value: &Value) -> Result<Value, Error> {
        self.vault.redact(value)
    }

    /// Mask a string before it reaches the model.
    pub fn redact_str(&mut self, text: &str) -> Result<String, Error> {
        self.vault.redact_str(text)
    }

    /// Restore the model's reply before showing it to the user.
    pub fn restore(&self, value: &Value) -> Value {
        self.vault.restore(value)
    }

    /// Restore a string reply.
    pub fn restore_str(&self, text: &str) -> String {
        self.vault.restore_str(text)
    }

    /// A restorer for a streamed reply.
    pub fn stream(&self) -> StreamRestorer {
        self.vault.stream()
    }

    /// A restorer for a streamed reply that is JSON.
    pub fn stream_json(&self) -> StreamRestorer {
        self.vault.stream_json()
    }

    /// Start a fresh conversation with no carried-over mappings.
    pub fn reset(&mut self) -> Result<(), Error> {
        self.vault = Vault::new(self.options.clone())?.style(self.style);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::decode_json_string_content as decode;

    #[test]
    fn decodes_json_string_content() {
        assert_eq!(decode("plain").as_deref(), Some("plain"));
        assert_eq!(decode(r#"q\"b\\s\/"#).as_deref(), Some(r#"q"b\s/"#));
        assert_eq!(decode(r"\b\f\n\r\t").as_deref(), Some("\u{8}\u{c}\n\r\t"));
        assert_eq!(decode(r"é😀").as_deref(), Some("\u{e9}\u{1F600}"));
        for text in [
            "a\"b", "a\nb", "a\\", r"\x", r"\u12", r"\ud800", r"\udc00", r"\ud800A",
        ] {
            assert_eq!(decode(text), None, "{text:?}");
        }
    }
}
