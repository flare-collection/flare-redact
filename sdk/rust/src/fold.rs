//! Case handling shared by every FRS-1 engine (SPEC §2 "Flags", §9).
//!
//! Case-insensitive matching is Unicode simple case folding plus one merge: i, I,
//! İ (U+0130) and ı (U+0131) form a single class. Simple folding alone keeps the
//! two Turkish letters apart from i, so `ŞİFRE`, `GİZLİ` or an identifier that
//! was upper-cased under a Turkish locale (`APİ_KEY`) would slip past every
//! keyword. The `regex` crate folds exactly, so case-insensitive patterns are
//! rewritten with [`expand_dotted_i`] before they are compiled.

use regex::Regex;

const DOTTED_CLASS: &str = "iI\u{130}\u{131}";
const DOTTED: [u32; 4] = [0x69, 0x49, 0x130, 0x131];

fn is_dotted(code: u32) -> bool {
    DOTTED.contains(&code)
}

/// Read one class or literal atom at byte `index`. The code is `None` for an
/// escape whose set is opaque (`\d`, `\p{…}`).
fn read_atom(source: &str, index: usize) -> (Option<u32>, usize) {
    let bytes = source.as_bytes();
    if bytes[index] != b'\\' {
        let ch = source[index..].chars().next().expect("index is a char boundary");
        return (Some(ch as u32), index + ch.len_utf8());
    }
    let Some(&esc) = bytes.get(index + 1) else {
        return (None, index + 1);
    };
    match esc {
        b'x' if index + 4 <= bytes.len()
            && bytes[index + 2].is_ascii_hexdigit()
            && bytes[index + 3].is_ascii_hexdigit() =>
        {
            let value = u32::from_str_radix(&source[index + 2..index + 4], 16).expect("two hex digits");
            (Some(value), index + 4)
        }
        b'p' | b'P' => {
            if bytes.get(index + 2) == Some(&b'{') {
                if let Some(close) = source[index + 3..].find('}') {
                    return (None, index + 3 + close + 1);
                }
            }
            (None, index + 2)
        }
        b't' => (Some(0x09), index + 2),
        b'n' => (Some(0x0A), index + 2),
        b'r' => (Some(0x0D), index + 2),
        b'f' => (Some(0x0C), index + 2),
        _ if esc.is_ascii_alphanumeric() => (None, index + 2),
        _ => {
            let ch = source[index + 1..].chars().next().expect("index is a char boundary");
            (Some(ch as u32), index + 1 + ch.len_utf8())
        }
    }
}

/// Rewrite a pattern that will be compiled case-insensitively so that i, I, İ
/// and ı are interchangeable. A literal becomes `[iIİı]`; a character class that
/// holds any of the four (directly or inside a range) gains the other three,
/// which for a negated class keeps all four out.
pub(crate) fn expand_dotted_i(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = String::with_capacity(source.len() + 16);
    let mut index = 0usize;
    while index < bytes.len() {
        let rest = &source[index..];
        if let Some(token) = rest.strip_prefix("{{") {
            let end = token.find("}}").map(|close| index + 2 + close + 2).unwrap_or(source.len());
            out.push_str(&source[index..end]);
            index = end;
            continue;
        }
        if is_named_group(rest) {
            // A named group header: its name is not a literal to rewrite.
            let end = rest.find('>').map(|close| index + close + 1).unwrap_or(source.len());
            out.push_str(&source[index..end]);
            index = end;
            continue;
        }
        if bytes[index] == b'[' {
            let (text, next) = rewrite_class(source, index);
            out.push_str(&text);
            index = next;
            continue;
        }
        let (code, next) = read_atom(source, index);
        if code.is_some_and(is_dotted) {
            out.push('[');
            out.push_str(DOTTED_CLASS);
            out.push(']');
        } else {
            out.push_str(&source[index..next]);
        }
        index = next;
    }
    out
}

fn is_named_group(rest: &str) -> bool {
    ["(?<", "(?P<"].iter().any(|head| {
        rest.starts_with(head) && rest.as_bytes().get(head.len()).is_some_and(|b| b.is_ascii_alphabetic())
    })
}

fn rewrite_class(source: &str, start: usize) -> (String, usize) {
    let bytes = source.as_bytes();
    let mut index = start + 1;
    if bytes.get(index) == Some(&b'^') {
        index += 1;
    }
    let body_start = index;
    if bytes.get(index) == Some(&b']') {
        index += 1;
    }
    let mut holds = false;
    let mut last_dash: Option<usize> = None;
    while index < bytes.len() && bytes[index] != b']' {
        let (mut low, next) = read_atom(source, index);
        let mut high = low;
        index = next;
        last_dash = None;
        if index + 1 < bytes.len() && bytes[index] == b'-' && bytes[index + 1] != b']' {
            let (second, next) = read_atom(source, index + 1);
            high = second;
            index = next;
            if low.is_none() || high.is_none() {
                low = None;
                high = None;
            }
        } else if bytes[index - 1] == b'-' && (index < 2 || bytes[index - 2] != b'\\') {
            last_dash = Some(index - 1);
        }
        if let (Some(low), Some(high)) = (low, high) {
            if DOTTED.iter().any(|code| (low..=high).contains(code)) {
                holds = true;
            }
        }
    }
    if index >= bytes.len() {
        // An unterminated class: leave it for the compiler to reject.
        return (source[start..].to_string(), source.len());
    }
    let mut text = source[start..body_start].to_string();
    let body = &source[body_start..index];
    if holds && last_dash == Some(index - 1) {
        // Never append right after a trailing literal '-': `[a-z-]` + `i` would
        // read as a range. Insert in front of that dash instead.
        text.push_str(&body[..body.len() - 1]);
        text.push_str(DOTTED_CLASS);
        text.push('-');
    } else {
        text.push_str(body);
        if holds {
            text.push_str(DOTTED_CLASS);
        }
    }
    text.push(']');
    (text, index + 1)
}

/// The form a key name is compared in (SPEC §9): İ and ı become i, every
/// character takes its lowercase mapping, and final sigma and long s fold to σ
/// and s, so every engine agrees.
pub(crate) fn normalize_key_name(name: &str) -> String {
    name.replace(['\u{130}', '\u{131}'], "i")
        .to_lowercase()
        .replace('\u{3c2}', "\u{3c3}")
        .replace('\u{17f}', "s")
}

/// One case-insensitive search for any of `literals`, with the same case rules
/// as a detector pattern, so a prefilter never skips a detector that would match.
pub(crate) fn compile_prefilter(literals: &[String]) -> Result<Option<Regex>, regex::Error> {
    if literals.is_empty() {
        return Ok(None);
    }
    let alternation = literals
        .iter()
        .map(|literal| expand_dotted_i(&regex::escape(literal)))
        .collect::<Vec<_>>()
        .join("|");
    Regex::new(&format!("(?i){alternation}")).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_literals_and_classes() {
        assert_eq!(expand_dotted_i("api"), "ap[iI\u{130}\u{131}]");
        assert_eq!(expand_dotted_i(r"\x49d"), "[iI\u{130}\u{131}]d");
        assert_eq!(expand_dotted_i("[a-z]"), "[a-ziI\u{130}\u{131}]");
        assert_eq!(expand_dotted_i("[a-z-]"), "[a-ziI\u{130}\u{131}-]");
        assert_eq!(expand_dotted_i("[^a-h]"), "[^a-h]");
        assert_eq!(expand_dotted_i("{{ANY}}i"), "{{ANY}}[iI\u{130}\u{131}]");
        assert_eq!(expand_dotted_i("[abc"), "[abc");
    }

    #[test]
    fn normalises_key_names() {
        assert_eq!(normalize_key_name("APİ_KEY"), "api_key");
        assert_eq!(normalize_key_name("ŞİFRE"), "şifre");
        assert_eq!(normalize_key_name("ΚΩΔΙΚΟΣ"), "κωδικοσ");
        assert_eq!(normalize_key_name("ſecret"), "secret");
    }
}
