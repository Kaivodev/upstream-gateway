use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fmt::Write;
pub fn object(b: &[u8]) -> Result<Value> {
    kaivo_upstream_sdk::json::object(b).context("invalid strict JSON object")
}
pub fn decode<T: DeserializeOwned>(b: &[u8]) -> Result<T> {
    Ok(serde_json::from_value(object(b)?)?)
}
fn quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c)
            }
            '\0'..='\x1f' => write!(out, "\\u{:04x}", c as u32).unwrap(),
            _ => out.push(c),
        }
    }
    out.push('"');
}
fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::String(s) => quote(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',')
                }
                write_value(x, out)
            }
            out.push(']')
        }
        Value::Object(o) => {
            out.push('{');
            let mut keys: Vec<_> = o.keys().collect();
            keys.sort_unstable();
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',')
                }
                quote(k, out);
                out.push(':');
                write_value(&o[k], out)
            }
            out.push('}')
        }
        _ => out.push_str(&v.to_string()),
    }
}
pub fn canonical(v: &Value) -> Vec<u8> {
    let mut out = String::new();
    write_value(v, &mut out);
    out.into_bytes()
}
/// Byte count under encoding/json's compact projection (including HTML escaping).
pub fn projected_len(v: &Value) -> usize {
    let bytes = serde_json::to_vec(v).unwrap();
    bytes.len()
        + bytes
            .iter()
            .filter(|b| matches!(b, b'<' | b'>' | b'&'))
            .count()
            * 5
        + bytes
            .windows(3)
            .filter(|s| matches!(*s, [0xe2, 0x80, 0xa8 | 0xa9]))
            .count()
            * 3
}

/// Inspect each decoded escaped JSON string, including overwritten duplicate members.
pub fn escaped_strings_match(b: &[u8], mut matches: impl FnMut(&[u8]) -> bool) -> bool {
    if !b.contains(&b'\\') || serde_json::from_slice::<serde::de::IgnoredAny>(b).is_err() {
        return false;
    }
    // Inspect every escaped string token, including duplicate object keys/values
    // that a map representation would collapse. Unescaped bytes were scanned above.
    let mut pos = 0;
    while let Some(start) = memchr::memchr(b'"', &b[pos..]).map(|i| i + pos) {
        pos = start + 1;
        let mut escaped = false;
        while let Some(i) = memchr::memchr2(b'"', b'\\', &b[pos..]).map(|i| i + pos) {
            if b[i] == b'\\' {
                escaped = true;
                pos = i + 2;
                continue;
            }
            pos = i + 1;
            if escaped
                && serde_json::from_slice::<String>(&b[start..pos])
                    .is_ok_and(|s| matches(s.as_bytes()))
            {
                return true;
            }
            break;
        }
    }
    false
}
