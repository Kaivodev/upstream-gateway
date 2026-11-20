//! Byte-oriented application/x-www-form-urlencoded encoding, including repeated values.
use std::collections::BTreeMap;
pub type Values = BTreeMap<Vec<u8>, Vec<Vec<u8>>>;
const HEX: &[u8; 16] = b"0123456789ABCDEF";
const fn literals(path: bool) -> [bool; 256] {
    let mut table = [false; 256];
    let mut i = 0;
    while i < 256 {
        let b = i as u8;
        table[i] = b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'_' | b'.' | b'~')
            || path && matches!(b, b'$' | b'&' | b'+' | b':' | b'=' | b'@');
        i += 1;
    }
    table
}
const QUERY_LITERAL: [bool; 256] = literals(false);
const PATH_LITERAL: [bool; 256] = literals(true);

fn escape_into(mut input: &[u8], path: bool, out: &mut Vec<u8>) {
    let table = if path { &PATH_LITERAL } else { &QUERY_LITERAL };
    while let Some(i) = input.iter().position(|&b| !table[b as usize]) {
        out.extend_from_slice(&input[..i]);
        let b = input[i];
        if b == b' ' && !path {
            out.push(b'+')
        } else {
            out.extend_from_slice(&[b'%', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]);
        }
        input = &input[i + 1..];
    }
    out.extend_from_slice(input);
}
fn escaped(input: &[u8], path: bool) -> String {
    let mut out = Vec::with_capacity(input.len());
    escape_into(input, path, &mut out);
    String::from_utf8(out).expect("escaping emits ASCII")
}
pub fn path_escape(s: &str) -> String {
    escaped(s.as_bytes(), true)
}
pub fn query_escape(s: &[u8]) -> String {
    escaped(s, false)
}
fn unescape(mut s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    while let Some(i) = s.iter().position(|b| matches!(b, b'+' | b'%')) {
        out.extend_from_slice(&s[..i]);
        s = &s[i..];
        if s[0] == b'+' {
            out.push(b' ');
            s = &s[1..]
        } else {
            let hi = (*s.get(1)? as char).to_digit(16)?;
            let lo = (*s.get(2)? as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            s = &s[3..];
        }
    }
    out.extend_from_slice(s);
    Some(out)
}
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueryError {
    InvalidSemicolon,
    InvalidEscape,
}

/// Return all valid pairs even when another pair is malformed, as Go ParseQuery does.
pub fn parse_query(raw: &[u8]) -> (Values, Option<QueryError>) {
    let mut out = Values::new();
    let mut error = None;
    for part in raw.split(|b| *b == b'&').filter(|p| !p.is_empty()) {
        if part.contains(&b';') {
            error = Some(QueryError::InvalidSemicolon);
            continue;
        }
        let i = part.iter().position(|b| *b == b'=').unwrap_or(part.len());
        match (
            unescape(&part[..i]),
            unescape(part.get(i + 1..).unwrap_or_default()),
        ) {
            (Some(k), Some(v)) => out.entry(k).or_default().push(v),
            _ => {
                error.get_or_insert(QueryError::InvalidEscape);
            }
        }
    }
    (out, error)
}
/// Strict form parsing for signing and replay.
pub fn parse(raw: &[u8]) -> Option<Values> {
    let (v, err) = parse_query(raw);
    err.is_none().then_some(v)
}
fn encode_pairs(v: &Values, omit_sign: bool) -> Vec<u8> {
    let include = |(k, _): &(&Vec<u8>, &Vec<Vec<u8>>)| !omit_sign || k.as_slice() != b"sign";
    let pairs = v.iter().filter(include);
    let capacity = pairs
        .clone()
        .map(|(k, vs)| vs.iter().map(|s| k.len() + s.len() + 2).sum::<usize>())
        .sum();
    let mut out = Vec::with_capacity(capacity);
    for (k, vs) in pairs {
        for value in vs {
            if !out.is_empty() {
                out.push(b'&')
            }
            escape_into(k, false, &mut out);
            out.push(b'=');
            escape_into(value, false, &mut out);
        }
    }
    out
}
pub fn encode_bytes(v: &Values) -> Vec<u8> {
    encode_pairs(v, false)
}
pub fn encode(v: &Values) -> String {
    String::from_utf8(encode_bytes(v)).expect("escaping emits ASCII")
}
pub fn single_values(v: &Values) -> bool {
    v.iter().all(|(k, vs)| !k.is_empty() && vs.len() == 1)
}
pub fn canonical_bytes(v: &Values) -> Option<Vec<u8>> {
    single_values(v).then(|| encode_pairs(v, true))
}
pub fn canonical(v: &Values) -> Option<String> {
    String::from_utf8(canonical_bytes(v)?).ok()
}
pub fn set(v: &mut Values, k: &str, s: &str) {
    v.insert(k.as_bytes().to_vec(), vec![s.as_bytes().to_vec()]);
}
pub fn get<'a>(v: &'a Values, k: &str) -> Option<&'a str> {
    std::str::from_utf8(v.get(k.as_bytes())?.first()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn go_query_escape_preserves_every_byte_and_pair_order() {
        let bytes: Vec<u8> = (0..=255).collect();
        let expected: String = bytes
            .iter()
            .map(|&b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                b' ' => "+".into(),
                _ => format!("%{b:02X}"),
            })
            .collect();
        assert_eq!(query_escape(&bytes), expected);
        let mut pairs = Values::from([
            (b"z".to_vec(), vec![bytes.clone()]),
            (b"a".to_vec(), vec![vec![]]),
        ]);
        set(&mut pairs, "sign", "excluded");
        assert_eq!(canonical(&pairs).unwrap(), format!("a=&z={expected}"));
        pairs.insert(b"a".to_vec(), vec![vec![], b" +".to_vec()]);
        assert_eq!(
            encode(&pairs),
            format!("a=&a=+%2B&sign=excluded&z={expected}")
        );
        assert_eq!(parse(&encode_bytes(&pairs)).unwrap(), pairs);
        let (partial, error) = parse_query(b"a&a=%xx&b=a+b&c=;%&z=%2b");
        assert!(error.is_some());
        assert_eq!(encode(&partial), "a=&b=a+b&z=%2B");
    }
}
