//! Go's encoding/json maps unpaired escaped surrogates to U+FFFD and reads -0
//! into an int64 as zero. Apply those wire-specific rules before schema checks.
use serde_json::Value;

fn code_unit(bytes: &[u8]) -> Option<u16> {
    let digits = bytes.strip_prefix(br"\u")?.get(..4)?;
    digits.iter().try_fold(0u16, |n, &b| {
        (b as char).to_digit(16).map(|d| (n << 4) | d as u16)
    })
}

pub fn object(bytes: &[u8]) -> Option<Value> {
    if let Some(v) = kaivo_upstream_sdk::json::object(bytes) {
        return Some(v);
    }
    if bytes.len() > 1 << 20 || !bytes.iter().any(|b| matches!(b, b'\\' | b'-')) {
        return None;
    }
    let mut fixed = bytes.to_vec();
    let mut changed = false;
    let mut quoted = false;
    let mut i = 0;
    while i < fixed.len() {
        match fixed[i] {
            b'"' => quoted = !quoted,
            b'\\' if quoted => {
                match code_unit(&fixed[i..]) {
                    Some(0xd800..=0xdbff)
                        if matches!(code_unit(&fixed[i + 6..]), Some(0xdc00..=0xdfff)) =>
                    {
                        i += 12
                    }
                    Some(0xd800..=0xdfff) => {
                        fixed[i..i + 6].copy_from_slice(br"\ufffd");
                        changed = true;
                        i += 6;
                    }
                    _ => i += 2,
                }
                continue;
            }
            b'-' if !quoted
                && fixed[i..].starts_with(b"-0")
                && (i == 0
                    || matches!(
                        fixed[i - 1],
                        b':' | b'[' | b',' | b' ' | b'\t' | b'\r' | b'\n'
                    ))
                && fixed.get(i + 2).is_none_or(|b| {
                    matches!(b, b'}' | b']' | b',' | b' ' | b'\t' | b'\r' | b'\n')
                }) =>
            {
                fixed[i] = b' ';
                changed = true;
            }
            _ => {}
        }
        i += 1;
    }
    if changed {
        kaivo_upstream_sdk::json::object(&fixed)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn go_integer_and_string_decoding() {
        let v = object(br#"{"amount":-0,"s":"\ud800x\ud800\udc00\udc01\\ud800"}"#).unwrap();
        assert_eq!(v["amount"], 0);
        assert_eq!(v["s"], "�x\u{10000}�\\ud800");
        for b in [
            br#"{"amount":-0.0}"#.as_slice(),
            br#"{"amount":0-0}"#,
            br#"{"amount":-0,"amount":1}"#,
            br#"{"x":"\ud800"}{}"#,
        ] {
            assert!(object(b).is_none());
        }
    }
}
