// encoding/json replaces each invalid UTF-8 byte and each unpaired UTF-16
// escape with U+FFFD. Keep the original compact JWT for the signature check.
use std::borrow::Cow;

fn code_unit(bytes: &[u8]) -> Option<u16> {
    let hex = bytes.strip_prefix(b"\\u")?.get(..4)?;
    u16::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()
}

pub(super) fn compatible(bytes: &[u8]) -> Option<Cow<'_, [u8]>> {
    let mut data = if std::str::from_utf8(bytes).is_ok() {
        Cow::Borrowed(bytes)
    } else {
        let mut text = String::with_capacity(bytes.len());
        for chunk in bytes.utf8_chunks() {
            text.push_str(chunk.valid());
            text.extend(std::iter::repeat_n('\u{fffd}', chunk.invalid().len()));
        }
        Cow::Owned(text.into_bytes())
    };
    let mut i = 0;
    let mut quoted = false;
    let mut depth = 0usize;
    while i < data.len() {
        match data[i] {
            b'"' => quoted = !quoted,
            b'\\' if quoted => {
                if let Some(unit @ 0xd800..=0xdfff) = code_unit(&data[i..]) {
                    i += 6;
                    if unit < 0xdc00 && matches!(code_unit(&data[i..]), Some(0xdc00..=0xdfff)) {
                        i += 6;
                    } else {
                        data.to_mut()[i - 6..i].copy_from_slice(b"\\ufffd");
                    }
                    continue;
                }
                i += 1;
            }
            b'{' | b'[' if !quoted => {
                depth += 1;
                if depth > 10_000 {
                    return None;
                }
            }
            b'}' | b']' if !quoted => depth = depth.checked_sub(1)?,
            _ => (),
        }
        i += 1;
    }
    Some(data)
}
