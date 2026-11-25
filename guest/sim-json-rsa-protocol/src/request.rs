//! The signed bytes follow encoding/json.Marshal on the simulator's wireRequest.
use super::Money;

#[derive(Default)]
pub(super) struct Request<'a> {
    pub operation: &'a str,
    pub order_id: &'a str,
    pub money: Option<&'a Money>,
    pub method: &'a str,
    pub bank_mode: &'a str,
    pub instruction: &'a str,
    pub callback_url: &'a str,
    pub refund_id: &'a str,
}

const fn escape_table() -> [bool; 256] {
    let mut escapes = [false; 256];
    let mut i = 0;
    while i < 32 {
        escapes[i] = true;
        i += 1;
    }
    escapes[b'"' as usize] = true;
    escapes[b'\\' as usize] = true;
    escapes[b'<' as usize] = true;
    escapes[b'>' as usize] = true;
    escapes[b'&' as usize] = true;
    escapes[0xe2] = true; // First UTF-8 byte of U+2028 and U+2029.
    escapes
}

fn quote(out: &mut Vec<u8>, s: &str) {
    const ESCAPE: [bool; 256] = escape_table();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push(b'"');
    let mut bytes = s.as_bytes();
    while let Some(i) = bytes.iter().position(|&b| ESCAPE[b as usize]) {
        out.extend_from_slice(&bytes[..i]);
        let b = bytes[i];
        bytes = &bytes[i + 1..];
        match b {
            b'"' | b'\\' => out.extend_from_slice(&[b'\\', b]),
            8 => out.extend_from_slice(br"\b"),
            12 => out.extend_from_slice(br"\f"),
            b'\n' => out.extend_from_slice(br"\n"),
            b'\r' => out.extend_from_slice(br"\r"),
            b'\t' => out.extend_from_slice(br"\t"),
            0xe2 => match bytes {
                [0x80, last @ (0xa8 | 0xa9), tail @ ..] => {
                    out.extend_from_slice(if *last == 0xa8 {
                        br"\u2028"
                    } else {
                        br"\u2029"
                    });
                    bytes = tail;
                }
                _ => out.push(b),
            },
            _ => out.extend_from_slice(&[
                b'\\',
                b'u',
                b'0',
                b'0',
                HEX[(b >> 4) as usize],
                HEX[(b & 15) as usize],
            ]),
        }
    }
    out.extend_from_slice(bytes);
    out.push(b'"');
}

impl Request<'_> {
    pub fn encode(&self, account: &str) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(self.method.len() + self.instruction.len() + 128);
        out.extend_from_slice(br#"{"account_id":"#);
        quote(&mut out, account);
        out.extend_from_slice(br#","operation":"#);
        quote(&mut out, self.operation);
        out.extend_from_slice(br#","order_id":"#);
        quote(&mut out, self.order_id);
        if let Some(m) = self.money {
            kaivo_upstream_sdk::cny_minor(&m.amount, &m.currency)?;
            out.extend_from_slice(br#","amount":"#);
            out.extend_from_slice(m.amount.as_bytes());
            out.extend_from_slice(br#","currency":"#);
            quote(&mut out, &m.currency);
        }
        for (key, value) in [
            ("method", self.method),
            ("bank_mode", self.bank_mode),
            ("instruction", self.instruction),
            ("callback_url", self.callback_url),
            ("refund_id", self.refund_id),
        ] {
            if !value.is_empty() {
                out.extend_from_slice(b",\"");
                out.extend_from_slice(key.as_bytes());
                out.extend_from_slice(b"\":");
                quote(&mut out, value);
            }
        }
        out.push(b'}');
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn marshal_wire_request() {
        let query = Request {
            operation: "query",
            ..Default::default()
        };
        assert_eq!(
            query.encode("").unwrap(),
            br#"{"account_id":"","operation":"query","order_id":""}"#
        );
        let money = Money {
            amount: i64::MAX.to_string(),
            currency: "CNY".into(),
        };
        let all = Request {
            operation: "create",
            order_id: "<&>/",
            money: Some(&money),
            method: "€水",
            bank_mode: "\u{2028}\u{2029}",
            instruction: "\"\\\x08\x0c\n\r\t\x00\x1f",
            callback_url: "url",
            refund_id: "r",
        };
        assert_eq!(all.encode("a").unwrap(), r#"{"account_id":"a","operation":"create","order_id":"\u003c\u0026\u003e/","amount":9223372036854775807,"currency":"CNY","method":"€水","bank_mode":"\u2028\u2029","instruction":"\"\\\b\f\n\r\t\u0000\u001f","callback_url":"url","refund_id":"r"}"#.as_bytes());
    }
}
