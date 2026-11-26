//! EPay V1 wire protocol for the trading and verification worlds.
use kaivo_upstream_sdk::form;
#[cfg(feature = "trade")]
use kaivo_upstream_sdk::trade::*;
#[cfg(feature = "verification")]
use kaivo_upstream_sdk::verification::*;
use serde::{Deserialize, de::IgnoredAny};
use serde_json::{Deserializer, Value};
use std::collections::BTreeMap;

mod query;
#[cfg(feature = "trade")]
pub mod trade;
pub use query::query_payment;

struct Endpoint {
    gateway: String,
    pid: String,
    unpaid_timeout_seconds: i64,
}

impl Endpoint {
    fn new(gateway: String, pid: String, unpaid_timeout_seconds: &str) -> Option<Self> {
        if !base_url(&gateway) || !digits(&pid) || pid.starts_with('0') {
            return None;
        }
        if !digits(unpaid_timeout_seconds) || unpaid_timeout_seconds.starts_with('0') {
            return None;
        }
        let unpaid_timeout_seconds = unpaid_timeout_seconds.parse().ok()?;
        if !(1..=2_592_000).contains(&unpaid_timeout_seconds) {
            return None;
        }
        Some(Self {
            gateway: gateway.trim_end_matches('/').into(),
            pid,
            unpaid_timeout_seconds,
        })
    }

    fn configured() -> Option<Self> {
        Self::new(
            host::config("gateway"),
            host::config("pid"),
            &host::config("unpaid_timeout_seconds"),
        )
    }
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn base_url(url: &str) -> bool {
    let Some(rest) = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
    else {
        return false;
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if !valid_path(path.as_bytes()) {
        return false;
    }
    if let Some(ip) = authority.strip_prefix('[') {
        return ip.split_once(']').is_some_and(|(ip, suffix)| {
            ip.parse::<std::net::Ipv6Addr>().is_ok()
                && (suffix.is_empty() || suffix.strip_prefix(':').is_some_and(valid_port))
        });
    }
    let host = match authority.split_once(':') {
        Some((host, port)) if valid_port(port) => host,
        Some(_) => return false,
        None => authority,
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.split('.').all(digits) {
        return host.parse::<std::net::Ipv4Addr>().is_ok();
    }
    host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn valid_port(port: &str) -> bool {
    digits(port) && port.parse::<u16>().is_ok()
}

// A base path consists of URI path characters and complete percent escapes.
fn valid_path(mut path: &[u8]) -> bool {
    while let [byte, rest @ ..] = path {
        if *byte == b'%' {
            let [hi, lo, remaining @ ..] = rest else {
                return false;
            };
            if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                return false;
            }
            path = remaining;
        } else if byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(byte) {
            path = rest;
        } else {
            return false;
        }
    }
    true
}

fn minor_units(raw: &str) -> Option<i64> {
    let (whole, fraction) = match raw.split_once('.') {
        None => (raw, 0),
        Some((whole, fraction)) if digits(fraction) && fraction.len() <= 2 => {
            let n = fraction.parse::<i64>().ok()?;
            (whole, if fraction.len() == 1 { n * 10 } else { n })
        }
        _ => return None,
    };
    if !digits(whole) || (whole.len() > 1 && whole.starts_with('0')) {
        return None;
    }
    let amount = whole
        .parse::<i64>()
        .ok()?
        .checked_mul(100)?
        .checked_add(fraction)?;
    (amount > 0).then_some(amount)
}

fn json_token<'a, T: Deserialize<'a>>(body: &mut &'a [u8]) -> Option<(T, &'a [u8])> {
    let mut stream = Deserializer::from_slice(body).into_iter::<T>();
    let value = stream.next()?.ok()?;
    let (token, rest) = body.split_at(stream.byte_offset());
    *body = rest;
    while let [b' ' | b'\n' | b'\r' | b'\t', tail @ ..] = *body {
        *body = tail;
    }
    Some((value, token.trim_ascii_start()))
}

type Fields<'a> = BTreeMap<String, &'a [u8]>;

fn response_fields<'a>(mut body: &'a [u8], names: &[&str]) -> Option<Fields<'a>> {
    body = body.strip_prefix(b"{")?;
    let mut fields = BTreeMap::new();
    loop {
        let (key, _) = json_token::<String>(&mut body)?;
        body = body.strip_prefix(b":")?;
        // Skip unknown values without imposing numeric or nesting limits on their contents.
        let (_, token) = json_token::<IgnoredAny>(&mut body)?;
        if key == "code" || names.contains(&key.as_str()) {
            // A repeated message is ambiguous, even when its values agree.
            let token = if key == "msg" && fields.contains_key(&key) {
                b"null"
            } else {
                token
            };
            fields.insert(key, token);
        }
        if body == b"}" {
            return Some(fields);
        }
        body = body.strip_prefix(b",")?;
    }
}

fn response_code(raw: &[u8]) -> Option<i64> {
    // Value represents the JSON integer -0 as a float, just like -0.0.
    if raw == b"-0" {
        return Some(0);
    }
    match serde_json::from_slice::<Value>(raw).ok()? {
        Value::String(code) if digits(code.strip_prefix('-').unwrap_or(&code)) => code.parse().ok(),
        value => value.as_i64(),
    }
}

fn api_response(
    status: u16,
    body: &[u8],
    names: &[&str],
    classify: impl FnOnce(i64, &Fields<'_>) -> Step,
) -> Step {
    if status != 200 {
        return unknown(Some("http_status".into()));
    }
    let body = body
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(body)
        .trim_ascii();
    let Some(fields) = response_fields(body, names) else {
        return unknown(Some("response_json".into()));
    };
    let Some(code) = fields.get("code").and_then(|v| response_code(v)) else {
        return unknown(Some("response_json".into()));
    };
    classify(code, &fields)
}

fn provider_rejection(code: i64) -> Step {
    rejected(format!("epay_code_{code}"))
}

fn string_field(fields: &Fields<'_>, name: &str) -> Option<String> {
    let raw = fields.get(name).copied().unwrap_or(b"null");
    serde_json::from_slice::<Option<String>>(raw)
        .ok()
        .map(Option::unwrap_or_default)
}
