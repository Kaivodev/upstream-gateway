use crate::{
    package::{Manifest, domain, token},
    types::Headers,
};
use std::{collections::BTreeMap, net::Ipv4Addr};
pub type Check<T> = Result<T, &'static str>;
pub fn id(s: &str) -> bool {
    (1..=100).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
pub fn url(s: &str, http: bool) -> Check<&str> {
    parse_url(s, http, true)
}
pub fn instruction_url(s: &str, http: bool) -> bool {
    parse_url(s, http, false).is_ok()
}
fn parse_url(s: &str, http: bool, egress: bool) -> Check<&str> {
    if s.bytes()
        .any(|b| b <= 32 || b == 127 || b == b'\\' || b == b'#')
    {
        return Err("request_url");
    }
    let (scheme, rest) = s.split_once("://").ok_or("request_url")?;
    if scheme != "https" && !(http && scheme == "http") {
        return Err("https_required");
    }
    let auth = rest.split(['/', '?']).next().unwrap_or("");
    if auth.contains(['@', '%']) || auth.is_empty() {
        return Err("request_url");
    }
    let host = if !egress && let Some(rest) = auth.strip_prefix('[') {
        let (addr, tail) = rest.split_once(']').ok_or("request_url")?;
        addr.parse::<std::net::Ipv6Addr>()
            .map_err(|_| "request_url")?;
        if !tail.is_empty()
            && !tail.strip_prefix(':').is_some_and(|p| {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok()
            })
        {
            return Err("request_url");
        }
        addr
    } else if let Some((h, p)) = auth.split_once(':') {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().is_err() {
            return Err("request_url");
        }
        h
    } else {
        auth
    };
    if egress && !domain(host)
        || !egress
            && !host.contains(':')
            && !domain(host.trim_end_matches('.').to_ascii_lowercase().as_str())
    {
        return Err("domain_forbidden");
    }
    if host.split('.').all(|s| {
        s.bytes().all(|b| b.is_ascii_digit())
            || s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
    }) && host.parse::<Ipv4Addr>().is_err()
    {
        return Err("request_url");
    }
    for (i, b) in s.bytes().enumerate() {
        if b == b'%'
            && !s
                .as_bytes()
                .get(i + 1..i + 3)
                .is_some_and(|p| p.iter().all(u8::is_ascii_hexdigit))
        {
            return Err("request_url");
        }
    }
    if egress
        && !http
        && (host == "localhost"
            || host.ends_with(".localhost")
            || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback()))
    {
        return Err("domain_forbidden");
    }
    Ok(host)
}
pub fn normalize(h: &Headers) -> Option<Headers> {
    let mut out = BTreeMap::new();
    let mut bytes = 0;
    for (n, vs) in h {
        if !token(n) || vs.is_empty() {
            return None;
        }
        let mut upper = true;
        let k = n
            .bytes()
            .map(|b| {
                let c = if upper {
                    b.to_ascii_uppercase()
                } else {
                    b.to_ascii_lowercase()
                };
                upper = b == b'-';
                c as char
            })
            .collect::<String>();
        for v in vs {
            bytes += n.len() + v.len();
            if bytes > 16384 || v.bytes().any(|b| b != 9 && (b < 32 || b == 127)) {
                return None;
            }
        }
        if out.insert(k, vs.clone()).is_some() {
            return None;
        }
    }
    Some(out.into_iter().collect())
}
pub fn values<'a>(h: &'a Headers, name: &str) -> &'a [String] {
    h.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map_or(&[], |(_, v)| v.as_slice())
}
pub fn expand(
    m: &Manifest,
    h: &Headers,
    mut secret: impl FnMut(&str) -> Option<String>,
) -> Check<Headers> {
    let mut out = normalize(h).ok_or("request_headers")?;
    for (name, vs) in &mut out {
        if [
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "Proxy-Authorization",
            "Proxy-Connection",
            "Upgrade",
            "Trailer",
            "Te",
        ]
        .contains(&name.as_str())
        {
            return Err("request_headers");
        }
        for v in vs {
            if !v.contains("{{") && !v.contains("}}") {
                continue;
            }
            let (pre, tail) = v.split_once("{{secret:").ok_or("secret_placeholder")?;
            let (key, post) = tail.split_once("}}").ok_or("secret_placeholder")?;
            if [pre, post]
                .iter()
                .any(|s| s.contains("{{") || s.contains("}}"))
                || m.secrets.get(key).map(String::as_str) != Some("shared")
            {
                return Err("secret_placeholder");
            }
            let s = zeroize::Zeroizing::new(secret(key).ok_or("secret_placeholder")?);
            if s.bytes().any(|b| b != 9 && (b < 32 || b == 127)) {
                return Err("secret_placeholder");
            }
            *v = format!("{pre}{}{post}", s.as_str());
        }
    }
    let size: usize = out
        .iter()
        .flat_map(|(k, vs)| vs.iter().map(move |v| k.len() + v.len()))
        .sum();
    if size > 16384 {
        for (_, values) in &mut out {
            for v in values {
                zeroize::Zeroize::zeroize(v)
            }
        }
        return Err("request_headers");
    }
    Ok(out)
}
