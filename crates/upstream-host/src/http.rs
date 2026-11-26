use crate::{
    package::{Manifest, domain, media, token},
    types::{Headers, HttpRequest},
};
use kaivo_upstream_sdk::form;
use memchr::memmem::find;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    ops::Range,
};
use zeroize::{Zeroize, Zeroizing};
pub type Check<T> = Result<T, &'static str>;
pub(crate) const REQUEST_BODY_LIMIT: usize = 256 << 10;
pub fn id(s: &str) -> bool {
    (1..=100).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}
pub fn valid_client_ip(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok_and(|ip| {
        ip.to_string() == s
            && !matches!(ip, std::net::IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some())
    })
}
pub fn valid_device(s: &str) -> bool {
    (1..=32).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
pub fn url(s: &str, http: bool) -> Check<&str> {
    check_url_placeholder(s)?;
    parse_url(s, http, true)
}
fn check_url_placeholder(url: &str) -> Check<()> {
    let (target, fragment) = url.split_once('#').unwrap_or((url, ""));
    let path = target.split_once('?').map_or(target, |(p, _)| p);
    if path.contains("{{secret:") || fragment.contains("{{secret:") {
        return Err("secret_placeholder");
    }
    Ok(())
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
    // Outbound query bytes are opaque unless the manifest declares secret fields.
    let escaped = if egress {
        s.split_once('?').map_or(s, |(path, _)| path)
    } else {
        s
    };
    for (i, b) in escaped.bytes().enumerate() {
        if b == b'%'
            && !escaped
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
            if invalid_secret_bytes(s.as_bytes()) {
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

fn invalid_secret_bytes(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| b != b'\t' && (b < 32 || b == 127))
}

// Match decoded names and values, retaining the original offsets for the wire request.
fn field_replacements<'a>(
    m: &'a Manifest,
    declared: &[String],
    bytes: &[u8],
    mut offset: usize,
) -> Check<Vec<(Range<usize>, &'a str)>> {
    let mut seen = BTreeSet::new();
    let mut replacements = Vec::new();
    for pair in bytes.split(|&b| b == b'&') {
        let end = offset + pair.len();
        offset = end + 1;
        if pair.is_empty() {
            continue;
        }
        let (key, values) = form::parse(pair)
            .and_then(|mut fields| fields.pop_first())
            .ok_or("secret_placeholder")?;
        let allowed = declared.iter().any(|n| n.as_bytes() == key);
        if find(&key, b"{{secret:").is_some() || allowed && !seen.insert(key) {
            return Err("secret_placeholder");
        }
        let value = &values[0];
        if !allowed {
            if find(value, b"{{secret:").is_some() {
                return Err("secret_placeholder");
            }
        } else if find(value, b"{{").is_some() || find(value, b"}}").is_some() {
            let name = value
                .strip_prefix(b"{{secret:")
                .and_then(|s| s.strip_suffix(b"}}"))
                .and_then(|s| std::str::from_utf8(s).ok())
                .and_then(|n| m.secrets.get_key_value(n))
                .filter(|(_, kind)| *kind == "shared")
                .ok_or("secret_placeholder")?
                .0;
            let eq = pair
                .iter()
                .position(|&b| b == b'=')
                .ok_or("secret_placeholder")?;
            replacements.push((end - pair.len() + eq + 1..end, name.as_str()));
        }
    }
    Ok(replacements)
}

fn replace_values(
    bytes: &[u8],
    replacements: &[(Range<usize>, &str)],
    limit: usize,
    secret: &mut impl FnMut(&str) -> Option<Zeroizing<Vec<u8>>>,
) -> Check<Vec<u8>> {
    let mut size = bytes.len() - replacements.iter().map(|(r, _)| r.len()).sum::<usize>();
    let mut values = Vec::with_capacity(replacements.len());
    for (range, name) in replacements {
        let key = secret(name).ok_or("secret_placeholder")?;
        if invalid_secret_bytes(&key) {
            return Err("secret_placeholder");
        }
        let encoded = Zeroizing::new(form::query_escape(&key));
        size += encoded.len();
        if size > limit {
            return Err("request_limit");
        }
        values.push((range, encoded));
    }
    let mut out = Vec::with_capacity(size);
    let mut pos = 0;
    for (range, encoded) in values {
        out.extend_from_slice(&bytes[pos..range.start]);
        out.extend_from_slice(encoded.as_bytes());
        pos = range.end;
    }
    out.extend_from_slice(&bytes[pos..]);
    Ok(out)
}

impl Zeroize for HttpRequest {
    fn zeroize(&mut self) {
        self.url.zeroize();
        self.body.zeroize();
        for (_, values) in &mut self.headers {
            values.zeroize();
        }
    }
}

pub(crate) struct RequestTemplate<'a> {
    manifest: &'a Manifest,
    request: &'a HttpRequest,
    query: Vec<(Range<usize>, &'a str)>,
    form: Vec<(Range<usize>, &'a str)>,
}
impl<'a> RequestTemplate<'a> {
    pub fn validate(
        m: &'a Manifest,
        template: &'a HttpRequest,
        test_only_allow_http_fields: bool,
    ) -> Check<Self> {
        let Some(fields) = &m.secret_fields else {
            if template.url.contains("{{secret:") || find(&template.body, b"{{secret:").is_some() {
                return Err("secret_placeholder");
            }
            return Ok(Self {
                manifest: m,
                request: template,
                query: Vec::new(),
                form: Vec::new(),
            });
        };
        check_url_placeholder(&template.url)?;
        let mut query = Vec::new();
        if let Some((path, raw)) = template.url.split_once('?') {
            query = field_replacements(
                m,
                fields.query.as_deref().unwrap_or_default(),
                raw.as_bytes(),
                path.len() + 1,
            )?;
        }
        let mut content_types = template
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("Content-Type"))
            .flat_map(|(_, values)| values);
        let form = if let Some(content_type) = content_types.next()
            && content_types.next().is_none()
            && media(content_type).as_deref() == Some("application/x-www-form-urlencoded")
        {
            field_replacements(
                m,
                fields.form.as_deref().unwrap_or_default(),
                &template.body,
                0,
            )?
        } else {
            if find(&template.body, b"{{secret:").is_some() {
                return Err("secret_placeholder");
            }
            Vec::new()
        };

        if !(query.is_empty() && form.is_empty())
            && !test_only_allow_http_fields
            && !template.url.starts_with("https://")
        {
            return Err("https_required");
        }
        Ok(Self {
            manifest: m,
            request: template,
            query,
            form,
        })
    }

    pub fn expand(
        &self,
        body_limit: usize,
        mut secret: impl FnMut(&str) -> Option<Zeroizing<Vec<u8>>>,
    ) -> Check<Zeroizing<HttpRequest>> {
        let template = self.request;
        let mut request = Zeroizing::new(template.clone());
        request.headers = expand(self.manifest, &template.headers, |n| {
            String::from_utf8(secret(n)?.to_vec()).ok()
        })?;
        if !self.query.is_empty() {
            // The gateway HTTP transport parses an http::Uri, whose maximum length is 65534 bytes.
            let url = replace_values(
                template.url.as_bytes(),
                &self.query,
                u16::MAX as usize - 1,
                &mut secret,
            )?;
            request.url = String::from_utf8(url).map_err(|_| "request_url")?;
        }
        if !self.form.is_empty() {
            request.body = replace_values(&template.body, &self.form, body_limit, &mut secret)?;
        }
        Ok(request)
    }
}
#[cfg(test)]
mod tests;
