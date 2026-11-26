use kaivo_upstream_sdk::{cny_minor, form, trade::*};
use serde::{Deserialize, de::IgnoredAny};
use serde_json::{Deserializer, Value};
use std::collections::BTreeMap;

pub(super) struct Config {
    gateway: String,
    pid: String,
    product_name: String,
}

impl Config {
    pub(super) fn new(mut gateway: String, pid: String, product_name: String) -> Option<Self> {
        if !base_url(&gateway)
            || !digits(&pid)
            || pid.starts_with('0')
            || !(1..=127).contains(&product_name.len())
        {
            return None;
        }
        gateway.truncate(gateway.trim_end_matches('/').len());
        Some(Self {
            gateway,
            pid,
            product_name,
        })
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

// form::Values orders decoded keys by byte. Callers supply a single value per key.
fn canonical(fields: &form::Values) -> Vec<u8> {
    let mut data = Vec::new();
    for (key, values) in fields {
        let value = &values[0];
        if matches!(key.as_slice(), b"sign" | b"sign_type") || value.is_empty() {
            continue;
        }
        if !data.is_empty() {
            data.push(b'&');
        }
        data.extend_from_slice(key);
        data.push(b'=');
        data.extend_from_slice(value);
    }
    data
}

fn yuan(money: &Money) -> Option<String> {
    let n = cny_minor(&money.amount, &money.currency)?;
    Some(format!("{}.{:02}", n / 100, n % 100))
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

fn supported_method(method: &str) -> bool {
    matches!(method, "alipay" | "wxpay")
}

pub(super) fn create_payment(
    call: CreateCall,
    config: &Config,
    sign: impl FnOnce(Vec<u8>) -> String,
) -> Step {
    let input = call.input;
    if !supported_method(&input.method) {
        return error("unsupported_method");
    }
    if input.bank_mode.is_some() {
        return error("bank_mode");
    }
    let callback_url = input.callback_url.as_bytes();
    if callback_url.contains(&b'?') || callback_url.contains(&b'#') {
        return error("callback_url");
    }
    match call.responses.as_slice() {
        [] => {
            let Some(ip) = input.client_ip.as_deref() else {
                return error("client_ip_unavailable");
            };
            mapi_request(config, &input, ip, input.device.as_deref(), sign)
        }
        [response] => mapi_response(input, response),
        _ => error("response_count"),
    }
}

fn mapi_request(
    config: &Config,
    input: &CreatePaymentInput,
    client_ip: &str,
    device: Option<&str>,
    sign: impl FnOnce(Vec<u8>) -> String,
) -> Step {
    let Some(money) = yuan(&input.money) else {
        return error("amount");
    };
    let mut fields = form::Values::new();
    // EPay chooses the instruction in its response; the input instruction is ignored.
    for (key, value) in [
        ("pid", &config.pid),
        ("type", &input.method),
        ("out_trade_no", &input.order_id),
        ("notify_url", &input.callback_url),
        ("name", &config.product_name),
        ("money", &money),
    ] {
        form::set(&mut fields, key, value);
    }
    form::set(&mut fields, "clientip", client_ip);
    if let Some(device) = device {
        form::set(&mut fields, "device", device);
    }
    let signature = sign(canonical(&fields));
    form::set(&mut fields, "sign", &signature);
    form::set(&mut fields, "sign_type", "MD5");
    request(HttpRequest {
        url: format!("{}/mapi.php", config.gateway),
        method: "POST".into(),
        headers: vec![(
            "Content-Type".into(),
            vec!["application/x-www-form-urlencoded".into()],
        )],
        body: form::encode(&fields).into_bytes(),
    })
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

fn response_fields(mut body: &[u8]) -> Option<BTreeMap<String, &[u8]>> {
    body = body.strip_prefix(b"{")?;
    let mut fields = BTreeMap::new();
    loop {
        let (key, _) = json_token::<String>(&mut body)?;
        body = body.strip_prefix(b":")?;
        // Skip unknown values without imposing numeric or nesting limits on their contents.
        let (_, token) = json_token::<IgnoredAny>(&mut body)?;
        if matches!(
            key.as_str(),
            "code" | "trade_no" | "payurl" | "qrcode" | "urlscheme"
        ) {
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

fn mapi_response(input: CreatePaymentInput, response: &HttpResponse) -> Step {
    if response.status != 200 {
        return unknown(Some("http_status".into()));
    }
    let body = response
        .body
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(&response.body)
        .trim_ascii();
    let Some(fields) = response_fields(body) else {
        return unknown(Some("response_json".into()));
    };
    let Some(code) = fields.get("code").and_then(|v| response_code(v)) else {
        return unknown(Some("response_json".into()));
    };
    if code != 1 {
        return rejected(format!("epay_code_{code}"));
    }
    let string_field = |name: &str| {
        let raw = fields.get(name).copied().unwrap_or(b"null");
        match serde_json::from_slice(raw).ok()? {
            Value::Null => Some(String::new()),
            Value::String(value) => Some(value),
            _ => None,
        }
    };
    let Some(upstream_id) = string_field("trade_no").filter(|id| !id.is_empty()) else {
        return unknown(Some("response_instruction".into()));
    };
    let [Some(url), Some(qr), Some(scheme)] = ["payurl", "qrcode", "urlscheme"].map(string_field)
    else {
        return unknown(Some("response_instruction".into()));
    };
    let (url, qrcode) = match (url.is_empty(), qr.is_empty(), scheme.is_empty()) {
        (false, true, true) => (Some(url), None),
        (true, false, true) => (None, Some(qr)),
        (true, true, false) => return unknown(Some("urlscheme_unsupported".into())),
        _ => return unknown(Some("response_instruction".into())),
    };
    completed(Output::Payment(PaymentOutput {
        order_id: input.order_id,
        upstream_id,
        money: input.money,
        status: PaymentStatus::Pending,
        url,
        qrcode,
        paid_at: None,
        expires_at: None,
    }))
}

fn callback_query(raw: &RouteCallbackInput, responses: &[HttpResponse]) -> Option<form::Values> {
    if raw.method != "GET"
        || !raw.body.is_empty()
        || raw.raw_query.is_empty()
        || !responses.is_empty()
    {
        return None;
    }
    form::parse(&raw.raw_query).filter(form::single_values)
}

fn valid_order(id: &str) -> bool {
    (1..=100).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

pub(super) fn route_callback(call: RouteCall) -> Step {
    let Some(fields) = callback_query(&call.input, &call.responses) else {
        return error("route_query");
    };
    match form::get(&fields, "out_trade_no").filter(|s| valid_order(s)) {
        Some(id) => completed(Output::Route(RouteCallbackOutput {
            order_id: id.into(),
        })),
        None => error("route_query"),
    }
}

pub(super) fn verify_callback(
    call: CallbackCall,
    config: &Config,
    sign: impl FnOnce(Vec<u8>) -> String,
    equal: impl FnOnce(&str, &str) -> bool,
) -> Step {
    let Some(fields) = callback_query(&call.input.raw, &call.responses) else {
        return error("callback_query");
    };
    let get = |key| form::get(&fields, key).unwrap_or_default();
    let required = [
        "pid",
        "trade_no",
        "out_trade_no",
        "type",
        "name",
        "money",
        "trade_status",
        "sign",
        "sign_type",
    ];
    if required.iter().any(|key| {
        fields
            .get(key.as_bytes())
            .is_none_or(|values| values[0].is_empty())
    }) {
        return error("callback_field");
    }
    let order_id = get("out_trade_no");
    if !valid_order(order_id) {
        return error("callback_query");
    }
    // Creation requires a query- and fragment-free notify_url because EPay signs only its own fields.
    let signature = get("sign");
    if get("sign_type") != "MD5"
        || signature.len() != 32
        || !signature
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || !equal(&sign(canonical(&fields)), signature)
    {
        return error("callback_signature");
    }
    if get("pid") != config.pid {
        return error("callback_identity");
    }
    if get("trade_status") != "TRADE_SUCCESS" {
        return error("callback_status");
    }
    if !supported_method(get("type")) {
        return error("callback_type");
    }
    let Some(amount) = minor_units(get("money")) else {
        return error("callback_amount");
    };
    let Some(trade_no) = form::get(&fields, "trade_no") else {
        return error("callback_field");
    };
    completed(Output::Callback(CallbackOutput {
        event_id: trade_no.into(),
        order_id: order_id.into(),
        upstream_id: trade_no.into(),
        money: Money {
            amount: amount.to_string(),
            currency: "CNY".into(),
        },
        status: PaymentStatus::Paid,
        ack: HttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), vec!["text/plain".into()])],
            body: b"success".to_vec(),
        },
    }))
}

#[cfg(test)]
mod tests;
