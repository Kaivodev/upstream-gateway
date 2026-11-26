use super::*;
use kaivo_upstream_sdk::cny_minor;

struct Config {
    endpoint: Endpoint,
    product_name: String,
}

impl Config {
    fn new(endpoint: Endpoint, product_name: String) -> Option<Self> {
        (1..=127).contains(&product_name.len()).then_some(Self {
            endpoint,
            product_name,
        })
    }
}

fn configured(operation: impl FnOnce(&Config) -> Step) -> Step {
    let Some(config) = Endpoint::configured()
        .and_then(|endpoint| Config::new(endpoint, host::config("product_name")))
    else {
        return error("config");
    };
    operation(&config)
}

fn sign(canonical: Vec<u8>) -> String {
    host::sign(
        "md5",
        None,
        &[
            host::Part::Data(canonical),
            host::Part::Secret("merchant_key".into()),
        ],
    )
}

pub fn create(call: CreateCall) -> Step {
    configured(|config| create_payment(call, config, sign))
}

pub fn route(call: RouteCall) -> Step {
    configured(|_| route_callback(call))
}

pub fn verify(call: CallbackCall) -> Step {
    configured(|config| verify_callback(call, config, sign, host::equal))
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

fn supported_method(method: &str) -> bool {
    matches!(method, "alipay" | "wxpay")
}

fn create_payment(call: CreateCall, config: &Config, sign: impl FnOnce(Vec<u8>) -> String) -> Step {
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
        ("pid", &config.endpoint.pid),
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
        url: format!("{}/mapi.php", config.endpoint.gateway),
        method: "POST".into(),
        headers: vec![(
            "Content-Type".into(),
            vec!["application/x-www-form-urlencoded".into()],
        )],
        body: form::encode(&fields).into_bytes(),
    })
}

fn mapi_response(input: CreatePaymentInput, response: &HttpResponse) -> Step {
    api_response(
        response.status,
        &response.body,
        &["trade_no", "payurl", "qrcode", "urlscheme"],
        |fields| mapi_payment(input, fields),
    )
}

fn mapi_payment(input: CreatePaymentInput, fields: &Fields<'_>) -> Step {
    let string_field = |name: &str| super::string_field(fields, name);
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

fn route_callback(call: RouteCall) -> Step {
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

fn verify_callback(
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
    if get("pid") != config.endpoint.pid {
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
