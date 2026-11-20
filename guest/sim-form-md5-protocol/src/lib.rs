//! Form/MD5 simulator protocol shared by trading and independent verification.
#[cfg(feature = "trade")]
use kaivo_upstream_sdk::trade::*;
#[cfg(feature = "verification")]
use kaivo_upstream_sdk::verification::*;
use kaivo_upstream_sdk::{form, json};
use serde_json::Value;
const MEDIA: &str = "application/x-www-form-urlencoded";
#[cfg(feature = "trade")]
const KEY: &str = "shared";
#[cfg(feature = "verification")]
const KEY: &str = "query_key";
fn sign_form(canonical: Vec<u8>) -> (Vec<u8>, String) {
    let parts = [
        host::Part::Data(canonical),
        host::Part::Data(b"&key=".to_vec()),
        host::Part::Secret(KEY.into()),
    ];
    let sig = host::sign("md5", None, &parts);
    let [host::Part::Data(bytes), _, _] = parts else {
        unreachable!()
    };
    (bytes, sig)
}
fn pay_status(s: &str) -> Option<PaymentStatus> {
    Some(match s {
        "pending" => PaymentStatus::Pending,
        "paid" => PaymentStatus::Paid,
        "closed" => PaymentStatus::Closed,
        "failed" => PaymentStatus::Failed,
        "unknown" => PaymentStatus::Unknown,
        _ => return None,
    })
}
fn refund_status(s: &str) -> Option<RefundStatus> {
    Some(match s {
        "pending" => RefundStatus::Pending,
        "success" | "succeeded" => RefundStatus::Succeeded,
        "failed" => RefundStatus::Failed,
        "unknown" => RefundStatus::Unknown,
        _ => return None,
    })
}
fn timestamp(s: &str) -> Option<Option<host::UtcTime>> {
    if s.is_empty() {
        Some(None)
    } else {
        parse_utc_time(s).map(Some)
    }
}
fn string(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or_default().to_owned()
}
fn optional(v: &Value, k: &str) -> Option<String> {
    v[k].as_str().filter(|s| !s.is_empty()).map(str::to_owned)
}
fn fields(v: &Value, strings: &[&str], ints: &[&str]) -> bool {
    v.as_object().is_some_and(|o| {
        o.iter().all(|(k, x)| {
            (strings.contains(&k.as_str()) && x.is_string())
                || (ints.contains(&k.as_str()) && x.is_i64())
        })
    })
}
fn response(op: &str, account: &str, res: &HttpResponse) -> Option<Step> {
    let v = json::object(&res.body)?;
    if !v.as_object()?.iter().all(|(k, x)| match k.as_str() {
        "result" | "code" => x.is_string(),
        "refund" => {
            x.is_null()
                || fields(
                    x,
                    &["account_id", "order_id", "refund_id", "currency", "status"],
                    &["amount"],
                )
        }
        "order" => {
            x.is_null()
                || fields(
                    x,
                    &[
                        "account_id",
                        "order_id",
                        "upstream_id",
                        "currency",
                        "method",
                        "bank_mode",
                        "status",
                        "url",
                        "qrcode",
                        "paid_at",
                        "expires_at",
                        "expire_time",
                    ],
                    &["amount"],
                )
        }
        _ => false,
    }) {
        return None;
    }
    match v["result"].as_str()? {
        "rejected" => return Some(rejected(string(&v, "code"))),
        "unknown" => return Some(unknown(optional(&v, "code"))),
        "accepted" if res.status == 200 => {}
        _ => return Some(error("response_status")),
    }
    let refund = op.starts_with("refund");
    let (key, other) = if refund {
        ("refund", "order")
    } else {
        ("order", "refund")
    };
    let data = &v[key];
    let amount = data["amount"].as_i64()?;
    if !v[other].is_null() || data["account_id"] != account || amount <= 0 {
        return None;
    }
    let money = Money {
        amount: amount.to_string(),
        currency: string(data, "currency"),
    };
    let order_id = string(data, "order_id");
    let output = if refund {
        Output::Refund(RefundOutput {
            order_id,
            refund_id: string(data, "refund_id"),
            upstream_refund_id: string(data, "refund_id"),
            money,
            status: refund_status(data["status"].as_str()?)?,
        })
    } else {
        let expires_at = if op == "create" && data["status"] == "pending" {
            timestamp(&string(data, "expire_time"))?
        } else {
            None
        };
        Output::Payment(PaymentOutput {
            order_id,
            upstream_id: string(data, "upstream_id"),
            money,
            status: pay_status(data["status"].as_str()?)?,
            url: optional(data, "url"),
            qrcode: optional(data, "qrcode"),
            paid_at: timestamp(&string(data, "paid_at"))?,
            expires_at,
        })
    };
    Some(completed(output))
}
fn run(
    op: &str,
    order: &str,
    res: &[HttpResponse],
    money: Option<&Money>,
    extra: &[(&str, &str)],
) -> Step {
    let account = host::config("account_id");
    match res {
        [r] => return response(op, &account, r).unwrap_or_else(|| error("response_json")),
        [] => {}
        _ => return error("response_count"),
    }
    let gateway = host::config("gateway");
    let mut v = form::Values::new();
    for (k, s) in [
        ("account_id", account.as_str()),
        ("operation", op),
        ("order_id", order),
    ] {
        form::set(&mut v, k, s)
    }
    for &(k, s) in extra {
        if !s.is_empty() {
            form::set(&mut v, k, s)
        }
    }
    if let Some(m) = money {
        if kaivo_upstream_sdk::cny_minor(&m.amount, &m.currency).is_none() {
            return error("amount");
        }
        form::set(&mut v, "amount", &m.amount);
        form::set(&mut v, "currency", &m.currency);
    }
    // Every request field in this protocol sorts before "sign". Reuse the signed
    // bytes; the host returns a lowercase hexadecimal MD5 digest.
    let (mut body, sig) = sign_form(form::encode_bytes(&v));
    body.extend_from_slice(b"&sign=");
    body.extend_from_slice(sig.as_bytes());
    request(HttpRequest {
        method: "POST".into(),
        url: format!(
            "{}/api/{}/{op}",
            gateway.trim_end_matches('/'),
            form::path_escape(&account)
        ),
        headers: vec![("Content-Type".into(), vec![MEDIA.into()])],
        body,
    })
}
pub fn query_payment(c: PaymentCall) -> Step {
    run("query", &c.input.order_id, &c.responses, None, &[])
}
pub fn query_refund(c: RefundCall) -> Step {
    run(
        "refund-query",
        &c.input.order_id,
        &c.responses,
        None,
        &[("refund_id", &c.input.refund_id)],
    )
}
#[cfg(feature = "trade")]
pub fn close_payment(c: PaymentCall) -> Step {
    run("close", &c.input.order_id, &c.responses, None, &[])
}
#[cfg(feature = "trade")]
pub fn refund(c: RefundCall) -> Step {
    run(
        "refund",
        &c.input.order_id,
        &c.responses,
        Some(&c.input.money),
        &[("refund_id", &c.input.refund_id)],
    )
}
#[cfg(feature = "trade")]
pub fn create_payment(c: CreateCall) -> Step {
    let i = c.input;
    run(
        "create",
        &i.order_id,
        &c.responses,
        Some(&i.money),
        &[
            ("method", &i.method),
            ("callback_url", &i.callback_url),
            ("bank_mode", i.bank_mode.as_deref().unwrap_or("")),
            ("instruction", i.instruction.as_deref().unwrap_or("")),
        ],
    )
}
#[cfg(feature = "trade")]
fn callback_form(c: &RouteCallbackInput, res: &[HttpResponse]) -> Option<form::Values> {
    if !res.is_empty() || c.method != "POST" || !c.raw_query.is_empty() {
        return None;
    }
    let v = form::parse(&c.body)?;
    Some(v)
}
#[cfg(feature = "trade")]
pub fn route_callback(c: RouteCall) -> Step {
    let Some(v) = callback_form(&c.input, &c.responses).filter(form::single_values) else {
        return error("route_form");
    };
    completed(Output::Route(RouteCallbackOutput {
        order_id: form::get(&v, "order_id").unwrap_or_default().into(),
    }))
}
#[cfg(feature = "trade")]
pub fn verify_callback(c: CallbackCall) -> Step {
    let Some(v) = callback_form(&c.input.raw, &c.responses) else {
        return error("callback_form");
    };
    let get = |k| form::get(&v, k).unwrap_or_default();
    let account = host::config("account_id");
    let Some(canonical) = form::canonical_bytes(&v) else {
        return error("callback_form");
    };
    if !host::equal(&sign_form(canonical).1, get("sign")) {
        return error("callback_signature");
    }
    if !v.keys().all(|k| {
        std::str::from_utf8(k).is_ok_and(|s| {
            [
                "sign",
                "account_id",
                "event_id",
                "order_id",
                "upstream_id",
                "amount",
                "currency",
                "status",
                "sequence",
                "paid_at",
            ]
            .contains(&s)
        })
    }) {
        return error("callback_field");
    }
    for k in ["sequence", "amount"] {
        if !get(k)
            .parse::<i64>()
            .is_ok_and(|n| n > 0 && n.to_string() == get(k))
        {
            return error("callback_amount");
        }
    }
    if get("account_id") != account || get("currency") != "CNY" || get("event_id").is_empty() {
        return error("callback_identity");
    }
    let Some(status) = pay_status(get("status")) else {
        return error("callback_status");
    };
    completed(Output::Callback(CallbackOutput {
        event_id: get("event_id").into(),
        order_id: get("order_id").into(),
        upstream_id: get("upstream_id").into(),
        money: Money {
            amount: get("amount").into(),
            currency: get("currency").into(),
        },
        status,
        ack: HttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), vec!["text/plain".into()])],
            body: b"success".to_vec(),
        },
    }))
}
