//! JSON/RSA simulator protocol for trade and independent verification.
use kaivo_upstream_sdk::form;
#[cfg(feature = "trade")]
use kaivo_upstream_sdk::trade::*;
#[cfg(feature = "verification")]
use kaivo_upstream_sdk::verification::*;
mod decode;
use serde_json::Value;
mod request;
use request::Request;
#[cfg(feature = "trade")]
const KEY: &str = "platform_private";
#[cfg(feature = "verification")]
const KEY: &str = "query_private_key";
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
            (strings.contains(&k.as_str()) && (x.is_null() || x.is_string()))
                || (ints.contains(&k.as_str()) && (x.is_null() || x.is_i64()))
        })
    })
}
fn response(op: &str, account: &str, res: &HttpResponse) -> Option<Step> {
    let v = decode::object(&res.body)?;
    if !v.as_object()?.iter().all(|(k, x)| match k.as_str() {
        "result" | "code" => x.is_string() || x.is_null(),
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
    match v["result"].as_str().unwrap_or_default() {
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
    let amount = data["amount"].as_i64().unwrap_or_default();
    if !v[other].is_null()
        || !data.is_object()
        || data["account_id"].as_str().unwrap_or_default() != account
        || amount <= 0
    {
        return Some(error(if refund {
            "refund_response"
        } else {
            "payment_response"
        }));
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
            timestamp(&string(data, "expires_at"))?
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
fn run(r: Request<'_>, responses: &[HttpResponse]) -> Step {
    let account = host::config("account_id");
    match responses {
        [res] => {
            return response(r.operation, &account, res).unwrap_or_else(|| error("response_json"));
        }
        [] => {}
        _ => return error("response_count"),
    }
    let gateway = host::config("gateway");
    let Some(body) = r.encode(&account) else {
        return error("amount");
    };
    let parts = [host::Part::Data(body)];
    let signature = host::sign("rsa-sha256", Some(KEY), &parts);
    let [host::Part::Data(body)] = parts else {
        unreachable!()
    };
    request(HttpRequest {
        method: "POST".into(),
        url: format!(
            "{}/api/{}/{}",
            gateway.trim_end_matches('/'),
            form::path_escape(&account),
            r.operation
        ),
        headers: vec![
            ("Content-Type".into(), vec!["application/json".into()]),
            ("X-Signature".into(), vec![signature]),
        ],
        body,
    })
}
pub fn query_payment(c: PaymentCall) -> Step {
    run(
        Request {
            operation: "query",
            order_id: &c.input.order_id,
            ..Default::default()
        },
        &c.responses,
    )
}
pub fn query_refund(c: RefundCall) -> Step {
    run(
        Request {
            operation: "refund-query",
            order_id: &c.input.order_id,
            refund_id: &c.input.refund_id,
            ..Default::default()
        },
        &c.responses,
    )
}
#[cfg(feature = "trade")]
pub fn close_payment(c: PaymentCall) -> Step {
    run(
        Request {
            operation: "close",
            order_id: &c.input.order_id,
            ..Default::default()
        },
        &c.responses,
    )
}
#[cfg(feature = "trade")]
pub fn refund(c: RefundCall) -> Step {
    run(
        Request {
            operation: "refund",
            order_id: &c.input.order_id,
            money: Some(&c.input.money),
            refund_id: &c.input.refund_id,
            ..Default::default()
        },
        &c.responses,
    )
}
#[cfg(feature = "trade")]
pub fn create_payment(c: CreateCall) -> Step {
    let i = c.input;
    run(
        Request {
            operation: "create",
            order_id: &i.order_id,
            money: Some(&i.money),
            method: &i.method,
            bank_mode: i.bank_mode.as_deref().unwrap_or_default(),
            instruction: i.instruction.as_deref().unwrap_or_default(),
            callback_url: &i.callback_url,
            ..Default::default()
        },
        &c.responses,
    )
}
#[cfg(feature = "trade")]
fn event(body: &[u8]) -> Option<Value> {
    let v = decode::object(body)?;
    fields(
        &v,
        &[
            "event_id",
            "account_id",
            "order_id",
            "upstream_id",
            "currency",
            "status",
            "paid_at",
        ],
        &["amount", "sequence"],
    )
    .then_some(v)
}
#[cfg(feature = "trade")]
fn callback_input(raw: &RouteCallbackInput, res: &[HttpResponse]) -> bool {
    res.is_empty() && raw.method == "POST" && raw.raw_query.is_empty()
}
#[cfg(feature = "trade")]
pub fn route_callback(c: RouteCall) -> Step {
    if !callback_input(&c.input, &c.responses) {
        return error("route_input");
    }
    let Some(v) = event(&c.input.body) else {
        return error("route_json");
    };
    completed(Output::Route(RouteCallbackOutput {
        order_id: string(&v, "order_id"),
    }))
}
#[cfg(feature = "trade")]
fn signature(headers: &Headers) -> Option<&str> {
    let mut values = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("X-Signature"))
        .flat_map(|(_, vs)| vs);
    let first = values.next()?;
    values.next().is_none().then_some(first)
}
#[cfg(feature = "trade")]
pub fn verify_callback(c: CallbackCall) -> Step {
    let raw = c.input.raw;
    if !callback_input(&raw, &c.responses) {
        return error("callback_input");
    }
    let account = host::config("account_id");
    let Some(sig) = signature(&raw.headers) else {
        return error("callback_signature");
    };
    let parts = [host::Part::Data(raw.body)];
    if !host::verify("rsa-sha256", "upstream_public", &parts, sig) {
        return error("callback_signature");
    }
    let [host::Part::Data(body)] = parts else {
        unreachable!()
    };
    let Some(v) = event(&body) else {
        return error("callback_json");
    };
    let amount = v["amount"].as_i64().unwrap_or_default();
    if v["account_id"].as_str().unwrap_or_default() != account
        || amount <= 0
        || v["sequence"].as_i64().unwrap_or_default() <= 0
        || v["event_id"].as_str().unwrap_or_default().is_empty()
        || v["currency"] != "CNY"
    {
        return error("callback_identity");
    }
    let Some(status) = pay_status(v["status"].as_str().unwrap_or_default()) else {
        return error("callback_status");
    };
    completed(Output::Callback(CallbackOutput {
        event_id: string(&v, "event_id"),
        order_id: string(&v, "order_id"),
        upstream_id: string(&v, "upstream_id"),
        money: Money {
            amount: amount.to_string(),
            currency: string(&v, "currency"),
        },
        status,
        ack: HttpResponse {
            status: 200,
            headers: vec![("Content-Type".into(), vec!["text/plain".into()])],
            body: b"success".to_vec(),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strict_response_checks_every_branch_before_reading_result() {
        for body in [
            br#"{"result":"rejected","order":{"account_id":7}}"#.as_slice(),
            br#"{"result":"unknown","refund":{"Order_id":"x"}}"#,
            br#"{"result":"accepted","order":{"amount":1,"amount":1}}"#,
            br#"{"result":"accepted","refund":{"amount":9223372036854775808}}"#,
            br#"{"result":"accepted","refund":{"amount":1.0}}"#,
            br#"{"result":"accepted"} {}"#,
            br#"{"result":"accepted","x":false}"#,
            b"null",
            b"{\"code\":\"\xff\"}",
        ] {
            let r = HttpResponse {
                body: body.to_vec(),
                status: 200,
                headers: vec![],
            };
            assert!(response("query", "a", &r).is_none());
        }
        let step = |body: &[u8]| {
            response(
                "query",
                "a",
                &HttpResponse {
                    body: body.to_vec(),
                    status: 503,
                    headers: vec![],
                },
            )
        };
        assert!(
            matches!(step(br#"{"result":"rejected","code":"no","order":null}"#), Some(Step::Result(OperationResult::Rejected(s))) if s == "no")
        );
        assert!(matches!(
            step(br#"{"result":"unknown","code":null}"#),
            Some(Step::Result(OperationResult::Unknown(None)))
        ));
    }
    #[cfg(feature = "trade")]
    #[test]
    fn callback_header_multiplicity_and_event_schema() {
        let header = ("x-SiGnAtUrE".to_owned(), vec!["value".to_owned()]);
        assert_eq!(signature(&vec![header.clone()]), Some("value"));
        assert_eq!(
            signature(&vec![
                header,
                ("X-Signature".into(), vec!["another".into()])
            ]),
            None
        );
        assert_eq!(
            signature(&vec![("X-Signature".into(), vec!["a".into(), "b".into()])]),
            None
        );
        for b in [
            br#"{"order_id":"ok","sequence":"1"}"#.as_slice(),
            br#"{"sequence":0,"sequence":1}"#,
            br#"{"Order_id":"no"}"#,
        ] {
            assert!(event(b).is_none());
        }
    }
}
