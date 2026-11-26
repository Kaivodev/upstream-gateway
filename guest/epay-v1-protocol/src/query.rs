use super::*;

pub fn query_payment(call: PaymentCall) -> Step {
    query(call, Endpoint::configured(), host::now)
}

fn query(
    call: PaymentCall,
    endpoint: Option<Endpoint>,
    now: impl FnOnce() -> host::UtcTime,
) -> Step {
    let Some(endpoint) = endpoint else {
        return error("config");
    };
    let order = call.input.order_id;
    match call.responses.as_slice() {
        [] => {
            let mut fields = form::Values::new();
            for (name, value) in [
                ("act", "order"),
                ("pid", &endpoint.pid),
                ("key", "{{secret:merchant_key}}"),
                ("out_trade_no", &order),
            ] {
                form::set(&mut fields, name, value);
            }
            request(HttpRequest {
                method: "GET".into(),
                url: format!("{}/api.php?{}", endpoint.gateway, form::encode(&fields)),
                headers: vec![],
                body: vec![],
            })
        }
        [r] => {
            if r.status == 200 && std::str::from_utf8(&r.body).is_err() {
                return unknown(Some("response_json".into()));
            }
            api_response(
                r.status,
                r.body.trim_ascii(),
                &[
                    "trade_no",
                    "out_trade_no",
                    "pid",
                    "money",
                    "status",
                    "addtime",
                    "endtime",
                ],
                |fields| order_response(fields, order, &endpoint, now),
            )
        }
        _ => error("response_count"),
    }
}

fn matches_pid(raw: &[u8], pid: &str) -> bool {
    // Compare decimal digits directly so a merchant ID need not fit in an i64.
    if raw.starts_with(b"\"") {
        serde_json::from_slice::<String>(raw).is_ok_and(|s| s.trim_start_matches('0') == pid)
    } else {
        raw == pid.as_bytes()
    }
}

fn shanghai_time(s: &str) -> Option<host::UtcTime> {
    // EPay supplies Asia/Shanghai civil time (UTC+8, no DST since 1991).
    // Add a timezone setting if a future upstream uses another zone.
    if s.len() != 19 || s.as_bytes()[10] != b' ' {
        return None;
    }
    let (date, clock) = s.split_once(' ')?;
    parse_utc_time(&format!("{date}T{clock}+08:00"))
}

fn order_response(
    fields: &Fields<'_>,
    order: String,
    endpoint: &Endpoint,
    now: impl FnOnce() -> host::UtcTime,
) -> Step {
    let Some(upstream_id) = string_field(fields, "trade_no").filter(|s| !s.is_empty()) else {
        return unknown(Some("response_identity".into()));
    };
    if string_field(fields, "out_trade_no").as_deref() != Some(&order)
        || !fields
            .get("pid")
            .is_some_and(|raw| matches_pid(raw, &endpoint.pid))
    {
        return unknown(Some("response_identity".into()));
    }
    let Some(amount) = string_field(fields, "money").and_then(|s| minor_units(&s)) else {
        return unknown(Some("response_amount".into()));
    };
    let (status, paid_at, code) = match fields.get("status").copied() {
        Some(b"0") => {
            let closed = string_field(fields, "addtime")
                .and_then(|s| shanghai_time(&s))
                .is_some_and(|created| {
                    let now = now().seconds;
                    created.seconds <= now + 300
                        && now >= created.seconds + endpoint.unpaid_timeout_seconds
                });
            // Closure is inferred locally. The upstream still reports unpaid.
            // The exchange preserves status=0 and addtime; the channel config preserves the threshold.
            if closed {
                (
                    PaymentStatus::Closed,
                    None,
                    Some("timeout_inferred_close".into()),
                )
            } else {
                (PaymentStatus::Pending, None, None)
            }
        }
        Some(b"1") => {
            let paid_at = match string_field(fields, "endtime") {
                Some(s) if s.is_empty() => None,
                Some(s) => match shanghai_time(&s) {
                    Some(t) => Some(t),
                    None => return unknown(Some("response_time".into())),
                },
                None => return unknown(Some("response_time".into())),
            };
            (PaymentStatus::Paid, paid_at, None)
        }
        _ => return unknown(Some("response_status".into())),
    };
    let value = Output::Payment(PaymentOutput {
        order_id: order,
        upstream_id,
        money: Money {
            amount: amount.to_string(),
            currency: "CNY".into(),
        },
        status,
        url: None,
        qrcode: None,
        paid_at,
        expires_at: None,
    });
    Step::Result(OperationResult::Completed(Completion { value, code }))
}

#[cfg(test)]
mod tests;
