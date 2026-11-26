use super::*;
use serde_json::json;

fn run(order_id: &str, responses: Vec<HttpResponse>) -> Step {
    run_with_timeout(order_id, responses, "2400")
}

fn run_with_timeout(order_id: &str, responses: Vec<HttpResponse>, timeout: &str) -> Step {
    query(
        PaymentCall {
            input: PaymentInput {
                order_id: order_id.into(),
                money: Money {
                    amount: "100".into(),
                    currency: "CNY".into(),
                },
            },
            responses,
        },
        Endpoint::new("https://provider.test/shop/".into(), "42".into(), timeout),
        || parse_utc_time("2024-02-28T16:40:00Z").unwrap(),
    )
}

fn response(status: u16, body: &[u8]) -> Step {
    run(
        "A",
        vec![HttpResponse {
            status,
            headers: vec![],
            body: body.to_vec(),
        }],
    )
}

fn paid() -> Value {
    json!({"code":1,"trade_no":"T7","out_trade_no":"A","pid":42,"money":"1.50","status":1,"endtime":"2024-02-29 00:00:01"})
}

fn payment(step: Step) -> PaymentOutput {
    let Step::Result(OperationResult::Completed(Completion {
        value: Output::Payment(p),
        code: None,
    })) = step
    else {
        panic!("expected payment: {step:?}")
    };
    p
}

fn assert_unknown(step: Step, expected: &str) {
    assert!(
        matches!(&step, Step::Result(OperationResult::Unknown(Some(code))) if code == expected),
        "{step:?}"
    );
}

#[test]
fn get_encodes_the_entire_placeholder_in_the_key_value() {
    let Step::Request(r) = run("A &+/", vec![]) else {
        panic!("expected request")
    };
    assert_eq!(r.method, "GET");
    assert_eq!(
        r.url,
        "https://provider.test/shop/api.php?act=order&key=%7B%7Bsecret%3Amerchant_key%7D%7D&out_trade_no=A+%26%2B%2F&pid=42"
    );
    assert!(r.headers.is_empty() && r.body.is_empty());
}

#[test]
fn paid_uses_response_money_and_converts_shanghai_midnight_to_utc() {
    let mut v = paid();
    v["addtime"] = json!("2024-02-28 23:59:59");
    let p = payment(response(200, &serde_json::to_vec(&v).unwrap()));
    assert_eq!(p.order_id, "A");
    assert_eq!(p.upstream_id, "T7");
    assert_eq!(
        (p.money.amount.as_str(), p.money.currency.as_str()),
        ("150", "CNY")
    );
    assert_eq!(p.status, PaymentStatus::Paid);
    assert_eq!(
        format_utc_time(p.paid_at.unwrap()).as_deref(),
        Some("2024-02-28T16:00:01Z")
    );
    assert!(p.url.is_none() && p.qrcode.is_none() && p.expires_at.is_none());
}

fn unpaid(addtime: Option<Value>) -> Step {
    let mut v = paid();
    v["status"] = json!(0);
    if let Some(time) = addtime {
        v["addtime"] = time;
    }
    response(200, &serde_json::to_vec(&v).unwrap())
}

#[test]
fn unpaid_closes_at_the_threshold_inclusively_with_an_inference_code() {
    let pending = payment(unpaid(Some(json!("2024-02-29 00:00:01"))));
    assert_eq!(pending.status, PaymentStatus::Pending);
    assert!(pending.paid_at.is_none());
    for addtime in ["2024-02-29 00:00:00", "2024-02-28 23:59:59"] {
        let step = unpaid(Some(json!(addtime)));
        let Step::Result(OperationResult::Completed(Completion {
            value: Output::Payment(p),
            code,
        })) = step
        else {
            panic!("expected payment: {step:?}")
        };
        assert_eq!(code.as_deref(), Some("timeout_inferred_close"));
        assert_eq!(p.status, PaymentStatus::Closed);
        assert!(p.paid_at.is_none());
    }
}

#[test]
fn missing_invalid_and_future_addtime_keep_unpaid_pending_without_a_code() {
    for addtime in [
        None,
        Some(Value::Null),
        Some(json!("")),
        Some(json!(0)),
        Some(json!("2024-02-30 00:00:00")),
        Some(json!("2024-02-29T00:00:00Z")),
        Some(json!("2024-02-29 00:45:01")),
        Some(json!("2024-02-29 00:44:59")),
    ] {
        let p = payment(unpaid(addtime));
        assert_eq!(p.status, PaymentStatus::Pending);
        assert!(p.paid_at.is_none());
    }
}

#[test]
fn only_canonical_timeouts_in_range_allow_a_request() {
    for timeout in [
        "",
        "0",
        "-1",
        "01",
        "+1",
        "2592001",
        "abc",
        "1.0",
        " 1",
        "１",
        "99999999999999999999999",
    ] {
        let step = run_with_timeout("A", vec![], timeout);
        assert!(
            matches!(step, Step::Result(OperationResult::Error(Some(ref c))) if c == "config"),
            "{timeout}: {step:?}"
        );
    }
    for timeout in ["1", "2592000"] {
        assert!(matches!(
            run_with_timeout("A", vec![], timeout),
            Step::Request(_)
        ));
    }
}

#[test]
fn accepts_bom_php_escapes_string_code_and_pid_and_ignores_pending_endtime() {
    let mut body = b"\xEF\xBB\xBF \n".to_vec();
    body.extend_from_slice(br#"{"code":"01","trade_no":"T\/\u8336","out_trade_no":"A","pid":"042","status":0,"money":"1","endtime":"unused","type":"","param":null,"extra":1e999} "#);
    let p = payment(response(200, &body));
    assert_eq!(p.upstream_id, "T/茶");
    assert_eq!(p.status, PaymentStatus::Pending);
    assert!(p.paid_at.is_none());
}

#[test]
fn missing_null_and_empty_paid_times_are_absent() {
    let mut v = paid();
    for endtime in [Some(Value::Null), Some(json!("")), None] {
        v.as_object_mut().unwrap().remove("endtime");
        if let Some(endtime) = endtime {
            v["endtime"] = endtime;
        }
        assert!(
            payment(response(200, &serde_json::to_vec(&v).unwrap()))
                .paid_at
                .is_none()
        );
    }
}

#[test]
fn provider_rejection_precedes_order_fields() {
    for code in [json!("-001"), json!(-1)] {
        let s = response(
            200,
            &serde_json::to_vec(&json!({"code":code,"money":false})).unwrap(),
        );
        assert!(matches!(s,Step::Result(OperationResult::Rejected(code)) if code=="epay_code_-1"));
    }
    assert_unknown(response(502, b"bad"), "http_status");
    for body in [
        b"[".as_slice(),
        b"[]",
        b"{}{}",
        b"{}",
        br#"{"code":1.0}"#,
        b"{\"code\":1,\"ignored\":\"\xff\"}",
    ] {
        assert_unknown(response(200, body), "response_json");
    }
}

#[test]
fn successful_envelope_requires_matching_identity_valid_money_status_and_time() {
    for (k, bad, code) in [
        ("trade_no", json!(""), "response_identity"),
        ("trade_no", json!(7), "response_identity"),
        ("out_trade_no", json!("B"), "response_identity"),
        ("pid", json!("43"), "response_identity"),
        ("pid", json!(42.0), "response_identity"),
        ("pid", json!("+42"), "response_identity"),
        ("money", json!("1.234"), "response_amount"),
        ("money", json!(1), "response_amount"),
        ("status", json!(2), "response_status"),
        ("status", json!(null), "response_status"),
        ("endtime", json!(0), "response_time"),
        ("endtime", json!("2023-02-29 00:00:00"), "response_time"),
        ("endtime", json!("2024-01-01T00:00:00"), "response_time"),
        ("endtime", json!("2024-01-01 00:00:00Z"), "response_time"),
    ] {
        let mut v = paid();
        v[k] = bad;
        assert_unknown(response(200, &serde_json::to_vec(&v).unwrap()), code);
    }
}
