use super::*;
use std::hash::{DefaultHasher, Hash, Hasher};

fn config() -> Config {
    Config::new(
        Endpoint::new("https://example.test/shop///".into(), "42".into(), "2400").unwrap(),
        "Tea 茶".into(),
    )
    .unwrap()
}

fn money(amount: &str, currency: &str) -> Money {
    Money {
        amount: amount.into(),
        currency: currency.into(),
    }
}

fn input() -> CreatePaymentInput {
    CreatePaymentInput {
        order_id: "Order-7_a".into(),
        money: money("150", "CNY"),
        method: "wxpay".into(),
        callback_url: "https://example.test/notify".into(),
        bank_mode: None,
        instruction: Some("url".into()),
        client_ip: None,
        device: None,
    }
}

fn response(status: u16, body: &[u8]) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![],
        body: body.to_vec(),
    }
}

fn output(step: Step) -> Output {
    let Step::Result(OperationResult::Completed(Completion { value, code: None })) = step else {
        panic!("expected a completion, got {step:?}");
    };
    value
}

fn assert_error(step: Step, expected: &str) {
    assert!(
        matches!(&step, Step::Result(OperationResult::Error(Some(code))) if code == expected),
        "{step:?}"
    );
}

fn assert_unknown(step: Step, expected: &str) {
    assert!(
        matches!(&step, Step::Result(OperationResult::Unknown(Some(code))) if code == expected),
        "{step:?}"
    );
}

#[test]
fn config_requires_a_base_url_decimal_pid_and_bounded_product_bytes() {
    let check = |url: &str, pid: &str, name: &str| {
        Config::new(Endpoint::new(url.into(), pid.into(), "2400")?, name.into())
    };
    assert_eq!(config().endpoint.gateway, "https://example.test/shop");
    for url in [
        "http://127.0.0.1:8080/",
        "https://example.test/pay%20here",
        "http://[::1]:9090",
    ] {
        assert!(check(url, "1", "x").is_some(), "{url}");
    }
    for url in [
        "",
        "example.test",
        "//example.test",
        "ftp://example.test",
        "http://",
        "https:///path",
        "http://:80",
        "http://a:",
        "http://a:+80",
        "http://a:70000",
        "http://127.0.0.256",
        "https://user@a",
        "https://a?q=x",
        "https://a/#frag",
        "https://a/b c",
        "https://a/\n",
        "https://a\\b",
        "https://a/%zz",
        "https://a/%3",
        "https://a/<path>",
        "https://example..test",
        "http://[broken]",
    ] {
        assert!(check(url, "1", "x").is_none(), "{url:?}");
    }
    for pid in ["", "0", "01", "+1", "-1", "1 ", "1.0", "１"] {
        assert!(check("https://example.test", pid, "x").is_none(), "{pid}");
    }
    let limit = format!("{}x", "茶".repeat(42));
    assert!(check("https://example.test", &"9".repeat(30), &limit).is_some());
    for name in ["", &format!("{limit}x")] {
        assert!(check("https://example.test", "42", name).is_none());
    }
}

#[test]
fn canonical_uses_sorted_decoded_bytes_and_omits_unsigned_fields() {
    let fields =
        form::parse(b"z=%FF&sign=x&name=%E8%8C%B6+shop&sign_type=MD5&Z=A%26B%3DC&empty=&_a=%2B")
            .unwrap();
    let mut expected = "Z=A&B=C&_a=+&name=茶 shop&z=".as_bytes().to_vec();
    expected.push(0xff);
    assert_eq!(canonical(&fields), expected);
    assert!(canonical(&form::parse(b"empty=&sign=x&sign_type=MD5").unwrap()).is_empty());
}

#[test]
fn formats_only_positive_cny_minor_units() {
    for (amount, formatted) in [
        ("1", "0.01"),
        ("100", "1.00"),
        ("12345", "123.45"),
        ("9223372036854775807", "92233720368547758.07"),
    ] {
        assert_eq!(yuan(&money(amount, "CNY")).as_deref(), Some(formatted));
    }
    for (amount, currency) in [
        ("0", "CNY"),
        ("01", "CNY"),
        ("-1", "CNY"),
        ("9223372036854775808", "CNY"),
        ("1", "USD"),
    ] {
        assert!(yuan(&money(amount, currency)).is_none());
    }
}

#[test]
fn parses_decimal_yuan_exactly_through_i64_max() {
    for (raw, expected) in [
        ("0.01", 1),
        ("0.1", 10),
        ("1", 100),
        ("1.5", 150),
        ("1.50", 150),
        ("92233720368547758.07", i64::MAX),
    ] {
        assert_eq!(minor_units(raw), Some(expected), "{raw}");
    }
    for raw in [
        "",
        "0",
        "0.00",
        "1.505",
        "01.00",
        "+1",
        "1e2",
        " 1.00",
        "1.00 ",
        "-1",
        ".01",
        "1.",
        "1..0",
        "1.a",
        "１",
        "92233720368547758.08",
        "92233720368547759",
        "99999999999999999999",
    ] {
        assert_eq!(minor_units(raw), None, "{raw:?}");
    }
}

#[test]
fn mapi_signs_raw_fields_and_posts_exact_encoded_bytes() {
    let mut input = input();
    input.callback_url.push_str("/a=1&b=2");
    for (device, method, device_field) in [
        (None, "alipay", ""),
        (Some("mobile"), "wxpay", "device=mobile&"),
    ] {
        input.method = method.into();
        input.client_ip = Some("127.0.0.1".into());
        input.device = device.map(str::to_owned);
        let step = create_payment(
            CreateCall {
                input: input.clone(),
                responses: vec![],
            },
            &config(),
            |bytes| {
                let expected = format!(
                    "clientip=127.0.0.1&{device_field}money=1.50&name=Tea 茶&notify_url=https://example.test/notify/a=1&b=2&out_trade_no=Order-7_a&pid=42&type={method}"
                );
                assert_eq!(bytes, expected.as_bytes());
                "test-signature".into()
            },
        );
        let Step::Request(req) = step else {
            panic!("{step:?}")
        };
        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "https://example.test/shop/mapi.php");
        assert_eq!(
            req.headers,
            [(
                "Content-Type".into(),
                vec!["application/x-www-form-urlencoded".into()]
            )]
        );
        let expected = format!(
            "clientip=127.0.0.1&{device_field}money=1.50&name=Tea+%E8%8C%B6&notify_url=https%3A%2F%2Fexample.test%2Fnotify%2Fa%3D1%26b%3D2&out_trade_no=Order-7_a&pid=42&sign=test-signature&sign_type=MD5&type={method}"
        );
        assert_eq!(req.body, expected.as_bytes());
    }
    input.money.currency = "USD".into();
    assert_error(
        mapi_request(&config(), &input, "127.0.0.1", None, |_| {
            panic!("signed invalid amount")
        }),
        "amount",
    );
}

fn create(input: CreatePaymentInput, responses: Vec<HttpResponse>) -> Step {
    create_payment(CreateCall { input, responses }, &config(), |_| {
        panic!("unexpected signing")
    })
}

#[test]
fn create_returns_local_errors_before_dispatch() {
    assert_error(create(input(), vec![]), "client_ip_unavailable");
    assert_error(
        create(
            CreatePaymentInput {
                method: "other".into(),
                ..input()
            },
            vec![],
        ),
        "unsupported_method",
    );
    assert_error(
        create(
            CreatePaymentInput {
                bank_mode: Some(String::new()),
                ..input()
            },
            vec![],
        ),
        "bank_mode",
    );
    assert_error(
        create(input(), vec![response(200, b"{}"); 2]),
        "response_count",
    );
}

#[test]
fn create_rejects_callback_query_or_fragment_before_dispatch() {
    for suffix in ["?", "?a=1&b=2", "#", "#fragment", "?a=1#fragment"] {
        let mut input = input();
        input.callback_url.push_str(suffix);
        assert_error(create(input, vec![]), "callback_url");
    }
    let mut input = input();
    input.callback_url.push_str("/%3F%23");
    assert_error(create(input, vec![]), "client_ip_unavailable");
}

#[test]
fn response_decodes_bom_php_escapes_and_exactly_one_instruction() {
    let mut body = b"\xef\xbb\xbf \t\r\n".to_vec();
    body.extend_from_slice(br#"{"code":"1","trade_no":"T7","payurl":"https:\/\/example.test\/\u8336","qrcode":null,"urlscheme":"","extra":{"cost":1.25}}"#);
    body.extend_from_slice(b" \r\n");
    let qr = br#"{"code":1,"trade_no":"T7","qrcode":"abc"}"#.to_vec();
    let padded = br#"{"code":"01","trade_no":"T7","extra":1e999,"qrcode":"abc"}"#.to_vec();
    for (body, url, qrcode) in [
        (body, Some("https://example.test/茶"), None),
        (qr, None, Some("abc")),
        (padded, None, Some("abc")),
    ] {
        let Output::Payment(p) = output(create(input(), vec![response(200, &body)])) else {
            panic!("expected payment")
        };
        assert_eq!(p.order_id, "Order-7_a");
        assert_eq!(p.upstream_id, "T7");
        assert_eq!(p.money.amount, "150");
        assert_eq!(p.money.currency, "CNY");
        assert_eq!(p.status, PaymentStatus::Pending);
        assert_eq!(p.url.as_deref(), url);
        assert_eq!(p.qrcode.as_deref(), qrcode);
        assert!(p.paid_at.is_none() && p.expires_at.is_none());
    }
    assert_unknown(
        create(
            input(),
            vec![response(
                200,
                br#"{"code":1,"trade_no":"T7","urlscheme":"weixin://pay"}"#,
            )],
        ),
        "urlscheme_unsupported",
    );
}

#[test]
fn response_keeps_missing_or_ambiguous_payment_details_unknown() {
    for fields in [
        r#""payurl":"x""#,
        r#""payurl":"x","trade_no":"""#,
        r#""trade_no":7,"qrcode":"x""#,
        r#""trade_no":"T7""#,
        r#""trade_no":"T7","payurl":"","qrcode":null"#,
        r#""trade_no":"T7","payurl":"x","qrcode":"y""#,
        r#""trade_no":"T7","qrcode":"x","urlscheme":"y""#,
        r#""trade_no":"T7","payurl":"x","qrcode":false"#,
    ] {
        let body = format!(r#"{{"code":1,{fields}}}"#);
        assert_unknown(
            create(input(), vec![response(200, body.as_bytes())]),
            "response_instruction",
        );
    }
}

#[test]
fn create_keeps_the_provider_code_for_an_order_not_found_message() {
    let body = r#"{"code":-1,"msg":"订单号不存在"}"#.as_bytes();
    let step = create(input(), vec![response(200, body)]);
    assert!(
        matches!(step, Step::Result(OperationResult::Rejected(code)) if code == "epay_code_-1")
    );
}

#[test]
fn response_separates_transport_json_and_provider_errors() {
    assert_unknown(
        create(input(), vec![response(503, br#"{"code":-1}"#)]),
        "http_status",
    );
    for body in [
        "bad",
        "[]",
        "{}{}",
        "{}",
        r#"{"code":1,}"#,
        r#"{"code":1 "trade_no":"T7"}"#,
        r#"{"code":-0.0}"#,
        r#"{"code":-0e0}"#,
        r#"{"code":1e0}"#,
        r#"{"code":1.0}"#,
        r#"{"code":"1e2"}"#,
        r#"{"code":"+1"}"#,
        r#"{"code":" 1"}"#,
        r#"{"code":"-"}"#,
        r#"{"code":"１"}"#,
        r#"{"code":9223372036854775808}"#,
        r#"{"code":-9223372036854775809}"#,
        r#"{"code":18446744073709551616}"#,
        r#"{"code":"18446744073709551616"}"#,
        r#"{"code":true}"#,
        r#"{"code":null}"#,
        r#"{"code":{}}"#,
    ] {
        assert_unknown(
            create(input(), vec![response(200, body.as_bytes())]),
            "response_json",
        );
    }
    for (raw, expected) in [
        ("0", "0"),
        ("-0", "0"),
        ("-2", "-2"),
        (r#""-2""#, "-2"),
        (r#""-002""#, "-2"),
        ("-9223372036854775808", "-9223372036854775808"),
        ("9223372036854775807", "9223372036854775807"),
    ] {
        let body = format!(r#"{{"code":{raw}}}"#);
        let step = create(input(), vec![response(200, body.as_bytes())]);
        assert!(
            matches!(step, Step::Result(OperationResult::Rejected(code)) if code == format!("epay_code_{expected}"))
        );
    }
}

fn raw(query: &[u8]) -> RouteCallbackInput {
    RouteCallbackInput {
        method: "GET".into(),
        raw_query: query.to_vec(),
        body: vec![],
        headers: vec![],
        source_ip: None,
    }
}

fn route(input: RouteCallbackInput) -> Step {
    route_callback(RouteCall {
        input,
        responses: vec![],
    })
}

fn callback(raw: RouteCallbackInput) -> CallbackCall {
    // The host, after the plugin returns, compares these expected values with the output.
    CallbackCall {
        input: CallbackInput {
            order_id: "host-order".into(),
            money: money("1", "CNY"),
            raw,
        },
        responses: vec![],
    }
}

#[test]
fn callback_query_rejects_invalid_envelopes_and_repeated_fields() {
    for input in [
        RouteCallbackInput {
            method: "POST".into(),
            ..raw(b"out_trade_no=A")
        },
        RouteCallbackInput {
            body: vec![b'a'],
            ..raw(b"out_trade_no=A")
        },
        raw(b""),
        raw(b"out_trade_no=A&%6Fut_trade_no=B"),
        raw(b"out_trade_no=A&x=&x="),
        raw(b"out_trade_no=A&extra=%GG"),
        raw(b"out_trade_no=A&bad;x"),
        raw(b"out_trade_no=A&=x"),
    ] {
        assert_error(route(input.clone()), "route_query");
        assert_error(
            verify_callback(callback(input), &config(), |_| panic!(), |_, _| panic!()),
            "callback_query",
        );
    }
    let raw = raw(b"out_trade_no=A");
    let responses = vec![response(200, b"")];
    assert_error(
        route_callback(RouteCall {
            input: raw.clone(),
            responses: responses.clone(),
        }),
        "route_query",
    );
    assert_error(
        verify_callback(
            CallbackCall {
                responses,
                ..callback(raw)
            },
            &config(),
            |_| panic!(),
            |_, _| panic!(),
        ),
        "callback_query",
    );
}

#[test]
fn route_returns_only_a_valid_candidate_order_id() {
    for id in ["A", "0-a_B9", &"z".repeat(100)] {
        let query = format!("out_trade_no={id}&sign=ignored");
        let Output::Route(r) = output(route(raw(query.as_bytes()))) else {
            panic!("expected route")
        };
        assert_eq!(r.order_id, id);
    }
    for query in [
        "sign=x",
        "out_trade_no=",
        "out_trade_no=a%2Fb",
        "out_trade_no=a+b",
        "out_trade_no=%FF",
        "out_trade_no=茶",
        &format!("out_trade_no={}", "z".repeat(101)),
    ] {
        assert_error(route(raw(query.as_bytes())), "route_query");
    }
}

// An in-memory stand-in binds each test signature to the exact supplied bytes.
fn fake_sign(bytes: Vec<u8>) -> String {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    format!("{:032x}", hasher.finish())
}

fn callback_fields() -> form::Values {
    form::parse(b"type=wxpay&pid=42&trade_no=T7&out_trade_no=Order-7_a&name=Tea+%E8%8C%B6&money=1.50&trade_status=TRADE_SUCCESS&sign_type=MD5").unwrap()
}

fn resign(fields: &mut form::Values) {
    let signature = fake_sign(canonical(fields));
    form::set(fields, "sign", &signature);
}

fn verify(fields: &form::Values) -> Step {
    verify_callback(
        callback(raw(&form::encode_bytes(fields))),
        &config(),
        fake_sign,
        str::eq,
    )
}

#[test]
fn verified_callback_uses_signed_identity_money_and_exact_ack() {
    for (method, param) in [
        ("wxpay", None),
        ("alipay", Some("")),
        ("wxpay", Some("context")),
    ] {
        let mut fields = callback_fields();
        form::set(&mut fields, "type", method);
        if let Some(p) = param {
            form::set(&mut fields, "param", p);
        }
        form::set(&mut fields, "extra", "covered");
        let param_field = if param == Some("context") {
            "param=context&"
        } else {
            ""
        };
        let expected = format!(
            "extra=covered&money=1.50&name=Tea 茶&out_trade_no=Order-7_a&{param_field}pid=42&trade_no=T7&trade_status=TRADE_SUCCESS&type={method}"
        );
        form::set(&mut fields, "sign", &fake_sign(expected.into_bytes()));
        let Output::Callback(c) = output(verify(&fields)) else {
            panic!("expected callback")
        };
        assert_eq!(c.event_id, "T7");
        assert_eq!(c.upstream_id, "T7");
        assert_eq!(c.order_id, "Order-7_a");
        assert_eq!(c.money.amount, "150");
        assert_eq!(c.money.currency, "CNY");
        assert_eq!(c.status, PaymentStatus::Paid);
        assert_eq!(c.ack.status, 200);
        assert_eq!(
            c.ack.headers,
            [("Content-Type".into(), vec!["text/plain".into()])]
        );
        assert_eq!(c.ack.body, b"success");
        form::set(&mut fields, "extra", "changed");
        assert_error(verify(&fields), "callback_signature");
    }
}

#[test]
fn verify_requires_every_mandatory_field_and_a_valid_order_id() {
    let mut all = callback_fields();
    resign(&mut all);
    for key in all.keys() {
        let mut fields = all.clone();
        fields.remove(key);
        assert_error(verify(&fields), "callback_field");
        form::set(&mut fields, std::str::from_utf8(key).unwrap(), "");
        assert_error(verify(&fields), "callback_field");
    }
    form::set(&mut all, "out_trade_no", "bad id");
    assert_error(verify(&all), "callback_query");
}

#[test]
fn verify_checks_signature_syntax_and_value_before_business_fields() {
    let mut fields = callback_fields();
    resign(&mut fields);
    form::set(&mut fields, "pid", "other");
    assert_error(verify(&fields), "callback_signature");
    for (key, bad) in [
        ("sign", "a".repeat(31)),
        ("sign", "a".repeat(33)),
        ("sign", "A".repeat(32)),
        ("sign", "g".repeat(32)),
        ("sign_type", "md5".into()),
    ] {
        let mut invalid = fields.clone();
        form::set(&mut invalid, key, &bad);
        assert_error(
            verify_callback(
                callback(raw(&form::encode_bytes(&invalid))),
                &config(),
                |_| panic!("signed malformed input"),
                |_, _| panic!(),
            ),
            "callback_signature",
        );
    }
}

#[test]
fn verify_classifies_signed_business_errors() {
    for (key, bad, code) in [
        ("pid", "43", "callback_identity"),
        ("trade_status", "PENDING", "callback_status"),
        ("type", "card", "callback_type"),
        ("money", "0", "callback_amount"),
        ("money", "92233720368547758.08", "callback_amount"),
    ] {
        let mut fields = callback_fields();
        form::set(&mut fields, key, bad);
        resign(&mut fields);
        assert_error(verify(&fields), code);
    }
}
