use super::{
    api::*,
    encoding::{Encoder, hash},
    *,
};
use prost::Message;
use upstream_host::environment::CapturedResponse;
use upstream_host::package::hex;
use upstream_host::types::HttpRequest;

#[test]
fn inferred_close_code_survives_projection_and_selects_a_distinct_event() {
    let query = "/aipay.upstream.v1.UpstreamService/QueryPayment";
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../guest/plugins/epay_v1_verify/fixtures/query_payment_unpaid_closed.json"
    ))
    .unwrap();
    let expected = &fixture["expected"];
    let project = |v| business::Outcome::from_host(serde_json::from_value(v).unwrap()).unwrap();
    let out = project(expected.clone());
    assert_eq!(
        out.result.upstream_code.as_deref(),
        Some("timeout_inferred_close")
    );
    assert_eq!(out.completion_event(query), Some("timeout_inferred_close"));
    assert_eq!(
        out.completion_event("/aipay.upstream.v1.UpstreamService/ClosePayment"),
        None
    );
    let mut paid = expected.clone();
    paid["result"]["payment"]["status"] = "paid".into();
    assert_eq!(project(paid).completion_event(query), None);
    let mut ordinary = expected.clone();
    ordinary["result"].as_object_mut().unwrap().remove("code");
    assert_eq!(project(ordinary).completion_event(query), None);
}

#[test]
fn not_found_event_requires_a_rejected_payment_query() {
    let query = "/aipay.upstream.v1.UpstreamService/QueryPayment";
    let fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../guest/plugins/epay_v1_verify/fixtures/query_payment_rejected.json"
    ))
    .unwrap();
    let mut out =
        business::Outcome::from_host(serde_json::from_value(fixture["expected"].clone()).unwrap())
            .unwrap();
    assert_eq!(out.result.upstream_code.as_deref(), Some("not_found"));
    assert_eq!(out.completion_event(query), Some("not_found"));
    assert_eq!(
        out.completion_event("/aipay.upstream.v1.UpstreamService/CreatePayment"),
        None
    );
    out.result.category = ExecutionCategory::Unknown.into();
    assert_eq!(out.completion_event(query), None);
    out.result.category = ExecutionCategory::Rejected.into();
    out.result.upstream_code = Some("epay_code_-1".into());
    assert_eq!(out.completion_event(query), None);
}

#[test]
fn credential_interoperability_vector() {
    let c = crypto::credentials(br#"{"b":"line\n", "a":"x<&"}"#).unwrap();
    assert_eq!(c.canonical.as_slice(), br#"{"a":"x<&","b":"line\u000a"}"#);
    assert_eq!(
        hex(&c.digest),
        "6d6eca2089f7a889f89ee6845013474b55b8c3977fe608635ac5195b3edcd164"
    );
    for bad in [
        br#"{"a":""}"#.as_slice(),
        br#"{"a":7}"#,
        br#"{"A":"x"}"#,
        br#"{"a":"a","a":"b"}"#,
        br#"{"a":"\udfff"}"#,
        br#"{"a":"\u0000"}"#,
        b"{}",
        b"[]",
        b"{\"a\":\"\xff\"}",
        b"{}{}",
    ] {
        assert!(crypto::credentials(bad).is_err())
    }
}
fn vector_context() -> OperationContext {
    OperationContext {
        idempotency_key: "k".into(),
        package_sha256: vec![1; 32],
        channel_account_id: "018f0000-0000-7000-8000-000000000001".into(),
        control_version: 2,
        config_json: b"{}".to_vec(),
        credentials_ref: "ref".into(),
        credentials_sha256: vec![2; 32],
        ..Default::default()
    }
}

#[test]
fn request_golden_header_order_and_presence() {
    let c = vector_context();
    let v = CallbackPayload {
        method: "POST".into(),
        raw_query: vec![255],
        headers: vec![
            HttpHeader {
                name: "Z".into(),
                values: vec!["2".into(), "1".into()],
            },
            HttpHeader {
                name: "A".into(),
                values: vec!["x".into()],
            },
        ],
        body: vec![0],
        source_ip: Some("::1".into()),
    };
    let mut e = Encoder::request(
        "payment",
        "/aipay.upstream.v1.UpstreamService/RouteCallback",
    );
    e.context(&c);
    e.callback(&v);
    assert_eq!(
        hex(&e.0),
        "0000001961697061792e757073747265616d2e726571756573742e7631000000077061796d656e74000000302f61697061792e757073747265616d2e76312e557073747265616d536572766963652f526f75746543616c6c6261636b000000016b0000002001010101010101010101010101010101010101010101010101010101010101010000002430313866303030302d303030302d373030302d383030302d303030303030303030303031000000000000000002000000027b7d0000000372656600000020020202020202020202020202020202020202020202020202020202020202020200000004504f535400000001ff000000020000000161000000010000000178000000017a0000000200000001320000000131000000010001000000033a3a31"
    );
    let m = business::Input::Route(v)
        .material(Role::Trade, "payment", c)
        .unwrap();
    assert_eq!(
        hex(&m.digest),
        "f82a5b833da62d7ee29001e6d7442bf992e5adbb38c938b0de2bb5a0f4db4da9"
    );
}
#[test]
fn create_buyer_fields_validate_and_bind_the_request_digest() {
    let material = |ip: Option<&str>, device: Option<&str>| {
        business::Input::Create(CreatePaymentInput {
            order_id: "order_1".into(),
            money: Some(Money {
                amount: "12345".into(),
                currency: "CNY".into(),
            }),
            method: "alipay".into(),
            callback_url: "https://example.test/callback".into(),
            instruction: Some("url".into()),
            client_ip: ip.map(str::to_owned),
            device: device.map(str::to_owned),
            ..Default::default()
        })
        .material(Role::Trade, "payment", vector_context())
    };
    for (ip, device, digest) in [
        (
            None,
            None,
            "dbd3ec950032739062bddba4985c5cd9f6e7d84622ab5c27b2bafcc6a09443ef",
        ),
        (
            Some("1.2.3.4"),
            None,
            "a6c12a78da145c96946c9f32b3f47180f2cc7da5e9ab703c4f4863b473475390",
        ),
        (
            None,
            Some("pc"),
            "5ccf79a6a30da2c3d3ae7358d1b2b5680ce3cddbf8ca638ba06768f76a2453a6",
        ),
        (
            Some("1.2.3.4"),
            Some("pc"),
            "e1c772272dfcc13838f85da9d19fcfc8ffb1b17d2c53b5a7ec1a7796dba579b1",
        ),
        (
            Some("2001:db8::1"),
            Some("pc"),
            "87009fdfea849850e6aa37bcf455d3de616baeef72900fc0b80f31464f686e4a",
        ),
        (
            Some("1.2.3.4"),
            Some("m_1"),
            "d89d662d4b71f51d847d86a07858fd1d8e5d4e0860e63b25c8f8e74d8a4fc40f",
        ),
    ] {
        let m = material(ip, device).unwrap();
        assert_eq!(hex(&m.digest), digest);
        let raw: serde_json::Value = serde_json::from_slice(&m.raw).unwrap();
        for (field, expected) in [("client_ip", ip), ("device", device)] {
            assert_eq!(
                raw.get(field),
                expected.map(serde_json::Value::from).as_ref()
            );
        }
    }
    for bad in [
        "2001:DB8::1",
        "::ffff:1.2.3.4",
        "::ffff:102:304",
        "1.2.3.4:80",
        "fe80::1%lo0",
        "",
    ] {
        let err = material(Some(bad), None).err().unwrap();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert_eq!(err.message(), "invalid request");
    }
    for bad in ["", "PC", "a-b", &"a".repeat(33)] {
        assert_eq!(
            material(None, Some(bad)).err().unwrap().code(),
            tonic::Code::InvalidArgument
        );
    }
}

#[test]
fn exchange_golden_partial_raw_headers() {
    let mut e = Encoder::domain(
        "aipay.upstream.exchange.v1",
        "payment",
        "/aipay.upstream.v1.UpstreamService/Refund",
    );
    e.string("018f0000-0000-7000-8000-000000000001");
    e.bytes(&[1; 32]);
    e.bytes(&[2; 32]);
    e.0.push(0);
    e.u32(1);
    e.0.extend(
        Encoder::attempt(
            1,
            &HttpRequest {
                method: "POST".into(),
                url: "https://a.test/".into(),
                headers: vec![("X".into(), vec!["{{secret:k}}".into()])],
                body: vec![0],
            },
        )
        .0,
    );
    e.0.extend(Encoder::reception(
        Some(&CapturedResponse {
            status: 502,
            headers: vec![("X".into(), vec![vec![0x80]])],
            body: vec![0xff],
            complete: false,
        }),
        "transport_error",
    ));
    e.finish(
        &ExecutionResult {
            category: 3,
            error_code: "transport_error".into(),
            requests: 1,
            steps: 1,
            ..Default::default()
        },
        None,
    );
    assert_eq!(
        hex(&e.0),
        "0000001a61697061792e757073747265616d2e65786368616e67652e7631000000077061796d656e74000000292f61697061792e757073747265616d2e76312e557073747265616d536572766963652f526566756e640000002430313866303030302d303030302d373030302d383030302d30303030303030303030303100000020010101010101010101010101010101010101010101010101010101010101010100000020020202020202020202020202020202020202020202020202020202020202020200000000010000000100000004504f53540000000f68747470733a2f2f612e746573742f000000010000000178000000010000000c7b7b7365637265743a6b7d7d000000010001000001f600000001000000017800000001000000018000000001ff000000020000000f7472616e73706f72745f6572726f72000000030000000f7472616e73706f72745f6572726f720000000001000000000000000100"
    );
    assert_eq!(
        hex(&hash(&e.0)),
        "ce2b357c73c907d6cfeed2a5612a405339a762237c278dad5d5c81b98e2a5115"
    );
}
#[test]
fn raw_decoder_and_method_options() {
    let req = QueryPaymentRequest::default();
    assert_eq!(
        wire::decode_request::<QueryPaymentRequest>(&req.encode_to_vec()).unwrap(),
        req
    );
    for bad in [
        &[0x78, 1][..],
        &[0x0a, 2, 0x78, 1],
        &[0x12, 4, 0x12, 2, 0x78, 1],
    ] {
        assert_eq!(
            wire::decode_request::<QueryPaymentRequest>(bad)
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
    for number in [0, 99] {
        assert!(wire::decode_request::<ExecutionResult>(&[8, number]).is_err())
    }
    let pool = &wire::DESCRIPTORS;
    let policy = pool.get_extension_by_name("aipay.authz.v1.policy").unwrap();
    let methods = pool
        .services()
        .flat_map(|s| s.methods().collect::<Vec<_>>())
        .collect::<Vec<_>>();
    assert_eq!(methods.len(), 12);
    assert!(methods.iter().all(|m| m.options().has_extension(&policy)));
}
#[test]
fn http_secret_fields_follow_the_development_http_settings() {
    for role in [Role::Trade, Role::Verification] {
        let production = Mode::Production.host_options(role);
        assert!(!production.test_only_allow_http_secret_fields);
        assert!(!production.test_only_allow_http);
        for (allow_loopback_http, allow_private_http) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let development = Mode::Development {
                allow_loopback_http,
                allow_private_http,
                allow_uncommitted: true,
            }
            .host_options(role);
            assert_eq!(
                development.test_only_allow_http_secret_fields,
                allow_loopback_http || allow_private_http
            );
            assert_eq!(
                development.test_only_allow_http,
                allow_loopback_http || allow_private_http
            );
        }
    }
}
#[test]
fn local_kms_mode_permissions_and_aad() {
    use std::{io::Write, os::unix::fs::PermissionsExt, sync::Arc};
    let mut file = tempfile::NamedTempFile::new().unwrap();
    let mut k = [0; 32];
    getrandom::fill(&mut k).unwrap();
    file.write_all(&k).unwrap();
    let dev = Mode::Development {
        allow_loopback_http: false,
        allow_private_http: false,
        allow_uncommitted: false,
    };
    assert!(crypto::LocalKms::from_file(Mode::Production, file.path()).is_err());
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o640))
        .unwrap();
    assert!(crypto::LocalKms::from_file(dev, file.path()).is_err());
    file.as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .unwrap();
    let v = crypto::Vault(Arc::new(
        crypto::LocalKms::from_file(dev, file.path()).unwrap(),
    ));
    let sealed = v.seal(b"test", b"one").unwrap();
    assert_eq!(v.open(&sealed, b"one").unwrap().as_slice(), b"test");
    assert!(v.open(&sealed, b"two").is_err());
}

#[test]
fn canonical_credentials_can_expand_after_admission() {
    let raw = serde_json::to_vec(&serde_json::json!({"key":"\n".repeat(15000)})).unwrap();
    let creds = crypto::credentials(&raw).unwrap();
    assert!(creds.canonical.len() > 65536);
    assert_eq!(
        crypto::stored_strings(&creds.canonical).unwrap()["key"].len(),
        15000
    );
}
