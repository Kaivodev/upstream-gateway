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
#[test]
fn request_golden_header_order_and_presence() {
    let c = OperationContext {
        idempotency_key: "k".into(),
        package_sha256: vec![1; 32],
        channel_account_id: "018f0000-0000-7000-8000-000000000001".into(),
        control_version: 2,
        config_json: b"{}".to_vec(),
        credentials_ref: "ref".into(),
        credentials_sha256: vec![2; 32],
        ..Default::default()
    };
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
fn local_kms_mode_permissions_and_aad() {
    use std::{io::Write, os::unix::fs::PermissionsExt, sync::Arc};
    let mut file = tempfile::NamedTempFile::new().unwrap();
    let mut k = [0; 32];
    getrandom::fill(&mut k).unwrap();
    file.write_all(&k).unwrap();
    let dev = Mode::Development {
        allow_loopback_http: false,
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
