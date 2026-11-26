use super::*;
use serde_json::json;

const FORM: &str = "application/x-www-form-urlencoded";

fn expand_request(
    m: &Manifest,
    r: &HttpRequest,
    allow_http: bool,
    secret: impl FnMut(&str) -> Option<Zeroizing<Vec<u8>>>,
) -> Check<Zeroizing<HttpRequest>> {
    RequestTemplate::validate(m, r, allow_http)?.expand(REQUEST_BODY_LIMIT, secret)
}

fn manifest() -> Manifest {
    let mut v = crate::tests::manifest();
    v["secret_fields"] = json!({"query":["key"],"form":["key"]});
    v["secrets"]["signer"] = json!("rsa-private");
    Manifest::parse(&crate::json::canonical(&v)).unwrap()
}

fn request(query: &str, body: &[u8], types: &[&str]) -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        url: format!("https://example.test/path?{query}"),
        headers: vec![(
            "content-TYPE".into(),
            types.iter().map(|s| s.to_string()).collect(),
        )],
        body: body.to_vec(),
    }
}

#[test]
fn requests_without_secret_fields_preserve_opaque_query_and_form_bytes() {
    let m = Manifest::parse(&crate::json::canonical(&crate::tests::manifest())).unwrap();
    let pairs = "tag=one&tag=two&bad%zz=%zz&encoded=%7B%7Bsecret%3Ashared%7D%7D";
    let r = request(pairs, pairs.as_bytes(), &[FORM]);
    assert_eq!(url(&r.url, false), Ok("example.test"));
    let wire = expand_request(&m, &r, false, |_| panic!("unexpected credential lookup")).unwrap();
    assert_eq!(wire.url, r.url);
    assert_eq!(wire.body, r.body);

    for r in [
        request("tag=%zz&tag={{secret:shared}}", b"", &[FORM]),
        request("", b"tag=%zz&tag={{secret:shared}}", &[FORM]),
        request("", br#"{"tag":"{{secret:shared}}"}"#, &["application/json"]),
    ] {
        assert_eq!(
            RequestTemplate::validate(&m, &r, false).err(),
            Some("secret_placeholder")
        );
    }
    assert_eq!(
        url("https://example.test/%zz?q=ok", false),
        Err("request_url")
    );
    assert!(!instruction_url(&r.url, false));
}

#[test]
fn rejects_ambiguous_or_unauthorized_field_templates() {
    let m = manifest();
    let reject = |r: &HttpRequest| {
        assert_eq!(
            expand_request(&m, r, false, |_| None).err(),
            Some("secret_placeholder")
        );
    };
    for pair in [
        "key=x%7b%7bsecret:shared}}",
        "key={{secret:shared}}x",
        "key={{bad}}",
        "key=%7D%7D",
        "key={{secret:shared}}{{secret:shared}}",
        "key={{secret:shared",
        "plain=%7B%7Bsecret%3Ashared%7D%7D",
        "%7b%7bsecret%3Ashared}}=v",
        "key=a&%6bey={{secret:shared}}",
        "k%65y=one&key=two",
        "plain%zz=value",
        "plain=%zz",
        "key={{secret:typo}}",
        "key={{secret:signer}}",
    ] {
        for r in [
            request(pair, b"", &[FORM]),
            request("", pair.as_bytes(), &[FORM]),
        ] {
            // Valid shared credentials must not make a malformed template sendable.
            assert_eq!(
                expand_request(&m, &r, false, |_| Some(Zeroizing::new(vec![b'x'; 16]))).err(),
                Some("secret_placeholder"),
                "{pair}"
            );
        }
    }
    for url in [
        "https://{{secret:shared}}/path",
        "https://example.test/{{secret:shared}}",
        "https://example.test/?q=x#{{secret:shared}}",
    ] {
        assert_eq!(super::url(url, false), Err("secret_placeholder"));
    }
    for types in [vec![], vec!["application/json"], vec![FORM, FORM]] {
        let mut r = request("", b"key={{secret:shared}}", &types);
        if types.is_empty() {
            r.headers.clear();
        }
        reject(&r);
    }
    let mut r = request("", b"key={{secret:shared}}", &[FORM]);
    r.headers.push(("Content-Type".into(), vec![FORM.into()]));
    reject(&r);
    for r in [
        request("key={{secret:shared}}", b"", &[FORM]),
        request("", b"key={{secret:shared}}", &[FORM]),
    ] {
        reject(&r);
        for b in [0, b'\r', b'\n', 31, 127] {
            assert_eq!(
                expand_request(&m, &r, false, |_| Some(Zeroizing::new(vec![b; 16]))).err(),
                Some("secret_placeholder")
            );
        }
    }
}

#[test]
fn http_field_expansion_requires_the_test_credential_exception() {
    let m = manifest();
    for mut r in [
        request("key={{secret:shared}}", b"", &[FORM]),
        request("", b"key={{secret:shared}}", &[FORM]),
    ] {
        r.url = r.url.replacen("https:", "http:", 1);
        assert_eq!(
            expand_request(&m, &r, false, |_| panic!("resolved before HTTPS check")).err(),
            Some("https_required")
        );
        assert!(expand_request(&m, &r, true, |_| Some(Zeroizing::new(vec![b'x'; 16]))).is_ok());
    }
}

#[test]
fn field_expansion_preserves_bytes_and_obeys_wire_limits() {
    let m = manifest();
    let r = request(
        "q=%2f&&k%65y=%7b%7Bsecret%3Ashared%7D%7d&%71=two&tail",
        b"name=one&%6Bey={{secret:shared}}&name=a%20b+z&",
        &["Application/X-Www-Form-Urlencoded; charset=UTF-8"],
    );
    // Include arbitrary shared-key bytes as well as UTF-8 and the allowed horizontal tab.
    let secret = || Zeroizing::new([" &=%é\t".as_bytes(), &[0xff]].concat());
    let wire = expand_request(&m, &r, false, |_| Some(secret())).unwrap();
    assert_eq!(
        wire.url,
        "https://example.test/path?q=%2f&&k%65y=+%26%3D%25%C3%A9%09%FF&%71=two&tail"
    );
    assert_eq!(
        wire.body,
        b"name=one&%6Bey=+%26%3D%25%C3%A9%09%FF&name=a%20b+z&"
    );
    let mut r = request("key={{secret:shared}}&pad=", b"", &[FORM]);
    // Each percent byte occupies three bytes on the wire.
    let key = || Some(Zeroizing::new(vec![b'%'; 16]));
    let padding = 65_534 - (r.url.len() - "{{secret:shared}}".len() + 48);
    r.url.push_str(&"x".repeat(padding));
    assert_eq!(
        expand_request(&m, &r, false, |_| key()).unwrap().url.len(),
        65_534
    );
    r.url.push('x');
    assert_eq!(
        expand_request(&m, &r, false, |_| key()).err(),
        Some("request_limit")
    );
    let mut r = request("", b"key={{secret:shared}}&pad=", &[FORM]);
    let bytes = (256 << 10) + "{{secret:shared}}".len() - 48;
    r.body.resize(bytes, b'x');
    assert_eq!(
        expand_request(&m, &r, false, |_| key()).unwrap().body.len(),
        256 << 10
    );
    r.body.push(b'x');
    assert_eq!(
        expand_request(&m, &r, false, |_| key()).err(),
        Some("request_limit")
    );
}
