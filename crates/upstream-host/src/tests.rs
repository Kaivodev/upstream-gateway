use super::{
    engine::{Host, Options},
    http, json,
    package::*,
    replay::{Fixture, SeedStream},
    state::Scanner,
};
use base64::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub(super) fn manifest() -> Value {
    let mut v = json::object(include_bytes!(
        "../../../guest/plugins/sim_form_md5/manifest.json"
    ))
    .unwrap();
    v["build"] = json!({"rust_version":"1.99.1","wasm_tools_version":"1.263.0","target":"wasm32-unknown-unknown","source_commit":"uncommitted","source_tree_sha256":"0".repeat(64)});
    v
}
#[test]
fn strict_and_canonical() {
    for b in [
        br#"{"x":{"z":1,"z":2}}"#.as_slice(),
        br#"{"a":"\ud800"}"#,
        b"null",
        b"[]",
        b"{} {}",
        br#"{"n":1.0}"#,
        br#"{"n":2e3}"#,
        b"{\"x\":\"\xff\"}",
    ] {
        assert!(json::object(b).is_err())
    }
    let nested = |n| format!("{{\"x\":{}0{}}}", "[".repeat(n), "]".repeat(n));
    assert!(json::object(nested(63).as_bytes()).is_ok());
    assert!(json::object(nested(64).as_bytes()).is_err());
    assert_eq!(
        json::canonical(&json!({"z":[true,"<&>\u{2028}"],"a":"\n\"\\\0"})),
        b"{\"a\":\"\\u000a\\\"\\\\\\u0000\",\"z\":[true,\"<&>\xe2\x80\xa8\"]}"
    );
}
#[test]
fn manifest_permissions() {
    let v = manifest();
    Manifest::parse(&json::canonical(&v)).unwrap();
    for (k, x) in [
        ("version", json!("1.0.0-01")),
        ("domains", json!(["EXAMPLE.test"])),
        ("secrets", Value::Null),
        ("type", json!("statement")),
        ("public_keys", json!(["shared"])),
        ("Code", json!("foo")),
        ("capabilities", json!(["verify_callback"])),
    ] {
        let mut bad = v.clone();
        bad[k] = x;
        assert!(Manifest::parse(&json::canonical(&bad)).is_err(), "{k}")
    }
    let mut bad = v;
    bad.as_object_mut().unwrap().remove("public_keys");
    assert!(Manifest::parse(&json::canonical(&bad)).is_err());
}
#[test]
fn declared_secret_fields_manifest() {
    // The canonical manifest projection is part of the package digest.
    let mut v = manifest();
    let before = json::canonical(&v);
    let m = Manifest::parse(&before).unwrap();
    assert_eq!(json::canonical(&json!(&m)), before);
    for fields in [
        json!({"query":["9.A_-"]}),
        json!({"form":["x".repeat(64)]}),
        json!({"query":["key"], "form":["key"]}),
    ] {
        v["secret_fields"] = fields;
        let canonical = json::canonical(&v);
        assert_eq!(
            json::canonical(&json!(Manifest::parse(&canonical).unwrap())),
            canonical
        );
    }
    for fields in [
        Value::Null,
        json!([]),
        json!({}),
        json!({"header":["x"]}),
        json!({"form":[]}),
        json!({"query":null}),
        json!({"query":"key"}),
        json!({"query":[""]}),
        json!({"form":["x","x"]}),
        json!({"form":["a/b"]}),
        json!({"query":["é"]}),
        json!({"query":["x".repeat(65)]}),
        json!({"form":(0..17).map(|i| i.to_string()).collect::<Vec<_>>()}),
    ] {
        v["secret_fields"] = fields;
        assert!(
            Manifest::parse(&json::canonical(&v)).is_err(),
            "accepted {}",
            v["secret_fields"]
        );
    }
    v["secret_fields"] = json!({"query":["key"]});
    for secrets in [json!({}), json!({"signer":"rsa-private"})] {
        v["secrets"] = secrets;
        assert!(Manifest::parse(&json::canonical(&v)).is_err());
    }
}
#[test]
fn verification_capabilities() {
    let mut v = manifest();
    v["type"] = json!("verification");
    v.as_object_mut().unwrap().remove("callback");
    for (ops, valid) in [
        (json!(["query_payment"]), true),
        (json!(["query_refund", "query_payment"]), true),
        (json!(["query_payment", "query_refund"]), true),
        (json!(["query_refund"]), false),
        (json!([]), false),
        (json!(["query_payment", "create_payment"]), false),
        (json!(["query_payment", "refund", "query_refund"]), false),
    ] {
        v["capabilities"] = ops;
        assert_eq!(Manifest::parse(&json::canonical(&v)).is_ok(), valid);
    }
}
#[test]
fn http_policy() {
    for s in [
        "HTTPS://example.test",
        "https://EXAMPLE.test",
        "https://example.test.",
        "https://x@example.test",
        "https://%65xample.test",
        "https://example.test\\foo",
        "https://127.1",
        "https://0x7f.1",
        "https://example.test/\u{1}",
        "https:example.test",
        "https://example.test/#",
    ] {
        assert!(http::url(s, false).is_err(), "{s}")
    }
    assert_eq!(
        http::url("https://example.test:443/path?q=1", false),
        Ok("example.test")
    );
    assert!(http::url("http://example.test", false).is_err());
    let h = |k: &str, v: &str| vec![(k.into(), vec![v.into()])];
    assert_eq!(http::normalize(&h("tE", "a\tb")).unwrap()[0].0, "Te");
    assert!(http::normalize(&h("a", "hi\x7f")).is_none());
    let mut alias = h("Name", "a");
    alias.extend(h("name", "b"));
    assert!(http::normalize(&alias).is_none());
    let m = Manifest::parse(&json::canonical(&manifest())).unwrap();
    for v in [
        "{{x}}",
        "{{secret:missing}}",
        "{{secret:shared}}{{again}}",
        "{{secret:shared",
    ] {
        assert!(http::expand(&m, &h("X-Key", v), |_| Some("value".into())).is_err())
    }
    assert!(http::expand(&m, &h("TE", "v"), |_| None).is_err());
    assert!(
        http::expand(&m, &h("X-Key", "{{secret:shared}}"), |_| Some(
            "a".repeat(16384)
        ))
        .is_err()
    );
}
#[test]
fn leak_encodings() {
    let mut b = vec![0; 32];
    getrandom::fill(&mut b).unwrap();
    let mut s = Scanner::default();
    s.add(&b);
    assert!(s.bytes(&b));
    for v in [
        hex(&b),
        hex(&b).to_ascii_uppercase(),
        BASE64_STANDARD.encode(&b),
        BASE64_STANDARD_NO_PAD.encode(&b),
        BASE64_URL_SAFE.encode(&b),
        BASE64_URL_SAFE_NO_PAD.encode(&b),
    ] {
        let escaped = v.bytes().map(|b| format!("\\u{b:04x}")).collect::<String>();
        assert!(s.bytes(format!("{{\"{escaped}\":0}}").as_bytes()))
    }
}
#[test]
fn entropy_and_fixtures() {
    let seed = [7; 32];
    let mut f = SeedStream::new(seed);
    let mut out = [0; 65];
    f.fill(&mut out[..3]);
    f.fill(&mut out[3..]);
    for i in 0..2 {
        let expected = Sha256::new()
            .chain_update(seed)
            .chain_update((i as u64).to_be_bytes())
            .finalize();
        assert_eq!(out[i * 32..i * 32 + 32], expected[..])
    }
    let fixture =
        include_bytes!("../../../guest/plugins/sim_form_md5/fixtures/query_payment_timeout.json");
    assert!(Fixture::decode(fixture).is_ok());
    let mut bad = json::object(fixture).unwrap();
    bad["exchanges"][0]["error"] = json!("other");
    assert!(Fixture::decode(&json::canonical(&bad)).is_err());
}
#[test]
fn exact_component_surface() {
    let h = Host::new(Options::replay("payment")).unwrap();
    let mut p = Package {
        manifest: Manifest::parse(&json::canonical(&manifest())).unwrap(),
        fixtures: BTreeMap::new(),
        wasm: vec![],
    };
    let reference = concat!(env!("OUT_DIR"), "/trade-plugin.wasm");
    let out = std::process::Command::new("wasm-tools")
        .args(["print", reference])
        .output()
        .unwrap();
    assert!(out.status.success());
    let wat = String::from_utf8(out.stdout).unwrap();
    for text in [
        wat.replace("kaivo:upstream/host@3.0.0", "kaivo:upstream/host@3.0.1"),
        wat.replace("kaivo:upstream/host@3.0.0", "wasi:random/random@0.2.0"),
        format!(
            "{} (export \"extra\" (instance 0)))",
            wat.trim_end().strip_suffix(')').unwrap()
        ),
    ] {
        p.wasm = wat::parse_str(text).unwrap();
        assert!(h.load(&p).is_err())
    }
    p.wasm = std::fs::read(reference).unwrap();
    assert!(h.load(&p).is_ok());
    assert!(
        Host::new(Options::production("payment"))
            .unwrap()
            .load(&p)
            .is_err()
    );
}

#[test]
fn cryptographic_imports() {
    use crate::{
        environment::{Cancellation, Environment},
        imports::{Host as _, Part},
        state::State,
    };
    use rsa::{Pkcs1v15Sign, PrivateKey, PublicKey};
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };
    use zeroize::Zeroizing;
    struct Keys {
        shared: Zeroizing<Vec<u8>>,
        rsa: Arc<PrivateKey>,
    }
    impl Environment for Keys {
        fn secret(&self, _: &str, _: &Cancellation) -> anyhow::Result<Zeroizing<Vec<u8>>> {
            Ok(self.shared.clone())
        }
        fn private_key(&self, _: &str, _: &Cancellation) -> Option<Arc<PrivateKey>> {
            Some(self.rsa.clone())
        }
        fn public_key(&self, _: &str, _: Instant, _: &Cancellation) -> anyhow::Result<PublicKey> {
            Ok(self.rsa.to_public_key())
        }
    }
    let mut shared = Zeroizing::new(vec![0; 32]);
    getrandom::fill(&mut shared).unwrap();
    let k = Arc::new(Keys {
        shared,
        rsa: Arc::new(PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap()),
    });
    let mut m = Manifest::parse(&json::canonical(&manifest())).unwrap();
    m.config.clear();
    m.public_keys.push("public".into());
    m.secrets.insert("private".into(), "rsa-private".into());
    let mut s = State::new(Arc::new(m), k.clone(), Default::default(), "query_payment");
    s.prepare().unwrap();
    s.deadline = Instant::now() + Duration::from_secs(30);
    let data = || vec![Part::Data(b"abc".to_vec())];
    assert_eq!(
        s.sign("md5".into(), None, data()).unwrap(),
        "900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(
        s.sign("sha1".into(), None, data()).unwrap(),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
    assert_eq!(
        s.sign("sha256".into(), None, data()).unwrap(),
        digest(b"abc")
    );
    let mut inner = Zeroizing::new([0x36; 64]);
    let mut outer = Zeroizing::new([0x5c; 64]);
    for (i, b) in k.shared.iter().enumerate() {
        inner[i] ^= b;
        outer[i] ^= b
    }
    let expected = Sha256::new()
        .chain_update(*outer)
        .chain_update(
            Sha256::new()
                .chain_update(*inner)
                .chain_update(b"abc")
                .finalize(),
        )
        .finalize();
    assert_eq!(
        s.sign("hmac-sha256".into(), Some("shared".into()), data())
            .unwrap(),
        hex(&expected)
    );
    let sig = s
        .sign("rsa-sha256".into(), Some("private".into()), data())
        .unwrap();
    k.rsa
        .to_public_key()
        .verify(
            Pkcs1v15Sign::new::<Sha256>(),
            &Sha256::digest(b"abc"),
            &BASE64_STANDARD.decode(&sig).unwrap(),
        )
        .unwrap();
    assert!(
        s.verify("rsa-sha256".into(), "public".into(), data(), sig)
            .unwrap()
    );
    assert!(
        !s.verify("rsa-sha256".into(), "public".into(), data(), "%".into())
            .unwrap()
    );
}
