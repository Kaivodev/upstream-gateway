use super::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use rsa::{Pkcs1v15Sign, PrivateKey, traits::PublicKeyParts};
use serde_json::{Value, json};
use std::{fs, path::Path, sync::LazyLock};

#[path = "../../tests/support/token.rs"]
pub(crate) mod token;
use token::{ISSUER, Signer, claims};

const NOW: i64 = 1_800_000_000;
static RSA: LazyLock<PrivateKey> =
    LazyLock::new(|| PrivateKey::new(&mut getrandom::SysRng, 2048).unwrap());

fn rsa_jwk() -> Value {
    json!({"kid":"rsa","kty":"RSA","n":B64.encode(RSA.n().to_be_bytes_trimmed_vartime()),"e":B64.encode(RSA.e().to_be_bytes_trimmed_vartime())})
}

pub(crate) fn config(path: &Path) -> ServiceToken {
    ServiceToken {
        jwks_file: path.into(),
        issuer: ISSUER.into(),
        service_namespaces: ["payment", "reconciliation"]
            .map(|s| (s.into(), "kaivo-business".into()))
            .into(),
    }
}

fn with_field(base: &Value, key: &str, value: Value) -> Value {
    let mut modified = base.clone();
    modified[key] = value;
    modified
}

#[test]
fn projected_token_decisions() {
    let signer = Signer::new();
    let mut padded = rsa_jwk();
    for member in ["n", "e"] {
        let mut bytes = vec![0, 0];
        bytes.extend(B64.decode(padded[member].as_str().unwrap()).unwrap());
        padded[member] = json!(B64.encode(bytes));
    }
    let jwks = json!({"keys":[signer.jwk(), padded]});
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("jwks");
    fs::write(&file, jwks.to_string()).unwrap();
    let config = config(&file);
    let trade = Verifier::load(config.clone(), Role::Trade, vec!["payment".into()]).unwrap();
    let verification = Verifier::load(
        config.clone(),
        Role::Verification,
        vec!["reconciliation".into()],
    )
    .unwrap();
    let base = claims("trade", "payment", NOW);
    let header = json!({"alg":"ES256","kid":"ec"});
    let valid = signer.token(&base);
    let mut vectors = vec![];
    let mut case = |label: &str, role: Role, tokens: Vec<String>, expected: &str| {
        let verifier = if role == Role::Trade {
            &trade
        } else {
            &verification
        };
        let result = verifier
            .authenticate_at(tokens.iter().map(|v| v.as_bytes()), NOW)
            .err()
            .unwrap_or("");
        assert_eq!(result, expected, "{label}");
        vectors.push(
            json!({"label": label, "service":format!("upstream-gateway-{}", role.name()),
            "allowed":[role.caller()],"tokens":tokens,"reason":expected}),
        );
    };
    case("absent", Role::Trade, vec![], "token_missing");
    case("repeated", Role::Trade, vec![valid.clone(); 2], MALFORMED);
    case(
        "cross-instance",
        Role::Verification,
        vec![valid.clone()],
        "token_audience",
    );
    let mut check = |label: &str, token: String, expected: &str| {
        case(label, Role::Trade, vec![token], expected)
    };
    check("ES256", valid.clone(), "");
    let input = format!(
        "{}.{}",
        B64.encode(br#"{"alg":"RS256","kid":"rsa"}"#),
        B64.encode(base.to_string())
    );
    let signature = RSA
        .sign_with_rng(
            &mut getrandom::SysRng,
            Pkcs1v15Sign::new::<Sha256>(),
            &Sha256::digest(&input),
        )
        .unwrap();
    check("RS256", format!("{input}.{}", B64.encode(signature)), "");
    for token in [
        "",
        ".",
        "..",
        "a.b",
        "a.b.c.d",
        ".e30.YQ",
        "e30..YQ",
        "e30.e30.",
        "e30=.e30.YQ",
        "e31.e30.YQ",
        "e30.e31.YQ",
        "e30.e30.YR",
        "e30.e30.YQ==",
        "e30.e30.+/",
    ] {
        check("compact encoding", token.into(), MALFORMED);
    }
    // Find an otherwise-valid signed token of exactly 64 KiB (raw lengths encode in steps of 4/3).
    let base_json = base.to_string();
    let mut exact = None;
    for extra in 0..4 {
        let mut h = header.to_string();
        h.push_str(&" ".repeat(extra));
        let overhead = B64.encode(&h).len() + 2 + 86;
        let large = format!("{base_json:<width$}", width = (65536 - overhead) * 3 / 4);
        let candidate = signer.sign_raw(h.as_bytes(), large.as_bytes());
        if candidate.len() == 65536 {
            exact = Some(candidate);
            break;
        }
    }
    let exact = exact.unwrap();
    check("maximum length", exact.clone(), "");
    check("over maximum length", format!("{exact}A"), MALFORMED);
    for h in [
        json!(null),
        json!([]),
        json!("header"),
        json!({}),
        json!({"Alg":"ES256","kid":"ec"}),
        json!({"alg":null,"kid":"ec"}),
        with_field(&header, "crit", Value::Null),
        with_field(&header, "crit", json!([])),
        with_field(&header, "b64", json!(false)),
        with_field(&header, "b64", Value::Null),
        with_field(&header, "alg", json!("HS256")),
        with_field(&header, "kid", json!(17)),
        with_field(&header, "kid", json!("")),
    ] {
        check(
            "malformed header",
            signer.sign_raw(h.to_string().as_bytes(), b"{}"),
            MALFORMED,
        );
    }
    for h in [
        with_field(&header, "kid", json!("unknown")),
        with_field(&header, "alg", json!("RS256")),
        with_field(&header, "kid", json!("rsa")),
    ] {
        check(
            "key selection",
            signer.sign_raw(h.to_string().as_bytes(), b"!"),
            "token_signature",
        );
    }
    let (signed, _) = valid.rsplit_once('.').unwrap();
    for n in [1, 63, 65] {
        check(
            "signature width",
            format!("{signed}.{}", B64.encode(vec![0; n])),
            "token_signature",
        );
    }
    check(
        "other signer",
        Signer::new().token(&base),
        "token_signature",
    );
    let changed = valid.replacen(&B64.encode(base.to_string()), &B64.encode(b"{}"), 1);
    check("modified payload", changed, "token_signature");
    for raw in [b"{".as_slice(), b"[]", b"null", b"\"s\""] {
        check(
            "malformed claims",
            signer.sign_raw(header.to_string().as_bytes(), raw),
            MALFORMED,
        );
    }
    let body = base.to_string();
    let raw_case = |body: &[u8]| signer.sign_raw(header.to_string().as_bytes(), body);
    let prefix = body.strip_suffix('}').unwrap();
    for (label, suffix, expected) in [
        (
            "unpaired surrogate",
            br#","\udc00":"unused"}"#.as_slice(),
            "",
        ),
        ("invalid UTF-8", b",\"\xff\":true}", ""),
        ("unknown number", br#","unknown":1e987654}"#, ""),
        ("negative zero", br#","iat":-0}"#, ""),
        ("exponent time", br#","iat":1e3}"#, MALFORMED),
        ("case-sensitive issuer", br#","ISS":"other"}"#, ""),
        ("duplicate issuer", br#","iss":"other"}"#, "token_issuer"),
        ("ill-formed JSON escape", br#","unknown":"\z"}"#, MALFORMED),
    ] {
        check(
            label,
            raw_case(&[prefix.as_bytes(), suffix].concat()),
            expected,
        );
    }
    for (depth, expected) in [(9999, ""), (10000, MALFORMED)] {
        let nested = format!(
            "{prefix},\"unused\":{}0{}}}",
            "[".repeat(depth),
            "]".repeat(depth)
        );
        check("JSON nesting limit", raw_case(nested.as_bytes()), expected);
    }
    let mut claim = |key: &str, value: Value, expected: &str| {
        check(key, signer.token(&with_field(&base, key, value)), expected)
    };
    claim("iss", json!("other"), "token_issuer");
    claim("iss", Value::Null, "token_issuer");
    let aud = &base["aud"];
    for (value, expected) in [
        (json!(["other", aud]), ""),
        (json!([aud, null]), "token_audience"),
        (json!([42, aud]), "token_audience"),
        (json!("other"), "token_audience"),
        (json!([]), "token_audience"),
        (Value::Null, "token_audience"),
    ] {
        claim("aud", value, expected);
    }
    for field in ["iat", "exp", "nbf"] {
        for v in [
            json!(1.1),
            json!(1.0),
            json!("100"),
            Value::Null,
            json!(u64::MAX),
        ] {
            claim(field, v, MALFORMED);
        }
    }
    for field in ["nbf", "iat"] {
        for (delta, expected) in [
            (29, ""),
            (30, ""),
            (31, "token_expired"),
            (600, "token_expired"),
            (601, "token_expired"),
        ] {
            claim(field, json!(NOW + delta), expected);
        }
    }
    for sub in [
        "",
        "system:other:kaivo-business:payment",
        "system:serviceaccount::payment",
        "system:serviceaccount:ns",
        "system:serviceaccount:ns:payment:x",
        "system:serviceaccount:ns:",
        "system:serviceaccount:ns:Payment",
        "system:serviceaccount:ns:9",
    ] {
        claim("sub", json!(sub), "token_subject");
    }
    claim(
        "sub",
        json!("system:serviceaccount:wrong:payment"),
        "token_namespace",
    );
    claim(
        "sub",
        json!("system:serviceaccount:kaivo-business:absent"),
        "token_namespace",
    );
    claim(
        "sub",
        json!("system:serviceaccount:kaivo-business:reconciliation"),
        "caller_not_allowed",
    );
    for (v, e) in [
        (
            json!({"namespace":"kaivo-business","serviceaccount":{"name":"payment"}}),
            "",
        ),
        (
            json!({"namespace":"other","serviceaccount":{"name":"payment"}}),
            "token_subject",
        ),
        (
            json!({"namespace":"kaivo-business","serviceaccount":{"name":"other"}}),
            "token_subject",
        ),
        (json!({"namespace":"kaivo-business"}), "token_subject"),
        (Value::Null, "token_subject"),
    ] {
        claim("kubernetes.io", v, e);
    }
    for (field, expected) in [
        ("iss", "token_issuer"),
        ("aud", "token_audience"),
        ("iat", MALFORMED),
        ("nbf", MALFORMED),
        ("exp", MALFORMED),
        ("sub", "token_subject"),
    ] {
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove(field);
        check("missing claim", signer.token(&missing), expected);
    }
    for (delta, expected) in [(-31, "token_expired"), (-30, "token_expired"), (-29, "")] {
        let mut body = base.clone();
        body["iat"] = json!(NOW - 600);
        body["nbf"] = json!(NOW - 600);
        body["exp"] = json!(NOW + delta);
        check("expiry boundary", signer.token(&body), expected);
    }
    for field in ["iat", "nbf"] {
        for delta in [0, 1] {
            let mut body = base.clone();
            body["exp"] = json!(NOW + 5);
            body[field] = json!(NOW + 5 + delta);
            check("lifetime ordering", signer.token(&body), "token_expired");
        }
    }
    if let Some(output) = std::env::var_os("UG4B_VECTOR_DIR") {
        let document = json!({"jwks":jwks,"issuer":ISSUER,"namespaces":config.service_namespaces,"now":NOW,"vectors":vectors});
        fs::write(
            Path::new(&output).join("tokens.json"),
            serde_json::to_vec(&document).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn jwks_admission() {
    let ec = Signer::new().jwk();
    let rsa = rsa_jwk();
    let mut vectors = vec![];
    let mut case = |label: &str, set: Value, expected: bool| {
        let raw = set.to_string();
        assert_eq!(jwks::parse(raw.as_bytes()).is_ok(), expected, "{label}");
        vectors.push(json!({"label":label,"jwks":set,"accepted":expected}));
    };
    for doc in [
        json!({}),
        json!(null),
        json!([]),
        json!({"keys":[]}),
        json!({"keys":null}),
        json!({"keys":{}}),
        json!({"keys":[ec,ec]}),
        json!({"keys":[ec,null]}),
    ] {
        case("document", doc, false);
    }
    case("both algorithms", json!({"keys":[ec,rsa]}), true);
    case(
        "Go struct field aliases",
        json!({"KEYS":[{"KID":"ec","KTY":"EC","CRV":"P-256","X":ec["x"],"Y":ec["y"]}]}),
        true,
    );
    case(
        "Unicode struct aliases",
        json!({"KEYſ":[{"KID":"ec","KTY":"EC","CRV":"P-256","X":ec["x"],"Y":ec["y"]}]}),
        true,
    );
    let mut key = |label: &str, k: Value, ok: bool| case(label, json!({"keys":[k]}), ok);
    let repeated_ops = with_field(&ec, "KEY_OPS", json!(["verify"]));
    key(
        "repeated operations with null",
        with_field(&repeated_ops, "key_ops", json!([null])),
        true,
    );
    key(
        "repeated empty operations",
        with_field(&repeated_ops, "key_ops", json!([])),
        false,
    );
    for private in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        key(
            "private field",
            with_field(&ec, private, Value::Null),
            false,
        );
    }
    for (field, value, expected) in [
        ("kid", Value::Null, false),
        ("kid", json!(""), false),
        ("kty", json!("OKP"), false),
        ("use", json!(""), true),
        ("use", json!("sig"), true),
        ("use", json!("enc"), false),
        ("alg", json!(""), true),
        ("alg", json!("ES256"), true),
        ("alg", json!("RS256"), false),
        ("key_ops", Value::Null, true),
        ("key_ops", json!([]), false),
        ("key_ops", json!(["sign"]), false),
        ("key_ops", json!(["sign", "verify"]), true),
        ("key_ops", json!([null, "verify"]), true),
        ("key_ops", json!(["verify", 1]), false),
        ("key_ops", json!("verify"), false),
        ("crv", json!("P-384"), false),
        ("x", json!(B64.encode([0u8; 31])), false),
        ("y", json!(B64.encode([0u8; 33])), false),
        ("x", json!(B64.encode([255u8; 32])), false),
        ("y", json!(B64.encode([0u8; 32])), false),
        ("x", json!(format!("{}=", ec["x"].as_str().unwrap())), false),
        ("y", json!("!"), false),
        ("n", json!(2), false),
    ] {
        key(field, with_field(&ec, field, value), expected);
    }
    for f in ["kid", "kty", "x", "y", "crv"] {
        let mut k = ec.clone();
        k.as_object_mut().unwrap().remove(f);
        key("missing", k, false);
    }
    let mut even = vec![255u8; 256];
    even[255] = 254;
    let mut short = vec![255u8; 256];
    short[0] = 127;
    for (field, value, expected) in [
        ("alg", json!("ES256"), false),
        ("alg", json!("RS256"), true),
        ("e", json!(B64.encode([3])), true),
        ("e", json!(B64.encode([0, 0, 3])), true),
        ("e", json!(B64.encode([127, 255, 255, 255])), true),
        ("e", json!(B64.encode([128, 0, 0, 1])), false),
        ("e", json!(B64.encode([0])), false),
        ("e", json!(B64.encode([1])), false),
        ("e", json!(B64.encode([4])), false),
        ("e", json!("Aw=="), false),
        ("e", json!("Ax"), false),
        ("n", json!(""), false),
        ("n", json!("!"), false),
        ("n", json!(B64.encode(short)), false),
        ("n", json!(B64.encode(even)), false),
        ("n", json!(B64.encode(vec![255; 255])), false),
        ("n", json!(B64.encode(vec![255; 1024])), true),
        (
            "n",
            json!(
                B64.encode(
                    [
                        &[0, 0][..],
                        B64.decode(rsa["n"].as_str().unwrap()).unwrap().as_slice()
                    ]
                    .concat()
                )
            ),
            true,
        ),
    ] {
        key(field, with_field(&rsa, field, value), expected);
    }
    for f in ["n", "e"] {
        let mut k = rsa.clone();
        k.as_object_mut().unwrap().remove(f);
        key("missing", k, false);
    }
    // This set is valid in Go, but exceeds ring's verification limit.
    let oversized = with_field(&rsa, "n", json!(B64.encode(vec![255; 1025])));
    assert!(jwks::parse(json!({"keys":[ec,oversized]}).to_string().as_bytes()).is_err());
    assert!(jwks::parse(b"{").is_err());
    if let Some(output) = std::env::var_os("UG4B_VECTOR_DIR") {
        fs::write(
            Path::new(&output).join("keys.json"),
            serde_json::to_vec(&vectors).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn startup_and_reload_publish_only_complete_valid_key_sets() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("jwks");
    let load = || Verifier::load(config(&file), Role::Trade, vec!["payment".into()]);
    assert!(load().is_err());
    fs::write(&file, b"{}").unwrap();
    assert!(load().is_err());
    let first = Signer::new();
    let second = Signer::new();
    let body = claims("trade", "payment", NOW);
    let token = first.token(&body);
    let write = |s: &Signer| fs::write(&file, json!({"keys":[s.jwk()]}).to_string()).unwrap();
    write(&first);
    let verifier = load().unwrap();
    let changes = verifier.snapshot.subscribe();
    verifier.reload().unwrap();
    assert!(!changes.has_changed().unwrap());
    for content in [None, Some(b"{}".as_slice())] {
        match content {
            Some(bytes) => fs::write(&file, bytes).unwrap(),
            None => fs::remove_file(&file).unwrap(),
        }
        assert!(verifier.reload().is_err());
        assert!(!changes.has_changed().unwrap());
        assert!(verifier.verify(&token, NOW).is_ok());
    }
    write(&second);
    verifier.reload().unwrap();
    assert!(changes.has_changed().unwrap());
    assert!(verifier.verify(&second.token(&body), NOW).is_ok());
    assert_eq!(verifier.verify(&token, NOW).err(), Some("token_signature"));
}
