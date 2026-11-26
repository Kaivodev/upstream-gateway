use super::*;
use crate::crypto::{Kms, Vault};
use base64::prelude::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use rustls::{RootCertStore, ServerConfig, pki_types::PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

const KEY: &str = "projects/p_1/locations/global/keyRings/test-ring/cryptoKeys/wrapping";
const AUDIENCE: &str = "//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/test-pool/providers/test-provider";
const IAM_PATH: &str = "/v1/projects/-/serviceAccounts/test-sa@test-project.iam.gserviceaccount.com:generateAccessToken";
const AAD: &[u8] = b"kaivo:upstream-gateway-trade:sealing:v7";

fn random() -> [u8; 32] {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).unwrap();
    bytes
}

// Printable random sentinels let the diagnostics test check raw bytes and wire encodings.
fn sentinel() -> [u8; 32] {
    random().map(|b| b'A' + b % 26)
}

fn account(token_file: &Path) -> Value {
    json!({"type":"external_account", "audience": AUDIENCE, "subject_token_type":"urn:ietf:params:oauth:token-type:jwt",
        "token_url":"https://sts.googleapis.com/v1/token",
        "service_account_impersonation_url": format!("https://iamcredentials.googleapis.com{IAM_PATH}"),
        "credential_source":{"file":token_file}, "other_top_level_field":"ignored"})
}

struct Files {
    dir: tempfile::TempDir,
    config: WrapConfig,
    token_path: PathBuf,
    subject: String,
    cipher: [u8; 32],
}

impl Files {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let token_path = dir.path().join("projected");
        let subject = BASE64_URL_SAFE_NO_PAD.encode(random());
        std::fs::write(&token_path, format!(" \t\x0b{subject}+/=&%\x0c\r\n")).unwrap();
        std::fs::write(dir.path().join("account"), account(&token_path).to_string()).unwrap();
        let path = dir.path().join("gateway.toml");
        // Provisioning works with just this subset of the service configuration.
        std::fs::write(
            &path,
            format!("role='trade'\n[kms]\nkey='{KEY}'\ncredentials_file='account'"),
        )
        .unwrap();
        let config = WrapConfig::read(&path).unwrap();
        Self {
            dir,
            config,
            token_path,
            subject,
            cipher: sentinel(),
        }
    }

    fn install_wrapped(&mut self) {
        let path = self.dir.path().join("wrapped.json");
        std::fs::write(
            &path,
            wrapped::encode(Role::Trade, 7, &self.cipher).unwrap(),
        )
        .unwrap();
        self.config.kms.wrapped_key_file = Some(path);
    }
}

#[test]
fn credential_configuration_pins_destinations_and_source() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("token");
    let template = account(&file);
    let valid = |value: &Value| {
        credentials::ExternalAccount::parse(serde_json::to_vec(value).unwrap().as_slice()).is_some()
    };
    assert!(valid(&template));
    let mut large_metadata = template.clone();
    large_metadata["metadata"] = "x".repeat(LIMIT + 1).into();
    assert!(valid(&large_metadata));
    let mut text = template.clone();
    text["universe_domain"] = "googleapis.com".into();
    text["credential_source"]["format"] = json!({"type":"text"});
    assert!(valid(&text));
    for field in [
        "type",
        "audience",
        "subject_token_type",
        "token_url",
        "service_account_impersonation_url",
        "credential_source",
    ] {
        let mut v = template.clone();
        v.as_object_mut().unwrap().remove(field);
        assert!(!valid(&v), "{field}");
    }
    for (field, values) in [
        ("universe_domain", vec![Value::Null, json!("other.test")]),
        ("type", vec![json!("service_account")]),
        ("subject_token_type", vec![json!("urn:ietf:params:oauth:token-type:id_token")]),
        ("audience", vec![json!(AUDIENCE.replace("123","12a")), json!(AUDIENCE.replace("global","other")),
            json!(AUDIENCE.replace("test-pool","")), json!(format!("{AUDIENCE}/extra")), json!(AUDIENCE.replace("iam.googleapis.com","other.test")), json!(AUDIENCE.replace("test-provider",""))]),
        ("token_url", vec![json!("http://sts.googleapis.com/v1/token"), json!("https://sts.googleapis.com.evil.test/v1/token"),
            json!("https://sts.googleapis.com@other.test/v1/token"), json!("https://sts.googleapis.com/v1/token?extra")]),
        ("service_account_impersonation_url", ["http://iamcredentials.googleapis.com/v1/", "https://other.test/v1/"].map(|prefix| json!(format!("{prefix}projects/-/serviceAccounts/test-sa@test-project.iam.gserviceaccount.com:generateAccessToken"))).to_vec()),
    ] {
        for value in values {
            let mut v = template.clone();
            v[field] = value;
            assert!(!valid(&v), "{field}");
        }
    }
    let url = template["service_account_impersonation_url"]
        .as_str()
        .unwrap();
    for (from, to) in [
        ("projects/-", "projects/123"),
        ("test-sa@", "short@"),
        ("test-sa@", "Test-sa@"),
        ("test-project.", "tiny."),
        ("test-sa@", "test-s-@"),
        ("iam.gserviceaccount.com", "other.test"),
        ("generateAccessToken", "generateAccessToken/"),
    ] {
        let mut v = template.clone();
        v["service_account_impersonation_url"] = url.replace(from, to).into();
        assert!(!valid(&v));
    }
    for source in [
        json!({}),
        json!({"file":"relative"}),
        json!([file]),
        json!({"file":file,"format":null}),
        json!({"file":file,"format":{"type":"json"}}),
        json!({"file":file,"format":{}}),
        json!({"file":file,"format":["text"]}),
        json!({"file":file,"format":{"type":"text","other":0}}),
    ] {
        let mut v = template.clone();
        v["credential_source"] = source;
        assert!(!valid(&v));
    }
    for field in ["url", "executable", "environment_id", "headers", "unknown"] {
        let mut v = template.clone();
        v["credential_source"][field] = json!({});
        assert!(!valid(&v));
    }
}

#[test]
fn wrapped_file_matches_servicekit_and_rejects_ambiguous_inputs() {
    let bytes = wrapped::encode(Role::Trade, 1, &[0xff]).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(
        text,
        "{\"format\":\"kaivo.sealing.v1\",\"service\":\"upstream-gateway-trade\",\"purpose\":\"sealing\",\"current\":1,\"keys\":[{\"version\":1,\"wrapped\":\"/w==\"}]}\n"
    );
    assert_eq!(
        wrapped::parse(&bytes, Role::Trade).unwrap(),
        (1, vec![0xff])
    );
    assert!(wrapped::parse(&bytes, Role::Verification).is_err());
    let verification = wrapped::encode(Role::Verification, i32::MAX, &[42]).unwrap();
    assert_eq!(
        wrapped::parse(&verification, Role::Verification).unwrap(),
        (i32::MAX, vec![42])
    );
    assert_eq!(
        wrapped::aad(Role::Verification, i32::MAX),
        "kaivo:upstream-gateway-verification:sealing:v2147483647"
    );
    for (from, to) in [
        ("\"format\":", "\"format\":\"other\",\"format\":"),
        ("\"current\":1,", ""),
        ("\"current\":1", "\"current\":2"),
        ("\"keys\":", "\"x\":1,\"keys\":"),
        ("v1\"", "v2\""),
        ("sealing\",", "other\","),
        ("\"version\":1", "\"version\":1,\"version\":1"),
        ("\"version\":1", "\"version\":1,\"x\":0"),
        ("\"version\":1,", ""),
        ("\"version\":1", "\"version\":0"),
        ("\"version\":1", "\"version\":2147483648"),
        ("/w==", ""),
        ("/w==", "/w"),
        ("/w==", "/x=="),
        ("/w==", "/w\\r=="),
        ("/w==", "/w==\\n"),
        ("{\"version\":1,\"wrapped\":\"/w==\"}", "[1,\"/w==\"]"),
        ("}]}\n", "}]} {}"),
    ] {
        assert!(
            wrapped::parse(text.replace(from, to).as_bytes(), Role::Trade).is_err(),
            "accepted {from} -> {to}"
        );
    }
    for version in [1, 2] {
        let many = text.replace(
            "}]}",
            &format!("}},{{\"version\":{version},\"wrapped\":\"/w==\"}}]}}"),
        );
        assert!(
            wrapped::parse(many.as_bytes(), Role::Trade)
                .unwrap_err()
                .to_string()
                .contains("exactly one KEK")
        );
    }
    let mut padded = bytes.clone();
    padded.resize(LIMIT, b' ');
    assert!(wrapped::parse(&padded, Role::Trade).is_ok());
    padded.push(b' ');
    assert!(wrapped::parse(&padded, Role::Trade).is_err());
    assert_eq!(keys::checksum(b"123456789"), "3808858755");
}

#[derive(Default)]
struct Capture(Mutex<Vec<Value>>);
impl Events for Capture {
    fn alert(&self, code: &'static str) {
        self.log(&json!(code));
    }
    fn log(&self, event: &Value) {
        self.0.lock().unwrap().push(event.clone());
    }
}

#[derive(Clone, Copy, Default)]
enum Fault {
    #[default]
    None,
    Status(&'static str, u16, usize),
    Oversize,
    Change(&'static str, &'static str, &'static str),
    WrongRoundTrip,
    Disconnect,
}

struct State {
    steps: Vec<&'static str>,
    fault: Fault,
    subject: String,
    sts: String,
    iam: String,
    cipher: [u8; 32],
    plain: [u8; 32],
}

impl State {
    // Check the wire checksum independently of the production lookup table.
    fn crc(bytes: &[u8]) -> String {
        let mut crc = u32::MAX;
        for b in bytes {
            crc ^= *b as u32;
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(crc & 1));
            }
        }
        (!crc).to_string()
    }

    fn reply(
        &mut self,
        head: hyper::http::request::Parts,
        body: &[u8],
        sni: &str,
    ) -> Response<Full<Bytes>> {
        assert_eq!(head.method, "POST");
        let path = head.uri.path_and_query().unwrap().as_str();
        let step = match (sni, path) {
            (credentials::STS, "/v1/token") => "sts",
            (credentials::IAM, IAM_PATH) => "impersonation",
            (keys::KMS, p) if p == format!("/v1/{KEY}:decrypt") => "decrypt",
            (keys::KMS, p) if p == format!("/v1/{KEY}:encrypt") => "encrypt",
            _ => panic!("unexpected Google API target"),
        };
        assert_eq!(head.headers["host"], sni);
        self.steps.push(step);
        let mut response = match step {
            "sts" => {
                assert!(head.headers.get("authorization").is_none());
                assert_eq!(
                    head.headers["content-type"],
                    "application/x-www-form-urlencoded"
                );
                let audience = AUDIENCE.replace('/', "%2F");
                let expected = format!(
                    "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&audience={audience}&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&subject_token={}{}&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt",
                    self.subject, "%2B%2F%3D%26%25"
                );
                assert!(body == expected.as_bytes());
                json!({"access_token":self.sts})
            }
            "impersonation" => {
                assert!(head.headers["authorization"] == format!("Bearer {}", self.sts));
                assert_eq!(head.headers["content-type"], "application/json");
                assert_eq!(
                    serde_json::from_slice::<Value>(body).unwrap(),
                    json!({"scope":["https://www.googleapis.com/auth/cloudkms"],"lifetime":"600s"})
                );
                json!({"accessToken":self.iam})
            }
            op => {
                assert!(head.headers["authorization"] == format!("Bearer {}", self.iam));
                assert_eq!(head.headers["content-type"], "application/json");
                let body: Value = serde_json::from_slice(body).unwrap();
                let field = if op == "encrypt" {
                    "plaintext"
                } else {
                    "ciphertext"
                };
                assert_eq!(body.as_object().unwrap().len(), 4);
                assert!(body["additionalAuthenticatedData"] == BASE64_STANDARD.encode(AAD));
                assert!(body["additionalAuthenticatedDataCrc32c"] == Self::crc(AAD));
                let payload = BASE64_STANDARD
                    .decode(body[field].as_str().unwrap())
                    .unwrap();
                assert!(body[format!("{field}Crc32c")] == Self::crc(&payload));
                if op == "encrypt" {
                    self.plain.copy_from_slice(&payload);
                    json!({"name":format!("{KEY}/cryptoKeyVersions/21"),"ciphertext":BASE64_STANDARD.encode(self.cipher),
                        "ciphertextCrc32c":Self::crc(&self.cipher),"verifiedPlaintextCrc32c":true,"verifiedAdditionalAuthenticatedDataCrc32c":true})
                } else {
                    assert!(payload == self.cipher);
                    let plain = if matches!(self.fault, Fault::WrongRoundTrip) {
                        random()
                    } else {
                        self.plain
                    };
                    json!({"plaintext":BASE64_STANDARD.encode(plain),"plaintextCrc32c":Self::crc(&plain)})
                }
            }
        };
        match self.fault {
            Fault::Status(target, status, n)
                if target == step && self.steps.iter().filter(|s| **s == step).count() <= n =>
            {
                // Even an error body reflecting every credential must stay out of diagnostics.
                response = json!([
                    self.subject,
                    self.sts,
                    self.iam,
                    BASE64_STANDARD.encode(self.plain),
                    BASE64_STANDARD.encode(self.cipher),
                    BASE64_STANDARD.encode(AAD)
                ]);
                return Response::builder()
                    .status(status)
                    .header("location", "/redirect")
                    .body(Full::new(response.to_string().into()))
                    .unwrap();
            }
            Fault::Oversize if step == "sts" => {
                let mut bytes = response.to_string().into_bytes();
                bytes.resize(LIMIT + 1, b' ');
                return Response::builder()
                    .header("transfer-encoding", "chunked")
                    .body(Full::new(bytes.into()))
                    .unwrap();
            }
            Fault::Change(target, field, value) if target == step => {
                if value == "missing" {
                    response.as_object_mut().unwrap().remove(field);
                } else if field == "plaintext" {
                    response[field] = BASE64_STANDARD.encode(value).into();
                    response["plaintextCrc32c"] = Self::crc(value.as_bytes()).into();
                } else {
                    response[field] = value.into();
                }
            }
            _ => {}
        }
        Response::new(Full::new(response.to_string().into()))
    }
}

struct Fake {
    http: Http,
    state: Arc<Mutex<State>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fake {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Fake {
    async fn new(files: &Files, proxy: bool, fault: Fault) -> Self {
        let hosts = [credentials::STS, credentials::IAM, keys::KMS].map(String::from);
        let cert = rcgen::generate_simple_self_signed(hosts.to_vec()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let server =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.cert.der().clone()],
                    PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
                )
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            steps: Vec::new(),
            fault,
            subject: files.subject.clone(),
            sts: BASE64_URL_SAFE_NO_PAD.encode(random()),
            iam: BASE64_URL_SAFE_NO_PAD.encode(random()),
            cipher: files.cipher,
            plain: sentinel(),
        }));
        let server_state = state.clone();
        let task = tokio::spawn(async move {
            let mut first = true;
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                if first && matches!(fault, Fault::Disconnect) {
                    first = false;
                    continue;
                }
                let mut tunnel = None;
                if proxy {
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        assert!(head.len() < 4096);
                        head.push(stream.read_u8().await.unwrap());
                    }
                    tunnel = Some(String::from_utf8(head).unwrap());
                    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                }
                let stream = acceptor.accept(stream).await.unwrap();
                let host = stream.get_ref().1.server_name().unwrap().to_owned();
                if let Some(head) = tunnel {
                    assert_eq!(
                        head.lines().next().unwrap(),
                        format!("CONNECT {host}:443 HTTP/1.1")
                    );
                }
                let state = server_state.clone();
                let handler = service_fn(|req: Request<Incoming>| async {
                    let (parts, body) = req.into_parts();
                    let body = body.collect().await.unwrap().to_bytes();
                    Ok::<_, Infallible>(state.lock().unwrap().reply(parts, &body, &host))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), handler)
                    .await;
            }
        });
        let proxy =
            proxy.then(|| ProxyAddress::try_from(format!("localhost:{}", addr.port())).unwrap());
        Self {
            http: Http::local(proxy, roots, addr),
            state,
            task,
        }
    }
}

#[tokio::test]
async fn startup_unwraps_once_and_vault_uses_the_key_in_memory() {
    let mut files = Files::new();
    files.install_wrapped();
    for (proxy, fault) in [
        (false, Fault::Disconnect),
        (true, Fault::Status("sts", 503, 1)),
    ] {
        let fake = Fake::new(&files, proxy, fault).await;
        let events = Capture::default();
        let kms = load(&files.config.kms, Role::Trade, &fake.http, &events)
            .await
            .unwrap();
        assert!(!kms.development_only());
        let vault = Vault(Arc::new(kms));
        let ciphertext = vault.seal(b"record", b"context").unwrap();
        assert!(vault.open(&ciphertext, b"context").unwrap().as_slice() == b"record");
        let expected = if proxy {
            vec!["sts", "sts", "impersonation", "decrypt"]
        } else {
            vec!["sts", "impersonation", "decrypt"]
        };
        assert_eq!(fake.state.lock().unwrap().steps, expected);
        assert!(events.0.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn wrap_kek_verifies_round_trip_before_writing_stdout() {
    let files = Files::new();
    let cases = [
        Fault::None,
        Fault::Change("encrypt", "verifiedPlaintextCrc32c", "missing"),
        Fault::Change(
            "encrypt",
            "verifiedAdditionalAuthenticatedDataCrc32c",
            "missing",
        ),
        Fault::Change("encrypt", "ciphertext", ""),
        Fault::Change("encrypt", "ciphertextCrc32c", "invalid"),
        Fault::Change("encrypt", "name", "projects/other/cryptoKeyVersions/1"),
        Fault::Change(
            "encrypt",
            "name",
            concat!(
                "projects/p_1/locations/global/keyRings/test-ring/cryptoKeys/wrapping",
                "/cryptoKeyVersions/1x"
            ),
        ),
        Fault::WrongRoundTrip,
    ];
    for fault in cases {
        let fake = Fake::new(&files, false, fault).await;
        let mut stdout = Vec::new();
        let events = Capture::default();
        let result = files
            .config
            .write(7, &fake.http, &events, &mut stdout)
            .await;
        if matches!(fault, Fault::None) {
            result.unwrap();
            let expected = format!(
                "{{\"format\":\"kaivo.sealing.v1\",\"service\":\"upstream-gateway-trade\",\"purpose\":\"sealing\",\"current\":7,\"keys\":[{{\"version\":7,\"wrapped\":\"{}\"}}]}}\n",
                BASE64_STANDARD.encode(files.cipher)
            );
            assert!(stdout == expected.as_bytes());
            assert_eq!(
                fake.state.lock().unwrap().steps,
                ["sts", "impersonation", "encrypt", "decrypt"]
            );
        } else {
            assert!(result.is_err() && stdout.is_empty());
        }
    }
}

#[tokio::test]
async fn failures_report_only_step_and_status_and_bound_retries() {
    let mut files = Files::new();
    files.install_wrapped();
    for (fault, step, status, calls) in [
        (Fault::Status("sts", 403, 4), "sts", 403, 1),
        (
            Fault::Status("impersonation", 302, 4),
            "impersonation",
            302,
            2,
        ),
        (Fault::Status("decrypt", 503, 4), "decrypt", 503, 6),
        (Fault::Status("decrypt", 403, 1), "decrypt", 403, 3),
        (Fault::Oversize, "sts", 200, 1),
        (
            Fault::Change("decrypt", "plaintextCrc32c", "invalid"),
            "decrypt",
            200,
            3,
        ),
        (
            Fault::Change("decrypt", "plaintext", "short"),
            "decrypt",
            200,
            3,
        ),
    ] {
        let fake = Fake::new(&files, false, fault).await;
        let events = Capture::default();
        let err = load(&files.config.kms, Role::Trade, &fake.http, &events)
            .await
            .err()
            .unwrap();
        let diagnostics = format!("{err:#?} {:?}", events.0.lock().unwrap());
        let state = fake.state.lock().unwrap();
        for value in [
            &state.subject,
            &state.sts,
            &state.iam,
            &BASE64_STANDARD.encode(state.plain),
            &BASE64_STANDARD.encode(state.cipher),
            &BASE64_STANDARD.encode(AAD),
            &String::from_utf8_lossy(AAD).into_owned(),
            &String::from_utf8_lossy(&state.cipher).into_owned(),
            &String::from_utf8_lossy(&state.plain).into_owned(),
        ] {
            assert!(
                !diagnostics.contains(value),
                "sensitive value in diagnostics"
            );
        }
        assert_eq!(state.steps.len(), calls);
        assert_eq!(
            err.to_string(),
            format!("kms_unwrap_failed step={step} status={status}")
        );
        assert_eq!(
            *events.0.lock().unwrap(),
            [json!({"event":"kms_unwrap_failed","step":step,"status":status})]
        );
    }
}

#[tokio::test]
async fn invalid_subject_token_never_reaches_sts() {
    let mut files = Files::new();
    files.install_wrapped();
    let fake = Fake::new(&files, false, Fault::None).await;
    for bytes in [
        vec![],
        b" \r\n".to_vec(),
        b"abc\nxyz".to_vec(),
        vec![0x80],
        vec![0x7f],
        vec![b'x'; LIMIT + 1],
    ] {
        std::fs::write(&files.token_path, bytes).unwrap();
        assert!(
            load(
                &files.config.kms,
                Role::Trade,
                &fake.http,
                &Capture::default()
            )
            .await
            .is_err()
        );
    }
    std::fs::remove_file(&files.token_path).unwrap();
    std::fs::create_dir(&files.token_path).unwrap();
    assert!(
        load(
            &files.config.kms,
            Role::Trade,
            &fake.http,
            &Capture::default()
        )
        .await
        .is_err()
    );
    assert!(fake.state.lock().unwrap().steps.is_empty());
}
