//! Deterministic offline replay. Only credential resolution and signature generation
//! are replaceable. Requests, recorded config, clock and entropy are owned here.
use crate::{
    engine::{Host, Loaded, Options},
    environment::{Cancellation, Environment, Incoming, Transport},
    execute::{Execution, headers_from, headers_value, request_value},
    http, json,
    package::{Manifest, Package, digest, hex},
    types::HttpRequest,
};
use anyhow::{Context, Result, bail, ensure};
use base64::prelude::*;
use kaivo_upstream_sdk::{form, time};
use rsa::{Pkcs1v15Sign, PrivateKey, PublicKey};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
    sync::{Arc, Mutex},
    time::Instant,
};
use zeroize::Zeroizing;
mod query;
pub use crate::state::Scanner;
pub use query::SignedQuery;

pub const MARK: &str = "TEST_SIGNATURE_REGENERATED_AT_REPLAY";
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    method: String,
    url: String,
    headers: BTreeMap<String, Vec<String>>,
    body: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    status: u16,
    headers: BTreeMap<String, Vec<String>>,
    body: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    request: WireRequest,
    response: Option<WireResponse>,
    error: Option<String>,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub name: String,
    pub source: String,
    pub operation: String,
    pub input: Value,
    pub config: BTreeMap<String, String>,
    time: String,
    random_seed: String,
    #[serde(default)]
    test_only_resign_callback: bool,
    exchanges: Vec<Exchange>,
    expected: Execution,
}
fn validate_expected_result(r: &Value, op: &str, category: &str) -> Result<()> {
    use crate::execute::only;
    ensure!(
        r.get("code")
            .is_none_or(|c| c.as_str().is_some_and(|s| s.len() <= 128)),
        "invalid expected result code"
    );
    if category == "rejected" {
        ensure!(
            only(r, &["outcome", "code"])
                && r["outcome"] == "rejected"
                && r["code"].as_str().is_some_and(|s| !s.is_empty()),
            "invalid expected rejection"
        );
        return Ok(());
    }
    let (kind, fields): (&str, &[&str]) = match op {
        "route_callback" => ("route", &["order_id"]),
        "verify_callback" => (
            "callback",
            &[
                "event_id",
                "order_id",
                "upstream_id",
                "money",
                "status",
                "ack",
            ],
        ),
        "query_refund" | "refund" => (
            "refund",
            &[
                "order_id",
                "refund_id",
                "upstream_refund_id",
                "money",
                "status",
            ],
        ),
        _ => (
            "payment",
            &[
                "order_id",
                "upstream_id",
                "money",
                "status",
                "url",
                "qrcode",
                "expires_at",
                "paid_at",
            ],
        ),
    };
    ensure!(
        category == "completed"
            && r["outcome"] == "completed"
            && only(r, &["outcome", "code", kind])
            && only(&r[kind], fields),
        "invalid expected completion"
    );
    let out = r[kind].as_object().unwrap();
    for (k, v) in out {
        match k.as_str() {
            "money" => ensure!(
                only(v, &["amount", "currency"])
                    && v["amount"].is_string()
                    && v["currency"].is_string(),
                "invalid expected money"
            ),
            "ack" => {
                let a: WireResponse = serde_json::from_value(v.clone())?;
                BASE64_STANDARD.decode(a.body)?;
            }
            _ => ensure!(v.is_string(), "invalid expected field"),
        }
    }
    Ok(())
}
impl Fixture {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let f: Self = json::decode(raw)?;
        ensure!(
            f.input.is_object()
                && !f.source.is_empty()
                && f.time.ends_with('Z')
                && time::parse(&f.time).is_some()
                && BASE64_STANDARD.decode(&f.random_seed)?.len() == 32,
            "invalid fixture"
        );
        crate::execute::input_schema(&f.operation, &f.input).map_err(anyhow::Error::msg)?;
        if let Some(r) = &f.expected.result {
            validate_expected_result(r, &f.operation, &f.expected.category)?;
        }
        for x in &f.exchanges {
            BASE64_STANDARD.decode(&x.request.body)?;
            match (&x.response, x.error.as_deref()) {
                (Some(r), None) => {
                    BASE64_STANDARD.decode(&r.body)?;
                }
                (None, Some("timeout" | "transport_error")) => {}
                _ => bail!("invalid recorded exchange"),
            }
        }
        let scenario = f
            .name
            .strip_prefix(&format!("{}/", f.operation))
            .context("invalid fixture name")?;
        let e = &f.expected;
        let callback = f.operation.ends_with("callback");
        ensure!(
            !callback || (e.requests == 0 && e.responses == 0),
            "callback exchange"
        );
        ensure!(
            match scenario {
                "success" => e.category == "completed" && e.result.is_some(),
                "malformed" => f.operation == "route_callback" && e.category == "not_sent",
                "signature_error" if f.operation == "verify_callback" => e.category == "not_sent",
                "rejected" | "signature_error" =>
                    !callback && e.category == "rejected" && e.responses > 0,
                "timeout" => !callback && e.category == "unknown" && e.requests > 0,
                "amount_mismatch" =>
                    f.operation != "route_callback"
                        && e.error_code.as_deref() == Some("amount_mismatch")
                        && e.category == if callback { "not_sent" } else { "unknown" },
                _ => false,
            },
            "invalid scenario expectation"
        );
        Ok(f)
    }
}
pub struct SeedStream {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    index: usize,
}
impl SeedStream {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            counter: 0,
            block: [0; 32],
            index: 32,
        }
    }
    pub fn fill(&mut self, b: &mut [u8]) {
        for out in b {
            if self.index == 32 {
                self.block = Sha256::new()
                    .chain_update(self.seed)
                    .chain_update(self.counter.to_be_bytes())
                    .finalize()
                    .into();
                self.counter += 1;
                self.index = 0
            }
            *out = self.block[self.index];
            self.index += 1
        }
    }
}
pub trait TestCredentials: Send + Sync {
    fn shared(&self, name: &str) -> Result<Zeroizing<Vec<u8>>>;
    fn private(&self, _name: &str) -> Option<Arc<PrivateKey>> {
        None
    }
    fn public(&self, _name: &str) -> Result<PublicKey> {
        bail!("test public key unavailable")
    }
    fn callback_signature(&self, _media: &str, _signing_bytes: &[u8]) -> Result<String> {
        bail!("callback re-signer unavailable")
    }
}
pub struct Ephemeral {
    shared: BTreeMap<String, Zeroizing<Vec<u8>>>,
    private: BTreeMap<String, Arc<PrivateKey>>,
    callback: Option<PrivateKey>,
}
impl Ephemeral {
    pub fn new(m: &Manifest) -> Result<Self> {
        let mut shared = BTreeMap::new();
        let mut private = BTreeMap::new();
        for (n, t) in &m.secrets {
            if t == "shared" {
                let mut b = Zeroizing::new([0; 32]);
                getrandom::fill(&mut *b).map_err(|_| anyhow::anyhow!("entropy unavailable"))?;
                shared.insert(n.clone(), Zeroizing::new(hex(b.as_slice()).into_bytes()));
            } else {
                private.insert(
                    n.clone(),
                    Arc::new(PrivateKey::new(&mut getrandom::SysRng, 2048)?),
                );
            }
        }
        let callback = if m.public_keys.is_empty() {
            None
        } else {
            Some(PrivateKey::new(&mut getrandom::SysRng, 2048)?)
        };
        Ok(Self {
            shared,
            private,
            callback,
        })
    }
}
impl TestCredentials for Ephemeral {
    fn shared(&self, n: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.shared
            .get(n)
            .cloned()
            .context("unknown shared credential")
    }
    fn private(&self, n: &str) -> Option<Arc<PrivateKey>> {
        self.private.get(n).cloned()
    }
    fn public(&self, _: &str) -> Result<PublicKey> {
        Ok(self
            .callback
            .as_ref()
            .context("unknown test public key")?
            .to_public_key())
    }
    fn callback_signature(&self, media: &str, b: &[u8]) -> Result<String> {
        if media == "application/json" {
            Ok(BASE64_STANDARD.encode(
                self.callback
                    .as_ref()
                    .context("missing signer")?
                    .sign_with_rng(
                        &mut getrandom::SysRng,
                        Pkcs1v15Sign::new::<Sha256>(),
                        &Sha256::digest(b),
                    )?,
            ))
        } else {
            Ok(hex(&md5::Md5::new()
                .chain_update(b)
                .chain_update(b"&key=")
                .chain_update(&*self.shared("shared")?)
                .finalize()))
        }
    }
}
fn resign(
    f: &mut Fixture,
    manifest: &Manifest,
    keys: &dyn TestCredentials,
    protected: &mut crate::state::Scanner,
) -> Result<()> {
    if !f.test_only_resign_callback {
        return Ok(());
    }
    ensure!(
        f.operation == "verify_callback",
        "invalid re-sign operation"
    );
    let mut h = headers_from(&f.input["headers"]).context("invalid callback headers")?;
    let b = BASE64_STANDARD.decode(f.input["body"].as_str().context("missing callback body")?)?;
    if b.is_empty()
        && !h
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("Content-Type"))
        && let Some(encoded) = f.input["raw_query"].as_str().filter(|s| !s.is_empty())
    {
        let raw = BASE64_STANDARD.decode(encoded)?;
        let query = SignedQuery::parse(&raw)?;
        let mut shared = manifest
            .secrets
            .iter()
            .filter(|(_, kind)| *kind == "shared");
        let (name, _) = shared.next().context("invalid re-sign credentials")?;
        ensure!(shared.next().is_none(), "invalid re-sign credentials");
        let mut md5 = md5::Md5::new();
        let mut first = true;
        for (key, value) in &query.fields {
            if value.is_empty() || matches!(key.as_slice(), b"sign" | b"sign_type") {
                continue;
            }
            if !first {
                md5.update(b"&");
            }
            first = false;
            md5.update(key);
            md5.update(b"=");
            md5.update(value);
        }
        let sig = hex(&md5.chain_update(&*keys.shared(name)?).finalize());
        protected.add(sig.as_bytes());
        f.input["raw_query"] = json!(BASE64_STANDARD.encode(query.replace_signature(&sig)));
        return Ok(());
    }
    let ct = http::values(&h, "Content-Type")
        .first()
        .context("missing media")?;
    if ct == "application/json" {
        let sig = keys.callback_signature(ct, &b)?;
        protected.add(sig.as_bytes());
        h.retain(|(k, _)| !k.eq_ignore_ascii_case("X-Signature"));
        h.push(("X-Signature".into(), vec![sig]));
        f.input["headers"] = headers_value(&h)
    } else {
        let mut v = form::parse(&b).context("invalid form")?;
        let canonical = form::canonical(&v).context("invalid callback fields")?;
        let sig = keys.callback_signature(ct, canonical.as_bytes())?;
        protected.add(sig.as_bytes());
        form::set(&mut v, "sign", &sig);
        f.input["body"] = json!(BASE64_STANDARD.encode(form::encode(&v)))
    }
    Ok(())
}
pub fn normalized(r: &HttpRequest) -> Value {
    let mut r = r.clone();
    for (n, v) in &mut r.headers {
        if n.eq_ignore_ascii_case("X-Signature") {
            *v = vec![MARK.into()]
        }
    }
    if http::values(&r.headers, "Content-Type")
        .first()
        .is_some_and(|s| s.starts_with("application/x-www-form-urlencoded"))
        && let Some(mut v) = form::parse(&r.body)
        && v.contains_key(b"sign".as_slice())
    {
        form::set(&mut v, "sign", MARK);
        r.body = form::encode(&v).into_bytes()
    }
    request_value(&r)
}
struct Recorded {
    m: Arc<Manifest>,
    f: Fixture,
    keys: Arc<dyn TestCredentials>,
    random: Mutex<SeedStream>,
    clock: time::Timestamp,
    position: Mutex<(usize, bool)>,
    signatures: Mutex<crate::state::Scanner>,
}
impl Environment for Recorded {
    fn observe_signature(&self, sig: &str) {
        self.signatures.lock().unwrap().add(sig.as_bytes())
    }
    fn config(&self, _: &Cancellation) -> BTreeMap<String, String> {
        self.f.config.clone()
    }
    fn secret(&self, n: &str, _: &Cancellation) -> Result<Zeroizing<Vec<u8>>> {
        self.keys.shared(n)
    }
    fn private_key(&self, n: &str, _: &Cancellation) -> Option<Arc<PrivateKey>> {
        self.keys.private(n)
    }
    fn public_key(&self, n: &str, _: Instant, _: &Cancellation) -> Result<PublicKey> {
        self.keys.public(n)
    }
    fn now(&self, _: Instant, _: &Cancellation) -> Result<time::Timestamp> {
        Ok(self.clock)
    }
    fn random(&self, b: &mut [u8], _: Instant, _: &Cancellation) -> Result<()> {
        self.random.lock().unwrap().fill(b);
        Ok(())
    }
    fn transport(&self) -> Option<&dyn Transport> {
        Some(self)
    }
}
impl Transport for Recorded {
    fn send(
        &self,
        _: &HttpRequest,
        r: &HttpRequest,
        _: Instant,
        _: &Cancellation,
    ) -> Result<Incoming> {
        let mut pos = self.position.lock().unwrap();
        let i = pos.0;
        pos.0 += 1;
        let Some(x) = self.f.exchanges.get(i) else {
            pos.1 = true;
            bail!("unexpected request")
        };
        let h = x.request.headers.clone().into_iter().collect();
        let h = http::expand(&self.m, &h, |n| {
            String::from_utf8(self.keys.shared(n).ok()?.to_vec()).ok()
        });
        let Ok(h) = h else {
            pos.1 = true;
            bail!("invalid recorded headers")
        };
        let expected = json!({"method":x.request.method,"url":x.request.url,"headers":headers_value(&h),"body":x.request.body});
        if normalized(r) != expected {
            pos.1 = true;
            bail!("recorded request mismatch")
        }
        let v = x.response.as_ref().context("recorded transport failure")?;
        Ok(Incoming {
            status: v.status,
            headers: v.headers.clone().into_iter().collect(),
            body: Box::new(Cursor::new(BASE64_STANDARD.decode(&v.body)?)),
        })
    }
}
pub fn required_scenarios(op: &str) -> &'static [&'static str] {
    match op {
        // Some create APIs, including EPay mapi, return no amount to compare.
        "create_payment" => &["success", "rejected", "signature_error", "timeout"],
        "route_callback" => &["success", "malformed"],
        "verify_callback" => &["success", "signature_error", "amount_mismatch"],
        _ => &[
            "success",
            "rejected",
            "signature_error",
            "timeout",
            "amount_mismatch",
        ],
    }
}
pub struct Replay {
    host: Host,
    loaded: Arc<Loaded>,
    cases: BTreeMap<String, (String, Fixture)>,
}
impl Replay {
    pub fn new(p: &Package) -> Result<Self> {
        Self::with_limits(p, Options::replay(&p.manifest.r#type))
    }
    pub fn for_calibration(p: &Package) -> Result<Self> {
        Self::new(p)
    }
    pub fn for_concurrency(p: &Package, threads: u32) -> Result<Self> {
        ensure!((1..=1024).contains(&threads), "invalid replay concurrency");
        let mut options = Options::replay(&p.manifest.r#type);
        options.pool_slots = threads.min(options.pool_slots);
        Self::with_limits(p, options)
    }
    fn with_limits(p: &Package, options: Options) -> Result<Self> {
        p.validate_fixtures()?;
        let host = Host::new(options)?;
        let loaded = host.load(p)?;
        let mut cases = BTreeMap::new();
        let mut coverage = BTreeSet::new();
        for (path, b) in &p.fixtures {
            let f = Fixture::decode(b)?;
            ensure!(
                p.manifest.capabilities.contains(&f.operation) && coverage.insert(f.name.clone()),
                "duplicate or undeclared fixture"
            );
            cases.insert(path.clone(), (digest(b), f));
        }
        for op in &p.manifest.capabilities {
            for s in required_scenarios(op) {
                ensure!(
                    coverage.contains(&format!("{op}/{s}")),
                    "missing required case {op}/{s}"
                )
            }
        }
        Ok(Self {
            host,
            loaded,
            cases,
        })
    }
    fn case(&self, mut f: Fixture, keys: Arc<dyn TestCredentials>) -> Result<(Execution, bool)> {
        let mut protected = crate::state::Scanner::default();
        resign(&mut f, self.loaded.manifest(), &*keys, &mut protected)?;
        let random = Mutex::new(SeedStream::new(
            BASE64_STANDARD
                .decode(&f.random_seed)?
                .try_into()
                .ok()
                .context("invalid seed")?,
        ));
        let clock = time::parse(&f.time).context("invalid timestamp")?;
        let env = Arc::new(Recorded {
            m: self.loaded.manifest.clone(),
            f,
            keys,
            random,
            clock,
            position: Mutex::default(),
            signatures: Mutex::new(protected),
        });
        let actual = self.host.execute(
            &self.loaded,
            &env.f.operation,
            &serde_json::to_vec(&env.f.input)?,
            env.clone(),
            Default::default(),
        );
        ensure!(
            !env.signatures.lock().unwrap().value(&json!(actual)),
            "execution contains a regenerated signature"
        );
        let pos = *env.position.lock().unwrap();
        let passed =
            json!(actual) == json!(env.f.expected) && !pos.1 && pos.0 == env.f.exchanges.len();
        Ok((actual, passed))
    }
    pub fn run(&self) -> Result<Value> {
        self.with_keys(Arc::new(Ephemeral::new(self.loaded.manifest())?))
    }
    pub fn with_keys(&self, keys: Arc<dyn TestCredentials>) -> Result<Value> {
        let mut cases = Vec::new();
        let mut passed = true;
        for (path, (hash, f)) in &self.cases {
            let (actual, ok) = self.case(f.clone(), keys.clone())?;
            passed &= ok;
            cases.push(json!({"path":path,"fixture_sha256":hash,"passed":ok,"actual":actual}))
        }
        Ok(json!({"version":3,"package_sha256":self.loaded.digest,"passed":passed,"cases":cases}))
    }
    pub fn measure(&self, name: &str) -> Result<Execution> {
        let f = &self
            .cases
            .values()
            .find(|(_, f)| f.name == name)
            .context("fixture not found")?
            .1;
        let (e, ok) = self.case(f.clone(), Arc::new(Ephemeral::new(self.loaded.manifest())?))?;
        ensure!(ok, "measurement fixture failed");
        Ok(e)
    }
}
mod calibration;
pub use calibration::{Calibration, OperationMaxima, Peak};

#[cfg(test)]
mod tests {
    use super::*;
    struct VectorKey;
    impl TestCredentials for VectorKey {
        fn shared(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
            ensure!(name == "merchant_key", "unexpected credential");
            Ok(Zeroizing::new(b"vector-secret".to_vec()))
        }
    }

    fn query_fixture(query: &[u8]) -> Fixture {
        let mut f = Fixture::decode(include_bytes!(
            "../../../guest/plugins/sim_form_md5/fixtures/verify_callback_success.json"
        ))
        .unwrap();
        f.input["body"] = json!("");
        f.input["headers"] = json!({});
        f.input["raw_query"] = json!(BASE64_STANDARD.encode(query));
        f
    }

    #[test]
    fn query_resigning_preserves_wire_bytes_and_protects_the_signature() {
        let mut m: Manifest = serde_json::from_value(crate::tests::manifest()).unwrap();
        m.secrets = BTreeMap::from([("merchant_key".into(), "shared".into())]);
        let mut f =
            query_fixture(b"name=%E8%8C%B6+shop&%73ign=old&sign_type=MD5&empty=&Z=a%2Fb&_key=0");
        let mut protected = Scanner::default();
        resign(&mut f, &m, &VectorKey, &mut protected).unwrap();
        let raw = BASE64_STANDARD
            .decode(f.input["raw_query"].as_str().unwrap())
            .unwrap();
        assert_eq!(raw, b"name=%E8%8C%B6+shop&%73ign=57ca3bd3c13fae53be240e4de17a1b9e&sign_type=MD5&empty=&Z=a%2Fb&_key=0");
        assert!(protected.bytes(b"57ca3bd3c13fae53be240e4de17a1b9e"));
        for invalid in [
            "x=1",
            "sign=a&%73ign=b",
            "=x&sign=x",
            "x=%&sign=x",
            "x=%ag&sign=x",
            "sign=x&k&%6b=y",
        ] {
            assert!(
                resign(
                    &mut query_fixture(invalid.as_bytes()),
                    &m,
                    &VectorKey,
                    &mut protected
                )
                .is_err()
            );
        }
        m.secrets.insert("second".into(), "shared".into());
        for secrets in [m.secrets.clone(), BTreeMap::new()] {
            m.secrets = secrets;
            assert_eq!(
                resign(&mut f, &m, &VectorKey, &mut protected)
                    .unwrap_err()
                    .to_string(),
                "invalid re-sign credentials"
            );
        }
    }
    #[test]
    fn signature_normalization_preserves_recorded_values_and_raw_json() {
        let mut r = HttpRequest {
            method: "POST".into(),
            url: "https://example.test".into(),
            headers: vec![
                ("Content-Type".into(), vec!["application/json".into()]),
                ("X-Signature".into(), vec!["temporary".into()]),
                ("X-Order".into(), vec!["two".into(), "one".into()]),
            ],
            body: br#"{ "k": 1 }"#.to_vec(),
        };
        let v = normalized(&r);
        assert_eq!(v["headers"]["X-Signature"], json!([MARK]));
        assert_eq!(v["body"], BASE64_STANDARD.encode(&r.body));
        assert_eq!(v["headers"]["X-Order"], json!(["two", "one"]));
        r.headers[0].1[0] = "application/x-www-form-urlencoded".into();
        r.body = b"z=%20&a=1&a=2&sign=temporary".to_vec();
        assert_eq!(
            BASE64_STANDARD
                .decode(normalized(&r)["body"].as_str().unwrap())
                .unwrap(),
            format!("a=1&a=2&sign={MARK}&z=+").as_bytes()
        );
    }
}
