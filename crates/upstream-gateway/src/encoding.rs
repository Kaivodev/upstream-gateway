use crate::api::*;
use prost_types::Timestamp;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use upstream_host::{environment::CapturedResponse, types::HttpRequest};

pub(crate) fn hash(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

#[derive(Default)]
pub(crate) struct Encoder(pub Vec<u8>);
impl Encoder {
    pub fn u32(&mut self, n: u32) {
        self.0.extend(n.to_be_bytes())
    }
    pub fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len().try_into().unwrap());
        self.0.extend(v)
    }
    pub fn string(&mut self, v: &str) {
        self.bytes(v.as_bytes())
    }
    pub fn optional<T>(&mut self, value: Option<T>, put: impl FnOnce(&mut Self, T)) {
        self.0.push(u8::from(value.is_some()));
        if let Some(v) = value {
            put(self, v)
        }
    }
    pub fn headers<'a>(&mut self, pairs: impl Iterator<Item = (String, Vec<&'a [u8]>)>) {
        let mut sorted = BTreeMap::<String, Vec<&[u8]>>::new();
        for (name, values) in pairs {
            sorted
                .entry(name.to_ascii_lowercase())
                .or_default()
                .extend(values);
        }
        self.u32(sorted.len() as u32);
        for (name, values) in sorted {
            self.string(&name);
            self.u32(values.len() as u32);
            for v in values {
                self.bytes(v)
            }
        }
    }
    fn api_headers(&mut self, headers: &[HttpHeader]) {
        self.headers(headers.iter().map(|h| {
            (
                h.name.clone(),
                h.values.iter().map(String::as_bytes).collect(),
            )
        }))
    }
    fn timestamp(&mut self, t: &Timestamp) {
        self.0.extend(t.seconds.to_be_bytes());
        self.u32(t.nanos as u32)
    }
    pub fn context(&mut self, v: &OperationContext) {
        self.string(&v.idempotency_key);
        self.bytes(&v.package_sha256);
        self.string(&v.channel_account_id);
        self.optional(v.verification_account_id.as_deref(), Self::string);
        self.0.extend(v.control_version.to_be_bytes());
        self.bytes(&v.config_json);
        self.string(&v.credentials_ref);
        self.bytes(&v.credentials_sha256);
    }
    pub fn money(&mut self, v: &Money) {
        self.string(&v.amount);
        self.string(&v.currency)
    }
    pub fn callback(&mut self, v: &CallbackPayload) {
        self.string(&v.method);
        self.bytes(&v.raw_query);
        self.api_headers(&v.headers);
        self.bytes(&v.body);
        self.optional(v.source_ip.as_deref(), Self::string);
    }
    pub fn payment(&mut self, v: &PaymentOutput) {
        self.string(&v.order_id);
        self.string(&v.upstream_id);
        self.money(v.money.as_ref().unwrap());
        self.u32(v.status as u32);
        self.optional(v.url.as_deref(), Self::string);
        self.optional(v.qrcode.as_deref(), Self::string);
        self.optional(v.paid_at.as_ref(), Self::timestamp);
        self.optional(v.expires_at.as_ref(), Self::timestamp);
    }
    pub fn refund(&mut self, v: &RefundOutput) {
        self.string(&v.order_id);
        self.string(&v.refund_id);
        self.string(&v.upstream_refund_id);
        self.money(v.money.as_ref().unwrap());
        self.u32(v.status as u32)
    }
    pub fn verified(&mut self, v: &CallbackOutput) {
        self.string(&v.event_id);
        self.string(&v.order_id);
        self.string(&v.upstream_id);
        self.money(v.money.as_ref().unwrap());
        self.u32(v.status as u32);
        let ack = v.ack.as_ref().unwrap();
        self.u32(ack.status);
        self.api_headers(&ack.headers);
        self.bytes(&ack.body);
    }
    pub fn package(&mut self, v: &PluginPackage) {
        self.bytes(&v.manifest_json);
        self.bytes(&v.plugin_wasm);
        let mut fixtures: Vec<_> = v.fixtures.iter().collect();
        fixtures.sort_by(|a, b| a.path.cmp(&b.path));
        self.u32(fixtures.len() as u32);
        for f in fixtures {
            self.string(&f.path);
            self.bytes(&f.content)
        }
        self.bytes(&v.package_sha256)
    }
    pub fn digests(&mut self, v: &PackageDigests) {
        self.bytes(&v.package_sha256);
        self.bytes(&v.fixtures_sha256);
        self.bytes(&v.regression_report_sha256)
    }
    pub fn domain(label: &str, caller: &str, method: &str) -> Self {
        let mut e = Self::default();
        for s in [label, caller, method] {
            e.string(s)
        }
        e
    }
    pub fn request(caller: &str, method: &str) -> Self {
        Self::domain("aipay.upstream.request.v1", caller, method)
    }
    pub fn attempt(n: usize, r: &HttpRequest) -> Self {
        let mut e = Self::default();
        e.u32(n as u32);
        e.string(&r.method);
        e.string(&r.url);
        e.headers(
            r.headers
                .iter()
                .map(|(k, vs)| (k.clone(), vs.iter().map(String::as_bytes).collect())),
        );
        e.bytes(&r.body);
        e
    }
    pub fn reception(r: Option<&CapturedResponse>, code: &str) -> Vec<u8> {
        let mut e = Self::default();
        e.optional(r, |e, r| {
            e.u32(r.status.into());
            e.headers(
                r.headers
                    .iter()
                    .map(|(k, vs)| (k.clone(), vs.iter().map(Vec::as_slice).collect())),
            );
            e.bytes(&r.body);
            e.u32(if r.complete { 1 } else { 2 })
        });
        e.string(code);
        e.0
    }
    pub fn finish(&mut self, x: &ExecutionResult, output: Option<&[u8]>) {
        self.u32(x.category as u32);
        self.string(&x.error_code);
        self.optional(x.upstream_code.as_deref(), Self::string);
        self.u32(x.requests);
        self.u32(x.responses);
        self.u32(x.steps);
        self.optional(output, |e, b| e.0.extend(b))
    }
}
