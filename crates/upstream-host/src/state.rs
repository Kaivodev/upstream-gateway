use crate::{
    environment::{Cancellation, Environment},
    http::Check,
    imports::{self, Part, UtcTime},
    json::projected_len,
    package::{Manifest, hex},
};
use base64::prelude::*;
use hmac::{Hmac, KeyInit, Mac};
use rsa::{Pkcs1v15Sign, PrivateKey, pkcs8::DecodePrivateKey, traits::PublicKeyParts};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Arc, time::Instant};
use subtle::ConstantTimeEq;
use wasmtime::{Error, ResourceLimiter, Result as WResult};
use zeroize::Zeroizing;
pub(crate) const MEMORY: usize = 32 << 20;
#[derive(Default)]
pub struct Scanner(Vec<Zeroizing<Vec<u8>>>);
impl Scanner {
    pub fn add(&mut self, b: &[u8]) {
        self.0.push(Zeroizing::new(b.to_vec()));
        for s in [
            hex(b),
            hex(b).to_ascii_uppercase(),
            BASE64_STANDARD.encode(b),
            BASE64_STANDARD_NO_PAD.encode(b),
            BASE64_URL_SAFE.encode(b),
            BASE64_URL_SAFE_NO_PAD.encode(b),
        ] {
            self.0.push(Zeroizing::new(s.into_bytes()))
        }
    }
    fn raw(&self, b: &[u8]) -> bool {
        self.0.iter().any(|p| memchr::memmem::find(b, p).is_some())
    }
    pub fn value(&self, v: &Value) -> bool {
        match v {
            Value::String(s) => self.bytes(s.as_bytes()),
            Value::Object(o) => o
                .iter()
                .any(|(k, v)| self.bytes(k.as_bytes()) || self.value(v)),
            Value::Array(a) => a.iter().any(|v| self.value(v)),
            _ => false,
        }
    }
    pub fn bytes(&self, b: &[u8]) -> bool {
        if self.raw(b) {
            return true;
        }
        !self.0.is_empty() && crate::json::escaped_strings_match(b, |s| self.raw(s))
    }
}
pub(crate) struct State {
    pub m: Arc<Manifest>,
    pub env: Arc<dyn Environment>,
    pub cancel: Cancellation,
    pub op: String,
    pub deadline: Instant,
    pub config: BTreeMap<String, String>,
    pub secrets: BTreeMap<String, Zeroizing<Vec<u8>>>,
    pub scan: Scanner,
    private: BTreeMap<String, Arc<PrivateKey>>,
    calls: u32,
    kaivo_calls: u32,
    random_bytes: usize,
    log_bytes: usize,
    log_text: Vec<u8>,
    log_messages: Vec<u8>,
    log_values: BTreeMap<String, Vec<u8>>,
    pub logs: Vec<Value>,
    pub memory: usize,
    pub fault: Option<&'static str>,
}
impl State {
    pub fn new(
        m: Arc<Manifest>,
        env: Arc<dyn Environment>,
        cancel: Cancellation,
        op: &str,
    ) -> Self {
        Self {
            m,
            env,
            cancel,
            op: op.into(),
            deadline: Instant::now(),
            config: BTreeMap::new(),
            secrets: BTreeMap::new(),
            scan: Scanner::default(),
            private: BTreeMap::new(),
            calls: 0,
            kaivo_calls: 0,
            random_bytes: 0,
            log_bytes: 0,
            log_text: Vec::new(),
            log_messages: Vec::new(),
            log_values: BTreeMap::new(),
            logs: Vec::new(),
            memory: 0,
            fault: None,
        }
    }
    pub fn prepare(&mut self) -> Check<()> {
        if self.op != "route_callback" {
            for (n, ty) in &self.m.secrets {
                if ty == "rsa-private"
                    && let Some(k) = self.env.private_key(n, &self.cancel)
                {
                    if k.n().bit_width() < 2048 || k.validate().is_err() {
                        return Err("credential_unavailable");
                    }
                    self.private.insert(n.clone(), k);
                    continue;
                }
                let s = self
                    .env
                    .secret(n, &self.cancel)
                    .map_err(|_| "credential_unavailable")?;
                if !(16..=16384).contains(&s.len()) {
                    return Err("credential_unavailable");
                }
                self.scan.add(&s);
                self.secrets.insert(n.clone(), s);
            }
        }
        self.config = self.env.config(&self.cancel);
        if self.scan.value(&json!(self.config)) {
            return Err("secret_leak");
        }
        if self.config.keys().any(|k| !self.m.config.contains_key(k)) {
            return Err("undeclared_config");
        }
        for (k, f) in &self.m.config {
            if f.required && self.config.get(k).is_none_or(String::is_empty) {
                return Err("config_unavailable");
            }
            if self.config.get(k).is_some_and(|v| v.len() > 8192) {
                return Err("config_limit");
            }
        }
        Ok(())
    }
    pub fn flush_logs(&self, private: &Scanner) {
        // Check the buffered streams as well as individual events before publishing any of them.
        if self.logs.is_empty()
            || private.bytes(&self.log_text)
            || private.bytes(&self.log_messages)
            || self.log_values.values().any(|v| private.bytes(v))
            || self.logs.iter().any(|v| private.value(v))
        {
            return;
        }
        for event in &self.logs {
            self.env.log(event);
        }
    }

    pub fn check(&self) -> Check<()> {
        if self.cancel.cancelled() {
            Err("cancelled")
        } else if Instant::now() >= self.deadline {
            Err("sandbox_timeout")
        } else {
            Ok(())
        }
    }
    pub fn fail<T>(&mut self, code: &'static str) -> WResult<T> {
        self.fault = Some(code);
        Err(Error::msg(code))
    }
    fn enter(&mut self) -> WResult<()> {
        self.calls += 1;
        self.kaivo_calls += 1;
        if self.kaivo_calls > 128 || self.calls > 4096 {
            return self.fail("host_call_limit");
        }
        self.checked()
    }
    pub fn checked(&mut self) -> WResult<()> {
        if let Err(c) = self.check() {
            self.fail(c)
        } else {
            Ok(())
        }
    }
    fn io(&mut self, v: &Value, limit: usize) -> WResult<()> {
        if self.scan.value(v) || self.scan.raw(&serde_json::to_vec(v).unwrap()) {
            return self.fail("secret_leak");
        }
        if projected_len(v) > limit {
            return self.fail("host_io_limit");
        }
        Ok(())
    }
    fn reply<T: serde::Serialize>(&mut self, value: T) -> WResult<T> {
        self.io(&json!({"value":value}), 65536)?;
        self.checked()?;
        Ok(value)
    }
    fn parts(&mut self, parts: &[Part]) -> WResult<Zeroizing<Vec<u8>>> {
        let mut data = Zeroizing::new(Vec::new());
        if parts.len() > 128 {
            return self.fail("host_service");
        }
        for part in parts {
            let chunk = match part {
                Part::Data(b) => {
                    if self.scan.bytes(b) {
                        return self.fail("secret_leak");
                    }
                    b.as_slice()
                }
                Part::Secret(n) if self.m.secrets.get(n).is_some_and(|t| t == "shared") => {
                    &self.secrets[n]
                }
                _ => return self.fail("host_service"),
            };
            if data.len() + chunk.len() > 1 << 20 {
                return self.fail("host_service");
            }
            data.extend_from_slice(chunk)
        }
        Ok(data)
    }
    fn crypto(
        &mut self,
        algorithm: &str,
        key: Option<&str>,
        parts: &[Part],
        signature: Option<&str>,
    ) -> WResult<Zeroizing<Vec<u8>>> {
        self.enter()?;
        if self.op == "route_callback" {
            return self.fail("route_crypto_forbidden");
        }
        let mut v = json!({"algorithm":algorithm,"parts":parts.iter().map(|p|match p{Part::Data(b) if b.is_empty()=>json!({}),Part::Data(b)=>json!({"data":BASE64_STANDARD.encode(b)}),Part::Secret(n)=>json!({"secret":n})}).collect::<Vec<_>>()});
        if let Some(k) = key {
            v["key"] = json!(k)
        }
        if let Some(s) = signature {
            v["signature"] = json!(s)
        }
        self.io(&v, 1 << 20)?;
        self.parts(parts)
    }
}
impl imports::Host for State {
    fn config(&mut self, name: String) -> WResult<String> {
        self.enter()?;
        self.io(&json!({"name":name}), 1 << 20)?;
        let Some(v) = self.config.get(&name).cloned() else {
            return self.fail("undeclared_config");
        };
        self.reply(v)
    }
    fn sign(
        &mut self,
        algorithm: String,
        key: Option<String>,
        parts: Vec<Part>,
    ) -> WResult<String> {
        let data = self.crypto(&algorithm, key.as_deref(), &parts, None)?;
        let s = match (algorithm.as_str(), key.as_deref()) {
            ("md5", None) => hex(&md5::Md5::digest(&*data)),
            ("sha1", None) => hex(&sha1::Sha1::digest(&*data)),
            ("sha256", None) => hex(&Sha256::digest(&*data)),
            ("hmac-sha256", Some(k)) if self.m.secrets.get(k).is_some_and(|s| s == "shared") => {
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.secrets[k]).unwrap();
                mac.update(&data);
                hex(&mac.finalize().into_bytes())
            }
            ("rsa-sha256", Some(k))
                if self.m.secrets.get(k).is_some_and(|s| s == "rsa-private") =>
            {
                let sig = self
                    .private
                    .get(k)
                    .cloned()
                    .or_else(|| {
                        std::str::from_utf8(self.secrets.get(k)?)
                            .ok()
                            .and_then(|s| PrivateKey::from_pkcs8_pem(s).ok())
                            .map(Arc::new)
                    })
                    .filter(|k| k.n().bit_width() >= 2048 && k.validate().is_ok())
                    .and_then(|k| {
                        k.sign_with_rng(
                            &mut getrandom::SysRng,
                            Pkcs1v15Sign::new::<Sha256>(),
                            &Sha256::digest(&*data),
                        )
                        .ok()
                    });
                let Some(sig) = sig else {
                    return self.fail("host_service");
                };
                BASE64_STANDARD.encode(sig)
            }
            _ => return self.fail("host_service"),
        };
        self.env.observe_signature(&s);
        self.reply(s)
    }
    fn verify(
        &mut self,
        algorithm: String,
        key: String,
        parts: Vec<Part>,
        signature: String,
    ) -> WResult<bool> {
        let data = self.crypto(&algorithm, Some(&key), &parts, Some(&signature))?;
        if algorithm != "rsa-sha256" || !self.m.public_keys.contains(&key) {
            return self.fail("undeclared_public_key");
        }
        let Some(k) = self
            .env
            .public_key(&key, self.deadline, &self.cancel)
            .ok()
            .filter(|k| k.n().bit_width() >= 2048)
            .and_then(|k| rsa::PublicKey::new(k.n().as_ref().clone(), k.e().clone()).ok())
        else {
            return self.fail("host_service");
        };
        self.reply(BASE64_STANDARD.decode(signature).is_ok_and(|sig| {
            k.verify(Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(&*data), &sig)
                .is_ok()
        }))
    }
    fn equal(&mut self, a: String, b: String) -> WResult<bool> {
        self.enter()?;
        self.io(&json!({"a":a,"b":b}), 1 << 20)?;
        self.reply(bool::from(a.as_bytes().ct_eq(b.as_bytes())))
    }
    fn log(
        &mut self,
        level: String,
        message: String,
        fields: Vec<(String, String)>,
    ) -> WResult<bool> {
        self.enter()?;
        let mut v = json!({"level":level,"message":message});
        let mut map = BTreeMap::new();
        for (k, s) in fields {
            if map.insert(k, s).is_some() {
                return self.fail("host_service");
            }
        }
        if !map.is_empty() {
            v["fields"] = json!(map)
        }
        self.io(&v, 1 << 20)?;
        if !matches!(level.as_str(), "debug" | "info" | "warn" | "error") {
            return self.fail("log_level");
        }
        if self.logs.len() == 32 {
            return self.fail("log_rate_limit");
        }
        self.log_bytes += projected_len(&v);
        if self.log_bytes > 8192 {
            return self.fail("log_limit");
        }
        self.log_messages.extend(message.as_bytes());
        self.log_text.extend(message.as_bytes());
        for (k, s) in map {
            let stream = self.log_values.entry(k.clone()).or_default();
            stream.extend(s.bytes());
            if self.scan.bytes(stream) {
                return self.fail("secret_leak");
            }
            self.log_text.extend(k.bytes());
            self.log_text.extend(s.bytes())
        }
        if self.scan.bytes(&self.log_text) || self.scan.bytes(&self.log_messages) {
            return self.fail("secret_leak");
        }
        self.logs.push(v);
        self.reply(true)
    }
    fn now(&mut self) -> WResult<UtcTime> {
        self.enter()?;
        let Some((seconds, nanos)) = self
            .env
            .now(self.deadline, &self.cancel)
            .ok()
            .filter(|t| kaivo_upstream_sdk::time::valid(*t))
        else {
            return self.fail("host_service");
        };
        let value = UtcTime { seconds, nanos };
        self.io(&json!(value), 1 << 20)?;
        self.checked()?;
        Ok(value)
    }
    fn random(&mut self, len: u32) -> WResult<Vec<u8>> {
        self.enter()?;
        let n = len as usize;
        if n > 65536 || self.random_bytes + n > 262144 {
            return self.fail("random_limit");
        }
        self.random_bytes += n;
        let mut b = vec![0; n];
        if self
            .env
            .random(&mut b, self.deadline, &self.cancel)
            .is_err()
        {
            return self.fail("host_service");
        }
        if self.scan.bytes(&b) {
            return self.fail("secret_leak");
        }
        self.checked()?;
        Ok(b)
    }
}
impl ResourceLimiter for State {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> WResult<bool> {
        let Some(total) = self.memory.checked_add(desired.saturating_sub(current)) else {
            return self.fail("memory_limit");
        };
        if total > MEMORY || maximum.is_some_and(|m| desired > m) {
            return self.fail("memory_limit");
        }
        self.memory = total;
        Ok(true)
    }
    fn memory_grow_failed(&mut self, _e: Error) -> WResult<()> {
        self.fail("memory_limit")
    }
    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> WResult<bool> {
        Ok(desired <= 8192 && maximum.is_none_or(|m| desired <= m))
    }
    fn instances(&self) -> usize {
        16
    }
    fn tables(&self) -> usize {
        8
    }
    fn memories(&self) -> usize {
        8
    }
}
