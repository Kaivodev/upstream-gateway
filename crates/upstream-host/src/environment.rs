use crate::types::{Headers, HttpRequest};
use anyhow::{Result, bail};
use kaivo_upstream_sdk::time::Timestamp;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    io::Read,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
#[derive(Clone, Default)]
pub struct Cancellation {
    pub flag: Arc<AtomicBool>,
    pub deadline: Option<Instant>,
}
impl Cancellation {
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release)
    }
    pub fn cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire) || self.deadline.is_some_and(|d| Instant::now() >= d)
    }
}
/// Adapter error for an absent HTTP response or body handle. An empty readable
/// body is a valid response. A read failure is a transport error.
#[derive(Debug)]
pub struct MissingResponse;
impl std::fmt::Display for MissingResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("missing transport response")
    }
}
impl std::error::Error for MissingResponse {}
pub struct Incoming {
    pub status: u16,
    pub headers: Headers,
    pub body: Box<dyn Read + Send>,
}
/// Trusted single-exchange adapter. Enforce validated DNS/IP/TLS and header limits,
/// disable retries and redirects, and honor the deadline through the final body read.
pub trait Transport: Send + Sync {
    fn send(
        &self,
        template: &HttpRequest,
        request: &HttpRequest,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<Incoming>;
}
/// Trusted services must bound native work by the supplied deadline. Alerts are
/// independent of cancellation. The default services offer only a UTC clock and entropy.
pub trait Environment: Send + Sync {
    fn config(&self, _: &Cancellation) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
    fn secret(&self, _name: &str, _: &Cancellation) -> Result<Zeroizing<Vec<u8>>> {
        bail!("secret unavailable")
    }
    /// Already-decoded keys allow in-memory test credentials and HSM adapters.
    fn private_key(&self, _name: &str, _: &Cancellation) -> Option<Arc<rsa::PrivateKey>> {
        None
    }
    fn public_key_pem(&self, _name: &str, _deadline: Instant, _: &Cancellation) -> Result<String> {
        bail!("public key unavailable")
    }
    fn public_key(
        &self,
        name: &str,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<rsa::PublicKey> {
        use rsa::pkcs8::DecodePublicKey;
        Ok(rsa::PublicKey::from_public_key_pem(
            &self.public_key_pem(name, deadline, cancel)?,
        )?)
    }
    fn now(&self, _deadline: Instant, _: &Cancellation) -> Result<Timestamp> {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => Ok((d.as_secs().try_into()?, d.subsec_nanos())),
            Err(e) => {
                let d = e.duration();
                let n = d.subsec_nanos();
                Ok((
                    -(i64::try_from(d.as_secs())?) - i64::from(n != 0),
                    (1_000_000_000 - n) % 1_000_000_000,
                ))
            }
        }
    }
    fn random(&self, b: &mut [u8], _deadline: Instant, _: &Cancellation) -> Result<()> {
        getrandom::fill(b).map_err(|_| anyhow::anyhow!("entropy unavailable"))
    }
    /// Offline replay uses this observer to exclude regenerated signatures from evidence.
    fn observe_signature(&self, _signature: &str) {}
    fn log(&self, _event: &Value) {}
    fn alert(&self, _code: &str) {}
    fn transport(&self) -> Option<&dyn Transport> {
        None
    }
}
pub struct SystemEnvironment;
impl Environment for SystemEnvironment {}
