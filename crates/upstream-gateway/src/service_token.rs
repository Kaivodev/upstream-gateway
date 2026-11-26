use crate::{
    Role,
    config::{ServiceToken, valid_service},
    tls::Peer,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hyper::HeaderMap;
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

mod json;
mod jwks;
use jwks::KeySet;

pub(super) const HEADER: &str = "x-kaivo-service-token";
const MALFORMED: &str = "token_malformed";
const INVALID_KEYS: &str = "service token public key set is unavailable or invalid";

type Object<'a> = BTreeMap<String, &'a RawValue>;

fn field<'a, T: serde::Deserialize<'a>>(object: &Object<'a>, key: &str) -> Option<T> {
    serde_json::from_str(object.get(key)?.get()).ok()
}

fn decode(value: &str) -> Option<Vec<u8>> {
    // Go's RawURLEncoding.Strict ignores CR and LF, including in JWK members.
    if value.contains(['\r', '\n']) {
        URL_SAFE_NO_PAD.decode(value.replace(['\r', '\n'], "")).ok()
    } else {
        URL_SAFE_NO_PAD.decode(value).ok()
    }
}

struct Snapshot {
    keys: KeySet,
    hash: [u8; 32],
}

pub(super) struct Verifier {
    config: ServiceToken,
    audience: String,
    allowed_peers: Vec<String>,
    snapshot: watch::Sender<Snapshot>,
}

impl Verifier {
    pub fn load(
        config: ServiceToken,
        role: Role,
        allowed_peers: Vec<String>,
    ) -> anyhow::Result<Self> {
        let bytes = std::fs::read(&config.jwks_file).map_err(|_| anyhow::anyhow!(INVALID_KEYS))?;
        let snapshot = Snapshot {
            keys: jwks::parse(&bytes)?,
            hash: Sha256::digest(&bytes).into(),
        };
        Ok(Self {
            config,
            audience: format!("kaivo:upstream-gateway-{}", role.name()),
            allowed_peers,
            snapshot: watch::channel(snapshot).0,
        })
    }

    pub fn reload(&self) -> anyhow::Result<()> {
        let bytes =
            std::fs::read(&self.config.jwks_file).map_err(|_| anyhow::anyhow!(INVALID_KEYS))?;
        let hash = Sha256::digest(&bytes).into();
        if self.snapshot.borrow().hash != hash {
            self.snapshot.send_replace(Snapshot {
                keys: jwks::parse(&bytes)?,
                hash,
            });
        }
        Ok(())
    }

    pub fn authenticate(&self, headers: &HeaderMap) -> Result<Peer, &'static str> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        self.authenticate_at(headers.get_all(HEADER).iter().map(|v| v.as_bytes()), now)
    }

    fn authenticate_at<'a>(
        &self,
        mut values: impl Iterator<Item = &'a [u8]>,
        now: i64,
    ) -> Result<Peer, &'static str> {
        let value = values.next().ok_or("token_missing")?;
        if values.next().is_some() {
            return Err(MALFORMED);
        }
        if value.len() > 64 << 10 {
            return Err(MALFORMED);
        }
        self.verify(std::str::from_utf8(value).map_err(|_| MALFORMED)?, now)
    }

    fn verify(&self, token: &str, now: i64) -> Result<Peer, &'static str> {
        let (header, rest) = token.split_once('.').ok_or(MALFORMED)?;
        let (payload, signature) = rest.split_once('.').ok_or(MALFORMED)?;
        if header.is_empty()
            || payload.is_empty()
            || signature.is_empty()
            || signature.contains('.')
        {
            return Err(MALFORMED);
        }
        let message = &token.as_bytes()[..header.len() + 1 + payload.len()];
        let signature = decode(signature).ok_or(MALFORMED)?;
        let payload = decode(payload).ok_or(MALFORMED)?;
        let header = decode(header).ok_or(MALFORMED)?;
        let header = json::compatible(&header).ok_or(MALFORMED)?;
        let hdr: Object = serde_json::from_slice(&header).map_err(|_| MALFORMED)?;
        if hdr.contains_key("crit") || hdr.contains_key("b64") {
            return Err(MALFORMED);
        }
        let alg: String = field(&hdr, "alg").ok_or(MALFORMED)?;
        let kid: String = field(&hdr, "kid").ok_or(MALFORMED)?;
        if kid.is_empty() || !matches!(alg.as_str(), "ES256" | "RS256") {
            return Err(MALFORMED);
        }
        if !self
            .snapshot
            .borrow()
            .keys
            .get(&kid)
            .is_some_and(|key| key.signed(&alg, message, &signature))
        {
            return Err("token_signature");
        }
        let payload = json::compatible(&payload).ok_or(MALFORMED)?;
        let claims: Object = serde_json::from_slice(&payload).map_err(|_| MALFORMED)?;
        if field::<String>(&claims, "iss").as_ref() != Some(&self.config.issuer) {
            return Err("token_issuer");
        }
        let matches = field::<String>(&claims, "aud").is_some_and(|aud| aud == self.audience)
            || field::<Vec<String>>(&claims, "aud").is_some_and(|aud| aud.contains(&self.audience));
        if !matches {
            return Err("token_audience");
        }
        // The JSON parser already validated the number syntax. Parsing the raw
        // integer also accepts JSON -0, which serde_json otherwise treats as a float.
        let timestamp = |key| {
            claims
                .get(key)
                .and_then(|v| v.get().parse::<i64>().ok())
                .ok_or(MALFORMED)
        };
        let exp = timestamp("exp")?;
        let nbf = timestamp("nbf")?;
        let iat = timestamp("iat")?;
        if exp <= now.saturating_sub(30)
            || nbf > now.saturating_add(30)
            || iat > now.saturating_add(30)
            || exp <= iat
            || exp <= nbf
        {
            return Err("token_expired");
        }
        let subject: String = field(&claims, "sub").ok_or("token_subject")?;
        let mut parts = subject.split(':');
        let (Some("system"), Some("serviceaccount"), Some(namespace), Some(name), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err("token_subject");
        };
        if namespace.is_empty() || !valid_service(name) {
            return Err("token_subject");
        }
        if claims.contains_key("kubernetes.io") {
            let kube: Object = field(&claims, "kubernetes.io").ok_or("token_subject")?;
            let account: Object = field(&kube, "serviceaccount").ok_or("token_subject")?;
            if field::<String>(&kube, "namespace").as_deref() != Some(namespace)
                || field::<String>(&account, "name").as_deref() != Some(name)
            {
                return Err("token_subject");
            }
        }
        if self.config.service_namespaces.get(name).map(String::as_str) != Some(namespace) {
            return Err("token_namespace");
        }
        if !self.allowed_peers.iter().any(|allowed| allowed == name) {
            return Err("caller_not_allowed");
        }
        Ok(Peer::new(name))
    }
}

#[cfg(test)]
pub(super) mod tests;
