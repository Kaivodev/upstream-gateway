use crate::{Mode, Role};
use anyhow::{Result, anyhow, ensure};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Timing {
    pub heartbeat_ms: u64,
    pub fence_ms: i64,
}
impl Default for Timing {
    fn default() -> Self {
        Self {
            heartbeat_ms: 3000,
            fence_ms: 30000,
        }
    }
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Tls {
    pub trust_domain: String,
    pub ca_file: PathBuf,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}
#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Transport {
    #[default]
    Mtls,
    Plaintext,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceToken {
    pub jwks_file: PathBuf,
    pub issuer: String,
    pub service_namespaces: BTreeMap<String, String>,
}

pub(crate) fn valid_service(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

fn valid_namespace(name: &str) -> bool {
    (1..=63).contains(&name.len())
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub role: Role,
    mode: String,
    pub listen: SocketAddr,
    pub allowed_peers: Vec<String>,
    #[serde(default)]
    pub transport: Transport,
    pub tls: Option<Tls>,
    pub service_token: Option<ServiceToken>,
    pub database_url_env: String,
    pub local_kek_file: Option<PathBuf>,
    #[serde(default)]
    allow_loopback_http: bool,
    #[serde(default)]
    allow_private_http: bool,
    #[serde(default)]
    allow_uncommitted: bool,
    pub egress_proxy: Option<SocketAddr>,
    pub egress_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub timing: Timing,
}

impl Config {
    pub fn read(path: &Path) -> Result<(Self, Mode)> {
        let text =
            std::fs::read_to_string(path).map_err(|_| anyhow!("cannot read configuration"))?;
        let mut c: Self =
            toml::from_str(&text).map_err(|_| anyhow!("invalid gateway configuration"))?;
        ensure!(
            c.allowed_peers == [c.role.caller()],
            "invalid peer for role"
        );
        match (c.transport, &c.tls, &c.service_token) {
            (Transport::Mtls, Some(tls), None) => {
                let domain = &tls.trust_domain;
                ensure!(
                    domain.len() <= 253
                        && domain.split(['.', '-']).all(|part| !part.is_empty()
                            && part
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())),
                    "invalid trust domain"
                );
            }
            (Transport::Plaintext, None, Some(token)) => {
                ensure!(
                    !token.issuer.trim().is_empty()
                        && !token.jwks_file.to_string_lossy().trim().is_empty(),
                    "invalid service token configuration"
                );
                ensure!(
                    token.service_namespaces.contains_key(c.role.caller())
                        && token
                            .service_namespaces
                            .iter()
                            .all(|(s, n)| valid_service(s) && valid_namespace(n)),
                    "invalid service namespace mapping"
                );
            }
            _ => anyhow::bail!("invalid authentication settings for transport"),
        }
        ensure!(
            (50..=60000).contains(&c.timing.heartbeat_ms)
                && (3 * c.timing.heartbeat_ms as i64..=600000).contains(&c.timing.fence_ms),
            "invalid executor timing"
        );
        ensure!(
            !c.database_url_env.is_empty()
                && c.database_url_env
                    .bytes()
                    .enumerate()
                    .all(|(i, b)| b.is_ascii_alphabetic()
                        || b == b'_'
                        || i > 0 && b.is_ascii_digit()),
            "invalid database environment reference"
        );
        let mode = match c.mode.as_str() {
            "development" if c.local_kek_file.is_some() => Mode::Development {
                allow_loopback_http: c.allow_loopback_http,
                allow_private_http: c.allow_private_http,
                allow_uncommitted: c.allow_uncommitted,
            },
            "development" => anyhow::bail!("development KMS file required"),
            "production"
                if c.allow_loopback_http
                    || c.allow_private_http
                    || c.allow_uncommitted
                    || c.local_kek_file.is_some() =>
            {
                anyhow::bail!("development settings in production")
            }
            "production" => anyhow::bail!("production KMS unavailable"),
            _ => anyhow::bail!("invalid gateway mode"),
        };
        let dir = path.parent().unwrap_or(Path::new("."));
        for value in c
            .tls
            .iter_mut()
            .flat_map(|tls| [&mut tls.ca_file, &mut tls.cert_file, &mut tls.key_file])
            .chain(c.service_token.iter_mut().map(|t| &mut t.jwks_file))
            .chain(c.local_kek_file.iter_mut())
            .chain(c.egress_ca_file.iter_mut())
        {
            ensure!(!value.as_os_str().is_empty(), "empty file reference");
            *value = dir.join(&*value);
        }
        Ok((c, mode))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const TEMPLATE: &str = include_str!("../../../config/development.example.toml");
    #[test]
    fn startup_configuration_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        std::fs::write(&path, TEMPLATE).unwrap();
        let (trade, _) = Config::read(&path).unwrap();
        assert_eq!(trade.role, Role::Trade);
        assert_eq!(trade.tls.unwrap().ca_file.parent(), Some(dir.path()));
        for (from, to) in [
            ("role = \"trade\"", ""),
            ("role = \"trade\"", "role = \"statement\""),
            ("role = \"trade\"", "role = \"verification\""),
            ("[\"payment\"]", "[]"),
            ("[\"payment\"]", "[\"payment\",\"payment\"]"),
            ("development", "production"),
            ("development", "unknown"),
            ("database_url_env", "database_url"),
            ("GATEWAY_DATABASE_URL", "invalid/reference"),
            ("[tls]", "[tls]\nunknown = true"),
            ("aipay.internal", "aipay..internal"),
            ("30000", "8999"),
            ("3000\n", "49\n"),
        ] {
            let input = TEMPLATE.replace(from, to);
            assert_ne!(input, TEMPLATE);
            std::fs::write(&path, input).unwrap();
            assert!(
                Config::read(&path).is_err(),
                "accepted invalid field {from}"
            );
        }
        let clean_production = TEMPLATE
            .replace("development", "production")
            .lines()
            .filter(|l| !l.starts_with("local_kek_file"))
            .collect::<Vec<_>>()
            .join("\n");
        for (option, error) in [
            ("allow_loopback_http", "development settings in production"),
            ("allow_uncommitted", "development settings in production"),
            ("allow_private_http", "development settings in production"),
            ("unused", "production KMS unavailable"),
        ] {
            std::fs::write(
                &path,
                clean_production.replace(&format!("{option} = false"), &format!("{option} = true")),
            )
            .unwrap();
            assert_eq!(Config::read(&path).err().unwrap().to_string(), error);
        }
    }

    const KUBE: &str = include_str!("../../../config/kubernetes.example.toml");
    #[test]
    fn plaintext_settings_match_transport_and_role() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        let parse = |text: &str| {
            std::fs::write(&path, text).unwrap();
            Config::read(&path)
        };
        let (config, mode) = parse(KUBE).unwrap();
        assert!(matches!(config.transport, Transport::Plaintext) && mode.allow_http());
        let absolute = "/var/run/kaivo/issuer/jwks.json";
        assert_eq!(config.service_token.unwrap().jwks_file, Path::new(absolute));
        let (config, _) = parse(&KUBE.replace(absolute, "issuer/jwks.json")).unwrap();
        assert_eq!(
            config.service_token.unwrap().jwks_file,
            dir.path().join("issuer/jwks.json")
        );
        let tls = TEMPLATE
            .split_once("[tls]")
            .unwrap()
            .1
            .split_once("[timing]")
            .unwrap()
            .0;
        let token = KUBE
            .split_once("[service_token]")
            .unwrap()
            .1
            .split_once("[timing]")
            .unwrap()
            .0;
        for input in [
            format!("{KUBE}\n[tls]{tls}"),
            format!("{TEMPLATE}\n[service_token]{token}"),
            KUBE.replace("plaintext", "mtls"),
            KUBE.replace("plaintext", "unknown"),
            KUBE.replace("payment =", "other ="),
            KUBE.replace("payment =", "Payment ="),
            KUBE.replace("payment =", &format!("{} =", "a".repeat(65))),
            KUBE.replace("kaivo-business", "-abc"),
            KUBE.replace("kaivo-business", "abc-"),
            KUBE.replace("kaivo-business", "a_b"),
            KUBE.replace("kaivo-business", &"a".repeat(64)),
            KUBE.replace("https://kubernetes.default.svc.cluster.local", ""),
            KUBE.replace("https://kubernetes.default.svc.cluster.local", "  "),
            KUBE.replace("issuer =", "typo = 1\nissuer ="),
            KUBE.split_once("[service_token]").unwrap().0.to_string(),
            TEMPLATE.split_once("[tls]").unwrap().0.to_string(),
            KUBE.replace("payment = \"kaivo-business\"", ""),
        ] {
            assert!(parse(&input).is_err());
        }
        assert!(
            parse(
                &KUBE
                    .replace("trade", "verification")
                    .replace("payment", "reconciliation")
            )
            .is_ok()
        );
        assert!(valid_service("a") && valid_service(&format!("a{}", "_".repeat(63))));
        assert!(valid_namespace("0") && valid_namespace(&"x".repeat(63)));
    }
}
