use crate::{Mode, Role};
use anyhow::{Result, anyhow, ensure};
use serde::Deserialize;
use std::{
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub role: Role,
    mode: String,
    pub listen: SocketAddr,
    allowed_peers: Vec<String>,
    pub tls: Tls,
    pub database_url_env: String,
    pub local_kek_file: Option<PathBuf>,
    #[serde(default)]
    allow_loopback_http: bool,
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
        let domain = &c.tls.trust_domain;
        ensure!(
            domain.len() <= 253
                && domain.split(['.', '-']).all(|part| !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())),
            "invalid trust domain"
        );
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
                allow_uncommitted: c.allow_uncommitted,
            },
            "development" => anyhow::bail!("development KMS file required"),
            "production"
                if c.allow_loopback_http || c.allow_uncommitted || c.local_kek_file.is_some() =>
            {
                anyhow::bail!("development settings in production")
            }
            "production" => anyhow::bail!("production KMS unavailable"),
            _ => anyhow::bail!("invalid gateway mode"),
        };
        let dir = path.parent().unwrap_or(Path::new("."));
        for value in [
            &mut c.tls.ca_file,
            &mut c.tls.cert_file,
            &mut c.tls.key_file,
        ]
        .into_iter()
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
        assert_eq!(trade.tls.ca_file.parent(), Some(dir.path()));
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
}
