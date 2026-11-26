use crate::{Mode, Role, egress::ProxyAddress, kms::KmsConfig};
use anyhow::{Result, anyhow, ensure};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{self, Read},
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
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
    pub issuer: Option<String>,
    pub issuer_file: Option<PathBuf>,
    pub service_namespaces: BTreeMap<String, String>,
}

pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    // Projected volumes use symlinks. Check the opened descriptor and avoid blocking on FIFOs.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(file)
}

impl ServiceToken {
    pub fn load_issuer(&self) -> Result<String> {
        match (&self.issuer, &self.issuer_file) {
            (Some(issuer), None) => Ok(issuer.clone()),
            (None, Some(path)) => {
                const LIMIT: usize = 1024;
                let invalid = || anyhow!("invalid service token issuer file");
                let file = open_regular(path).map_err(|_| invalid())?;
                let mut text = String::new();
                file.take((LIMIT + 1) as u64)
                    .read_to_string(&mut text)
                    .map_err(|_| invalid())?;
                let issuer = text.trim_matches(|c: char| c.is_ascii() && c.is_whitespace());
                ensure!(
                    text.len() <= LIMIT
                        && !issuer.is_empty()
                        && !issuer.contains(char::is_whitespace),
                    "invalid service token issuer file"
                );
                Ok(issuer.to_owned())
            }
            _ => anyhow::bail!("configure exactly one of issuer and issuer_file"),
        }
    }
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
    pub listen: SocketAddr,
    pub allowed_peers: Vec<String>,
    #[serde(default)]
    pub transport: Transport,
    pub tls: Option<Tls>,
    pub service_token: Option<ServiceToken>,
    #[serde(flatten)]
    pub startup: StartupConfig,
    pub local_kek_file: Option<PathBuf>,
    pub kms: Option<KmsConfig>,
    pub egress_proxy: Option<ProxyAddress>,
    pub egress_ca_file: Option<PathBuf>,
    #[serde(default)]
    pub timing: Timing,
}

// Shared by the service configuration and the database-only migration command.
#[derive(Deserialize)]
pub(crate) struct StartupConfig {
    mode: String,
    #[serde(default)]
    pub migrate_on_start: bool,
    database_url_env: String,
    database_ca_file: Option<PathBuf>,
    #[serde(default = "default_database_connections")]
    database_max_connections: usize,
    #[serde(default)]
    allow_loopback_http: bool,
    #[serde(default)]
    allow_private_http: bool,
    #[serde(default)]
    allow_uncommitted: bool,
}

// Requests, journal workers and maintenance share this pool. Managed databases
// have small connection limits, so deployments size it explicitly.
fn default_database_connections() -> usize {
    16
}

fn read_config<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let text = std::fs::read_to_string(path).map_err(|_| anyhow!("cannot read configuration"))?;
    toml::from_str(&text).map_err(|_| anyhow!("invalid gateway configuration"))
}

impl StartupConfig {
    pub fn migration_pool(path: &Path) -> Result<deadpool_postgres::Pool> {
        let mut settings: Self = read_config(path)?;
        let mode = settings.mode()?;
        settings.resolve_database(path.parent().unwrap_or(Path::new(".")), mode)?;
        settings.pool(mode)
    }

    fn mode(&self) -> Result<Mode> {
        match self.mode.as_str() {
            "development" => Ok(Mode::Development {
                allow_loopback_http: self.allow_loopback_http,
                allow_private_http: self.allow_private_http,
                allow_uncommitted: self.allow_uncommitted,
            }),
            "production"
                if self.migrate_on_start
                    || self.allow_loopback_http
                    || self.allow_private_http
                    || self.allow_uncommitted =>
            {
                anyhow::bail!("development settings in production")
            }
            "production" => Ok(Mode::Production),
            _ => anyhow::bail!("invalid gateway mode"),
        }
    }

    fn resolve_database(&mut self, dir: &Path, mode: Mode) -> Result<()> {
        ensure!(
            !self.database_url_env.is_empty()
                && self.database_url_env.bytes().enumerate().all(|(i, b)| {
                    b.is_ascii_alphabetic() || b == b'_' || i > 0 && b.is_ascii_digit()
                }),
            "invalid database environment reference"
        );
        ensure!(
            (4..=64).contains(&self.database_max_connections),
            "database_max_connections must be between 4 and 64"
        );
        ensure!(
            !matches!(mode, Mode::Production) || self.database_ca_file.is_some(),
            "production requires database_ca_file and sslmode=require"
        );
        if let Some(path) = &mut self.database_ca_file {
            ensure!(!path.as_os_str().is_empty(), "empty file reference");
            *path = dir.join(&*path);
        }
        Ok(())
    }

    pub fn pool(&self, mode: Mode) -> Result<deadpool_postgres::Pool> {
        let url = zeroize::Zeroizing::new(
            std::env::var(&self.database_url_env)
                .map_err(|_| anyhow!("missing database configuration"))?,
        );
        crate::db::configured_pool(
            url.parse()
                .map_err(|_| anyhow!("invalid database configuration"))?,
            mode,
            self.database_ca_file.as_deref(),
            self.database_max_connections,
        )
    }
}

impl Config {
    pub fn read(path: &Path) -> Result<(Self, Mode)> {
        let mut c: Self = read_config(path)?;
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
                    token.issuer.is_some() != token.issuer_file.is_some(),
                    "configure exactly one of issuer and issuer_file"
                );
                ensure!(
                    token.issuer.as_ref().is_none_or(|v| !v.trim().is_empty())
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
        let mode = c.startup.mode()?;
        match mode {
            Mode::Development { .. } => ensure!(
                c.local_kek_file.is_some() != c.kms.is_some(),
                "development requires exactly one of local_kek_file and [kms]"
            ),
            Mode::Production => {
                ensure!(
                    c.local_kek_file.is_none(),
                    "development settings in production"
                );
                ensure!(c.kms.is_some(), "[kms] required in production");
            }
        }
        let dir = path.parent().unwrap_or(Path::new("."));
        c.startup.resolve_database(dir, mode)?;
        if let Some(kms) = &mut c.kms {
            kms.resolve(dir)?;
            let wrapped = kms
                .wrapped_key_file
                .as_mut()
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or_else(|| anyhow!("wrapped_key_file required"))?;
            *wrapped = dir.join(&*wrapped);
        }
        for value in
            c.tls
                .iter_mut()
                .flat_map(|tls| [&mut tls.ca_file, &mut tls.cert_file, &mut tls.key_file])
                .chain(c.service_token.iter_mut().flat_map(|t| {
                    std::iter::once(&mut t.jwks_file).chain(t.issuer_file.iter_mut())
                }))
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
        assert!(trade.startup.migrate_on_start);
        std::fs::write(&path, TEMPLATE.replace("migrate_on_start = true", "")).unwrap();
        assert!(!Config::read(&path).unwrap().0.startup.migrate_on_start);
        assert_eq!(trade.startup.database_max_connections, 16);
        std::fs::write(
            &path,
            TEMPLATE.replace("[tls]", "database_max_connections = 4\n[tls]"),
        )
        .unwrap();
        assert_eq!(
            Config::read(&path)
                .unwrap()
                .0
                .startup
                .database_max_connections,
            4
        );
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
            ("[tls]", "unexpected_top_level = true\n[tls]"),
            ("aipay.internal", "aipay..internal"),
            ("30000", "8999"),
            ("[tls]", "database_max_connections = 3\n[tls]"),
            ("[tls]", "database_max_connections = 65\n[tls]"),
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
            .replace("migrate_on_start = true", "migrate_on_start = false")
            .replace("development", "production")
            .lines()
            .filter(|l| !l.starts_with("local_kek_file"))
            .collect::<Vec<_>>()
            .join("\n");
        for (option, error) in [
            ("allow_loopback_http", "development settings in production"),
            ("allow_uncommitted", "development settings in production"),
            ("allow_private_http", "development settings in production"),
            ("migrate_on_start", "development settings in production"),
            ("unused", "[kms] required in production"),
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
    fn startup_selects_exactly_one_kek_source_for_the_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        let parse = |text: String| {
            std::fs::write(&path, text).unwrap();
            Config::read(&path)
        };
        let no_key = TEMPLATE
            .replace("migrate_on_start = true", "migrate_on_start = false")
            .lines()
            .filter(|l| !l.starts_with("local_kek_file"))
            .collect::<Vec<_>>()
            .join("\n");
        let kms = "\n[kms]\nkey='projects/p/locations/l/keyRings/r/cryptoKeys/k'\ncredentials_file='gcp/config'\nwrapped_key_file='kek.json'\n";
        for mode in ["development", "production"] {
            let base = format!(
                "database_ca_file='db-ca.pem'\n{}",
                no_key.replace("development", mode)
            );
            assert!(parse(base.clone()).is_err());
            assert!(parse(format!("{}{kms}", TEMPLATE.replace("development", mode))).is_err());
            let (config, selected_mode) = parse(format!("{base}{kms}")).unwrap();
            assert_eq!(
                config.startup.database_ca_file.unwrap(),
                dir.path().join("db-ca.pem")
            );
            if mode == "production" {
                assert_eq!(
                    parse(format!("{}{kms}", no_key.replace("development", mode)))
                        .err()
                        .unwrap()
                        .to_string(),
                    "production requires database_ca_file and sslmode=require"
                );
            }
            assert_eq!(
                matches!(selected_mode, Mode::Production),
                mode == "production"
            );
            assert_eq!(
                config.kms.unwrap().wrapped_key_file.unwrap(),
                dir.path().join("kek.json")
            );
            assert!(
                parse(format!(
                    "{base}{}",
                    kms.replace("wrapped_key_file='kek.json'", "")
                ))
                .is_err()
            );
        }
        for key in [
            "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
            "projects/p/locations//keyRings/r/cryptoKeys/k",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k?",
            "/projects/p/locations/l/keyRings/r/cryptoKeys/k",
            "projects/p/locations/l/keyRings/r/cryptoKeys/k.x",
        ] {
            assert!(
                parse(format!(
                    "{no_key}{}",
                    kms.replace("projects/p/locations/l/keyRings/r/cryptoKeys/k", key)
                ))
                .is_err()
            );
        }
        for (address, valid) in [
            ("gateway-egress.kaivo-business.svc:3128", true),
            ("127.0.0.1:1", true),
            ("[::1]:65535", true),
            ("gateway:3128", true),
            ("host", false),
            (":80", false),
            ("host:0", false),
            ("host:65536", false),
            ("https://host:443", false),
            ("user@host:80", false),
            ("bad..host:80", false),
            ("::1:80", false),
            ("[no-ip]:80", false),
            ("-bad:3128", false),
        ] {
            let field = format!("egress_proxy='{address}'\n");
            assert_eq!(parse(format!("{field}{TEMPLATE}")).is_ok(), valid);
            assert_eq!(parse(format!("{no_key}{kms}{field}")).is_ok(), valid);
        }
    }

    #[test]
    fn issuer_sources_and_projected_file_limits() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config");
        let issuer = dir.path().join("issuer");
        let example = r#"issuer_file = "/run/kaivo/issuer/issuer""#;
        let parse = |setting: &str| -> Result<ServiceToken> {
            std::fs::write(&path, KUBE.replace(example, setting))?;
            Ok(Config::read(&path)?.0.service_token.unwrap())
        };
        let inline = r#"issuer = "https://issuer.test""#;
        let file = r#"issuer_file = "projected""#;
        assert_eq!(parse(inline)?.load_issuer()?, "https://issuer.test");
        assert!(parse("").is_err());
        assert!(parse(&format!("{inline}\n{file}")).is_err());
        assert!(parse(r#"issuer = "  ""#).is_err());
        let token = parse(file)?;
        std::os::unix::fs::symlink(&issuer, dir.path().join("projected"))?;
        assert!(token.load_issuer().is_err());
        std::fs::write(&issuer, " \t\x0bhttps://issuer.test \r\n")?;
        assert_eq!(token.load_issuer()?, "https://issuer.test");
        std::fs::write(&issuer, "a".repeat(1024))?;
        assert_eq!(token.load_issuer()?.len(), 1024);
        for data in [
            &b""[..],
            b" \n",
            b"a b",
            b"a\tb",
            b"a\nb",
            b"\xff",
            &[b'a'; 1025],
        ] {
            std::fs::write(&issuer, data)?;
            assert_eq!(
                token.load_issuer().unwrap_err().to_string(),
                "invalid service token issuer file"
            );
        }
        std::fs::remove_file(&issuer)?;
        std::fs::create_dir(&issuer)?;
        assert!(token.load_issuer().is_err());
        Ok(())
    }

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
        let absolute = "/run/kaivo/issuer/jwks.json";
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
            KUBE.replace("/run/kaivo/issuer/issuer", ""),
            KUBE.replace("issuer_file =", "typo = 1\nissuer_file ="),
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
