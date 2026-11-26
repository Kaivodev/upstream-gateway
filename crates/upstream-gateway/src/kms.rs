//! Cloud KMS is used only while loading or provisioning the in-memory KEK.
mod credentials;
mod http;
mod keys;
mod wrapped;

use self::{http::Http, keys::Key};
use crate::{Events, Role, crypto::LocalKms, egress::ProxyAddress, server::Observer};
use anyhow::{Result, anyhow, ensure};
use regex::Regex;
use serde::{Deserialize, Deserializer, de};
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    marker::PhantomData,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::LazyLock,
    time::Duration,
};
use tokio::time::{Instant, timeout_at};
use zeroize::Zeroizing;

const LIMIT: usize = 64 << 10;
const BUDGET: Duration = Duration::from_secs(60);
static KEY_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\Aprojects/[A-Za-z0-9_-]+/locations/[A-Za-z0-9_-]+",
        r"/keyRings/[A-Za-z0-9_-]+/cryptoKeys/[A-Za-z0-9_-]+\z"
    ))
    .unwrap()
});

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KmsConfig {
    key: String,
    credentials_file: PathBuf,
    egress_proxy: Option<ProxyAddress>,
    pub wrapped_key_file: Option<PathBuf>,
}

impl KmsConfig {
    pub(crate) fn resolve(&mut self, dir: &Path) -> Result<()> {
        ensure!(KEY_PATH.is_match(&self.key), "invalid KMS key resource");
        ensure!(
            !self.credentials_file.as_os_str().is_empty(),
            "missing KMS credentials file"
        );
        self.credentials_file = dir.join(&self.credentials_file);
        Ok(())
    }

    async fn authenticate<'a>(&'a self, http: &'a Http) -> Result<Key<'a>, Failure> {
        let token = credentials::authenticate(http, &self.credentials_file).await?;
        Ok(Key {
            http,
            key: &self.key,
            token,
        })
    }
}

// serde derives also accept positional arrays. These formats require JSON objects.
fn object<'de, D: Deserializer<'de>, T: Deserialize<'de>>(de: D) -> Result<T, D::Error> {
    struct Object<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> de::Visitor<'de> for Object<T> {
        type Value = T;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a JSON object")
        }
        fn visit_map<A: de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
            T::deserialize(de::value::MapAccessDeserializer::new(map))
        }
    }
    de.deserialize_map(Object(PhantomData))
}

fn json_object<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Option<T> {
    let mut json = serde_json::Deserializer::from_slice(data);
    let value = object(&mut json).ok()?;
    json.end().ok()?;
    Some(value)
}

fn secret_string<'de, D: Deserializer<'de>>(de: D) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(de).map(Zeroizing::new)
}

fn open_regular(path: &Path) -> io::Result<File> {
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

async fn read_file(path: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || {
        let file = open_regular(&path)?;
        let mut data = Zeroizing::new(Vec::with_capacity(LIMIT + 1));
        file.take(LIMIT as u64 + 1).read_to_end(&mut data)?;
        if data.len() > LIMIT {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(data)
    })
    .await?
}

#[derive(Clone, Copy, Debug)]
struct Failure {
    step: &'static str,
    status: Option<u16>,
}
impl Failure {
    fn new(step: &'static str) -> Self {
        Self { step, status: None }
    }
    fn invalid_response(step: &'static str) -> Self {
        Self {
            step,
            status: Some(200),
        }
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "step={}", self.step)?;
        if let Some(status) = self.status {
            write!(f, " status={status}")?;
        }
        Ok(())
    }
}

async fn run_until<T>(
    deadline: Instant,
    event: &'static str,
    events: &dyn Events,
    work: impl Future<Output = Result<T, Failure>>,
) -> Result<T> {
    timeout_at(deadline, work)
        .await
        .unwrap_or_else(|_| Err(Failure::new("deadline")))
        .map_err(|failure| {
            events.kms_failed(event, failure.step, failure.status);
            anyhow!("{event} {failure}")
        })
}

pub(crate) async fn unwrap(
    config: &KmsConfig,
    role: Role,
    events: &dyn Events,
) -> Result<LocalKms> {
    let http = Http::google(config.egress_proxy.clone())?;
    load(config, role, &http, events).await
}

async fn load(
    config: &KmsConfig,
    role: Role,
    http: &Http,
    events: &dyn Events,
) -> Result<LocalKms> {
    let deadline = Instant::now() + BUDGET;
    let path = config
        .wrapped_key_file
        .as_deref()
        .ok_or_else(|| anyhow!("wrapped_key_file required"))?;
    let bytes = timeout_at(deadline, read_file(path))
        .await
        .ok()
        .and_then(Result::ok)
        .ok_or_else(|| anyhow!("cannot read wrapped key file"))?;
    let (version, ciphertext) = wrapped::parse(&bytes, role)?;
    let aad = wrapped::aad(role, version);
    run_until(deadline, "kms_unwrap_failed", events, async {
        let key = config.authenticate(http).await?;
        Ok(LocalKms::from_cloud_kms(
            key.decrypt(&ciphertext, aad.as_bytes()).await?,
        ))
    })
    .await
}

#[derive(Deserialize)]
struct WrapConfig {
    role: Role,
    kms: KmsConfig,
}

impl WrapConfig {
    fn read(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).map_err(|_| anyhow!("cannot read configuration"))?;
        let mut config: Self =
            toml::from_str(&text).map_err(|_| anyhow!("wrap-kek requires role and [kms]"))?;
        config
            .kms
            .resolve(path.parent().unwrap_or(Path::new(".")))?;
        Ok(config)
    }

    async fn write(
        &self,
        version: i32,
        http: &Http,
        events: &dyn Events,
        mut output: impl Write,
    ) -> Result<()> {
        ensure!(version > 0, "KEK version must be in 1..=2147483647");
        let aad = wrapped::aad(self.role, version);
        let ciphertext = run_until(Instant::now() + BUDGET, "kms_wrap_failed", events, async {
            let key = self.kms.authenticate(http).await?;
            let mut plain = Zeroizing::new([0; 32]);
            getrandom::fill(plain.as_mut()).map_err(|_| Failure::new("generate"))?;
            let ciphertext = key.encrypt(&plain, aad.as_bytes()).await?;
            if key.decrypt(&ciphertext, aad.as_bytes()).await?.as_ref() != plain.as_ref() {
                return Err(Failure::invalid_response("decrypt"));
            }
            Ok(ciphertext)
        })
        .await?;
        output.write_all(&wrapped::encode(self.role, version, &ciphertext)?)?;
        Ok(())
    }
}

pub async fn wrap_kek(path: &Path, version: i32, output: impl Write) -> Result<()> {
    let config = WrapConfig::read(path)?;
    let http = Http::google(config.kms.egress_proxy.clone())?;
    config.write(version, &http, &Observer, output).await
}

#[cfg(test)]
mod tests;
