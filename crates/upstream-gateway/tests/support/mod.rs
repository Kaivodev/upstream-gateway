use anyhow::{Result, anyhow, ensure};
use bytes::BufMut;
use futures_util::FutureExt;
use prost::{Message, Name};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, SanType,
};
use std::{
    fs,
    net::SocketAddr,
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    panic::AssertUnwindSafe,
    path::{Path, PathBuf},
    process::{Child, Command},
    time::Duration,
};
use tempfile::TempDir;
use tonic::{
    Code, Request, Status,
    codec::{Codec, EncodeBuf, Encoder},
    transport::{Certificate as Trust, Channel, ClientTlsConfig, Endpoint, Identity},
};
use upstream_gateway::api::*;
use uuid::Uuid;

pub fn uid() -> String {
    Uuid::now_v7().to_string()
}
pub struct Authority {
    pub cert: Certificate,
    issuer: Issuer<'static, KeyPair>,
}
impl Authority {
    pub fn new() -> Result<Self> {
        let mut ca = CertificateParams::new(vec![])?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate()?;
        Ok(Self {
            cert: ca.self_signed(&key)?,
            issuer: Issuer::new(ca, key),
        })
    }
    pub fn leaf(&self, uris: &[String], server: bool) -> Result<(Certificate, KeyPair)> {
        let mut p = CertificateParams::new(vec!["localhost".into()])?;
        for uri in uris {
            p.subject_alt_names
                .push(SanType::URI(uri.as_str().try_into()?));
        }
        p.extended_key_usages.push(if server {
            ExtendedKeyUsagePurpose::ServerAuth
        } else {
            ExtendedKeyUsagePurpose::ClientAuth
        });
        let k = KeyPair::generate()?;
        Ok((p.signed_by(&k, &self.issuer)?, k))
    }
}
pub fn spiffe(name: &str) -> String {
    format!("spiffe://aipay.internal/service/{name}")
}
pub struct Instance {
    pub ca: Authority,
    pub addr: SocketAddr,
    pub role: &'static str,
    pub schema: String,
    pub db: deadpool_postgres::Pool,
    pub dir: TempDir,
    url: String,
    child: Option<Child>,
}
impl Drop for Instance {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl Instance {
    pub fn config(&self) -> PathBuf {
        self.dir.path().join("gateway.toml")
    }
    pub fn owner(&self) -> &'static str {
        if self.role == "trade" {
            "payment"
        } else {
            "reconciliation"
        }
    }
    fn new(role: &'static str, schema: String, url: &str) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let ca = Authority::new()?;
        let (cert, key) = ca.leaf(&[spiffe(&format!("upstream-gateway-{role}"))], true)?;
        fs::write(dir.path().join("ca"), ca.cert.pem())?;
        fs::write(dir.path().join("cert"), cert.pem())?;
        fs::write(dir.path().join("key"), key.serialize_pem())?;
        let mut kek = [0u8; 32];
        getrandom::fill(&mut kek)?;
        let kek_file = dir.path().join("kek");
        fs::write(&kek_file, kek)?;
        fs::set_permissions(kek_file, fs::Permissions::from_mode(0o600))?;
        let addr = std::net::TcpListener::bind(("127.0.0.1", 0))?.local_addr()?;
        let delim = if url.contains('?') { '&' } else { '?' };
        let url = format!("{url}{delim}options=-csearch_path%3D{schema}");
        let db = upstream_gateway::pool(url.parse()?)?;
        let result = Self {
            ca,
            addr,
            role,
            schema,
            db,
            dir,
            url,
            child: None,
        };
        fs::write(
            result.config(),
            format!(
                r#"
role="{role}"
mode="development"
listen="{addr}"
allowed_peers=["{}"]
database_url_env="GATEWAY_TEST_DSN"
local_kek_file="kek"
allow_loopback_http=true
allow_uncommitted=true
[tls]
trust_domain="aipay.internal"
ca_file="ca"
cert_file="cert"
key_file="key"
[timing]
heartbeat_ms=100
fence_ms=1500
"#,
                result.owner()
            ),
        )?;
        Ok(result)
    }
    pub fn spawn(&mut self) -> Result<()> {
        self.child = Some(
            Command::new(env!("CARGO_BIN_EXE_upstream-gateway"))
                .arg("--config")
                .arg(self.config())
                .env("GATEWAY_TEST_DSN", &self.url)
                .spawn()?,
        );
        Ok(())
    }
    pub async fn start(&mut self) -> Result<Rpc> {
        self.spawn()?;
        let (cert, key) = self.ca.leaf(&[spiffe(self.owner())], false)?;
        tokio::time::timeout(Duration::from_secs(45), async {
            loop {
                if let Some(status) = self.child.as_mut().unwrap().try_wait()? {
                    anyhow::bail!("gateway exited {status}");
                }
                if let Ok(rpc) = self.connect(&cert, &key).await {
                    let reply: Result<GetExchangeResponse, _> =
                        rpc.call(GetExchangeRequest { exchange_id: uid() }).await;
                    if reply.is_err_and(|s| s.code() == Code::NotFound) {
                        return Ok(rpc);
                    }
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        })
        .await?
    }
    pub async fn connect(&self, cert: &Certificate, key: &KeyPair) -> Result<Rpc> {
        let tls = ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(Trust::from_pem(self.ca.cert.pem()))
            .identity(Identity::from_pem(cert.pem(), key.serialize_pem()));
        let chan = Endpoint::from_shared(format!("https://{}", self.addr))?
            .tls_config(tls)?
            .connect_timeout(Duration::from_secs(3))
            .connect()
            .await?;
        Ok(Rpc(chan))
    }
    pub fn kill(&mut self) -> Result<()> {
        let mut child = self.child.take().ok_or_else(|| anyhow!("no child"))?;
        child.kill()?;
        ensure!(child.wait()?.signal() == Some(9));
        Ok(())
    }
    pub async fn stop(&mut self, success: bool) -> Result<()> {
        self.signal_term()?;
        self.wait_exit(success).await
    }
    pub fn signal_term(&self) -> Result<()> {
        let child = self.child.as_ref().unwrap();
        ensure!(
            Command::new("kill")
                .args(["-TERM", &child.id().to_string()])
                .status()?
                .success()
        );
        Ok(())
    }
    pub async fn wait_exit(&mut self, success: bool) -> Result<()> {
        let child = self.child.as_mut().unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let Some(status) = child.try_wait()? {
                    ensure!(status.success() == success);
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await??;
        self.child = None;
        Ok(())
    }
}

pub async fn instances<F>(roles: &[&'static str], test: F) -> Result<()>
where
    F: AsyncFnOnce(&mut [Instance]) -> Result<()>,
{
    let url = std::env::var("AIPAY_TEST_DATABASE_URL")?;
    let admin = upstream_gateway::pool(url.parse()?)?;
    let client = admin.get().await?;
    let mut instances = vec![];
    for &role in roles {
        instances.push(Instance::new(
            role,
            format!("edge_{}", Uuid::now_v7().simple()),
            &url,
        )?);
    }
    let schemas = instances
        .iter()
        .map(|i| i.schema.clone())
        .collect::<Vec<_>>();
    let create = schemas
        .iter()
        .map(|s| format!("CREATE SCHEMA {s};"))
        .collect::<String>();
    client.batch_execute(&create).await?;
    let outcome = AssertUnwindSafe(test(&mut instances)).catch_unwind().await;
    drop(instances);
    for s in schemas {
        client
            .batch_execute(&format!("DROP SCHEMA {s} CASCADE"))
            .await?;
    }
    match outcome {
        Ok(r) => r,
        Err(p) => std::panic::resume_unwind(p),
    }
}

#[derive(Clone)]
pub struct Rpc(pub Channel);

impl Rpc {
    pub async fn check_serving(&self) -> Result<()> {
        #[derive(Clone, prost::Message)]
        struct HealthCheckResponse {
            #[prost(int32, tag = "1")]
            status: i32,
        }
        let mut grpc = tonic::client::Grpc::new(self.0.clone());
        grpc.ready().await?;
        let reply: tonic::Response<HealthCheckResponse> = grpc
            .unary(
                Request::new(()),
                "/grpc.health.v1.Health/Check".parse()?,
                tonic_prost::ProstCodec::default(),
            )
            .await?;
        ensure!(reply.get_ref().status == 1, "expected SERVING");
        Ok(())
    }
}

struct Raw<U>(std::marker::PhantomData<U>);
struct BytesEncoder;
impl Encoder for BytesEncoder {
    type Item = Vec<u8>;
    type Error = Status;
    fn encode(&mut self, item: Vec<u8>, buf: &mut EncodeBuf<'_>) -> Result<(), Status> {
        buf.put_slice(&item);
        Ok(())
    }
}
impl<U: Message + Default + Send + 'static> Codec for Raw<U> {
    type Encode = Vec<u8>;
    type Decode = U;
    type Encoder = BytesEncoder;
    type Decoder = tonic_prost::ProstDecoder<U>;
    fn encoder(&mut self) -> BytesEncoder {
        BytesEncoder
    }
    fn decoder(&mut self) -> Self::Decoder {
        Default::default()
    }
}
impl Rpc {
    pub async fn raw<U: Message + Default + Send + 'static>(
        &self,
        service: &str,
        method: &str,
        bytes: Vec<u8>,
        assertion: bool,
    ) -> Result<U, Status> {
        let mut grpc = tonic::client::Grpc::new(self.0.clone())
            .max_decoding_message_size(16 << 20)
            .max_encoding_message_size((16 << 20) + 1);
        grpc.ready()
            .await
            .map_err(|_| Status::unavailable("channel unavailable"))?;
        let mut req = Request::new(bytes);
        req.set_timeout(Duration::from_secs(55));
        if assertion {
            req.metadata_mut()
                .insert("x-aipay-assertion", "".parse().unwrap());
        }
        let path = format!("/aipay.upstream.v1.{service}/{method}")
            .parse()
            .unwrap();
        Ok(grpc
            .unary(req, path, Raw(std::marker::PhantomData))
            .await?
            .into_inner())
    }
    pub async fn call<M: Message + Name, U: Message + Default + Send + 'static>(
        &self,
        req: M,
    ) -> Result<U, Status> {
        let method = M::NAME.strip_suffix("Request").unwrap();
        let service = match method {
            "ReplayPackage" | "RegisterPackage" | "RevokePackage" | "StoreCredentials"
            | "GetExchange" => "UpstreamAdminService",
            _ => "UpstreamService",
        };
        self.raw(service, method, req.encode_to_vec(), false).await
    }
}
pub fn packages() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .join("dist/packages")
}
pub mod simulator;
pub mod token;
