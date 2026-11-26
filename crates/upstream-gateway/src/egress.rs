use crate::Mode;
use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, Uri, body::Incoming as Body, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use std::{
    future::Future,
    io::{self, Cursor, Read},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, lookup_host},
    runtime::Handle,
    task::JoinHandle,
};
use tokio_rustls::TlsConnector;
use upstream_host::{
    environment::{AddressForbidden, Cancellation, Connection, Incoming, Transport, WireIncoming},
    types::HttpRequest,
};

const HEAD_LIMIT: usize = 16 << 10;
const BODY_LIMIT: usize = 256 << 10;

pub struct Egress {
    runtime: Handle,
    mode: Mode,
    proxy: Option<ProxyAddress>,
    tls: TlsConnector,
    #[cfg(test)]
    direct_dials: std::sync::atomic::AtomicUsize,
    /// Test seam: a direct TCP handshake that never completes.
    #[cfg(test)]
    stall_direct_connect: std::sync::atomic::AtomicBool,
}
pub(crate) trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub(crate) type Socket = Box<dyn Stream>;

fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, c, _] = v.octets();
            !matches!(a, 0 | 10 | 127 | 224..=255)
                && !(a == 100 && (64..128).contains(&b))
                && !(a == 169 && b == 254)
                && !(a == 172 && (16..32).contains(&b))
                && !(a == 192 && (b == 168 || b == 0 && matches!(c, 0 | 2) || b == 88 && c == 99))
                && !(a == 198 && (matches!(b, 18 | 19) || b == 51 && c == 100))
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(v) => {
            let [a, b, ..] = v.segments();
            (a & 0xe000) == 0x2000
                && !(a == 0x2001 && (b < 0x200 || b == 0xdb8))
                && a != 0x2002
                && !(a == 0x3fff && b < 0x1000)
        }
    }
}
fn allowed_address(ip: IpAddr, tls: bool, mode: Mode) -> bool {
    if tls && public(ip) {
        return true;
    }
    let Mode::Development {
        allow_private_http,
        allow_loopback_http,
        ..
    } = mode
    else {
        return false;
    };
    allow_loopback_http && ip.is_loopback()
        || allow_private_http
            && match ip {
                IpAddr::V4(ip) => ip.is_private(),
                IpAddr::V6(ip) => ip.is_unique_local(),
            }
}

fn direct_target(addresses: &[SocketAddr], tls: bool, mode: Mode) -> Result<SocketAddr> {
    let target = *addresses.first().context("no upstream address")?;
    ensure!(
        addresses.iter().all(|a| allowed_address(a.ip(), tls, mode)),
        AddressForbidden
    );
    Ok(target)
}
pub(crate) struct Driver(JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort()
    }
}
struct Partial;
impl Read for Partial {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("incomplete response"))
    }
}

async fn bounded<T>(
    deadline: Instant,
    cancel: &Cancellation,
    work: impl Future<Output = Result<T>>,
) -> Result<T> {
    let deadline = cancel.deadline.map_or(deadline, |d| d.min(deadline));
    if cancel.cancelled() || Instant::now() >= deadline {
        bail!("exchange expired")
    }
    tokio::select! {
        biased;
        _=tokio::time::sleep_until(deadline.into())=>bail!("exchange expired"),
        _=async{while !cancel.cancelled(){tokio::time::sleep(Duration::from_millis(5)).await}}=>bail!("exchange cancelled"),
        result=work=>result,
    }
}

pub(crate) async fn request(
    socket: Socket,
    req: Request<Full<Bytes>>,
    upgrade: bool,
) -> Result<(Response<Body>, Driver)> {
    let (mut sender, connection) = http1::Builder::new()
        .max_buf_size(HEAD_LIMIT)
        .max_headers(HEAD_LIMIT / 4)
        .handshake(TokioIo::new(socket))
        .await?;
    let driver = Driver(tokio::spawn(async move {
        if upgrade {
            let _ = connection.with_upgrades().await;
        } else {
            let _ = connection.await;
        }
    }));
    let response = sender.send_request(req).await?;
    Ok((response, driver))
}
/// A trusted CONNECT proxy. DNS is resolved anew for each connection.
#[derive(Clone, serde::Deserialize)]
#[serde(try_from = "String")]
pub(crate) struct ProxyAddress(String);

impl From<SocketAddr> for ProxyAddress {
    fn from(address: SocketAddr) -> Self {
        Self(address.to_string())
    }
}

impl TryFrom<String> for ProxyAddress {
    type Error = &'static str;

    fn try_from(address: String) -> Result<Self, Self::Error> {
        let invalid = "invalid proxy host:port";
        let (host, port) = address.rsplit_once(':').ok_or(invalid)?;
        if !port.bytes().all(|b| b.is_ascii_digit()) || !matches!(port.parse::<u16>(), Ok(1..)) {
            return Err(invalid);
        }
        let dns = host.strip_suffix('.').unwrap_or(host);
        if address.parse::<SocketAddr>().is_err()
            && !upstream_host::package::domain(&dns.to_ascii_lowercase())
        {
            return Err(invalid);
        }
        Ok(Self(address))
    }
}

impl ProxyAddress {
    pub(crate) async fn tunnel(&self, host: &str, port: u16) -> Result<Socket> {
        let stream = Box::new(TcpStream::connect(self.0.as_str()).await?);
        let target = format!("{host}:{port}");
        let connect = Request::connect(target.as_str())
            .header("host", &target)
            .body(Full::new(Bytes::new()))?;
        let (mut response, _driver) = request(stream, connect, true).await?;
        if !response.status().is_success() {
            return Err(anyhow::Error::msg(response.status()).context("proxy refused tunnel"));
        }
        Ok(Box::new(TokioIo::new(
            hyper::upgrade::on(&mut response).await?,
        )))
    }
}

pub(crate) fn tls_connector(roots: RootCertStore) -> Result<TlsConnector> {
    ensure!(!roots.is_empty(), "empty upstream trust store");
    let tls =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(tls)))
}

#[derive(PartialEq, Eq)]
struct Origin {
    host: String,
    port: u16,
    tls: bool,
}
impl Origin {
    fn parse(url: &str, allow_http: bool) -> Result<(Self, Uri)> {
        let host = upstream_host::http::url(url, allow_http).map_err(|_| AddressForbidden)?;
        let uri: Uri = url.parse()?;
        let tls = uri.scheme_str() == Some("https");
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        Ok((
            Self {
                host: host.into(),
                port,
                tls,
            },
            uri,
        ))
    }
}

struct Opened<'a> {
    egress: &'a Egress,
    origin: Origin,
    socket: Socket,
}

impl Egress {
    pub fn new(
        runtime: Handle,
        mode: Mode,
        proxy: Option<SocketAddr>,
        roots: RootCertStore,
    ) -> Result<Self> {
        Self::with_proxy(runtime, mode, proxy.map(ProxyAddress::from), roots)
    }
    pub(crate) fn with_proxy(
        runtime: Handle,
        mode: Mode,
        proxy: Option<ProxyAddress>,
        roots: RootCertStore,
    ) -> Result<Self> {
        let tls = tls_connector(roots)?;
        Ok(Self {
            runtime,
            mode,
            proxy,
            tls,
            #[cfg(test)]
            direct_dials: Default::default(),
            #[cfg(test)]
            stall_direct_connect: Default::default(),
        })
    }
    pub fn public_roots() -> RootCertStore {
        RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
    }
    async fn connect(&self, template: &HttpRequest) -> Result<Opened<'_>> {
        let (origin, _) = Origin::parse(&template.url, self.mode.allow_http())?;
        let host = origin.host.as_str();
        let port = origin.port;
        let mut stream: Socket = if let Some(proxy) = &self.proxy {
            proxy.tunnel(host, port).await?
        } else {
            let addresses = lookup_host((host, port)).await?.collect::<Vec<_>>();
            let target = direct_target(&addresses, origin.tls, self.mode)?;
            #[cfg(test)]
            self.direct_dials
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            #[cfg(test)]
            if self
                .stall_direct_connect
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                std::future::pending::<()>().await;
            }
            Box::new(TcpStream::connect(target).await?)
        };
        if origin.tls {
            stream = Box::new(
                self.tls
                    .connect(ServerName::try_from(host.to_owned())?, stream)
                    .await?,
            );
        }
        Ok(Opened {
            egress: self,
            origin,
            socket: stream,
        })
    }
}
impl Opened<'_> {
    async fn start(self, r: &HttpRequest) -> Result<(Response<Body>, Driver)> {
        let (origin, uri) = Origin::parse(&r.url, self.egress.mode.allow_http())?;
        ensure!(origin == self.origin, "expanded request changed origin");
        let mut req = Request::builder()
            .method(r.method.as_str())
            .uri(uri.path_and_query().map_or("/", |v| v.as_str()))
            .header(
                "host",
                uri.authority().context("missing authority")?.as_str(),
            );
        for (name, values) in &r.headers {
            for value in values {
                req = req.header(name, value)
            }
        }
        request(
            self.socket,
            req.body(Full::new(Bytes::copy_from_slice(&r.body)))?,
            false,
        )
        .await
    }
    async fn exchange(
        self,
        r: &HttpRequest,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<WireIncoming> {
        let (response, _driver) = bounded(deadline, cancel, self.start(r)).await?;
        let status = response.status().as_u16();
        let mut headers = Vec::new();
        let mut header_bytes = 0;
        for name in response.headers().keys() {
            let values = response
                .headers()
                .get_all(name)
                .iter()
                .map(|v| v.as_bytes().to_vec())
                .collect::<Vec<_>>();
            header_bytes += values
                .iter()
                .map(|v| name.as_str().len() + v.len())
                .sum::<usize>();
            ensure!(header_bytes <= HEAD_LIMIT, "response headers too large");
            headers.push((name.to_string(), values))
        }
        let mut body = response.into_body();
        let mut data = Vec::new();
        let complete = bounded(deadline, cancel, async {
            while let Some(frame) = body.frame().await {
                if let Ok(bytes) = frame?.into_data() {
                    let left = BODY_LIMIT + 1 - data.len();
                    data.extend(&bytes[..left.min(bytes.len())]);
                    if data.len() > BODY_LIMIT {
                        break;
                    }
                }
            }
            Ok(())
        })
        .await
        .is_ok();
        let body: Box<dyn Read + Send> = if complete {
            Box::new(Cursor::new(data))
        } else {
            Box::new(Cursor::new(data).chain(Partial))
        };
        Ok(WireIncoming {
            status,
            headers,
            body,
        })
    }
}
impl Connection for Opened<'_> {
    fn send_wire(
        self: Box<Self>,
        _: &HttpRequest,
        r: &HttpRequest,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<WireIncoming> {
        self.egress
            .runtime
            .block_on(self.exchange(r, deadline, cancel))
    }
}
impl Transport for Egress {
    fn open(
        &self,
        template: &HttpRequest,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<Box<dyn Connection + '_>> {
        let opened = self
            .runtime
            .block_on(bounded(deadline, cancel, self.connect(template)))?;
        Ok(Box::new(opened))
    }

    fn send_wire(
        &self,
        template: &HttpRequest,
        r: &HttpRequest,
        deadline: Instant,
        cancel: &Cancellation,
    ) -> Result<WireIncoming> {
        self.open(template, deadline, cancel)?
            .send_wire(template, r, deadline, cancel)
    }
    fn send(
        &self,
        t: &HttpRequest,
        r: &HttpRequest,
        d: Instant,
        c: &Cancellation,
    ) -> Result<Incoming> {
        let raw = self.send_wire(t, r, d, c)?;
        let headers = raw
            .headers
            .into_iter()
            .map(|(k, vs)| {
                Ok((
                    k,
                    vs.into_iter()
                        .map(String::from_utf8)
                        .collect::<Result<Vec<_>, _>>()?,
                ))
            })
            .collect::<Result<_>>()?;
        Ok(Incoming {
            status: raw.status,
            headers,
            body: raw.body,
        })
    }
}

#[cfg(test)]
mod tests;
