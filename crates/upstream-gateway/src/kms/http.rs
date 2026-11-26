use super::{Failure, LIMIT};
use crate::egress::{Egress, ProxyAddress, Socket, request, tls_connector};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode, body::Body, header::HeaderValue};
use rustls::pki_types::ServerName;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

pub(super) struct Http {
    proxy: Option<ProxyAddress>,
    tls: TlsConnector,
    #[cfg(test)]
    test_address: Option<std::net::SocketAddr>,
}

struct AttemptError {
    status: Option<u16>,
    retry: bool,
}

impl AttemptError {
    fn network() -> Self {
        Self {
            status: None,
            retry: true,
        }
    }
    fn http(status: StatusCode) -> Self {
        Self {
            status: Some(status.as_u16()),
            retry: matches!(status.as_u16(), 429 | 500 | 502 | 503 | 504),
        }
    }
}

impl Http {
    pub(super) fn google(proxy: Option<ProxyAddress>) -> anyhow::Result<Self> {
        Ok(Self {
            proxy,
            tls: tls_connector(Egress::public_roots())?,
            #[cfg(test)]
            test_address: None,
        })
    }

    #[cfg(test)]
    pub(super) fn local(
        proxy: Option<ProxyAddress>,
        roots: rustls::RootCertStore,
        address: std::net::SocketAddr,
    ) -> Self {
        Self {
            proxy,
            tls: tls_connector(roots).unwrap(),
            test_address: Some(address),
        }
    }

    async fn socket(&self, host: &'static str) -> Result<Socket, AttemptError> {
        let socket: Socket = if let Some(proxy) = &self.proxy {
            proxy.tunnel(host, 443).await.map_err(|err| {
                err.downcast_ref::<StatusCode>()
                    .copied()
                    .map_or_else(AttemptError::network, AttemptError::http)
            })?
        } else {
            #[cfg(test)]
            let direct = match self.test_address {
                Some(addr) => TcpStream::connect(addr).await,
                None => TcpStream::connect((host, 443)).await,
            };
            #[cfg(not(test))]
            let direct = TcpStream::connect((host, 443)).await;
            Box::new(direct.map_err(|_| AttemptError::network())?)
        };
        let name = ServerName::try_from(host).expect("fixed Google hostname");
        let tls = self
            .tls
            .connect(name, socket)
            .await
            .map_err(|_| AttemptError::network())?;
        Ok(Box::new(tls))
    }

    pub(super) async fn post(
        &self,
        step: &'static str,
        host: &'static str,
        path: &str,
        token: Option<&str>,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let content_type = if token.is_some() {
            "application/json"
        } else {
            "application/x-www-form-urlencoded"
        };
        let mut builder = Request::post(path)
            .header("host", host)
            .header("content-type", content_type);
        if let Some(token) = token {
            let mut value = Zeroizing::new(Vec::with_capacity(7 + token.len()));
            value.extend_from_slice(b"Bearer ");
            value.extend_from_slice(token.as_bytes());
            let mut header = HeaderValue::from_maybe_shared(Bytes::from_owner(value))
                .map_err(|_| Failure::new(step))?;
            header.set_sensitive(true);
            builder = builder.header("authorization", header);
        }
        // Bytes clones retain the zeroizing owner until the final HTTP driver releases it.
        let req = builder
            .body(Full::new(Bytes::from_owner(body)))
            .map_err(|_| Failure::new(step))?;
        let mut delay_ms = 200;
        for attempt in 1..=4 {
            let result =
                tokio::time::timeout(Duration::from_secs(10), self.attempt(host, req.clone()))
                    .await
                    .unwrap_or_else(|_| Err(AttemptError::network()));
            let error = match result {
                Ok(body) => return Ok(body),
                Err(error) => error,
            };
            if !error.retry || attempt == 4 {
                return Err(Failure {
                    step,
                    status: error.status,
                });
            }
            let half = delay_ms / 2;
            let jitter = getrandom::u64().map_err(|_| Failure::new(step))? % half;
            tokio::time::sleep(Duration::from_millis(half + jitter)).await;
            delay_ms = (2 * delay_ms).min(1000);
        }
        unreachable!()
    }

    async fn attempt(
        &self,
        host: &'static str,
        req: Request<Full<Bytes>>,
    ) -> Result<Zeroizing<Vec<u8>>, AttemptError> {
        let (response, _driver) = request(self.socket(host).await?, req, false)
            .await
            .map_err(|_| AttemptError::network())?;
        let status = response.status();
        let mut body = response.into_body();
        if status != StatusCode::OK || body.size_hint().lower() > LIMIT as u64 {
            return Err(AttemptError::http(status));
        }
        let mut data = Zeroizing::new(Vec::with_capacity(LIMIT));
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| AttemptError {
                status: Some(status.as_u16()),
                retry: true,
            })?;
            if let Ok(bytes) = frame.into_data() {
                if bytes.len() > LIMIT - data.len() {
                    return Err(AttemptError::http(status));
                }
                data.extend_from_slice(&bytes);
            }
        }
        Ok(data)
    }
}
