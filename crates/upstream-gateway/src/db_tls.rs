//! PostgreSQL negotiates TLS on the database socket before sending its startup message.
use crate::Mode;
use anyhow::{Result, anyhow, ensure};
use futures_util::future::BoxFuture;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, ring, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use std::{
    io,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::{
    Config, Socket,
    config::{Host, SslMode, SslNegotiation},
    tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream},
};
use tokio_rustls::{TlsConnector, client};

#[derive(Clone)]
pub(super) struct DatabaseTls(TlsConnector);

impl DatabaseTls {
    pub(super) fn configure(
        config: &Config,
        mode: Mode,
        ca: Option<&Path>,
    ) -> Result<Option<Self>> {
        if matches!(mode, Mode::Production) {
            ensure!(
                ca.is_some() && config.get_ssl_mode() == SslMode::Require,
                "production requires database_ca_file and sslmode=require"
            );
        }
        if config.get_ssl_mode() != SslMode::Require {
            ensure!(ca.is_none(), "database_ca_file requires sslmode=require");
            return Ok(None);
        }
        let [Host::Tcp(host)] = config.get_hosts() else {
            anyhow::bail!("database TLS requires a single TCP host");
        };
        ensure!(
            config.get_hostaddrs().len() <= 1 && config.get_ports().len() <= 1,
            "database TLS requires a single TCP host"
        );
        ServerName::try_from(host.as_str()).map_err(|_| anyhow!("invalid database TLS host"))?;

        let provider = ring::default_provider();
        let algorithms = provider.signature_verification_algorithms;
        let builder = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?;
        let mut tls = match ca {
            Some(path) => builder.with_root_certificates(
                crate::tls::roots(path).map_err(|_| anyhow!("invalid database CA bundle"))?,
            ),
            None => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(EncryptionOnly(algorithms))),
        }
        .with_no_client_auth();
        if config.get_ssl_negotiation() == SslNegotiation::Direct {
            tls.alpn_protocols.push(b"postgresql".to_vec());
        }
        Ok(Some(Self(TlsConnector::from(Arc::new(tls)))))
    }
}

// Development sslmode=require still authenticates the handshake signature with the peer's key.
#[derive(Debug)]
struct EncryptionOnly(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for EncryptionOnly {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(msg, cert, sig, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(msg, cert, sig, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

pub(super) struct Connect(TlsConnector, ServerName<'static>);

impl MakeTlsConnect<Socket> for DatabaseTls {
    type Stream = Stream;
    type TlsConnect = Connect;
    type Error = io::Error;

    fn make_tls_connect(&mut self, domain: &str) -> io::Result<Connect> {
        let name = ServerName::try_from(domain.to_owned())
            .map_err(|_| io::Error::other("invalid database TLS host"))?;
        Ok(Connect(self.0.clone(), name))
    }
}

impl TlsConnect<Socket> for Connect {
    type Stream = Stream;
    type Error = io::Error;
    type Future = BoxFuture<'static, io::Result<Stream>>;

    fn connect(self, socket: Socket) -> Self::Future {
        Box::pin(async move {
            self.0
                .connect(self.1, socket)
                .await
                .map(Stream)
                .map_err(|_| io::Error::other("database TLS handshake failed"))
        })
    }
}

pub(super) struct Stream(client::TlsStream<Socket>);

impl TlsStream for Stream {
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests;
