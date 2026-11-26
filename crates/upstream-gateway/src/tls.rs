use crate::{Role, config::Tls};
use anyhow::{Result, anyhow, ensure};
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error, RootCertStore, ServerConfig,
    SignatureScheme,
    client::{danger::HandshakeSignatureValid, verify_server_cert_signed_by_trust_anchor},
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject},
    server::{
        ParsedCertificate, WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};
use std::{
    io,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tonic::transport::server::Connected;
use x509_parser::{extensions::GeneralName, prelude::*};

#[derive(Clone)]
pub struct VerifiedCaller {
    name: String,
    deadline: Instant,
}
impl VerifiedCaller {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    #[cfg(test)]
    pub(crate) fn for_test(name: &str, deadline: Instant) -> Self {
        Self {
            name: name.into(),
            deadline,
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Peer(String);
impl Peer {
    pub(crate) fn new(name: &str) -> Self {
        Self(name.to_owned())
    }
    pub(crate) fn name(&self) -> &str {
        &self.0
    }
    pub fn caller(&self, budget: Duration) -> VerifiedCaller {
        VerifiedCaller {
            name: self.0.clone(),
            deadline: Instant::now() + budget,
        }
    }
}
fn identity(cert: &CertificateDer<'_>, domain: &str, name: &str) -> Result<Peer, Error> {
    let invalid = || Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure);
    let (rest, cert) = parse_x509_certificate(cert.as_ref()).map_err(|_| invalid())?;
    let san = cert
        .subject_alternative_name()
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    let mut uris = san.value.general_names.iter().filter_map(|n| match n {
        GeneralName::URI(v) => Some(*v),
        _ => None,
    });
    let found = uris
        .next()
        .and_then(|uri| uri.strip_prefix(&format!("spiffe://{domain}/service/")))
        .ok_or_else(invalid)?;
    if !rest.is_empty() || found != name || uris.next().is_some() {
        return Err(invalid());
    }
    Ok(Peer::new(found))
}

#[derive(Debug)]
struct Verifier {
    chain: Arc<dyn ClientCertVerifier>,
    domain: String,
    name: &'static str,
}
impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.chain.root_hint_subjects()
    }
    fn verify_client_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        let valid = self.chain.verify_client_cert(leaf, chain, now)?;
        identity(leaf, &self.domain, self.name)?;
        Ok(valid)
    }
    fn verify_tls12_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.chain.verify_tls12_signature(msg, cert, sig)
    }
    fn verify_tls13_signature(
        &self,
        msg: &[u8],
        cert: &CertificateDer<'_>,
        sig: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.chain.verify_tls13_signature(msg, cert, sig)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.chain.supported_verify_schemes()
    }
}
pub(crate) fn roots(path: &Path) -> Result<RootCertStore> {
    parse_roots(&std::fs::read(path)?)
}
fn parse_roots(pem: &[u8]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        roots.add(cert?)?;
    }
    ensure!(!roots.is_empty(), "empty trust bundle");
    Ok(roots)
}
#[derive(Clone)]
pub(crate) struct Material {
    accept: TlsAcceptor,
    verifier: Arc<Verifier>,
    fingerprint: [u8; 32],
    client_auth: bool,
}
impl Material {
    pub fn load(config: &Tls, role: Role) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        use sha2::{Digest, Sha256};
        let ca = std::fs::read(&config.ca_file)?;
        let certificates = std::fs::read(&config.cert_file)?;
        let key = zeroize::Zeroizing::new(std::fs::read(&config.key_file)?);
        let mut digest = Sha256::new();
        for file in [&ca, &certificates, &*key] {
            digest.update(Sha256::digest(file));
        }
        let roots = Arc::new(parse_roots(&ca)?);
        let certs = CertificateDer::pem_slice_iter(&certificates).collect::<Result<Vec<_>, _>>()?;
        let (leaf, intermediates) = certs
            .split_first()
            .ok_or_else(|| anyhow!("missing server certificate"))?;
        identity(
            leaf,
            &config.trust_domain,
            &format!("upstream-gateway-{}", role.name()),
        )?;
        verify_server_cert_signed_by_trust_anchor(
            &ParsedCertificate::try_from(leaf)?,
            &roots,
            intermediates,
            UnixTime::now(),
            provider.signature_verification_algorithms.all,
        )?;
        let chain = WebPkiClientVerifier::builder_with_provider(roots, provider.clone()).build()?;
        let client_auth = chain
            .verify_client_cert(leaf, intermediates, UnixTime::now())
            .is_ok();
        let verifier = Arc::new(Verifier {
            chain,
            domain: config.trust_domain.clone(),
            name: role.caller(),
        });
        let mut tls = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_client_cert_verifier(verifier.clone())
            .with_single_cert(certs, PrivateKeyDer::from_pem_slice(&key)?)?;
        tls.alpn_protocols = vec![b"h2".to_vec()];
        tls.send_tls13_tickets = 0;
        Ok(Self {
            accept: TlsAcceptor::from(Arc::new(tls)),
            verifier,
            fingerprint: digest.finalize().into(),
            client_auth,
        })
    }
    pub fn reload(&self, config: &Tls, role: Role) -> Result<Option<Self>> {
        let next = Self::load(config, role)?;
        ensure!(
            !self.client_auth || next.client_auth,
            "TLS key usage downgraded"
        );
        Ok((self.fingerprint != next.fingerprint).then_some(next))
    }
    pub async fn handshake(&self, socket: TcpStream) -> io::Result<Connection> {
        let stream =
            tokio::time::timeout(Duration::from_secs(5), self.accept.accept(socket)).await??;
        if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(io::Error::other("HTTP/2 required"));
        }
        let leaf = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|chain| chain.first())
            .ok_or_else(|| io::Error::other("missing verified peer"))?;
        let peer =
            identity(leaf, &self.verifier.domain, self.verifier.name).map_err(io::Error::other)?;
        Ok(Connection { stream, peer })
    }
}
pub(crate) struct Connection {
    stream: TlsStream<TcpStream>,
    peer: Peer,
}
impl Connected for Connection {
    type ConnectInfo = Peer;
    fn connect_info(&self) -> Peer {
        self.peer.clone()
    }
}
impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
