use super::*;
use crate::db::{Db, configured_pool};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
use std::fs;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

const DEV: Mode = Mode::Development {
    allow_loopback_http: false,
    allow_private_http: false,
    allow_uncommitted: false,
};

fn authority() -> Result<(String, Issuer<'static, KeyPair>)> {
    let mut params = CertificateParams::new(vec![])?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate()?;
    Ok((params.self_signed(&key)?.pem(), Issuer::new(params, key)))
}

#[test]
fn database_transport_matrix() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let ca = dir.path().join("ca");
    fs::write(&ca, authority()?.0)?;
    for query in [
        "",
        "?sslmode=disable",
        "?sslmode=prefer",
        "?sslmode=require",
    ] {
        let required = query == "?sslmode=require";
        let config: Config = format!("postgres://db.test/data{query}").parse()?;
        for file in [None, Some(ca.as_path())] {
            for mode in [DEV, Mode::Production] {
                let result = DatabaseTls::configure(&config, mode, file);
                if matches!(mode, Mode::Production) && file.is_none() || file.is_some() && !required
                {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result?.is_some(), required);
                }
            }
        }
    }
    let required: Config = "postgres://db.test/data?sslmode=require".parse()?;
    for bytes in ["", "not a PEM certificate"] {
        fs::write(&ca, bytes)?;
        let error = DatabaseTls::configure(&required, Mode::Production, Some(&ca))
            .err()
            .unwrap();
        assert_eq!(error.to_string(), "invalid database CA bundle");
    }
    Ok(())
}

#[test]
fn database_tls_requires_one_named_tcp_host() -> Result<()> {
    for url in [
        "postgres://a,b/data",
        "postgres://%2Fvar%2Frun%2Fpostgresql/data",
        "postgres:///data?hostaddr=127.0.0.1",
        "postgres://a/data?hostaddr=127.0.0.1,127.0.0.2",
        "postgres://a/data?host=b",
    ] {
        let mut config: Config = url.parse()?;
        assert!(DatabaseTls::configure(&config, DEV, None)?.is_none());
        config.ssl_mode(SslMode::Require);
        assert!(DatabaseTls::configure(&config, DEV, None).is_err());
    }
    for host in ["cluster.db.test", "127.0.0.1", "[::1]"] {
        let config = format!("postgres://{host}/data?sslmode=require").parse()?;
        assert!(DatabaseTls::configure(&config, DEV, None)?.is_some());
    }
    Ok(())
}

#[tokio::test]
async fn ssl_request_verifies_the_database_host_and_only_configured_roots() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let trusted = dir.path().join("trusted");
    let unrelated = dir.path().join("unrelated");
    let (pem, ca) = authority()?;
    fs::write(&trusted, pem)?;
    fs::write(&unrelated, authority()?.0)?;
    let key = KeyPair::generate()?;
    let leaf = CertificateParams::new(vec!["cluster.db.test".to_owned(), "127.0.0.1".to_owned()])?
        .signed_by(&key, &ca)?;

    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let server = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(&[version])?
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )?;
        let acceptor = TlsAcceptor::from(Arc::new(server));
        for (host, bundle, accepted) in [
            ("cluster.db.test", Some(trusted.as_path()), true),
            ("127.0.0.1", Some(trusted.as_path()), true),
            ("wrong.db.test", Some(trusted.as_path()), false),
            ("127.0.0.2", Some(trusted.as_path()), false),
            ("cluster.db.test", Some(unrelated.as_path()), false),
            ("wrong.db.test", None, true),
        ] {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
            let port = listener.local_addr()?.port();
            let accept = acceptor.clone();
            let server = async move {
                let (mut socket, _) = listener.accept().await?;
                let mut request = [0; 8];
                socket.read_exact(&mut request).await?;
                assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
                socket.write_all(b"S").await?;
                let Ok(mut stream) = accept.accept(socket).await else {
                    return Ok::<_, anyhow::Error>(false);
                };
                let size = stream.read_u32().await?;
                ensure!((8..=2048).contains(&size), "invalid startup packet size");
                let mut startup = vec![0; (size - 4) as usize];
                stream.read_exact(&mut startup).await?;
                assert_eq!(&startup[..4], &[0, 3, 0, 0]);
                // AuthenticationOk and ReadyForQuery complete the synthetic login.
                stream.write_all(b"R\0\0\0\x08\0\0\0\0Z\0\0\0\x05I").await?;
                stream.shutdown().await?;
                Ok(true)
            };
            // hostaddr fixes the local socket destination; host supplies the certificate identity.
            let config =
                format!("postgres://pilot@{host}:{port}/pilot?hostaddr=127.0.0.1&sslmode=require")
                    .parse()?;
            let mode = if bundle.is_some() {
                Mode::Production
            } else {
                DEV
            };
            let pool = configured_pool(config, mode, bundle, 16)?;
            let (server_result, client) =
                tokio::time::timeout(std::time::Duration::from_secs(5), async {
                    tokio::join!(server, pool.get())
                })
                .await?;
            assert_eq!(server_result?, accepted, "{host}");
            let client = client.db();
            assert_eq!(client.is_ok(), accepted, "{host}");
            if let Err(status) = client {
                assert_eq!(status.message(), "gateway storage unavailable");
            }
        }
    }
    Ok(())
}
