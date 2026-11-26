use super::*;
use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::TlsAcceptor;

fn dev() -> Mode {
    Mode::Development {
        allow_loopback_http: true,
        allow_private_http: false,
        allow_uncommitted: false,
    }
}
fn get(url: String) -> HttpRequest {
    HttpRequest {
        method: "GET".into(),
        url,
        headers: vec![],
        body: vec![],
    }
}
async fn head(s: &mut (impl AsyncRead + Unpin)) -> Result<String> {
    let mut b = Vec::new();
    while !b.ends_with(b"\r\n\r\n") {
        ensure!(b.len() < HEAD_LIMIT);
        b.push(s.read_u8().await?)
    }
    Ok(String::from_utf8(b)?)
}
#[test]
fn direct_egress_checks_every_address_for_each_scheme_and_switch() {
    for loopback in [false, true] {
        for private in [false, true] {
            let mode = Mode::Development {
                allow_private_http: private,
                allow_loopback_http: loopback,
                allow_uncommitted: false,
            };
            for tls in [false, true] {
                for (ips, allowed) in [
                    (&["127.0.0.1", "::1"][..], loopback),
                    (
                        &[
                            "10.0.0.0",
                            "10.255.255.255",
                            "172.16.0.0",
                            "172.31.255.255",
                            "192.168.0.1",
                            "fc00::1",
                            "fdff::1",
                        ],
                        private,
                    ),
                    (
                        &[
                            "8.8.8.8",
                            "2606:4700:4700::1111",
                            "172.15.255.255",
                            "172.32.0.0",
                        ],
                        tls,
                    ),
                    (
                        &[
                            "0.0.0.0",
                            "::",
                            "169.254.169.254",
                            "fe80::1",
                            "100.64.0.0",
                            "100.127.255.255",
                            "224.0.0.1",
                            "ff02::1",
                            "3fff::1",
                            "198.18.0.1",
                            "198.19.255.255",
                            "255.255.255.255",
                            "240.0.0.1",
                            "::ffff:10.0.0.1",
                        ],
                        false,
                    ),
                ] {
                    for ip in ips {
                        assert_eq!(
                            allowed_address(ip.parse().unwrap(), tls, mode),
                            allowed,
                            "{ip}"
                        );
                    }
                }
                let mixed = ["10.0.0.1:80", "169.254.169.254:80"].map(|s| s.parse().unwrap());
                assert!(direct_target(&mixed, tls, mode).is_err());
                assert!(direct_target(&[], tls, mode).is_err());
            }
        }
    }
}
#[test]
fn public_address_policy() {
    for s in [
        "127.0.0.1",
        "10.1.1.1",
        "100.127.1.1",
        "169.254.1.1",
        "172.31.0.1",
        "192.168.3.1",
        "198.19.0.1",
        "224.0.0.1",
        "::",
        "::1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "::ffff:8.8.8.8",
        "2002::1",
        "3fff::1",
    ] {
        assert!(!public(s.parse().unwrap()), "{s}");
    }
    assert!(public("8.8.8.8".parse().unwrap()));
    assert!(public("2606:4700:4700::1111".parse().unwrap()));
}
#[tokio::test]
async fn direct_tls_and_proxy_resolved_hostname() -> Result<()> {
    let cert = rcgen::generate_simple_self_signed(vec![
        "upstream.invalid".to_owned(),
        "127.0.0.1".to_owned(),
    ])?;
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone())?;
    let server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
            )?;
    let accept = TlsAcceptor::from(Arc::new(server));
    for proxy_port in [None, Some(443), Some(8443)] {
        let endpoint = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = endpoint.local_addr()?;
        let tls = accept.clone();
        let server = tokio::spawn(async move {
            let (mut s, _) = endpoint.accept().await?;
            if let Some(port) = proxy_port {
                let h = head(&mut s).await?;
                let line = h.lines().next().unwrap();
                ensure!(line == format!("CONNECT upstream.invalid:{port} HTTP/1.1"));
                ensure!(
                    h.lines()
                        .any(|v| v.eq_ignore_ascii_case(&format!("host: upstream.invalid:{port}")))
                );
                s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
            }
            let mut s = tls.accept(s).await?;
            if proxy_port.is_some() {
                ensure!(s.get_ref().1.server_name() == Some("upstream.invalid"));
            }
            let h = head(&mut s).await?;
            ensure!(h.starts_with("GET /pay?tag=one&tag=%zz HTTP/1.1\r\n"));
            s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Multi: a\r\nX-Multi: b\r\n\r\ntest",
            )
            .await?;
            s.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        });
        let e = Egress::with_proxy(
            Handle::current(),
            dev(),
            proxy_port
                .map(|_| ProxyAddress::try_from(format!("localhost:{}", addr.port())).unwrap()),
            roots.clone(),
        )?;
        let authority = match proxy_port {
            None => addr.to_string(),
            Some(443) => "upstream.invalid".to_owned(),
            Some(port) => format!("upstream.invalid:{port}"),
        };
        let r = get(format!("https://{authority}/pay?tag=one&tag=%zz"));
        let mut response = e
            .exchange(
                &r,
                Instant::now() + Duration::from_secs(3),
                &Default::default(),
            )
            .await?;
        let mut body = Vec::new();
        response.body.read_to_end(&mut body)?;
        assert_eq!(body, b"test");
        assert_eq!(response.status, 200);
        assert!(
            response
                .headers
                .iter()
                .any(|(k, v)| k == "x-multi" && *v == [b"a", b"b"])
        );
        server.await??;
    }
    Ok(())
}
async fn local(response: Vec<u8>, pause: Duration) -> Result<(String, JoinHandle<()>)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let job = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let _ = head(&mut s).await;
        let _ = s.write_all(&response).await;
        tokio::time::sleep(pause).await;
    });
    Ok((format!("http://{addr}/test"), job))
}
#[tokio::test]
async fn http_limits_redirect_deadline_and_cancellation() -> Result<()> {
    let e = Egress::new(Handle::current(), dev(), None, Egress::public_roots())?;
    let prod = Egress::new(
        Handle::current(),
        Mode::Production,
        None,
        Egress::public_roots(),
    )?;
    for url in [
        "https://127.0.0.1/test",
        "https://10.0.0.1/test",
        "http://example.test/",
    ] {
        assert!(
            prod.exchange(
                &get(url.into()),
                Instant::now() + Duration::from_secs(2),
                &Default::default()
            )
            .await
            .is_err()
        );
    }
    let (url, job) = local(
        b"HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n".to_vec(),
        Duration::ZERO,
    )
    .await?;
    let r = e
        .exchange(
            &get(url),
            Instant::now() + Duration::from_secs(2),
            &Default::default(),
        )
        .await?;
    assert_eq!(r.status, 302);
    job.await?;
    let mut large = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        BODY_LIMIT + 100
    )
    .into_bytes();
    large.resize(large.len() + BODY_LIMIT + 100, b'x');
    let (url, job) = local(large, Duration::ZERO).await?;
    let mut r = e
        .exchange(
            &get(url),
            Instant::now() + Duration::from_secs(2),
            &Default::default(),
        )
        .await?;
    let mut body = Vec::new();
    r.body.read_to_end(&mut body)?;
    assert_eq!(body.len(), BODY_LIMIT + 1);
    job.await?;
    let huge = format!(
        "HTTP/1.1 200 OK\r\nX-Large: {}\r\n\r\n",
        "a".repeat(HEAD_LIMIT)
    );
    let (url, job) = local(huge.into_bytes(), Duration::ZERO).await?;
    assert!(
        e.exchange(
            &get(url),
            Instant::now() + Duration::from_secs(2),
            &Default::default()
        )
        .await
        .is_err()
    );
    job.await?;
    for cancel in [false, true] {
        let (url, job) = local(
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc".to_vec(),
            Duration::from_secs(2),
        )
        .await?;
        let flag = Cancellation::default();
        let deadline = Instant::now()
            + if cancel {
                Duration::from_secs(4)
            } else {
                Duration::from_millis(120)
            };
        if cancel {
            let flag = flag.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(120)).await;
                flag.cancel();
            });
        }
        let mut response = e.exchange(&get(url), deadline, &flag).await?;
        let mut body = Vec::new();
        ensure!(response.body.read_to_end(&mut body).is_err() && body == b"abc");
        job.abort();
    }
    Ok(())
}
