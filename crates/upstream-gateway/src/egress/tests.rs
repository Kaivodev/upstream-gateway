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
async fn tls_and_pinned_connect_tunnel() -> Result<()> {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
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
    for proxy in [false, true] {
        let endpoint = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = endpoint.local_addr()?;
        let tls = accept.clone();
        let server = tokio::spawn(async move {
            let (mut s, _) = endpoint.accept().await?;
            if proxy {
                let h = head(&mut s).await?;
                let line = h.lines().next().unwrap();
                let dest = line
                    .strip_prefix("CONNECT ")
                    .unwrap()
                    .strip_suffix(" HTTP/1.1")
                    .unwrap()
                    .parse::<SocketAddr>()?;
                ensure!(dest.ip().is_loopback() && dest.port() == 443);
                s.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
            }
            let mut s = tls.accept(s).await?;
            if proxy {
                ensure!(s.get_ref().1.server_name() == Some("localhost"));
            }
            let h = head(&mut s).await?;
            ensure!(h.starts_with("GET /pay HTTP/1.1"));
            s.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Multi: a\r\nX-Multi: b\r\n\r\ntest",
            )
            .await?;
            s.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        });
        let e = Egress::new(
            Handle::current(),
            dev(),
            proxy.then_some(addr),
            roots.clone(),
        )?;
        let r = get(if proxy {
            "https://localhost/pay".into()
        } else {
            format!("https://{addr}/pay")
        });
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
