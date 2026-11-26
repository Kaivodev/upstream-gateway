use super::*;
use rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer};
use std::sync::atomic::Ordering;
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
fn send(
    e: &Egress,
    r: &HttpRequest,
    deadline: Instant,
    cancel: &Cancellation,
) -> Result<WireIncoming> {
    tokio::task::block_in_place(|| e.send_wire(r, r, deadline, cancel))
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}
fn open_error(e: &Egress, url: String, deadline: Instant, cancel: &Cancellation) -> anyhow::Error {
    tokio::task::block_in_place(|| e.open(&get(url), deadline, cancel))
        .err()
        .expect("open should fail")
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
fn test_tls(names: Vec<String>) -> Result<(TlsAcceptor, RootCertStore)> {
    let cert = rcgen::generate_simple_self_signed(names)?;
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
    Ok((TlsAcceptor::from(Arc::new(server)), roots))
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn direct_tls_and_proxy_resolved_hostname() -> Result<()> {
    let (accept, roots) = test_tls(vec!["upstream.invalid".into(), "127.0.0.1".into()])?;
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
        let mut response = send(
            &e,
            &r,
            Instant::now() + Duration::from_secs(3),
            &Default::default(),
        )?;
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
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
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
        "http://upstream.invalid/",
    ] {
        assert!(
            send(
                &prod,
                &get(url.into()),
                Instant::now() + Duration::from_secs(2),
                &Default::default()
            )
            .is_err()
        );
    }
    let (url, job) = local(
        b"HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n".to_vec(),
        Duration::ZERO,
    )
    .await?;
    let r = send(
        &e,
        &get(url),
        Instant::now() + Duration::from_secs(2),
        &Default::default(),
    )?;
    assert_eq!(r.status, 302);
    job.await?;
    let mut large = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        BODY_LIMIT + 100
    )
    .into_bytes();
    large.resize(large.len() + BODY_LIMIT + 100, b'x');
    let (url, job) = local(large, Duration::ZERO).await?;
    let mut r = send(
        &e,
        &get(url),
        Instant::now() + Duration::from_secs(2),
        &Default::default(),
    )?;
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
        send(
            &e,
            &get(url),
            Instant::now() + Duration::from_secs(2),
            &Default::default()
        )
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
        let mut response = send(&e, &get(url), deadline, &flag)?;
        let mut body = Vec::new();
        ensure!(response.body.read_to_end(&mut body).is_err() && body == b"abc");
        job.abort();
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forbidden_addresses_fail_open_before_tcp() -> Result<()> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let prod = Egress::new(
        Handle::current(),
        Mode::Production,
        None,
        Egress::public_roots(),
    )?;
    for url in [
        format!("https://198.18.0.161:{port}/"),
        format!("http://127.0.0.1:{port}/"),
    ] {
        assert!(
            open_error(&prod, url, deadline(), &Cancellation::default()).is::<AddressForbidden>()
        );
        assert_eq!(prod.direct_dials.load(Ordering::Relaxed), 0);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_failure_fails_open() -> Result<()> {
    let e = Egress::new(Handle::current(), dev(), None, Egress::public_roots())?;
    let err = open_error(
        &e,
        "http://unresolvable.invalid/".into(),
        deadline(),
        &Cancellation::default(),
    );
    assert!(err.is::<io::Error>() && !err.is::<AddressForbidden>());
    assert_eq!(e.direct_dials.load(Ordering::Relaxed), 0);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_tcp_fails_open() -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let url = format!("http://{}/", listener.local_addr()?);
    drop(listener);
    let e = Egress::new(Handle::current(), dev(), None, Egress::public_roots())?;
    let err = open_error(&e, url, deadline(), &Cancellation::default());
    assert_eq!(
        err.downcast::<io::Error>()?.kind(),
        io::ErrorKind::ConnectionRefused
    );
    assert_eq!(e.direct_dials.load(Ordering::Relaxed), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_connect_timeout_fails_open() -> Result<()> {
    // The listener exists, but the direct TCP handshake never completes, as when
    // SYNs are dropped on the path. Only the open deadline can end it.
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let e = Egress::new(Handle::current(), dev(), None, Egress::public_roots())?;
    e.stall_direct_connect.store(true, Ordering::Relaxed);
    let limit = Instant::now() + Duration::from_millis(250);
    let err = open_error(
        &e,
        format!("http://{addr}/pay"),
        limit,
        &Cancellation::default(),
    );
    let finished = Instant::now();
    assert_eq!(err.to_string(), "exchange expired");
    assert!(finished >= limit && finished < limit + Duration::from_secs(1));
    assert_eq!(e.direct_dials.load(Ordering::Relaxed), 1);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    Ok(())
}

async fn stalled_open(proxy: bool, cancel_during_setup: bool) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let flag = Cancellation::default();
    let peer_flag = flag.clone();
    let peer = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await?;
        if proxy {
            assert!(
                head(&mut s)
                    .await?
                    .starts_with("CONNECT upstream.invalid:443 HTTP/1.1\r\n")
            );
        } else {
            let mut header = [0; 5];
            s.read_exact(&mut header).await?;
            assert_eq!(header[0], 22); // TLS handshake record
            let mut hello = vec![0; u16::from_be_bytes([header[3], header[4]]) as usize];
            s.read_exact(&mut hello).await?;
            assert_eq!(hello[0], 1); // ClientHello
        }
        if cancel_during_setup {
            peer_flag.cancel();
        }
        let mut trailing = Vec::new();
        s.read_to_end(&mut trailing).await?;
        assert!(trailing.is_empty());
        Ok::<_, anyhow::Error>(())
    });
    let e = Egress::new(
        Handle::current(),
        dev(),
        proxy.then_some(addr),
        Egress::public_roots(),
    )?;
    let url = if proxy {
        "https://upstream.invalid/pay".into()
    } else {
        format!("https://{addr}/pay")
    };
    let limit = Instant::now()
        + if cancel_during_setup {
            Duration::from_secs(5)
        } else {
            Duration::from_millis(250)
        };
    let err = open_error(&e, url, limit, &flag);
    let finished = Instant::now();
    if cancel_during_setup {
        assert_eq!(err.to_string(), "exchange cancelled");
        assert!(finished < limit);
    } else {
        assert_eq!(err.to_string(), "exchange expired");
        assert!(finished >= limit && finished < limit + Duration::from_secs(1));
    }
    tokio::time::timeout(Duration::from_secs(2), peer).await???;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_and_connect_proxy_stalls_expire_before_send() -> Result<()> {
    stalled_open(false, false).await?;
    stalled_open(true, false).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancellation_interrupts_connection_setup() -> Result<()> {
    stalled_open(false, true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untrusted_and_wrong_name_certificates_fail_open() -> Result<()> {
    for wrong_name in [false, true] {
        let name = if wrong_name {
            "other.invalid"
        } else {
            "127.0.0.1"
        };
        let (tls, roots) = test_tls(vec![name.into()])?;
        let roots = if wrong_name {
            roots
        } else {
            Egress::public_roots()
        };
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let url = format!("https://{}/pay", listener.local_addr()?);
        let peer = tokio::spawn(async move {
            let (s, _) = listener.accept().await?;
            // No authenticated stream exists on which to receive a request.
            ensure!(tls.accept(s).await.is_err());
            Ok::<_, anyhow::Error>(())
        });
        let e = Egress::new(Handle::current(), dev(), None, roots)?;
        let err =
            open_error(&e, url, deadline(), &Cancellation::default()).downcast::<io::Error>()?;
        let tls_error = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<rustls::Error>());
        assert!(
            matches!(tls_error, Some(rustls::Error::InvalidCertificate(reason)) if
            matches!((wrong_name, reason),
                (true, rustls::CertificateError::NotValidForNameContext { .. }) |
                (false, rustls::CertificateError::UnknownIssuer)))
        );
        peer.await??;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_refusal_fails_open_without_forwarding() -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let e = Egress::new(
        Handle::current(),
        dev(),
        Some(listener.local_addr()?),
        Egress::public_roots(),
    )?;
    let peer = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await?;
        assert!(
            head(&mut s)
                .await?
                .starts_with("CONNECT upstream.invalid:443 HTTP/1.1\r\n")
        );
        s.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await?;
        let mut bytes = Vec::new();
        s.read_to_end(&mut bytes).await?;
        assert!(bytes.is_empty());
        Ok::<_, anyhow::Error>(())
    });
    let err = open_error(
        &e,
        "https://upstream.invalid/pay".into(),
        deadline(),
        &Cancellation::default(),
    );
    assert_eq!(err.to_string(), "proxy refused tunnel");
    peer.await??;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_and_partial_responses_fail_after_send() -> Result<()> {
    let e = Egress::new(Handle::current(), dev(), None, Egress::public_roots())?;
    for response in [
        b"".as_slice(),
        b"HTTP/1.",
        b"HTTP/1.1 200 OK\r\nContent-Len",
    ] {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let r = get(format!("http://{}/pay", listener.local_addr()?));
        let peer = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await?;
            assert!(head(&mut s).await?.starts_with("GET /pay HTTP/1.1\r\n"));
            s.write_all(response).await?;
            Ok::<_, anyhow::Error>(())
        });
        tokio::task::block_in_place(|| -> Result<()> {
            let limit = deadline();
            let cancel = Cancellation::default();
            let connection = e.open(&r, limit, &cancel)?;
            assert!(connection.send_wire(&r, &r, limit, &cancel).is_err());
            Ok(())
        })?;
        peer.await??;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expanded_origin_change_writes_no_request() -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let addr = listener.local_addr()?;
    let template = get(format!("http://{addr}/pay?key={{{{secret:key}}}}"));
    let e = Egress::new(Handle::current(), dev(), None, Egress::public_roots())?;
    for url in [
        format!("https://{addr}/pay"),
        format!("http://other.invalid:{}/pay", addr.port()),
        "http://127.0.0.1:0/pay".into(),
    ] {
        tokio::task::block_in_place(|| -> Result<()> {
            let limit = deadline();
            let cancel = Cancellation::default();
            let connection = e.open(&template, limit, &cancel)?;
            let err = connection
                .send_wire(&template, &get(url), limit, &cancel)
                .err()
                .expect("changed origin");
            assert_eq!(err.to_string(), "expanded request changed origin");
            Ok(())
        })?;
        let (mut s, _) = listener.accept().await?;
        let mut bytes = Vec::new();
        s.read_to_end(&mut bytes).await?;
        assert!(bytes.is_empty());
    }
    Ok(())
}
