mod support;
use anyhow::{Context, Result, ensure};
use prost::Message;
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use support::{simulator::*, *};
use tokio::io::AsyncReadExt;
use tonic::Code;
use upstream_gateway::api::*;

async fn rejected_handshake(
    i: &Instance,
    ca: &Authority,
    uris: &[String],
    client_cert: bool,
) -> Result<()> {
    expect_tls_alert(i, ca, uris, client_cert, &rustls::version::TLS13).await
}

async fn expect_tls_alert(
    i: &Instance,
    ca: &Authority,
    uris: &[String],
    client_cert: bool,
    version: &'static rustls::SupportedProtocolVersion,
) -> Result<()> {
    use rustls::{ClientConfig, RootCertStore, pki_types::PrivatePkcs8KeyDer};
    let mut roots = RootCertStore::empty();
    roots.add(i.ca.cert.der().clone())?;
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])?
            .with_root_certificates(roots);
    let mut config = if client_cert {
        let (cert, key) = ca.leaf(uris, false)?;
        builder.with_client_auth_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )?
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    let socket = tokio::net::TcpStream::connect(i.addr).await?;
    // A TLS 1.3 client may see ServerFinished before the server rejects its certificate.
    let error = match tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect("localhost".try_into()?, socket)
        .await
    {
        Ok(mut tls) => tokio::time::timeout(Duration::from_secs(3), tls.read_u8())
            .await?
            .unwrap_err(),
        Err(e) => e,
    };
    ensure!(
        error
            .get_ref()
            .and_then(|e| e.downcast_ref::<rustls::Error>())
            .is_some_and(|e| matches!(e, rustls::Error::AlertReceived(_))),
        "expected server TLS alert, got {error}"
    );
    Ok(())
}
#[tokio::test]
#[ignore = "starts real gateway processes"]
async fn tls_identity_and_rpc_policy() -> Result<()> {
    instances(&["trade", "verification"], async |both| {
        for i in both {
            let rpc = i.start().await?;
            let other = if i.role == "trade" {
                "reconciliation"
            } else {
                "payment"
            };
            let owner = spiffe(i.owner());
            expect_tls_alert(
                i,
                &i.ca,
                std::slice::from_ref(&owner),
                true,
                &rustls::version::TLS12,
            )
            .await?;
            rejected_handshake(i, &i.ca, &[spiffe(other)], true).await?;
            rejected_handshake(i, &Authority::new()?, std::slice::from_ref(&owner), true).await?;
            rejected_handshake(
                i,
                &i.ca,
                &[owner.replace("aipay.internal", "other.test")],
                true,
            )
            .await?;
            rejected_handshake(i, &i.ca, &[owner.clone(), owner], true).await?;
            rejected_handshake(i, &i.ca, &[], true).await?;
            rejected_handshake(i, &i.ca, &[], false).await?;
            for (method, assertion, expected) in [
                ("QueryPayment", true, Code::Unauthenticated),
                ("CreatePayment", true, Code::Unauthenticated),
                ("Unknown", false, Code::PermissionDenied),
            ] {
                ensure!(
                    rpc.raw::<QueryPaymentResponse>(
                        "UpstreamService",
                        method,
                        vec![0xff],
                        assertion
                    )
                    .await
                    .unwrap_err()
                    .code()
                        == expected
                );
            }
            if i.role == "verification" {
                for method in [
                    "CreatePayment",
                    "ClosePayment",
                    "Refund",
                    "RouteCallback",
                    "VerifyCallback",
                ] {
                    ensure!(
                        rpc.raw::<CreatePaymentResponse>(
                            "UpstreamService",
                            method,
                            vec![0xff],
                            false
                        )
                        .await
                        .unwrap_err()
                        .code()
                            == Code::PermissionDenied
                    );
                }
            }
            i.stop(true).await?;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "starts a real gateway process"]
async fn raw_wire_rejected_before_journaling() -> Result<()> {
    instances(&["trade"], async |rows| {
        let i = &mut rows[0];
        let rpc = i.start().await?;
        let p = PackageCase::publish(&rpc, "sim_form_md5").await?;
        let valid = p.query().encode_to_vec();
        for (length, expected) in [
            (16 << 20, Code::InvalidArgument),
            ((16 << 20) + 1, Code::OutOfRange),
        ] {
            // One field tag and a four-byte length prefix. At the limit the
            // request reaches UUID validation. Above it tonic rejects the frame.
            let bytes = GetExchangeRequest {
                exchange_id: "a".repeat(length - 5),
            }
            .encode_to_vec();
            ensure!(bytes.len() == length);
            let status = rpc
                .raw::<GetExchangeResponse>("UpstreamAdminService", "GetExchange", bytes, false)
                .await
                .unwrap_err();
            ensure!(status.code() == expected);
        }
        // Duplicate context occurrences merge under ordinary prost decoding.
        for extra in [
            &[0xa0, 0x06, 0x01][..],
            &[0x0a, 0x03, 0xa0, 0x06, 0x01],
            &[0x12, 0x04, 0x12, 0x02, 0x18, 0x01],
        ] {
            let mut bytes = valid.clone();
            bytes.extend(extra);
            ensure!(
                rpc.raw::<QueryPaymentResponse>("UpstreamService", "QueryPayment", bytes, false)
                    .await
                    .unwrap_err()
                    .code()
                    == Code::InvalidArgument
            );
        }
        // The contract's enum fields live exclusively in responses. Submit an
        // ExecutionResult carrying an unknown category as a raw request as well.
        let wire = ExecutionResult {
            category: 99,
            ..Default::default()
        }
        .encode_to_vec();
        ensure!(
            upstream_gateway::wire::decode_request::<ExecutionResult>(&wire)
                .unwrap_err()
                .code()
                == Code::InvalidArgument
        );
        ensure!(
            rpc.raw::<QueryPaymentResponse>("UpstreamService", "QueryPayment", wire, false)
                .await
                .unwrap_err()
                .code()
                == Code::InvalidArgument
        );
        ensure!(
            i.db.get()
                .await?
                .query_one("SELECT count(*) FROM operations", &[])
                .await?
                .get::<_, i64>(0)
                == 0
        );
        let reply: QueryPaymentResponse = rpc
            .raw("UpstreamService", "QueryPayment", valid, false)
            .await?;
        succeeded(reply.execution)?;
        Ok(())
    })
    .await
}

async fn business_paths(rpc: &Rpc, name: &str) -> Result<()> {
    let p = PackageCase::publish(rpc, name).await?;
    let pay: QueryPaymentResponse = rpc.call(p.query()).await?;
    succeeded(pay.execution)?;
    ensure!(pay.output.is_some());
    let result: QueryRefundResponse = rpc
        .call(QueryRefundRequest {
            context: p.context(),
            input: Some(p.refund("query_refund")),
        })
        .await?;
    succeeded(result.execution)?;
    ensure!(result.output.is_some());
    if name.ends_with("_verify") {
        ensure!(p.calls() == 2);
        return Ok(());
    }
    let payment: CreatePaymentResponse = rpc.call(p.create()).await?;
    succeeded(payment.execution)?;
    ensure!(payment.output.is_some());
    let close: ClosePaymentResponse = rpc
        .call(ClosePaymentRequest {
            context: p.context(),
            input: Some(p.pay("close_payment")),
        })
        .await?;
    succeeded(close.execution)?;
    ensure!(close.output.is_some());
    let refund: RefundResponse = rpc
        .call(RefundRequest {
            context: p.context(),
            input: Some(p.refund("refund")),
        })
        .await?;
    succeeded(refund.execution)?;
    ensure!(refund.output.is_some());
    for large in [false, true] {
        let raw = p.callback(large)?;
        let pay = p.pay("verify_callback");
        let start = Instant::now();
        let route: RouteCallbackResponse = rpc
            .call(RouteCallbackRequest {
                context: p.context(),
                input: Some(raw.clone()),
            })
            .await?;
        let route_us = start.elapsed().as_micros();
        succeeded(route.execution)?;
        ensure!(route.output.unwrap().order_id == pay.order_id);
        let start = Instant::now();
        let verify: VerifyCallbackResponse = rpc
            .call(VerifyCallbackRequest {
                context: p.context(),
                input: Some(VerifyCallbackInput {
                    order_id: pay.order_id.clone(),
                    money: pay.money,
                    raw: Some(raw),
                }),
            })
            .await?;
        let verify_us = start.elapsed().as_micros();
        succeeded(verify.execution)?;
        ensure!(verify.output.unwrap().order_id == pay.order_id);
        if large {
            println!("64 KiB {name} RouteCallback {route_us} us VerifyCallback {verify_us} us");
        }
    }
    ensure!(p.calls() == 5);
    Ok(())
}
macro_rules! suite {
    ($test:ident,$role:literal,$name:literal) => {
        #[tokio::test]
        #[ignore = "runs packaged components through the gateway binary"]
        async fn $test() -> Result<()> {
            instances(&[$role], async |rows| {
                let rpc = rows[0].start().await?;
                business_paths(&rpc, $name).await
            })
            .await
        }
    };
}
suite!(trade_form_md5, "trade", "sim_form_md5");
suite!(trade_json_rsa, "trade", "sim_json_rsa");
suite!(verification_form_md5, "verification", "sim_form_md5_verify");
suite!(verification_json_rsa, "verification", "sim_json_rsa_verify");

#[tokio::test]
#[ignore = "starts two independent gateway processes"]
async fn independent_instances_and_write_only_credentials() -> Result<()> {
    instances(&["trade", "verification"], async |rows| {
        let trade = rows[0].start().await?;
        let verify = rows[1].start().await?;
        let p = PackageCase::publish(&trade, "sim_form_md5").await?;
        let req = p.query();
        let r: QueryPaymentResponse = trade.call(req.clone()).await?;
        let x = succeeded(r.execution)?;
        let evidence = GetExchangeRequest {
            exchange_id: x.exchange_id,
        };
        let e: GetExchangeResponse = trade.call(evidence.clone()).await?;
        ensure!(
            x.evidence_sha256 == Sha256::digest(&e.canonical_record).as_slice()
                && x.evidence_sha256 == e.evidence_sha256
        );
        ensure!(
            verify
                .call::<_, GetExchangeResponse>(evidence)
                .await
                .unwrap_err()
                .code()
                == Code::NotFound
        );
        let mut other = req.clone();
        other.context.as_mut().unwrap().verification_account_id = Some(uid());
        let r: QueryPaymentResponse = verify.call(other).await?;
        let x = r.execution.unwrap();
        ensure!(x.error_code == "package_unavailable" && x.package_sha256.is_empty());
        let v = PackageCase::publish(&verify, "sim_form_md5_verify").await?;
        let mut foreign = v.query();
        let ctx = foreign.context.as_mut().unwrap();
        ctx.credentials_ref = p.ctx.credentials_ref.clone();
        ctx.credentials_sha256 = p.ctx.credentials_sha256.clone();
        ctx.channel_account_id = p.ctx.channel_account_id.clone();
        let r: QueryPaymentResponse = verify.call(foreign).await?;
        ensure!(r.execution.unwrap().error_code == "credential_unavailable" && v.calls() == 0);
        for method in ["GetCredentials", "ListCredentials"] {
            ensure!(
                trade
                    .raw::<StoreCredentialsResponse>("UpstreamAdminService", method, vec![], false)
                    .await
                    .unwrap_err()
                    .code()
                    == Code::PermissionDenied
            );
        }
        let mut conflict = req;
        conflict.input.as_mut().unwrap().order_id = "other".into();
        ensure!(
            trade
                .call::<_, QueryPaymentResponse>(conflict)
                .await
                .unwrap_err()
                .code()
                == Code::AlreadyExists
        );
        ensure!(p.calls() == 1);
        Ok(())
    })
    .await
}
#[tokio::test]
#[ignore = "starts a real gateway process"]
async fn revocation_race_and_echo_quarantine() -> Result<()> {
    instances(&["trade"], async |rows| {
        let rpc = rows[0].start().await?;
        let p = PackageCase::publish(&rpc, "sim_form_md5").await?;
        p.echo()?;
        let r: QueryPaymentResponse = rpc.call(p.query()).await?;
        let x = r.execution.unwrap();
        ensure!(x.error_code == "secret_leak" && x.evidence_sha256.len() == 32);
        ensure!(
            rpc.call::<_, GetExchangeResponse>(GetExchangeRequest {
                exchange_id: x.exchange_id
            })
            .await
            .unwrap_err()
            .code()
                == Code::FailedPrecondition
        );
        let release = p.hold();
        let create = p.create();
        let c = rpc.clone();
        let first = create.clone();
        let request = tokio::spawn(async move { c.call::<_, CreatePaymentResponse>(first).await });
        p.wait_calls(2).await?;
        p.revoke(&rpc).await?;
        let _ = release.send(());
        let x = request.await??;
        succeeded(x.execution.clone())?;
        let old: CreatePaymentResponse = rpc.call(create).await?;
        ensure!(x == old);
        let new: CreatePaymentResponse = rpc.call(p.create()).await?;
        ensure!(new.execution.unwrap().error_code == "package_revoked" && p.calls() == 2);
        Ok(())
    })
    .await
}

async fn crash(after_dispatch: bool) -> Result<()> {
    instances(&["trade"], async |rows| {
        let instance = &mut rows[0];
        let rpc = instance.start().await?;
        let package = PackageCase::publish(&rpc, "sim_form_md5").await?;
        let create = package.create();
        let first = create.clone();
        let key = &create.context.as_ref().unwrap().idempotency_key;

        let mut conn = instance.db.get().await?;
        let lock = conn.transaction().await?;
        let hold = if after_dispatch {
            Some(package.hold())
        } else {
            lock.batch_execute("LOCK attempts IN ACCESS EXCLUSIVE MODE").await?;
            None
        };
        let pending = tokio::spawn(async move {
            rpc.call::<_, CreatePaymentResponse>(first).await
        });
        if after_dispatch {
            package.wait_calls(1).await?;
        } else {
            let db = instance.db.get().await?;
            // Wait for the real dispatch INSERT to block, after claim committed.
            let blocked = "SELECT EXISTS (SELECT 1 FROM pg_locks
                              WHERE relation='attempts'::regclass AND NOT granted)
                              AND EXISTS (SELECT 1 FROM operations
                              WHERE key=$1 AND requests=0 AND terminal IS NULL)";
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if db.query_one(blocked, &[key]).await?.get::<_, bool>(0) {
                        return Ok::<_, anyhow::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }).await.context("waiting for pre-dispatch barrier")??;
        }

        let before = package.calls();
        ensure!(before == usize::from(after_dispatch));
        instance.kill()?;
        drop(hold);
        lock.rollback().await?;
        ensure!(pending.await?.is_err());

        let second = instance.start().await?;
        let reply: CreatePaymentResponse = second.call(create.clone()).await?;
        let x = reply.execution.as_ref().unwrap();
        if after_dispatch {
            ensure!(x.category == ExecutionCategory::Unknown as i32);
            ensure!(x.error_code == "dispatch_interrupted" && x.responses == 0);
        } else {
            succeeded(reply.execution.clone())?;
            ensure!(x.responses == 1);
        }
        ensure!(x.requests == 1);
        let saved: GetExchangeResponse = second.call(GetExchangeRequest {
            exchange_id: x.exchange_id.clone()
        }).await?;
        ensure!(x.evidence_sha256 == Sha256::digest(saved.canonical_record).as_slice());
        ensure!(second.call::<_, CreatePaymentResponse>(create).await? == reply);
        ensure!(package.calls() == 1);
        println!(
            "SIGKILL after_dispatch={after_dispatch} before_kill={before} after_retry={} category={} error={} requests={} responses={}",
            package.calls(), x.category, x.error_code, x.requests, x.responses
        );
        Ok(())
    }).await
}
#[tokio::test]
#[ignore = "uses SIGKILL on a real gateway binary"]
async fn sigkill_after_upstream_receives_request() -> Result<()> {
    crash(true).await
}
#[tokio::test]
#[ignore = "uses SIGKILL on a real gateway binary"]
async fn sigkill_before_first_dispatch() -> Result<()> {
    crash(false).await
}

#[tokio::test]
#[ignore = "uses SIGTERM and database fencing on a real gateway binary"]
async fn sigterm_drains_and_fenced_executor_exits() -> Result<()> {
    instances(&["trade"], async |rows| {
        let instance = &mut rows[0];
        let rpc = instance.start().await?;
        let p = PackageCase::publish(&rpc, "sim_form_md5").await?;
        let create = p.create();
        let first = create.clone();
        let release = p.hold();
        let pending =
            tokio::spawn(async move { rpc.call::<_, CreatePaymentResponse>(first).await });
        p.wait_calls(1).await?;
        instance.signal_term()?;
        tokio::time::timeout(Duration::from_secs(3), async {
            while tokio::net::TcpStream::connect(instance.addr).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        let _ = release.send(());
        let before = pending.await??;
        succeeded(before.execution.clone())?;
        instance.wait_exit(true).await?;
        let rpc = instance.start().await?;
        ensure!(rpc.call::<_, CreatePaymentResponse>(create).await? == before && p.calls() == 1);
        let interrupted = p.create();
        let key = interrupted
            .context
            .as_ref()
            .unwrap()
            .idempotency_key
            .clone();
        let release = p.hold();
        let pending =
            tokio::spawn(async move { rpc.call::<_, CreatePaymentResponse>(interrupted).await });
        p.wait_calls(2).await?;
        instance
            .db
            .get()
            .await?
            .execute("UPDATE executors SET fenced=true WHERE NOT fenced", &[])
            .await?;
        let _ = release.send(());
        ensure!(pending.await?.is_err());
        instance.wait_exit(false).await?;
        let terminal: Vec<u8> = instance
            .db
            .get()
            .await?
            .query_one("SELECT terminal FROM operations WHERE key=$1", &[&key])
            .await?
            .try_get(0)?;
        let result = CreatePaymentResponse::decode(terminal.as_slice())?
            .execution
            .unwrap();
        ensure!(
            result.category == ExecutionCategory::Unknown as i32
                && result.error_code == "dispatch_interrupted"
        );
        ensure!(p.calls() == 2);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "exercises two scheduled TLS reloads"]
async fn reload_preserves_live_connections_and_last_good_bundle() -> Result<()> {
    instances(&["trade"], async |rows| {
        let instance = &mut rows[0];
        let existing = instance.start().await?;
        let (old, old_key) = instance.ca.leaf(&[spiffe("payment")], false)?;
        std::fs::write(instance.dir.path().join("key"), b"incomplete")?;
        tokio::time::sleep(Duration::from_secs(31)).await;
        let previous = instance.connect(&old, &old_key).await?;
        let request = GetExchangeRequest { exchange_id: uid() };
        ensure!(
            previous
                .call::<_, GetExchangeResponse>(request.clone())
                .await
                .unwrap_err()
                .code()
                == Code::NotFound
        );
        let next_ca = Authority::new()?;
        let (next_server, key) = next_ca.leaf(&[spiffe("upstream-gateway-trade")], true)?;
        let (next_client, client_key) = next_ca.leaf(&[spiffe("payment")], false)?;
        std::fs::write(instance.dir.path().join("ca"), next_ca.cert.pem())?;
        std::fs::write(instance.dir.path().join("cert"), next_server.pem())?;
        std::fs::write(instance.dir.path().join("key"), key.serialize_pem())?;
        let old_ca = std::mem::replace(&mut instance.ca, next_ca);
        tokio::time::timeout(Duration::from_secs(40), async {
            loop {
                if let Ok(next) = instance.connect(&next_client, &client_key).await
                    && next
                        .call::<_, GetExchangeResponse>(request.clone())
                        .await
                        .is_err_and(|s| s.code() == Code::NotFound)
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await?;
        ensure!(
            existing
                .call::<_, GetExchangeResponse>(request.clone())
                .await
                .unwrap_err()
                .code()
                == Code::NotFound
        );
        rejected_handshake(instance, &old_ca, &[spiffe("payment")], true).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "starts the gateway with mismatched TLS material"]
async fn startup_checks_self_identity_before_storage() -> Result<()> {
    instances(&["trade"], async |rows| {
        let i = &rows[0];
        let (cert, key) =
            i.ca.leaf(&[spiffe("upstream-gateway-verification")], true)?;
        std::fs::write(i.dir.path().join("cert"), cert.pem())?;
        std::fs::write(i.dir.path().join("key"), key.serialize_pem())?;
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_upstream-gateway"))
            .arg("--config")
            .arg(i.config())
            .env_remove("GATEWAY_TEST_DSN")
            .output()?;
        ensure!(!out.status.success() && out.stdout.is_empty());
        ensure!(
            String::from_utf8(out.stderr)?.trim()
                == "gateway stopped: invalid TLS material or service identity"
        );
        ensure!(
            i.db.get()
                .await?
                .query_one("SELECT to_regclass('gateway_migrations') IS NULL", &[])
                .await?
                .get::<_, bool>(0)
        );
        Ok(())
    })
    .await
}
