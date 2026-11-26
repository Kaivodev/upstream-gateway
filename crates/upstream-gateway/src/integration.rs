use super::{
    api::*,
    business::{Input, Material},
    crypto::{Kms, LocalKms},
    encoding::hash,
    journal::{Claim, Lease},
    *,
};
use anyhow::{Result, ensure};
use base64::prelude::*;
use deadpool_postgres::Pool;
use kaivo_upstream_sdk::form;
use prost::Message;
use serde_json::{Value, json};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    io::Cursor,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio_postgres::Config;
use tonic::Code;
use upstream_host::{
    environment::{Cancellation, CapturedResponse, Dispatch, Incoming, Transport},
    package::{Package, hex},
    types::HttpRequest,
};
use uuid::Uuid;

fn uid() -> String {
    Uuid::now_v7().to_string()
}
fn caller(role: Role) -> VerifiedCaller {
    VerifiedCaller::for_test(role.caller(), Instant::now() + Duration::from_secs(60))
}
#[derive(Default)]
struct Observer {
    alerts: Mutex<Vec<String>>,
    logs: Mutex<Vec<String>>,
}
impl Events for Observer {
    fn alert(&self, c: &'static str) {
        self.alerts.lock().unwrap().push(c.into())
    }
    fn log(&self, v: &Value) {
        self.logs.lock().unwrap().push(v.to_string())
    }
}
struct CountingKms {
    local: LocalKms,
    credential_reads: AtomicUsize,
    before_open: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}
impl Kms for CountingKms {
    fn wrap(&self, d: &[u8], a: &[u8]) -> Result<Vec<u8>, tonic::Status> {
        self.local.wrap(d, a)
    }
    fn unwrap(&self, d: &[u8], a: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, tonic::Status> {
        if a.get(4..)
            .is_some_and(|b| b.starts_with(b"aipay.upstream.credentials.v1"))
        {
            self.credential_reads.fetch_add(1, Ordering::SeqCst);
            if let Some(resume) = self.before_open.lock().unwrap().take() {
                resume
                    .recv_timeout(Duration::from_secs(10))
                    .map_err(|_| tonic::Status::unavailable("test deadline"))?;
            }
        }
        self.local.unwrap(d, a)
    }
    fn development_only(&self) -> bool {
        true
    }
}
struct Offline {
    calls: AtomicUsize,
    responses: BTreeMap<String, Vec<u8>>,
    echo: Mutex<Option<(bool, Vec<u8>)>>,
    pause: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
}
impl Transport for Offline {
    fn send(
        &self,
        _: &HttpRequest,
        r: &HttpRequest,
        _: Instant,
        _: &Cancellation,
    ) -> Result<Incoming> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(rx) = self.pause.lock().unwrap().take() {
            rx.recv_timeout(Duration::from_secs(10))?
        }
        let mut headers = vec![("Content-Type".into(), vec!["application/json".into()])];
        let body = if let Some((header, v)) = self.echo.lock().unwrap().take() {
            if header {
                headers.push(("X-Echo".into(), vec![String::from_utf8(v)?]));
                vec![]
            } else {
                v
            }
        } else {
            self.responses
                .get(&r.url)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unrecorded URL"))?
        };
        Ok(Incoming {
            status: 200,
            headers,
            body: Box::new(Cursor::new(body)),
        })
    }
}
struct Suite {
    g: Gateway,
    pool: Pool,
    kms: Arc<CountingKms>,
    up: Arc<Offline>,
    events: Arc<Observer>,
    pkg: PluginPackage,
    publication: RegisterPackageRequest,
    ctx: OperationContext,
    secret: String,
    fixtures: BTreeMap<String, Value>,
}
async fn schema<F, Fut>(role: Role, body: F) -> Result<()>
where
    F: FnOnce(Suite) -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let mut cfg = std::env::var("AIPAY_TEST_DATABASE_URL")?.parse::<Config>()?;
    let admin = pool(cfg.clone())?;
    let schema = format!("ug3_{}", Uuid::now_v7().simple());
    let mut c = admin.get().await?;
    let tx = c.transaction().await?;
    tx.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    tx.commit().await?;
    cfg.options(format!("-c search_path={schema}"));
    let p = pool(cfg)?;
    let job = tokio::spawn(async move { body(Suite::new(role, p).await?).await }).await;
    let tx = c.transaction().await?;
    tx.batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await?;
    tx.commit().await?;
    job?
}
impl Suite {
    async fn new(role: Role, pool: Pool) -> Result<Self> {
        let name = if role == Role::Trade {
            "sim_form_md5"
        } else {
            "sim_form_md5_verify"
        };
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .unwrap()
            .join("dist/packages")
            .join(name);
        let p = Package::read(&path)?;
        let mut bytes = std::fs::read(path.join("manifest.json"))?;
        let mut package_input = bytes.clone();
        package_input.extend(&p.wasm);
        let mut fixtures = BTreeMap::new();
        let mut responses = BTreeMap::new();
        for (k, data) in &p.fixtures {
            if !k.ends_with("_success.json") {
                continue;
            }
            let f: Value = serde_json::from_slice(data)?;
            if let Some(x) = f["exchanges"].as_array().unwrap().first() {
                let b = BASE64_STANDARD.decode(x["response"]["body"].as_str().unwrap())?;
                let mut value: Value = serde_json::from_slice(&b)?;
                if let Some(order) = value["order"].as_object_mut() {
                    order.remove("expire_time");
                }
                responses.insert(
                    x["request"]["url"].as_str().unwrap().into(),
                    serde_json::to_vec(&value)?,
                );
            }
            fixtures.insert(f["operation"].as_str().unwrap().into(), f);
        }
        let pkg = PluginPackage {
            manifest_json: std::mem::take(&mut bytes),
            plugin_wasm: p.wasm,
            fixtures: p
                .fixtures
                .into_iter()
                .map(|(path, content)| PluginFixture { path, content })
                .collect(),
            package_sha256: hash(&package_input),
        };
        let kms = Arc::new(CountingKms {
            local: LocalKms::ephemeral(),
            credential_reads: 0.into(),
            before_open: Default::default(),
        });
        let up = Arc::new(Offline {
            calls: 0.into(),
            responses,
            echo: Default::default(),
            pause: Default::default(),
        });
        let events = Arc::new(Observer::default());
        let mode = Mode::Development {
            allow_loopback_http: true,
            allow_uncommitted: true,
        };
        let g = Gateway::init(
            pool.clone(),
            role,
            mode,
            kms.clone(),
            up.clone(),
            events.clone(),
        )
        .await?;
        let digests = g
            .replay_package(
                caller(role),
                ReplayPackageRequest {
                    package: Some(pkg.clone()),
                },
            )
            .await?
            .digests;
        let publication = RegisterPackageRequest {
            idempotency_key: "publish".into(),
            package: Some(pkg.clone()),
            approved_digests: digests,
            publication: Some(ApprovalReference {
                approval_request_id: uid(),
                request_digest: vec![7; 32],
            }),
        };
        g.register_package(caller(role), publication.clone())
            .await?;
        let mut random = [0; 32];
        getrandom::fill(&mut random).unwrap();
        let secret = BASE64_STANDARD.encode(random);
        let field = if role == Role::Trade {
            "shared"
        } else {
            "query_key"
        };
        let channel = uid();
        let cred = g
            .store_credentials(
                caller(role),
                StoreCredentialsRequest {
                    idempotency_key: "store".into(),
                    channel_account_id: channel.clone(),
                    channel_code: "sim_form_md5".into(),
                    credentials_json: serde_json::to_vec(&json!({(field):secret}))?,
                },
            )
            .await?;
        let ctx = OperationContext {
            idempotency_key: "op".into(),
            package_sha256: pkg.package_sha256.clone(),
            channel_account_id: channel,
            verification_account_id: (role == Role::Verification).then(uid),
            control_version: 1,
            config_json: upstream_host::json::canonical(&fixtures["query_payment"]["config"]),
            credentials_ref: cred.credentials_ref,
            credentials_sha256: cred.credentials_sha256,
        };
        Ok(Self {
            g,
            pool,
            kms,
            up,
            events,
            pkg,
            publication,
            ctx,
            secret,
            fixtures,
        })
    }
    fn caller(&self) -> VerifiedCaller {
        caller(self.g.0.role)
    }
    fn ctx(&self, key: &str) -> Option<OperationContext> {
        let mut c = self.ctx.clone();
        c.idempotency_key = key.into();
        Some(c)
    }
    fn money(&self) -> Option<Money> {
        Some(Money {
            amount: "12345".into(),
            currency: "CNY".into(),
        })
    }
    fn payment(&self, op: &str) -> PaymentInput {
        PaymentInput {
            order_id: self.fixtures[op]["input"]["order_id"]
                .as_str()
                .unwrap()
                .into(),
            money: self.money(),
        }
    }
    fn refund(&self, op: &str) -> RefundInput {
        let v = &self.fixtures[op]["input"];
        RefundInput {
            order_id: v["order_id"].as_str().unwrap().into(),
            refund_id: v["refund_id"].as_str().unwrap().into(),
            money: self.money(),
        }
    }
    fn create(&self, key: &str) -> CreatePaymentRequest {
        let v = &self.fixtures["create_payment"]["input"];
        CreatePaymentRequest {
            context: self.ctx(key),
            input: Some(CreatePaymentInput {
                order_id: v["order_id"].as_str().unwrap().into(),
                money: self.money(),
                method: "alipay".into(),
                callback_url: v["callback_url"].as_str().unwrap().into(),
                bank_mode: None,
                instruction: Some("url".into()),
                client_ip: v["client_ip"].as_str().map(str::to_owned),
                device: v["device"].as_str().map(str::to_owned),
            }),
        }
    }
    fn query(&self, key: &str) -> QueryPaymentRequest {
        QueryPaymentRequest {
            context: self.ctx(key),
            input: Some(self.payment("query_payment")),
        }
    }
    fn raw(&self) -> CallbackPayload {
        let v = &self.fixtures["verify_callback"]["input"];
        let body = BASE64_STANDARD.decode(v["body"].as_str().unwrap()).unwrap();
        let mut fields = form::parse(&body).unwrap();
        let sig = md5::Md5::new()
            .chain_update(form::canonical_bytes(&fields).unwrap())
            .chain_update(b"&key=")
            .chain_update(&self.secret)
            .finalize();
        form::set(&mut fields, "sign", &hex(&sig));
        CallbackPayload {
            method: "POST".into(),
            headers: vec![HttpHeader {
                name: "Content-Type".into(),
                values: vec!["application/x-www-form-urlencoded".into()],
            }],
            body: form::encode_bytes(&fields),
            ..Default::default()
        }
    }
    async fn restart(&self) -> Result<Gateway> {
        Ok(Gateway::init(
            self.pool.clone(),
            self.g.0.role,
            self.g.0.mode,
            self.kms.clone(),
            self.up.clone(),
            self.events.clone(),
        )
        .await?)
    }
    async fn revoke(&self) -> Result<()> {
        self.g
            .revoke_package(
                self.caller(),
                RevokePackageRequest {
                    idempotency_key: "stop".into(),
                    package_sha256: self.pkg.package_sha256.clone(),
                    owner_action_id: uid(),
                },
            )
            .await?;
        Ok(())
    }
    async fn evidence(&self, x: &ExecutionResult) -> Result<Vec<u8>> {
        let r = self
            .g
            .get_exchange(
                self.caller(),
                GetExchangeRequest {
                    exchange_id: x.exchange_id.clone(),
                },
            )
            .await?;
        ensure!(
            hash(&r.canonical_record) == x.evidence_sha256
                && r.evidence_sha256 == x.evidence_sha256
        );
        Ok(r.canonical_record)
    }
    fn count(&self) -> usize {
        self.up.calls.load(Ordering::SeqCst)
    }
    async fn lease(&self, key: &str) -> Result<(Lease, Material)> {
        let r = self.create(key);
        let m =
            Input::Create(r.input.unwrap()).material(Role::Trade, "payment", r.context.unwrap())?;
        match self.g.claim("payment", &m).await? {
            Claim::Run(l) => Ok((l, m)),
            _ => anyhow::bail!("expected new lease"),
        }
    }
    async fn scan(&self) -> Result<()> {
        let secret = self.secret.as_bytes();
        let mut patterns = vec![
            secret.to_vec(),
            hex(secret).into_bytes(),
            hex(secret).to_uppercase().into_bytes(),
        ];
        for enc in [
            &BASE64_STANDARD,
            &BASE64_STANDARD_NO_PAD,
            &BASE64_URL_SAFE,
            &BASE64_URL_SAFE_NO_PAD,
        ] {
            patterns.push(enc.encode(secret).into_bytes())
        }
        // row_to_json renders bytea as hex. Search both literal text and the database's byte representation.
        let more = patterns
            .iter()
            .map(|v| hex(v).into_bytes())
            .collect::<Vec<_>>();
        patterns.extend(more);
        let c = self.pool.get().await?;
        for row in c
            .query(
                "SELECT quote_ident(tablename) FROM pg_tables WHERE schemaname=current_schema()",
                &[],
            )
            .await?
        {
            let name: String = row.get(0);
            for row in c
                .query(&format!("SELECT row_to_json(t)::text FROM {name} t"), &[])
                .await?
            {
                let b = row.get::<_, &str>(0).as_bytes();
                ensure!(
                    !patterns.iter().any(|p| b.windows(p.len()).any(|w| w == p)),
                    "unexpected credential representation in {name}"
                );
            }
        }
        for line in self
            .events
            .logs
            .lock()
            .unwrap()
            .iter()
            .chain(self.events.alerts.lock().unwrap().iter())
        {
            ensure!(
                !patterns
                    .iter()
                    .any(|p| line.as_bytes().windows(p.len()).any(|w| w == p))
            );
        }
        Ok(())
    }
}
fn success(x: Option<ExecutionResult>) -> Result<ExecutionResult> {
    let x = x.unwrap();
    ensure!(
        x.category == 1,
        "unexpected classification {:?} {}",
        x.category,
        x.error_code
    );
    Ok(x)
}
fn template() -> HttpRequest {
    HttpRequest {
        method: "POST".into(),
        url: "https://upstream.test/pay".into(),
        headers: vec![],
        body: vec![],
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn idempotency_evidence_and_revoked_trade_paths() -> Result<()> {
    schema(Role::Trade, |s| async move {
        let r = s.create("original");
        let first = s.g.create_payment(s.caller(), r.clone()).await?;
        let x = success(first.execution.clone())?;
        ensure!(s.evidence(&x).await?.len() > 100);
        ensure!(
            s.g.create_payment(s.caller(), r.clone())
                .await?
                .encode_to_vec()
                == first.encode_to_vec()
        );
        let mut different = r.clone();
        different.input.as_mut().unwrap().order_id = "different".into();
        ensure!(
            s.g.create_payment(s.caller(), different)
                .await
                .unwrap_err()
                .code()
                == Code::AlreadyExists
        );
        ensure!(
            s.g.query_payment(s.caller(), s.query("original"))
                .await
                .unwrap_err()
                .code()
                == Code::AlreadyExists
        );
        success(
            s.g.refund(
                s.caller(),
                RefundRequest {
                    context: s.ctx("refund"),
                    input: Some(s.refund("refund")),
                },
            )
            .await?
            .execution,
        )?;
        s.revoke().await?;
        let count = s.count();
        ensure!(s.g.create_payment(s.caller(), r).await?.encode_to_vec() == first.encode_to_vec());
        let x =
            s.g.create_payment(s.caller(), s.create("stopped"))
                .await?
                .execution
                .unwrap();
        ensure!(
            x.category == 4 && x.error_code == "package_revoked" && x.package_sha256.is_empty()
        );
        ensure!(s.count() == count);
        success(
            s.g.query_payment(s.caller(), s.query("query"))
                .await?
                .execution,
        )?;
        success(
            s.g.close_payment(
                s.caller(),
                ClosePaymentRequest {
                    context: s.ctx("close"),
                    input: Some(s.payment("close_payment")),
                },
            )
            .await?
            .execution,
        )?;
        success(
            s.g.query_refund(
                s.caller(),
                QueryRefundRequest {
                    context: s.ctx("query-refund"),
                    input: Some(s.refund("query_refund")),
                },
            )
            .await?
            .execution,
        )?;
        let before = s.kms.credential_reads.load(Ordering::SeqCst);
        let raw = s.raw();
        success(
            s.g.route_callback(
                s.caller(),
                RouteCallbackRequest {
                    context: s.ctx("route"),
                    input: Some(raw.clone()),
                },
            )
            .await?
            .execution,
        )?;
        ensure!(before == s.kms.credential_reads.load(Ordering::SeqCst));
        let c = s.payment("verify_callback");
        success(
            s.g.verify_callback(
                s.caller(),
                VerifyCallbackRequest {
                    context: s.ctx("verify"),
                    input: Some(VerifyCallbackInput {
                        order_id: c.order_id,
                        money: c.money,
                        raw: Some(raw),
                    }),
                },
            )
            .await?
            .execution,
        )?;
        let g = s.restart().await?;
        success(
            g.query_payment(s.caller(), s.query("restart-query"))
                .await?
                .execution,
        )?;
        ensure!(
            g.create_payment(s.caller(), s.create("restart-create"))
                .await?
                .execution
                .unwrap()
                .error_code
                == "package_revoked"
        );
        let mut p = s.publication.clone();
        p.idempotency_key = "late".into();
        ensure!(
            g.register_package(s.caller(), p).await.unwrap_err().code() == Code::FailedPrecondition
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn write_only_credentials_and_admission() -> Result<()> {
    schema(Role::Trade, |s| async move {
        let mut r = StoreCredentialsRequest {
            idempotency_key: "store".into(),
            channel_account_id: s.ctx.channel_account_id.clone(),
            channel_code: "sim_form_md5".into(),
            credentials_json: serde_json::to_vec(&json!({"shared":s.secret}))?,
        };
        let c = s.g.store_credentials(s.caller(), r.clone()).await?;
        ensure!(
            c.credentials_ref == s.ctx.credentials_ref
                && c.credentials_sha256
                    == hash(&upstream_host::json::canonical(&json!({"shared":s.secret})))
        );
        r.credentials_json = serde_json::to_vec(&json!({"shared":uid()}))?;
        ensure!(
            s.g.store_credentials(s.caller(), r)
                .await
                .unwrap_err()
                .code()
                == Code::AlreadyExists
        );
        for i in 0..3 {
            let mut r = s.query(&format!("bad-{i}"));
            let c = r.context.as_mut().unwrap();
            match i {
                0 => c.channel_account_id = uid(),
                1 => c.credentials_sha256[0] ^= 1,
                _ => c.credentials_ref = uid(),
            }
            let x = s.g.query_payment(s.caller(), r).await?.execution.unwrap();
            ensure!(
                x.category == 4
                    && x.error_code == "credential_unavailable"
                    && x.package_sha256 == s.pkg.package_sha256
            );
        }
        let mut r = s.query("schema");
        r.context.as_mut().unwrap().config_json = b"{}".to_vec();
        ensure!(
            s.g.query_payment(s.caller(), r)
                .await?
                .execution
                .unwrap()
                .error_code
                == "config_unavailable"
        );
        let mut r = s.query("bad-before-log");
        r.context.as_mut().unwrap().control_version = 0;
        ensure!(
            s.g.query_payment(s.caller(), r).await.unwrap_err().code() == Code::InvalidArgument
        );
        let c = s.pool.get().await?;
        ensure!(
            c.query_opt("SELECT 1 FROM operations WHERE key='bad-before-log'", &[])
                .await?
                .is_none()
        );
        ensure!(s.count() == 0);
        s.scan().await
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn sealed_evidence_ownership_integrity_and_echo_quarantine() -> Result<()> {
    schema(Role::Trade, |s| async move {
        let x = success(
            s.g.query_payment(s.caller(), s.query("query"))
                .await?
                .execution,
        )?;
        s.evidence(&x).await?;
        let req = GetExchangeRequest {
            exchange_id: x.exchange_id.clone(),
        };
        ensure!(
            s.g.get_exchange(caller(Role::Verification), req.clone())
                .await
                .unwrap_err()
                .code()
                == Code::NotFound
        );
        let mut c = s.pool.get().await?;
        let tx = c.transaction().await?;
        tx.batch_execute("ALTER TABLE operations DISABLE TRIGGER immutable_terminal")
            .await?;
        tx.execute(
            "UPDATE operations SET evidence=set_byte(evidence, octet_length(evidence)-1,
     get_byte(evidence, octet_length(evidence)-1)#1) WHERE exchange=$1",
            &[&x.exchange_id],
        )
        .await?;
        tx.batch_execute("ALTER TABLE operations ENABLE TRIGGER immutable_terminal")
            .await?;
        tx.commit().await?;
        ensure!(s.g.get_exchange(s.caller(), req).await.unwrap_err().code() == Code::DataLoss);
        for (n, header) in [true, false].into_iter().enumerate() {
            let reflected = if header {
                s.secret.as_bytes().to_vec()
            } else {
                BASE64_URL_SAFE.encode(&s.secret).into_bytes()
            };
            *s.up.echo.lock().unwrap() = Some((header, reflected.clone()));
            let before = s.events.logs.lock().unwrap().len();
            let x =
                s.g.query_payment(s.caller(), s.query(&format!("echo-{n}")))
                    .await?
                    .execution
                    .unwrap();
            ensure!(
                x.category == 3
                    && x.error_code == "secret_leak"
                    && x.requests == 1
                    && x.responses == 0
            );
            ensure!(
                s.events.alerts.lock().unwrap().len() == n + 1
                    && s.events.logs.lock().unwrap().len() == before
            );
            ensure!(
                s.g.get_exchange(
                    s.caller(),
                    GetExchangeRequest {
                        exchange_id: x.exchange_id.clone()
                    }
                )
                .await
                .unwrap_err()
                .code()
                    == Code::FailedPrecondition
            );
            let row = c
                .query_one(
                    "SELECT evidence FROM operations WHERE exchange=$1",
                    &[&x.exchange_id],
                )
                .await?;
            let record = s.g.0.vault.open(
                row.get(0),
                &s.g.evidence_aad("payment", &x.exchange_id, "quarantine"),
            )?;
            ensure!(
                record.windows(reflected.len()).any(|w| w == reflected)
                    && hash(&record) == x.evidence_sha256
            );
        }
        s.scan().await
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn executor_fence_before_dispatch() -> Result<()> {
    schema(Role::Trade, |s| async move {
        let (lease, _) = s.lease("orphan").await?;
        let next = s.restart().await?;
        let mut c = s.pool.get().await?;
        let tx = c.transaction().await?;
        tx.execute(
            "UPDATE executors SET heartbeat=clock_timestamp()-interval '1 hour' WHERE id=$1",
            &[&s.g.0.executor],
        )
        .await?;
        tx.commit().await?;
        next.maintain().await?;
        ensure!(lease.authorize(&s.g, 1, &template()).await.is_err());
        let x = success(
            next.create_payment(s.caller(), s.create("orphan"))
                .await?
                .execution,
        )?;
        ensure!(x.exchange_id == lease.exchange && s.count() == 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn interrupted_dispatch_and_unconfirmed_commit() -> Result<()> {
    schema(Role::Trade, |s| async move {
        s.g.0.unconfirm.store(true, Ordering::SeqCst);
        let x =
            s.g.create_payment(s.caller(), s.create("unconfirmed"))
                .await?
                .execution
                .unwrap();
        ensure!(
            x.category == 3
                && x.error_code == "dispatch_unconfirmed"
                && x.requests == 1
                && s.count() == 0
        );
        let no_response:bool=s.pool.get().await?.query_one(
            "SELECT dispatched_at IS NOT NULL AND received_at IS NULL FROM attempts WHERE exchange=$1",
            &[&x.exchange_id],
        ).await?.get(0);
        ensure!(no_response);
        s.evidence(&x).await?;
        let (l, _) = s.lease("lost").await?;
        let r = template();
        ensure!(
            l.select(&s.g, &s.ctx.package_sha256).await?.is_none()
                && matches!(l.authorize(&s.g, 1, &r).await?, Dispatch::Granted)
        );
        let (received, _) = s.lease("received").await?;
        received.select(&s.g, &s.ctx.package_sha256).await?;
        ensure!(matches!(
            received.authorize(&s.g, 1, &r).await?,
            Dispatch::Granted
        ));
        let resp = CapturedResponse {
            status: 200,
            headers: vec![],
            body: b"saved response".to_vec(),
            complete: true,
        };
        received
            .record(&s.g, &received.receipt(&s.g, 1, &r, Some(&resp), "")?)
            .await?;
        s.g.retire().await?;
        let next = s.restart().await?;
        for key in ["lost", "received"] {
            let first = next.create_payment(s.caller(), s.create(key)).await?;
            let x = first.execution.as_ref().unwrap();
            ensure!(
                x.category == 3
                    && x.error_code == "dispatch_interrupted"
                    && x.requests == 1
                    && x.responses == u32::from(key == "received")
            );
            let bytes = s.evidence(x).await?;
            ensure!(bytes.windows(14).any(|w| w == b"saved response") == (key == "received"));
            ensure!(
                next.create_payment(s.caller(), s.create(key))
                    .await?
                    .encode_to_vec()
                    == first.encode_to_vec()
            );
        }
        ensure!(s.count() == 0);
        Ok(())
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[ignore = "requires PostgreSQL and packaged components"]
async fn revocation_wins_before_first_permission() -> Result<()> {
    schema(Role::Trade, |s| async move {
        let (resume, rx) = std::sync::mpsc::channel();
        *s.kms.before_open.lock().unwrap() = Some(rx);
        let g = s.g.clone();
        let req = s.create("admitted");
        let retry = req.clone();
        let job = tokio::spawn(async move { g.create_payment(caller(Role::Trade), req).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while s.kms.credential_reads.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await
            }
        })
        .await?;
        s.revoke().await?;
        resume.send(())?;
        let x = job.await??.execution.unwrap();
        ensure!(
            x.category == 4
                && x.error_code == "package_revoked"
                && x.package_sha256 == s.ctx.package_sha256
                && x.requests == 0
                && s.count() == 0
        );
        ensure!(s.g.create_payment(s.caller(), retry).await?.execution == Some(x));
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn first_permission_wins_concurrent_revocation_and_duplicate() -> Result<()> {
    schema(Role::Trade, |s| async move {
        let (resume, rx) = std::sync::mpsc::channel();
        *s.up.pause.lock().unwrap() = Some(rx);
        let r = s.create("in-flight");
        let g = s.g.clone();
        let copy = r.clone();
        let call = tokio::spawn(async move { g.create_payment(caller(Role::Trade), copy).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while s.count() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await
            }
        })
        .await?;
        let short = VerifiedCaller::for_test("payment", Instant::now() + Duration::from_millis(60));
        ensure!(
            s.g.create_payment(short, r.clone())
                .await
                .unwrap_err()
                .code()
                == Code::Unavailable
        );
        s.revoke().await?;
        resume.send(())?;
        let x = success(call.await??.execution)?;
        s.evidence(&x).await?;
        ensure!(x == s.g.create_payment(s.caller(), r).await?.execution.unwrap() && s.count() == 1);
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn verification_role_and_permanent_tombstones() -> Result<()> {
    schema(Role::Verification, |s| async move {
        ensure!(
            s.g.create_payment(s.caller(), Default::default())
                .await
                .unwrap_err()
                .code()
                == Code::PermissionDenied
        );
        ensure!(
            s.g.query_payment(caller(Role::Trade), s.query("peer"))
                .await
                .unwrap_err()
                .code()
                == Code::PermissionDenied
        );
        success(
            s.g.query_payment(s.caller(), s.query("ok"))
                .await?
                .execution,
        )?;
        s.revoke().await?;
        let next = s.restart().await?;
        ensure!(
            next.query_payment(s.caller(), s.query("blocked"))
                .await?
                .execution
                .unwrap()
                .error_code
                == "package_revoked"
        );
        ensure!(
            next.query_refund(
                s.caller(),
                QueryRefundRequest {
                    context: s.ctx("stopped"),
                    input: Some(s.refund("query_refund"))
                }
            )
            .await?
            .execution
            .unwrap()
            .error_code
                == "package_revoked"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn fence_while_transport_is_in_flight() -> Result<()> {
    schema(Role::Trade, |s| async move {
        let (resume, rx) = std::sync::mpsc::channel();
        *s.up.pause.lock().unwrap() = Some(rx);
        let g = s.g.clone();
        let request = s.create("crash");
        let copy = request.clone();
        let old = tokio::spawn(async move { g.create_payment(caller(Role::Trade), copy).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while s.count() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await
            }
        })
        .await?;
        s.g.retire().await?;
        let next = s.restart().await?;
        let result = next.create_payment(s.caller(), request.clone()).await?;
        let x = result.execution.as_ref().unwrap();
        ensure!(
            x.category == 3
                && x.error_code == "dispatch_interrupted"
                && x.requests == 1
                && x.responses == 0
        );
        resume.send(())?;
        ensure!(old.await?.is_err());
        ensure!(
            next.create_payment(s.caller(), request)
                .await?
                .encode_to_vec()
                == result.encode_to_vec()
                && s.count() == 1
        );
        s.evidence(x).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn cancelled_caller_still_seals_terminal() -> Result<()> {
    schema(Role::Trade, |s| async move {
        let (resume, rx) = std::sync::mpsc::channel();
        *s.up.pause.lock().unwrap() = Some(rx);
        let g = s.g.clone();
        let req = s.create("disconnect");
        let copy = req.clone();
        let old = tokio::spawn(async move { g.create_payment(caller(Role::Trade), copy).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while s.count() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await
            }
        })
        .await?;
        old.abort();
        let _ = old.await;
        resume.send(())?;
        let x =
            s.g.create_payment(s.caller(), req)
                .await?
                .execution
                .unwrap();
        ensure!(
            x.category == 3 && x.error_code == "cancelled" && x.requests == 1 && s.count() == 1
        );
        s.evidence(&x).await?;
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn revoke_unknown_digest_before_publication() -> Result<()> {
    schema(Role::Trade, |s| async move {
        let mut p = s.pkg.clone();
        let mut m: Value = serde_json::from_slice(&p.manifest_json)?;
        m["version"] = json!("0.3.1");
        p.manifest_json = upstream_host::json::canonical(&m);
        p.package_sha256 = sha2::Sha256::new()
            .chain_update(&p.manifest_json)
            .chain_update(&p.plugin_wasm)
            .finalize()
            .to_vec();
        let mut reg = s.publication.clone();
        reg.idempotency_key = "future".into();
        reg.package = Some(p.clone());
        reg.approved_digests =
            s.g.replay_package(
                s.caller(),
                ReplayPackageRequest {
                    package: Some(p.clone()),
                },
            )
            .await?
            .digests;
        let revoke = RevokePackageRequest {
            idempotency_key: "stop-early".into(),
            package_sha256: p.package_sha256.clone(),
            owner_action_id: uid(),
        };
        let first = s.g.revoke_package(s.caller(), revoke.clone()).await?;
        let next = s.restart().await?;
        ensure!(first == next.revoke_package(s.caller(), revoke).await?);
        ensure!(
            next.register_package(s.caller(), reg)
                .await
                .unwrap_err()
                .code()
                == Code::FailedPrecondition
        );
        let mut req = s.create("late-create");
        req.context.as_mut().unwrap().package_sha256 = p.package_sha256;
        ensure!(
            next.create_payment(s.caller(), req)
                .await?
                .execution
                .unwrap()
                .error_code
                == "package_revoked"
                && s.count() == 0
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn callback_secret_quarantined_without_opening_credentials() -> Result<()> {
    schema(Role::Trade, |s| async move {
        for op in ["route", "verify"] {
            let mut raw = s.raw();
            if op == "route" {
                let escaped = s
                    .secret
                    .bytes()
                    .map(|b| format!("\\u{b:04x}"))
                    .collect::<String>();
                raw.body = format!(r#"{{"value":"{escaped}","value":"other"}}"#).into_bytes();
            } else {
                raw.body.extend(s.secret.as_bytes());
            }
            let x = if op == "route" {
                s.g.route_callback(
                    s.caller(),
                    RouteCallbackRequest {
                        context: s.ctx(op),
                        input: Some(raw),
                    },
                )
                .await?
                .execution
            } else {
                let p = s.payment("verify_callback");
                s.g.verify_callback(
                    s.caller(),
                    VerifyCallbackRequest {
                        context: s.ctx(op),
                        input: Some(VerifyCallbackInput {
                            order_id: p.order_id,
                            money: p.money,
                            raw: Some(raw),
                        }),
                    },
                )
                .await?
                .execution
            }
            .unwrap();
            ensure!(x.category == 4 && x.error_code == "secret_leak" && x.requests == 0);
            ensure!(
                s.g.get_exchange(
                    s.caller(),
                    GetExchangeRequest {
                        exchange_id: x.exchange_id
                    }
                )
                .await
                .unwrap_err()
                .code()
                    == Code::FailedPrecondition
            );
        }
        ensure!(
            s.kms.credential_reads.load(Ordering::SeqCst) == 0
                && s.events.alerts.lock().unwrap().len() == 2
        );
        s.scan().await
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn independent_package_replay_and_immutable_publication() -> Result<()> {
    schema(Role::Trade, |s| async move {
        let mut same = s.publication.clone();
        same.package.as_mut().unwrap().fixtures.reverse();
        ensure!(
            s.g.register_package(s.caller(), same).await?.digests == s.publication.approved_digests
        );
        let mut altered = s.publication.clone();
        altered.publication.as_mut().unwrap().approval_request_id = uid();
        ensure!(
            s.g.register_package(s.caller(), altered.clone())
                .await
                .unwrap_err()
                .code()
                == Code::AlreadyExists
        );
        altered.idempotency_key = "different-approval".into();
        ensure!(
            s.g.register_package(s.caller(), altered)
                .await
                .unwrap_err()
                .code()
                == Code::FailedPrecondition
        );
        let mut fixture = s.pkg.clone();
        fixture.fixtures[0].path = "../bad.json".into();
        ensure!(
            s.g.replay_package(
                s.caller(),
                ReplayPackageRequest {
                    package: Some(fixture)
                }
            )
            .await
            .unwrap_err()
            .code()
                == Code::FailedPrecondition
        );
        let mut failed = s.pkg.clone();
        let case = failed
            .fixtures
            .iter_mut()
            .find(|f| f.path.ends_with("create_payment_success.json"))
            .unwrap();
        let mut value: Value = serde_json::from_slice(&case.content)?;
        value["expected"]["steps"] = json!(4);
        case.content = serde_json::to_vec(&value)?;
        ensure!(
            s.g.replay_package(
                s.caller(),
                ReplayPackageRequest {
                    package: Some(failed)
                }
            )
            .await
            .unwrap_err()
            .code()
                == Code::FailedPrecondition
        );
        let mut p = s.pkg.clone();
        let mut manifest: Value = serde_json::from_slice(&p.manifest_json)?;
        manifest["build"]["source_tree_sha256"] = json!("1".repeat(64));
        p.manifest_json = upstream_host::json::canonical(&manifest);
        p.package_sha256 = sha2::Sha256::new()
            .chain_update(&p.manifest_json)
            .chain_update(&p.plugin_wasm)
            .finalize()
            .to_vec();
        let replay =
            s.g.replay_package(
                s.caller(),
                ReplayPackageRequest {
                    package: Some(p.clone()),
                },
            )
            .await?;
        let mut req = s.query("unregistered");
        req.context.as_mut().unwrap().package_sha256 = p.package_sha256.clone();
        let x = s.g.query_payment(s.caller(), req).await?.execution.unwrap();
        ensure!(x.error_code == "package_unavailable" && x.package_sha256.is_empty());
        let mut reg = s.publication.clone();
        reg.package = Some(p);
        reg.approved_digests = replay.digests;
        reg.idempotency_key = "version-collision".into();
        ensure!(
            s.g.register_package(s.caller(), reg)
                .await
                .unwrap_err()
                .code()
                == Code::FailedPrecondition
        );
        Ok(())
    })
    .await
}

#[tokio::test]
#[ignore = "requires PostgreSQL and packaged components"]
async fn transient_terminal_write_preserves_executor() -> Result<()> {
    schema(Role::Trade, |s| async move {
        // Sequence increments survive rollback. Exactly the first terminal write fails.
        let c = s.pool.get().await?;
        c.batch_execute("CREATE SEQUENCE terminal_attempts; CREATE SEQUENCE receipt_attempts;
            CREATE FUNCTION transient_failure() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN IF nextval(TG_ARGV[0]::regclass) = 1 THEN
            RAISE EXCEPTION 'temporary failure' USING ERRCODE='40001';
            END IF; RETURN NEW; END $$;
            CREATE TRIGGER fail_once BEFORE UPDATE OF terminal ON operations
            FOR EACH ROW EXECUTE FUNCTION transient_failure('terminal_attempts');
            CREATE TRIGGER fail_receipt_once BEFORE UPDATE OF reception ON attempts
            FOR EACH ROW EXECUTE FUNCTION transient_failure('receipt_attempts')").await?;
        let x = success(s.g.create_payment(s.caller(), s.create("retry-finish")).await?.execution)?;
        ensure!(s.count() == 1 && !s.g.needs_restart());
        ensure!(c.query_one("SELECT least(t.last_value,r.last_value) FROM terminal_attempts t, receipt_attempts r",&[]).await?.get::<_,i64>(0)==2);
        ensure!(c.query_one("SELECT created_at <= dispatched_at AND dispatched_at <= received_at AND received_at <= completed_at FROM operations JOIN attempts USING(exchange) WHERE exchange=$1",&[&x.exchange_id]).await?.get::<_,bool>(0));
        Ok(())
    }).await
}
