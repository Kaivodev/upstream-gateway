use crate::{
    api::*,
    business::{Input, Material, Outcome, required},
    crypto::{Kms, Vault, aad, stored_strings},
    db::{Db, unavailable},
    journal::{Claim, Lease},
    wire::invalid,
    *,
};
use anyhow::Result as AnyResult;
use deadpool_postgres::Pool;
use prost::Message;
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    traits::PublicKeyParts,
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use tokio::runtime::Handle;
use tonic::Status;
use upstream_host::{
    engine::{Host, Loaded, Options},
    environment::{Cancellation, CapturedResponse, Dispatch, Environment, Transport},
    types::HttpRequest,
};
use uuid::Uuid;
use zeroize::Zeroizing;

pub trait Events: Send + Sync {
    fn alert(&self, code: &'static str);
    fn log(&self, event: &serde_json::Value);
}
#[derive(Clone)]
pub struct Gateway(pub(crate) Arc<Inner>);
pub(crate) struct Inner {
    pub pool: Pool,
    pub role: Role,
    pub mode: Mode,
    pub vault: Vault,
    pub fingerprints: crate::callback::Fingerprints,
    pub timing: crate::config::Timing,
    pub workers: tokio::sync::watch::Sender<usize>,
    pub retiring: std::sync::atomic::AtomicBool,
    pub host: Arc<Host>,
    pub cache: RwLock<HashMap<Vec<u8>, Arc<Loaded>>>,
    pub executor: String,
    transport: Arc<dyn Transport>,
    events: Arc<dyn Events>,
    #[cfg(test)]
    pub unconfirm: std::sync::atomic::AtomicBool,
}
impl Gateway {
    pub async fn start(
        pool: Pool,
        role: Role,
        mode: Mode,
        kms: Arc<dyn Kms>,
        proxy: Option<std::net::SocketAddr>,
        roots: rustls::RootCertStore,
        events: Arc<dyn Events>,
    ) -> Result<Self, Status> {
        let transport = egress::Egress::new(Handle::current(), mode, proxy, roots)
            .map_err(|_| Status::failed_precondition("invalid egress configuration"))?;
        Self::initialize(
            pool,
            role,
            mode,
            kms,
            Arc::new(transport),
            events,
            Default::default(),
        )
        .await
    }
    #[cfg(test)]
    pub(crate) async fn init(
        pool: Pool,
        role: Role,
        mode: Mode,
        kms: Arc<dyn Kms>,
        transport: Arc<dyn Transport>,
        events: Arc<dyn Events>,
    ) -> Result<Self, Status> {
        Self::initialize(pool, role, mode, kms, transport, events, Default::default()).await
    }
    pub(crate) async fn initialize(
        pool: Pool,
        role: Role,
        mode: Mode,
        kms: Arc<dyn Kms>,
        transport: Arc<dyn Transport>,
        events: Arc<dyn Events>,
        timing: crate::config::Timing,
    ) -> Result<Self, Status> {
        if matches!(mode, Mode::Production) && kms.development_only() {
            return Err(Status::failed_precondition("development KMS"));
        }
        let vault = Vault(kms);
        let fingerprints = db::migrate(&pool, role, &vault).await?;
        let mut options = Options::production(role.world());
        options.test_only_allow_http = mode.allow_http();
        options.test_only_allow_uncommitted = mode.allow_uncommitted();
        let host = tokio::task::spawn_blocking(move || Host::new(options))
            .await
            .db()?
            .map_err(|_| Status::internal("host unavailable"))?;
        let executor = Uuid::now_v7().to_string();
        let g = Self(Arc::new(Inner {
            pool,
            role,
            mode,
            transport,
            events,
            vault,
            fingerprints,
            timing,
            workers: tokio::sync::watch::channel(0).0,
            retiring: Default::default(),
            host: Arc::new(host),
            cache: Default::default(),
            executor,
            #[cfg(test)]
            unconfirm: Default::default(),
        }));
        let mut c = g.0.pool.get().await.db()?;
        let tx = c.transaction().await.db()?;
        tx.execute("INSERT INTO executors(id) VALUES($1)", &[&g.0.executor])
            .await
            .db()?;
        tx.commit().await.db()?;
        drop(c);
        // A large recovery backlog must not delay the process heartbeat.
        for heartbeat in [true, false] {
            let weak = Arc::downgrade(&g.0);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(timing.heartbeat_ms)).await;
                    let Some(inner) = weak.upgrade() else { break };
                    let g = Self(inner);
                    let result = if heartbeat {
                        g.refresh().await
                    } else {
                        g.recover().await
                    };
                    if result.is_err() {
                        g.0.events.alert("journal_maintenance")
                    }
                }
            });
        }
        let c = g.0.pool.get().await.db()?;
        let rows = c
            .query(
                "SELECT digest FROM packages WHERE ready AND (NOT EXISTS (SELECT 1 FROM
         revocations r WHERE r.digest=packages.digest) OR $1)",
                &[&(role == Role::Trade)],
            )
            .await
            .db()?;
        drop(c);
        for row in rows {
            let digest: Vec<u8> = row.get(0);
            if g.load_package(&digest).await.is_err() {
                let mut c = g.0.pool.get().await.db()?;
                let tx = c.transaction().await.db()?;
                tx.execute(
                    "UPDATE packages SET ready=false WHERE digest=$1",
                    &[&digest],
                )
                .await
                .db()?;
                tx.commit().await.db()?;
                g.0.events.alert("package_unavailable");
            }
        }
        g.maintain().await?;
        Ok(g)
    }
    /// A fenced executor needs a fresh process identity to accept new work.
    pub fn needs_restart(&self) -> bool {
        self.0.retiring.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub(crate) fn authorize(
        &self,
        caller: &VerifiedCaller,
        trade_only: bool,
    ) -> Result<(), Status> {
        if caller.name() != self.0.role.caller() || trade_only && self.0.role != Role::Trade {
            return Err(Status::permission_denied("method denied"));
        }
        if Instant::now() >= caller.deadline() {
            return Err(Status::unavailable("request expired"));
        }
        Ok(())
    }
    async fn business<M: Message + Default>(
        &self,
        caller: VerifiedCaller,
        ctx: OperationContext,
        input: Input,
    ) -> Result<M, Status> {
        let m = input.material(self.0.role, caller.name(), ctx)?;
        let cancel = Cancellation {
            deadline: Some(caller.deadline()),
            ..Default::default()
        };
        struct CancelOnDrop(Cancellation);
        impl Drop for CancelOnDrop {
            fn drop(&mut self) {
                self.0.cancel()
            }
        }
        let _guard = CancelOnDrop(cancel.clone());
        let g = self.clone();
        let deadline = caller.deadline();
        // The worker owns its journal and can finish after loss of the response receiver.
        struct Worker(tokio::sync::watch::Sender<usize>);
        impl Drop for Worker {
            fn drop(&mut self) {
                self.0.send_modify(|n| *n -= 1);
            }
        }
        g.0.workers.send_modify(|n| *n += 1);
        let tracked = Worker(g.0.workers.clone());
        let worker = tokio::spawn(async move {
            let _tracked = tracked;
            let mut waiting = false;
            loop {
                if cancel.cancelled() {
                    return Err(unavailable());
                }
                let observed = if waiting {
                    g.observe(caller.name(), &m.context.idempotency_key).await?
                } else {
                    None
                };
                match if let Some(action) = observed {
                    action
                } else {
                    g.claim(caller.name(), &m).await?
                } {
                    Claim::Done(bytes) => return Ok(bytes),
                    Claim::Wait => {
                        waiting = true;
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Claim::Run(lease) => return g.execute(lease, m, cancel).await,
                }
            }
        });
        let b = tokio::time::timeout_at(deadline.into(), worker)
            .await
            .map_err(|_| unavailable())?
            .db()??;
        M::decode(b.as_slice()).map_err(|_| Status::data_loss("invalid terminal response"))
    }
    async fn execute(
        &self,
        lease: Lease,
        m: Material,
        cancel: Cancellation,
    ) -> Result<Vec<u8>, Status> {
        let g = self.clone();
        let outcome = async {
            // Screen the original callback even when later package or account checks fail.
            if let Some(raw) = &m.callback {
                let row = retry_storage(|| async {
                    self.0
                        .pool
                        .get()
                        .await
                        .db()?
                        .query_opt(
                            "SELECT markers FROM credentials WHERE ref=$1",
                            &[&m.context.credentials_ref],
                        )
                        .await
                        .db()
                })
                .await?;
                if let Some(row) = row
                    && self.0.fingerprints.contains(
                        &row.get::<_, Vec<Vec<u8>>>(0),
                        raw,
                        &m.config,
                    )?
                {
                    self.0.events.alert("secret_leak");
                    return Ok(Outcome::failure("secret_leak"));
                }
            }
            let digest = &m.context.package_sha256;
            if let Some(code) = retry_storage(|| self.availability(digest, lease.blocked)).await? {
                return Ok(Outcome::failure(code));
            }
            let p = match retry_storage(|| self.load_package(digest)).await {
                Ok(p) => p,
                Err(status) if status.code() == tonic::Code::FailedPrecondition => {
                    return Ok(Outcome::failure("package_unavailable"));
                }
                Err(s) => return Err(s),
            };
            if let Some(code) = retry_storage(|| lease.select(self, digest)).await? {
                return Ok(Outcome::failure(code));
            }
            let values = match retry_storage(|| self.bound_credentials(&m, &p)).await? {
                Ok(v) => v,
                Err(code) => return Ok(Outcome::failure(code)),
            };
            let env = Arc::new(RuntimeEnvironment {
                g: g.clone(),
                lease: lease.clone(),
                runtime: Handle::current(),
                values,
                config: m.config,
                write_error: Mutex::default(),
            });
            let host = self.0.host.clone();
            let environment = env.clone();
            let result = tokio::task::spawn_blocking(move || {
                host.execute(&p, m.op, &m.raw, environment, cancel)
            })
            .await
            .db()?;
            if let Some(status) = env.write_error.lock().unwrap().take() {
                return Err(status);
            }
            Outcome::from_host(result)
        }
        .await;
        let result = match outcome {
            Ok(out) => retry_storage(|| lease.finish(self, out.clone())).await,
            Err(status) => Err(status),
        };
        // An abandoned owner must never keep receiving heartbeats for a stuck operation.
        if result.is_err() {
            self.retire().await?;
        }
        result
    }
    pub(crate) async fn retire(&self) -> Result<(), Status> {
        self.0
            .retiring
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut c = self.0.pool.get().await.db()?;
        let tx = c.transaction().await.db()?;
        tx.execute(
            "UPDATE executors SET fenced=true WHERE id=$1",
            &[&self.0.executor],
        )
        .await
        .db()?;
        tx.commit().await.db()
    }
    async fn bound_credentials(
        &self,
        m: &Material,
        p: &Arc<Loaded>,
    ) -> Result<Result<BTreeMap<String, Zeroizing<String>>, &'static str>, Status> {
        let ctx = &m.context;
        let manifest = p.manifest();
        let c = self.0.pool.get().await.db()?;
        // Keep the route path independent of both ciphertext access and KMS availability.
        let row = c
            .query_opt(
                "SELECT code, names FROM credentials WHERE ref=$1 AND channel=$2 AND
                 digest=$3",
                &[
                    &ctx.credentials_ref,
                    &ctx.channel_account_id,
                    &ctx.credentials_sha256,
                ],
            )
            .await
            .db()?;
        let Some(row) = row else {
            return Ok(Err("credential_unavailable"));
        };
        let code: &str = row.get(0);
        let names: Vec<String> = row.get(1);
        let expected = manifest
            .secrets
            .keys()
            .chain(&manifest.public_keys)
            .collect::<BTreeSet<_>>();
        if names.iter().collect::<BTreeSet<_>>() != expected
            || self.0.role == Role::Trade && code != manifest.code
        {
            return Ok(Err("credential_unavailable"));
        }
        if m.op == "route_callback" {
            return Ok(Ok(BTreeMap::new()));
        }
        let sealed = c
            .query_one(
                "SELECT sealed FROM credentials WHERE ref=$1",
                &[&ctx.credentials_ref],
            )
            .await
            .db()?;
        let aad = aad(
            "aipay.upstream.credentials.v1",
            self.0.role,
            &[&ctx.credentials_ref, &ctx.channel_account_id, code],
        );
        let digest = ctx.credentials_sha256.clone();
        let vault = self.0.vault.clone();
        let sealed: Vec<u8> = sealed.get(0);
        let p = p.clone();
        drop(c);
        tokio::task::spawn_blocking(move || {
            let manifest = p.manifest();
            let Ok(plain) = vault.open(&sealed, &aad) else {
                return Ok(Err("credential_unavailable"));
            };
            if encoding::hash(&plain) != digest {
                return Ok(Err("credential_unavailable"));
            }
            let values = stored_strings(&plain)?
                .into_iter()
                .map(|(k, v)| (k, Zeroizing::new(v)))
                .collect::<BTreeMap<_, _>>();
            if values.keys().ne(names.iter()) {
                return Ok(Err("credential_unavailable"));
            }
            for (n, v) in &values {
                let valid = match manifest.secrets.get(n).map(String::as_str) {
                    Some("shared") => (16..=16384).contains(&v.len()),
                    Some("rsa-private") => rsa::PrivateKey::from_pkcs8_pem(v)
                        .is_ok_and(|k| k.n().bit_width() >= 2048 && k.validate().is_ok()),
                    None => rsa::PublicKey::from_public_key_pem(v)
                        .is_ok_and(|k| k.n().bit_width() >= 2048),
                    _ => false,
                };
                if !valid {
                    return Ok(Err("credential_unavailable"));
                }
            }
            Ok(Ok(values))
        })
        .await
        .db()?
    }
}
macro_rules! business {
    ($name:ident,$req:ident,$resp:ident,$variant:ident,$trade:expr) => {
        impl Gateway {
            pub async fn $name(&self, caller: VerifiedCaller, req: $req) -> Result<$resp, Status> {
                self.authorize(&caller, $trade)?;
                crate::wire::check_size(&req)?;
                self.business(
                    caller,
                    required(req.context)?,
                    Input::$variant(req.input.ok_or_else(invalid)?),
                )
                .await
            }
        }
    };
}
business!(
    create_payment,
    CreatePaymentRequest,
    CreatePaymentResponse,
    Create,
    true
);
business!(
    query_payment,
    QueryPaymentRequest,
    QueryPaymentResponse,
    Query,
    false
);
business!(
    close_payment,
    ClosePaymentRequest,
    ClosePaymentResponse,
    Close,
    true
);
business!(refund, RefundRequest, RefundResponse, Refund, true);
business!(
    query_refund,
    QueryRefundRequest,
    QueryRefundResponse,
    QueryRefund,
    false
);
business!(
    route_callback,
    RouteCallbackRequest,
    RouteCallbackResponse,
    Route,
    true
);
business!(
    verify_callback,
    VerifyCallbackRequest,
    VerifyCallbackResponse,
    Verify,
    true
);

async fn retry_storage<T, F: Future<Output = Result<T, Status>>>(
    mut operation: impl FnMut() -> F,
) -> Result<T, Status> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut delay = Duration::from_millis(25);
        loop {
            match operation().await {
                Err(e) if crate::db::retryable(&e) => {
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_millis(500));
                }
                result => return result,
            }
        }
    })
    .await
    .map_err(|_| unavailable())?
}

struct RuntimeEnvironment {
    g: Gateway,
    lease: Lease,
    runtime: Handle,
    values: BTreeMap<String, Zeroizing<String>>,
    config: BTreeMap<String, String>,
    write_error: Mutex<Option<Status>>,
}
impl Environment for RuntimeEnvironment {
    fn secret(&self, name: &str, _: &Cancellation) -> AnyResult<Zeroizing<Vec<u8>>> {
        self.values
            .get(name)
            .map(|v| Zeroizing::new(v.as_bytes().to_vec()))
            .ok_or_else(|| anyhow::anyhow!("credential unavailable"))
    }
    fn public_key_pem(&self, name: &str, _: Instant, _: &Cancellation) -> AnyResult<String> {
        self.values
            .get(name)
            .map(|v| v.to_string())
            .ok_or_else(|| anyhow::anyhow!("credential unavailable"))
    }
    fn config(&self, _: &Cancellation) -> BTreeMap<String, String> {
        self.config.clone()
    }
    fn alert(&self, _: &str) {
        self.g.0.events.alert("secret_leak")
    }
    fn log(&self, event: &serde_json::Value) {
        self.g.0.events.log(event)
    }
    fn transport(&self) -> Option<&dyn Transport> {
        Some(&*self.g.0.transport)
    }
    fn authorize_dispatch(&self, n: usize, r: &HttpRequest) -> Dispatch {
        self.runtime
            .block_on(self.lease.authorize(&self.g, n, r))
            .unwrap_or(Dispatch::Unconfirmed)
    }
    fn record_attempt(
        &self,
        n: usize,
        r: &HttpRequest,
        response: Option<&CapturedResponse>,
        code: &str,
    ) -> AnyResult<()> {
        let persisted = self
            .lease
            .receipt(&self.g, n, r, response, code)
            .and_then(|receipt| {
                self.runtime
                    .block_on(retry_storage(|| self.lease.record(&self.g, &receipt)))
            });
        if let Err(status) = persisted {
            *self.write_error.lock().unwrap() = Some(status);
            anyhow::bail!("attempt persistence unavailable")
        }
        Ok(())
    }
}
