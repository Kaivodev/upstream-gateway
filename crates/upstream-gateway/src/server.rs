use crate::{
    Events, Gateway, VerifiedCaller,
    api::{
        upstream_admin_service_server::{UpstreamAdminService, UpstreamAdminServiceServer},
        upstream_service_server::{UpstreamService, UpstreamServiceServer},
        *,
    },
    config::{Config, Tls},
    crypto::LocalKms,
    egress::Egress,
    health::{Health, Lifecycle, health_server::HealthServer},
    service_token::{HEADER, Verifier},
    tls::{Material, Peer},
    wire::{DESCRIPTORS, MESSAGE_LIMIT},
};
use anyhow::{Result, anyhow, ensure};
use futures_util::StreamExt;
use hyper::{Request as HttpRequest, Response as HttpResponse};
use prost_reflect::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{Arc, LazyLock},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
    sync::watch,
};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status, body::Body, transport::Server};
use tower::Service;

type Policies = BTreeMap<String, BTreeSet<String>>;
static POLICIES: LazyLock<Policies> = LazyLock::new(|| {
    let mut policies = Policies::new();
    let Some(ext) = DESCRIPTORS.get_extension_by_name("aipay.authz.v1.policy") else {
        return policies;
    };
    for service in DESCRIPTORS.services() {
        for method in service.methods() {
            let options = method.options();
            if !options.has_extension(&ext) {
                continue;
            }
            let policy = options.get_extension(&ext);
            let Some(rules) = policy
                .as_message()
                .and_then(|p| p.get_field_by_name("rules"))
            else {
                continue;
            };
            let mut names = BTreeSet::new();
            for rule in rules
                .as_list()
                .unwrap_or_default()
                .iter()
                .filter_map(Value::as_message)
            {
                if rule
                    .get_field_by_name("assertion")
                    .and_then(|v| v.as_enum_number())
                    != Some(1)
                    || !rule
                        .get_field_by_name("permissions")
                        .is_some_and(|v| v.as_list().is_some_and(|p| p.is_empty()))
                    || rule
                        .get_field_by_name("recent_auth_max_age_seconds")
                        .and_then(|v| v.as_u32())
                        != Some(0)
                {
                    continue;
                }
                if let Some(callers) = rule.get_field_by_name("callers") {
                    names.extend(
                        callers
                            .as_list()
                            .unwrap_or_default()
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned),
                    );
                }
            }
            policies.insert(format!("/{}/{}", service.full_name(), method.name()), names);
        }
    }
    policies
});

const REQUEST_BUDGET: Duration = Duration::from_secs(60);
const DRAIN_BUDGET: Duration = Duration::from_secs(75);
fn budget(value: Option<&hyper::header::HeaderValue>) -> Result<Duration, Status> {
    let Some(value) = value else {
        return Ok(REQUEST_BUDGET);
    };
    let value = value.as_bytes();
    let (unit, digits) = value.split_last().ok_or_else(crate::wire::invalid)?;
    if digits.is_empty() || digits.len() > 8 || !digits.iter().all(u8::is_ascii_digit) {
        return Err(crate::wire::invalid());
    }
    let n = digits
        .iter()
        .fold(0u64, |n, b| n * 10 + u64::from(*b - b'0'));
    let d = match unit {
        b'H' => Duration::from_secs(n * 3600),
        b'M' => Duration::from_secs(n * 60),
        b'S' => Duration::from_secs(n),
        b'm' => Duration::from_millis(n),
        b'u' => Duration::from_micros(n),
        b'n' => Duration::from_nanos(n),
        _ => return Err(crate::wire::invalid()),
    };
    Ok(d.min(REQUEST_BUDGET))
}
#[derive(Clone)]
struct Boundary<S> {
    inner: S,
    lifecycle: watch::Receiver<Lifecycle>,
    verifier: Option<Arc<Verifier>>,
    events: Arc<dyn Events>,
}
impl<S, B> Service<HttpRequest<B>> for Boundary<S>
where
    S: Service<HttpRequest<B>, Response = HttpResponse<Body>>,
    S::Future: Send + 'static,
    S::Error: 'static,
{
    type Response = HttpResponse<Body>;
    type Error = S::Error;
    type Future = futures_util::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, mut req: HttpRequest<B>) -> Self::Future {
        let health = req.uri().path().starts_with("/grpc.health.v1.Health/");
        let token = self
            .verifier
            .as_ref()
            .filter(|_| !health)
            .map(|verifier| verifier.authenticate(req.headers()));
        req.headers_mut().remove(HEADER);
        let authorize = || {
            let token_peer = token.transpose().map_err(|reason| {
                self.events
                    .authentication_rejected(reason, req.uri().path());
                Status::unauthenticated("service authentication required")
            })?;
            if !health && *self.lifecycle.borrow() != Lifecycle::Serving {
                return Err(Status::unavailable("executor draining"));
            }
            if req.headers().contains_key("x-aipay-assertion") {
                return Err(Status::unauthenticated("unexpected assertion"));
            }
            if health {
                return Ok(None);
            }
            let peer = token_peer
                .as_ref()
                .or_else(|| req.extensions().get::<Peer>())
                .ok_or_else(|| Status::unauthenticated("missing peer"))?;
            if !POLICIES
                .get(req.uri().path())
                .is_some_and(|p| p.contains(peer.name()))
            {
                return Err(Status::permission_denied("method denied"));
            }
            Ok(Some(
                peer.caller(budget(req.headers().get("grpc-timeout"))?),
            ))
        };
        match authorize() {
            Ok(caller) => {
                if let Some(caller) = caller {
                    req.extensions_mut().insert(caller);
                } else {
                    req.headers_mut().remove("x-request-id");
                    req.headers_mut().remove("x-trace-id");
                }
                Box::pin(self.inner.call(req))
            }
            Err(status) => Box::pin(async move { Ok(status.into_http()) }),
        }
    }
}
macro_rules! handlers {
    ($service:ident, $( $method:ident($req:ident) -> $resp:ident ),+ ) => {
        #[tonic::async_trait]
        impl $service for Gateway {
            $(async fn $method(&self, mut request:Request<$req>)->Result<Response<$resp>,Status> {
                let caller = request.extensions_mut().remove::<VerifiedCaller>().ok_or_else(|| Status::unauthenticated("missing peer"))?;
                self.$method(caller,request.into_inner()).await.map(Response::new)
            })+
        }
    }
}
handlers!(UpstreamService, create_payment(CreatePaymentRequest)->CreatePaymentResponse,
    query_payment(QueryPaymentRequest)->QueryPaymentResponse, close_payment(ClosePaymentRequest)->ClosePaymentResponse,
    refund(RefundRequest)->RefundResponse, query_refund(QueryRefundRequest)->QueryRefundResponse,
    route_callback(RouteCallbackRequest)->RouteCallbackResponse, verify_callback(VerifyCallbackRequest)->VerifyCallbackResponse);
handlers!(UpstreamAdminService, replay_package(ReplayPackageRequest)->ReplayPackageResponse,
    register_package(RegisterPackageRequest)->RegisterPackageResponse,revoke_package(RevokePackageRequest)->RevokePackageResponse,
    store_credentials(StoreCredentialsRequest)->StoreCredentialsResponse,get_exchange(GetExchangeRequest)->GetExchangeResponse);

pub(crate) struct Observer;
impl Events for Observer {
    fn alert(&self, code: &'static str) {
        eprintln!("gateway event {code}");
    }
    fn log(&self, _: &serde_json::Value) {}
    fn authentication_rejected(&self, reason: &'static str, method: &str) {
        eprintln!("gateway rejection {reason} {method}");
    }
    fn kms_failed(&self, event: &'static str, step: &'static str, status: Option<u16>) {
        match status {
            Some(status) => eprintln!("{event} step={step} status={status}"),
            None => eprintln!("{event} step={step}"),
        }
    }
    fn completion(&self, code: &'static str) {
        eprintln!("gateway completion {code}");
    }
}
enum Identity {
    Mtls(Tls, watch::Sender<Material>),
    Plaintext(Arc<Verifier>),
}
impl Identity {
    fn server(&self) -> Server {
        let builder = Server::builder();
        match self {
            Self::Mtls(..) => builder,
            // Room for a 64 KiB token plus ordinary gRPC metadata, so the verifier
            // (not the HTTP/2 layer) classifies oversized tokens. Callers are
            // limited by NetworkPolicy; keep the per-request header memory bounded.
            Self::Plaintext(_) => builder.http2_max_header_list_size(128 << 10),
        }
    }

    async fn watch(self, role: crate::Role, events: Arc<dyn Events>) {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            match &self {
                Self::Mtls(config, material) => {
                    let next = material.borrow().reload(config, role);
                    match next {
                        Ok(Some(new)) => {
                            material.send_replace(new);
                        }
                        Ok(None) => (),
                        Err(_) => events.alert("tls_reload_rejected"),
                    }
                }
                Self::Plaintext(verifier) => {
                    if verifier.reload().is_err() {
                        events.alert("service_token_keys_reload_rejected");
                    }
                }
            }
        }
    }
}

pub async fn run(path: &Path) -> Result<()> {
    let (config, mode) = Config::read(path)?;
    let identity = match (config.tls, config.service_token) {
        (Some(tls), None) => {
            let material = Material::load(&tls, config.role)
                .map_err(|_| anyhow!("invalid TLS material or service identity"))?;
            Identity::Mtls(tls, watch::channel(material).0)
        }
        (None, Some(config_token)) => Identity::Plaintext(Arc::new(Verifier::load(
            config_token,
            config.role,
            config.allowed_peers,
        )?)),
        _ => anyhow::bail!("invalid authentication settings for transport"),
    };
    let pool = config.startup.pool(mode)?;
    if config.startup.migrate_on_start {
        crate::schema::apply(&pool, None).await?;
    }
    let kms = match (&config.kms, &config.local_kek_file) {
        (Some(config_kms), None) => crate::kms::unwrap(config_kms, config.role, &Observer).await?,
        (None, Some(file)) => {
            LocalKms::from_file(mode, file).map_err(|_| anyhow!("invalid KMS file"))?
        }
        _ => anyhow::bail!("invalid KEK configuration"),
    };
    let roots = match config.egress_ca_file {
        Some(ref path) => {
            crate::tls::roots(path).map_err(|_| anyhow!("invalid egress trust bundle"))?
        }
        None => Egress::public_roots(),
    };
    let transport = Egress::with_proxy(
        tokio::runtime::Handle::current(),
        mode,
        config.egress_proxy,
        roots,
    )?;
    let mut term = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    let gateway = Gateway::initialize(
        pool,
        config.role,
        mode,
        Arc::new(kms),
        Arc::new(transport),
        Arc::new(Observer),
        config.timing,
    )
    .await?;
    let listener = TcpListener::bind(config.listen)
        .await
        .map_err(|_| anyhow!("cannot bind gateway listener"))?;
    let lifecycle = gateway.0.lifecycle.subscribe();
    let verifier = match &identity {
        Identity::Plaintext(v) => Some(v.clone()),
        Identity::Mtls(..) => None,
    };
    let boundary = {
        let lifecycle = lifecycle.clone();
        let events = gateway.0.events.clone();
        tower::layer::layer_fn(move |inner| Boundary {
            inner,
            lifecycle: lifecycle.clone(),
            verifier: verifier.clone(),
            events: events.clone(),
        })
    };
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let router = identity
        .server()
        .layer(boundary)
        .add_service(HealthServer::new(Health(lifecycle.clone())))
        .add_service(
            UpstreamServiceServer::new(gateway.clone())
                .max_decoding_message_size(MESSAGE_LIMIT)
                .max_encoding_message_size(MESSAGE_LIMIT),
        )
        .add_service(
            UpstreamAdminServiceServer::new(gateway.clone())
                .max_decoding_message_size(MESSAGE_LIMIT)
                .max_encoding_message_size(MESSAGE_LIMIT),
        );
    let shutdown = async {
        let _ = stopped.await;
    };
    use futures_util::future::Either;
    let server = match &identity {
        Identity::Mtls(_, material) => {
            let current = material.subscribe();
            let incoming = TcpListenerStream::new(listener)
                .map(move |socket| {
                    let material = current.borrow().clone();
                    async move {
                        match socket {
                            Ok(socket) => material.handshake(socket).await.ok().map(Ok),
                            Err(e) => Some(Err(e)),
                        }
                    }
                })
                .buffer_unordered(64)
                .filter_map(std::future::ready);
            Either::Left(router.serve_with_incoming_shutdown(Box::pin(incoming), shutdown))
        }
        Identity::Plaintext(_) => Either::Right(
            router.serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown),
        ),
    };
    let mut reload = tokio::task::JoinSet::new();
    reload.spawn(identity.watch(config.role, gateway.0.events.clone()));
    tokio::pin!(server);
    let mut workers = gateway.0.workers.subscribe();
    let mut retiring = lifecycle;
    tokio::select! {
        _ = term.recv() => (), _ = interrupt.recv() => (),
        _ = retiring.wait_for(|v| *v == Lifecycle::RestartRequired) => (),
        res = &mut server => { res?; anyhow::bail!("gateway listener stopped"); }
    }
    gateway.0.lifecycle.send_if_modified(|state| {
        if *state == Lifecycle::Serving {
            *state = Lifecycle::Draining;
            true
        } else {
            false
        }
    });
    reload.abort_all();
    let _ = stop.send(());
    tokio::time::timeout(DRAIN_BUDGET, async {
        server.await?;
        workers
            .wait_for(|n| *n == 0)
            .await
            .map_err(|_| anyhow!("worker tracking unavailable"))?;
        if gateway.needs_restart() {
            // Workers cannot write through a fence. Finalize marked attempts and
            // release unmarked claims under the same drain deadline.
            gateway.retire().await?;
            gateway.recover().await?;
        }
        Ok::<(), anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow!("gateway drain timed out"))??;
    ensure!(!gateway.needs_restart(), "executor fenced");
    Ok(())
}

#[cfg(test)]
mod tests;
