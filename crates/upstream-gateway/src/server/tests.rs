use super::*;
use crate::{
    Role,
    service_token::tests::{
        config,
        token::{Signer, claims},
    },
};
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tonic::Code;
use tower::ServiceExt;

#[derive(Default)]
struct Capture(Mutex<Vec<Value>>);
impl Events for Capture {
    fn alert(&self, code: &'static str) {
        self.log(&json!(code));
    }
    fn log(&self, event: &Value) {
        self.0.lock().unwrap().push(event.clone());
    }
}

#[tokio::test]
async fn plaintext_authentication_precedes_method_policy_and_strips_credentials() {
    const HEALTH: &str = "/grpc.health.v1.Health/Check";
    const QUERY: &str = "/aipay.upstream.v1.UpstreamService/QueryPayment";
    const CREATE: &str = "/aipay.upstream.v1.UpstreamService/CreatePayment";
    let signer = Signer::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("jwks.json");
    std::fs::write(&path, json!({"keys":[signer.jwk()]}).to_string()).unwrap();
    let verifier = Verifier::load(
        config(&path),
        Role::Verification,
        vec!["reconciliation".into()],
    )
    .unwrap();
    let events = Arc::new(Capture::default());
    let (state, lifecycle) = watch::channel(Lifecycle::Serving);
    let boundary = Boundary {
        inner: tower::service_fn(|req: HttpRequest<()>| async move {
            assert!(!req.headers().contains_key(HEADER));
            let caller = req
                .extensions()
                .get::<VerifiedCaller>()
                .map(VerifiedCaller::name);
            if req.uri().path() == HEALTH {
                assert!(caller.is_none() && !req.headers().contains_key("x-trace-id"));
            } else {
                assert_eq!(caller, Some("reconciliation"));
            }
            Ok::<_, Infallible>(HttpResponse::new(Body::empty()))
        }),
        events: events.clone(),
        verifier: Some(Arc::new(verifier)),
        lifecycle,
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let valid = signer.token(&claims("verification", "reconciliation", now));
    let rejected = signer.token(&claims("trade", "payment", now));
    let forbidden = signer.token(&claims("verification", "payment", now));
    let call =
        |path: &'static str, tokens: &[&str], extra: Option<(&'static str, &'static str)>| {
            let mut req = HttpRequest::builder()
                .uri(path)
                .header("x-trace-id", "untrusted");
            for value in tokens {
                req = req.header(HEADER, *value);
            }
            if let Some((name, value)) = extra {
                req = req.header(name, value);
            }
            boundary.clone().oneshot(req.body(()).unwrap())
        };
    let status = |r: HttpResponse<Body>| Status::from_header_map(r.headers());
    assert!(status(call(HEALTH, &[], None).await.unwrap()).is_none());
    assert!(status(call(HEALTH, &[&rejected], None).await.unwrap()).is_none());
    for (tokens, expected) in [
        (vec![], "token_missing"),
        (vec![valid.as_str(); 2], "token_malformed"),
        (vec![rejected.as_str()], "token_audience"),
        (vec![forbidden.as_str()], "caller_not_allowed"),
    ] {
        events.0.lock().unwrap().clear();
        let response = status(call(QUERY, &tokens, None).await.unwrap()).unwrap();
        assert_eq!(response.code(), Code::Unauthenticated);
        assert!(
            response.message() == "service authentication required",
            "unexpected authentication response"
        );
        let records = events.0.lock().unwrap();
        assert!(
            records.as_slice() == [json!({"reason":expected,"method":QUERY})],
            "unexpected rejection event fields"
        );
        let captured = serde_json::to_string(&*records).unwrap();
        assert!(
            tokens
                .iter()
                .flat_map(|t| t.split('.'))
                .all(|part| !captured.contains(part))
        );
    }
    assert!(status(call(QUERY, &[&valid], None).await.unwrap()).is_none());
    let bad_timeout = Some(("grpc-timeout", "invalid"));
    assert_eq!(
        status(call(CREATE, &[&valid], bad_timeout).await.unwrap())
            .unwrap()
            .code(),
        Code::PermissionDenied
    );
    assert_eq!(
        status(call(QUERY, &[&valid], bad_timeout).await.unwrap())
            .unwrap()
            .code(),
        Code::InvalidArgument
    );
    for path in [HEALTH, QUERY] {
        assert_eq!(
            status(
                call(path, &[&valid], Some(("x-aipay-assertion", "")))
                    .await
                    .unwrap()
            )
            .unwrap()
            .code(),
            Code::Unauthenticated
        );
    }
    state.send_replace(Lifecycle::Draining);
    assert!(status(call(HEALTH, &[], None).await.unwrap()).is_none());
    assert_eq!(
        status(call(QUERY, &[&valid], None).await.unwrap())
            .unwrap()
            .code(),
        Code::Unavailable
    );
}

#[tokio::test]
async fn h2c_native_probe_observes_graceful_shutdown() -> anyhow::Result<()> {
    use crate::health::{
        HealthCheckRequest, HealthCheckResponse, health_check_response::ServingStatus,
    };
    use tonic::transport::Endpoint;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("jwks");
    std::fs::write(&path, json!({"keys":[Signer::new().jwk()]}).to_string())?;
    let verifier = Arc::new(Verifier::load(
        config(&path),
        Role::Trade,
        vec!["payment".into()],
    )?);
    let (state, lifecycle) = watch::channel(Lifecycle::Serving);
    let health = Health(lifecycle.clone());
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let endpoint = Endpoint::from_shared(format!("http://{}", listener.local_addr()?))?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let router = Identity::Plaintext(verifier.clone())
        .server()
        .layer(tower::layer::layer_fn(move |inner| Boundary {
            inner,
            verifier: Some(verifier.clone()),
            lifecycle: lifecycle.clone(),
            events: Arc::new(Observer),
        }))
        .add_service(HealthServer::new(health));
    let server = tokio::spawn(router.serve_with_incoming_shutdown(
        TcpListenerStream::new(listener),
        async {
            let _ = stopped.await;
        },
    ));
    let mut client = tonic::client::Grpc::new(endpoint.connect().await?);
    client.ready().await?;
    let mut updates: tonic::Streaming<HealthCheckResponse> = client
        .server_streaming(
            Request::new(HealthCheckRequest::default()),
            "/grpc.health.v1.Health/Watch".parse()?,
            tonic_prost::ProstCodec::default(),
        )
        .await?
        .into_inner();
    assert_eq!(
        updates.message().await?.unwrap().status(),
        ServingStatus::Serving
    );
    let mut request = Request::new(());
    request
        .metadata_mut()
        .insert(HEADER, "A".repeat((64 << 10) + 1).parse()?);
    client.ready().await?;
    let rejected: Result<Response<()>, _> = client
        .unary(
            request,
            "/aipay.upstream.v1.UpstreamService/QueryPayment".parse()?,
            tonic_prost::ProstCodec::default(),
        )
        .await;
    assert_eq!(rejected.unwrap_err().code(), Code::Unauthenticated);
    state.send_replace(Lifecycle::Draining);
    let _ = stop.send(());
    tokio::time::timeout(Duration::from_secs(5), async {
        assert_eq!(
            updates.message().await?.unwrap().status(),
            ServingStatus::NotServing
        );
        assert!(updates.message().await?.is_none());
        server.await??;
        anyhow::Ok(())
    })
    .await??;
    Ok(())
}
