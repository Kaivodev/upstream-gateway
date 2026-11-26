use super::*;
use anyhow::Context;
use base64::prelude::*;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Response, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use kaivo_upstream_sdk::form;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use upstream_host::{
    package::Package,
    replay::{Ephemeral, TestCredentials},
};

#[derive(Default)]
struct Hooks {
    hold: Option<oneshot::Receiver<()>>,
    echo: Option<Vec<u8>>,
}
struct Mock {
    calls: AtomicUsize,
    hooks: Mutex<Hooks>,
    responses: BTreeMap<String, Vec<u8>>,
    requests: BTreeMap<String, Vec<u8>>,
    signing_key: SigningKey,
}
enum SigningKey {
    Form(zeroize::Zeroizing<Vec<u8>>),
    Rsa(rsa::PublicKey),
}
impl SigningKey {
    fn check(
        &self,
        request: &hyper::http::request::Parts,
        body: &[u8],
        recorded: &[u8],
    ) -> Result<()> {
        ensure!(request.method == hyper::Method::POST);
        let media = request.headers["content-type"].to_str()?;
        match self {
            Self::Form(key) => {
                ensure!(media == "application/x-www-form-urlencoded");
                let values = form::parse(body).context("invalid simulator form")?;
                let signed = form::canonical_bytes(&values).context("invalid simulator fields")?;
                let expected = form::parse(recorded)
                    .and_then(|v| form::canonical_bytes(&v))
                    .unwrap();
                ensure!(signed == expected);
                let digest = md5::Md5::new()
                    .chain_update(signed)
                    .chain_update(b"&key=")
                    .chain_update(&**key)
                    .finalize();
                ensure!(
                    form::get(&values, "sign")
                        == Some(upstream_host::package::hex(&digest).as_str())
                );
            }
            Self::Rsa(key) => {
                ensure!(media == "application/json" && body == recorded);
                let signature = BASE64_STANDARD.decode(
                    request
                        .headers
                        .get("x-signature")
                        .context("missing signature")?
                        .as_bytes(),
                )?;
                key.verify(
                    rsa::Pkcs1v15Sign::new::<Sha256>(),
                    &Sha256::digest(body),
                    &signature,
                )?;
            }
        }
        Ok(())
    }
}
pub struct PackageCase {
    pub ctx: OperationContext,
    keys: Ephemeral,
    mock: Arc<Mock>,
    server: JoinHandle<()>,
    inputs: BTreeMap<String, Value>,
}
impl Drop for PackageCase {
    fn drop(&mut self) {
        self.server.abort();
    }
}
impl PackageCase {
    pub async fn publish(rpc: &Rpc, name: &str) -> Result<Self> {
        let path = packages().join(name);
        let pkg = Package::read(&path)?;
        let keys = Ephemeral::new(&pkg.manifest)?;
        let mut values = BTreeMap::new();
        for (n, kind) in &pkg.manifest.secrets {
            let value = if kind == "shared" {
                String::from_utf8(keys.shared(n)?.to_vec())?
            } else {
                keys.private(n)
                    .unwrap()
                    .to_pkcs8_pem(LineEnding::LF)?
                    .to_string()
            };
            values.insert(n.clone(), value);
        }
        for n in &pkg.manifest.public_keys {
            values.insert(
                n.clone(),
                keys.public(n)?.to_public_key_pem(LineEnding::LF)?,
            );
        }
        let manifest_json = fs::read(path.join("manifest.json"))?;
        let digest = Sha256::new()
            .chain_update(&manifest_json)
            .chain_update(&pkg.wasm)
            .finalize()
            .to_vec();
        let mut inputs = BTreeMap::new();
        let mut responses = BTreeMap::new();
        let mut requests = BTreeMap::new();
        let mut account = String::new();
        for (path, data) in &pkg.fixtures {
            if !path.ends_with("_success.json") {
                continue;
            }
            let f: Value = serde_json::from_slice(data)?;
            account = f["config"]["account_id"].as_str().unwrap().into();
            inputs.insert(f["operation"].as_str().unwrap().into(), f["input"].clone());
            for x in f["exchanges"].as_array().unwrap() {
                let uri: hyper::Uri = x["request"]["url"].as_str().unwrap().parse()?;
                requests.insert(
                    uri.path().to_owned(),
                    BASE64_STANDARD.decode(x["request"]["body"].as_str().unwrap())?,
                );
                let mut response: Value = serde_json::from_slice(
                    &BASE64_STANDARD.decode(x["response"]["body"].as_str().unwrap())?,
                )?;
                if let Some(order) = response["order"].as_object_mut() {
                    // Expiry in a recording is relative to its recorded clock.
                    order.remove("expire_time");
                    order.remove("expires_at");
                }
                responses.insert(uri.path().to_owned(), serde_json::to_vec(&response)?);
            }
        }
        let package = Some(PluginPackage {
            manifest_json,
            plugin_wasm: pkg.wasm,
            package_sha256: digest.clone(),
            fixtures: pkg
                .fixtures
                .into_iter()
                .map(|(path, content)| PluginFixture { path, content })
                .collect(),
        });
        let replay: ReplayPackageResponse = rpc
            .call(ReplayPackageRequest {
                package: package.clone(),
            })
            .await?;
        let registration: RegisterPackageResponse = rpc
            .call(RegisterPackageRequest {
                idempotency_key: uid(),
                package,
                approved_digests: replay.digests.clone(),
                publication: Some(ApprovalReference {
                    approval_request_id: uid(),
                    request_digest: vec![1; 32],
                }),
            })
            .await?;
        ensure!(registration.digests == replay.digests);
        let channel = uid();
        let credential_json = serde_json::to_vec(&values)?;
        let credentials: StoreCredentialsResponse = rpc
            .call(StoreCredentialsRequest {
                idempotency_key: uid(),
                channel_account_id: channel.clone(),
                channel_code: name.trim_end_matches("_verify").into(),
                credentials_json: credential_json,
            })
            .await?;
        ensure!(
            credentials.credentials_sha256
                == Sha256::digest(upstream_host::json::canonical(&json!(values))).as_slice()
        );
        let verify = name.ends_with("_verify");
        ensure!(credentials.credentials_ref.starts_with(if verify {
            "reconciliation:verification:"
        } else {
            "payment:trade:"
        }));
        let wire = credentials.encode_to_vec();
        ensure!(
            values
                .values()
                .all(|v| !wire.windows(v.len()).any(|b| b == v.as_bytes()))
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let gateway = format!("http://{}", listener.local_addr()?);
        let mock = Arc::new(Mock {
            calls: 0.into(),
            hooks: Default::default(),
            requests,
            signing_key: if name.contains("json_rsa") {
                SigningKey::Rsa(
                    keys.private(if verify {
                        "query_private_key"
                    } else {
                        "platform_private"
                    })
                    .unwrap()
                    .to_public_key(),
                )
            } else {
                SigningKey::Form(keys.shared(if verify { "query_key" } else { "shared" })?)
            },
            responses,
        });
        let state = mock.clone();
        let server = tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                let state = state.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |r: hyper::Request<hyper::body::Incoming>| {
                        let state = state.clone();
                        async move {
                            let (parts, body) = r.into_parts();
                            let path = parts.uri.path();
                            let bytes = body.collect().await?.to_bytes();
                            state.calls.fetch_add(1, Ordering::SeqCst);
                            let recorded =
                                state.requests.get(path).context("unknown simulator URL")?;
                            state.signing_key.check(&parts, &bytes, recorded)?;
                            let Hooks { hold, echo } =
                                std::mem::take(&mut *state.hooks.lock().unwrap());
                            if let Some(pause) = hold {
                                let _ = pause.await;
                            }
                            let body = echo
                                .or_else(|| state.responses.get(path).cloned())
                                .unwrap_or_default();
                            Ok::<_, anyhow::Error>(
                                Response::builder()
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from(body)))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(s), svc)
                        .await;
                });
            }
        });
        let ctx = OperationContext {
            idempotency_key: uid(),
            channel_account_id: channel,
            verification_account_id: verify.then(uid),
            control_version: 1,
            credentials_sha256: credentials.credentials_sha256,
            credentials_ref: credentials.credentials_ref,
            package_sha256: digest,
            config_json: upstream_host::json::canonical(
                &json!({"account_id":account,"gateway":gateway}),
            ),
        };
        Ok(Self {
            ctx,
            keys,
            mock,
            server,
            inputs,
        })
    }
    pub fn calls(&self) -> usize {
        self.mock.calls.load(Ordering::SeqCst)
    }
    pub async fn wait_calls(&self, n: usize) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.calls() < n {
                tokio::time::sleep(Duration::from_millis(5)).await
            }
        })
        .await?;
        ensure!(self.calls() == n);
        Ok(())
    }
    pub fn hold(&self) -> oneshot::Sender<()> {
        let (tx, rx) = oneshot::channel();
        self.mock.hooks.lock().unwrap().hold = Some(rx);
        tx
    }
    pub fn echo(&self) -> Result<()> {
        self.mock.hooks.lock().unwrap().echo = Some(self.keys.shared("shared")?.to_vec());
        Ok(())
    }
    pub fn context(&self) -> Option<OperationContext> {
        Some(OperationContext {
            idempotency_key: uid(),
            ..self.ctx.clone()
        })
    }
    pub fn pay(&self, op: &str) -> PaymentInput {
        let v = &self.inputs[op];
        PaymentInput {
            order_id: v["order_id"].as_str().unwrap().into(),
            money: Some(Money {
                amount: v["money"]["amount"].as_str().unwrap().into(),
                currency: v["money"]["currency"].as_str().unwrap().into(),
            }),
        }
    }
    pub fn refund(&self, op: &str) -> RefundInput {
        let input = self.pay(op);
        RefundInput {
            order_id: input.order_id,
            money: input.money,
            refund_id: self.inputs[op]["refund_id"].as_str().unwrap().into(),
        }
    }
    pub fn create(&self) -> CreatePaymentRequest {
        let pay = self.pay("create_payment");
        let v = &self.inputs["create_payment"];
        CreatePaymentRequest {
            context: self.context(),
            input: Some(CreatePaymentInput {
                order_id: pay.order_id,
                money: pay.money,
                method: v["method"].as_str().unwrap().into(),
                callback_url: v["callback_url"].as_str().unwrap().into(),
                bank_mode: None,
                instruction: Some("url".into()),
                client_ip: v["client_ip"].as_str().map(str::to_owned),
                device: v["device"].as_str().map(str::to_owned),
            }),
        }
    }
    pub fn query(&self) -> QueryPaymentRequest {
        QueryPaymentRequest {
            context: self.context(),
            input: Some(self.pay("query_payment")),
        }
    }
    pub fn callback(&self, large: bool) -> Result<CallbackPayload> {
        let v = &self.inputs["verify_callback"];
        let mut body = BASE64_STANDARD.decode(v["body"].as_str().unwrap())?;
        let media = v["headers"]["Content-Type"][0].as_str().unwrap();
        let mut headers = vec![HttpHeader {
            name: "Content-Type".into(),
            values: vec![media.into()],
        }];
        if media == "application/json" {
            if large {
                let mut event: Value = serde_json::from_slice(&body)?;
                event["event_id"] = json!("");
                event["event_id"] = json!("e".repeat(65536 - serde_json::to_vec(&event)?.len()));
                body = serde_json::to_vec(&event)?;
            }
            headers.push(HttpHeader {
                name: "X-Signature".into(),
                values: vec![self.keys.callback_signature(media, &body)?],
            });
        } else {
            let mut fields = form::parse(&body).unwrap();
            form::set(&mut fields, "sign", &"0".repeat(32));
            if large {
                form::set(&mut fields, "event_id", "");
                let pad = 65536 - form::encode_bytes(&fields).len();
                form::set(&mut fields, "event_id", &"e".repeat(pad));
            }
            let sig = self
                .keys
                .callback_signature(media, &form::canonical_bytes(&fields).unwrap())?;
            form::set(&mut fields, "sign", &sig);
            body = form::encode_bytes(&fields);
        }
        ensure!(!large || body.len() == 65536);
        Ok(CallbackPayload {
            method: "POST".into(),
            body,
            headers,
            ..Default::default()
        })
    }
    pub async fn revoke(&self, rpc: &Rpc) -> Result<()> {
        let _: RevokePackageResponse = rpc
            .call(RevokePackageRequest {
                idempotency_key: uid(),
                package_sha256: self.ctx.package_sha256.clone(),
                owner_action_id: uid(),
            })
            .await?;
        Ok(())
    }
}

pub fn succeeded(x: Option<ExecutionResult>) -> Result<ExecutionResult> {
    let x = x.ok_or_else(|| anyhow!("missing execution"))?;
    ensure!(
        x.category == ExecutionCategory::Succeeded as i32,
        "category {} code {}",
        x.category,
        x.error_code
    );
    Ok(x)
}
