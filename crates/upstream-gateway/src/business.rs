use crate::{
    Role,
    api::*,
    crypto::strings,
    encoding::{Encoder, hash},
    wire::invalid,
};
use base64::prelude::*;
use prost::Message;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use tonic::Status;
use upstream_host::{execute::Execution, http};
use uuid::Uuid;

pub(crate) fn id(s: &str) -> bool {
    Uuid::parse_str(s).is_ok_and(|u| u.get_version_num() == 7 && u.to_string() == s)
}
pub(crate) fn visible(s: &str, max: usize) -> bool {
    (1..=max).contains(&s.len()) && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}
pub(crate) fn required<T>(v: Option<T>) -> Result<T, Status> {
    v.ok_or_else(invalid)
}

pub(crate) enum Input {
    Create(CreatePaymentInput),
    Query(PaymentInput),
    Close(PaymentInput),
    Refund(RefundInput),
    QueryRefund(RefundInput),
    Route(CallbackPayload),
    Verify(VerifyCallbackInput),
}
pub(crate) struct Material {
    pub context: OperationContext,
    pub method: String,
    pub op: &'static str,
    pub digest: Vec<u8>,
    pub raw: Vec<u8>,
    pub callback: Option<CallbackPayload>,
    pub config: BTreeMap<String, String>,
}
fn order(
    e: &mut Encoder,
    order: &str,
    refund: Option<&str>,
    money: Option<&Money>,
) -> Result<Value, Status> {
    if !http::id(order) {
        return Err(invalid());
    }
    let m = money.ok_or_else(invalid)?;
    if !kaivo_upstream_sdk::valid_money(&m.amount, &m.currency) || m.amount == "0" {
        return Err(invalid());
    }
    e.string(order);
    if let Some(id) = refund {
        if !http::id(id) {
            return Err(invalid());
        }
        e.string(id)
    }
    e.money(m);
    Ok(json!({"order_id":order,"money":{"amount":m.amount,"currency":m.currency}}))
}
fn callback(v: &CallbackPayload) -> Result<Value, Status> {
    if v.method.is_empty()
        || !upstream_host::package::token(&v.method)
        || v.raw_query.len() > 16384
        || v.body.len() > 65536
        || v.source_ip
            .as_ref()
            .is_some_and(|s| s.parse::<std::net::IpAddr>().is_err())
    {
        return Err(invalid());
    }
    let mut headers = BTreeMap::<String, Vec<String>>::new();
    for h in &v.headers {
        if h.values.is_empty() {
            return Err(invalid());
        }
        headers
            .entry(h.name.to_ascii_lowercase())
            .or_default()
            .extend(h.values.iter().cloned());
    }
    let normalized = http::normalize(&headers.into_iter().collect()).ok_or_else(invalid)?;
    let mut value = json!({
        "method": v.method,
        "raw_query": BASE64_STANDARD.encode(&v.raw_query),
        "body": BASE64_STANDARD.encode(&v.body),
        "headers": normalized.into_iter().collect::<BTreeMap<_,_>>(),
    });
    if let Some(ip) = &v.source_ip {
        value["source_ip"] = json!(ip)
    }
    Ok(value)
}
impl Input {
    fn names(&self) -> (&'static str, &'static str) {
        match self {
            Self::Create(_) => ("CreatePayment", "create_payment"),
            Self::Query(_) => ("QueryPayment", "query_payment"),
            Self::Close(_) => ("ClosePayment", "close_payment"),
            Self::Refund(_) => ("Refund", "refund"),
            Self::QueryRefund(_) => ("QueryRefund", "query_refund"),
            Self::Route(_) => ("RouteCallback", "route_callback"),
            Self::Verify(_) => ("VerifyCallback", "verify_callback"),
        }
    }
    pub fn material(
        self,
        role: Role,
        caller: &str,
        ctx: OperationContext,
    ) -> Result<Material, Status> {
        let (rpc, op) = self.names();
        if !visible(&ctx.idempotency_key, 128)
            || ctx.package_sha256.len() != 32
            || ctx.credentials_sha256.len() != 32
            || !id(&ctx.channel_account_id)
            || !visible(&ctx.credentials_ref, 256)
            || ctx.control_version == 0
            || ctx.control_version >= i64::MAX as u64
            || match role {
                Role::Trade => ctx.verification_account_id.is_some(),
                Role::Verification => ctx
                    .verification_account_id
                    .as_deref()
                    .is_none_or(|s| !id(s)),
            }
        {
            return Err(invalid());
        }
        let config = strings(&ctx.config_json)?;
        if upstream_host::json::canonical(&json!(config)) != ctx.config_json {
            return Err(invalid());
        }
        let method = format!("/aipay.upstream.v1.UpstreamService/{rpc}");
        let mut e = Encoder::request(caller, &method);
        e.context(&ctx);
        let mut payload = None;
        let mut put_callback = |e: &mut Encoder, v: &CallbackPayload| {
            e.callback(v);
            payload = Some(v.clone());
            callback(v)
        };
        let v = match self {
            Self::Create(v) => {
                if v.method.is_empty()
                    || v.callback_url.is_empty()
                    || v.client_ip
                        .as_deref()
                        .is_some_and(|s| !http::valid_client_ip(s))
                    || v.device.as_deref().is_some_and(|s| !http::valid_device(s))
                    || [v.bank_mode.as_ref(), v.instruction.as_ref()]
                        .into_iter()
                        .flatten()
                        .any(String::is_empty)
                {
                    return Err(invalid());
                }
                let mut j = order(&mut e, &v.order_id, None, v.money.as_ref())?;
                e.string(&v.method);
                e.string(&v.callback_url);

                j["method"] = json!(v.method);
                j["callback_url"] = json!(v.callback_url);
                for (field, value) in [
                    ("bank_mode", v.bank_mode),
                    ("instruction", v.instruction),
                    ("client_ip", v.client_ip),
                    ("device", v.device),
                ] {
                    e.optional(value.as_deref(), Encoder::string);
                    if let Some(s) = value {
                        j[field] = Value::String(s);
                    }
                }
                j
            }
            Self::Query(v) | Self::Close(v) => order(&mut e, &v.order_id, None, v.money.as_ref())?,
            Self::Refund(v) | Self::QueryRefund(v) => {
                let mut j = order(&mut e, &v.order_id, Some(&v.refund_id), v.money.as_ref())?;
                j["refund_id"] = json!(v.refund_id);
                j
            }
            Self::Route(v) => put_callback(&mut e, &v)?,
            Self::Verify(v) => {
                let mut j = order(&mut e, &v.order_id, None, v.money.as_ref())?;
                let raw = put_callback(&mut e, &required(v.raw)?)?;
                j.as_object_mut()
                    .unwrap()
                    .extend(raw.as_object().unwrap().clone());
                j
            }
        };
        let raw = serde_json::to_vec(&v).unwrap();
        Ok(Material {
            context: ctx,
            method,
            op,
            digest: hash(&e.0),
            raw,
            callback: payload,
            config,
        })
    }
}
#[derive(Clone, PartialEq, Message)]
pub(crate) struct Reply {
    #[prost(message, optional, tag = "1")]
    pub execution: Option<ExecutionResult>,
    #[prost(bytes = "vec", optional, tag = "2")]
    pub output: Option<Vec<u8>>,
}
#[derive(Clone)]
pub(crate) struct Outcome {
    pub result: ExecutionResult,
    pub output: Option<Vec<u8>>,
    pub canonical: Option<Vec<u8>>,
}
impl Outcome {
    pub fn failure(code: &str) -> Self {
        Self {
            result: ExecutionResult {
                category: ExecutionCategory::NotSent.into(),
                error_code: code.into(),
                ..Default::default()
            },
            output: None,
            canonical: None,
        }
    }
    pub fn from_host(x: Execution) -> Result<Self, Status> {
        let bad = || Status::internal("invalid host projection");
        let category = match x.category.as_str() {
            "completed" => ExecutionCategory::Succeeded,
            "rejected" => ExecutionCategory::Rejected,
            "unknown" => ExecutionCategory::Unknown,
            "not_sent" => ExecutionCategory::NotSent,
            _ => return Err(bad()),
        };
        let mut out = Self {
            result: ExecutionResult {
                category: category.into(),
                error_code: x.error_code.unwrap_or_default(),
                requests: x.requests as u32,
                responses: x.responses as u32,
                steps: x.steps as u32,
                ..Default::default()
            },
            output: None,
            canonical: None,
        };
        let Some(result) = x.result else {
            return Ok(out);
        };
        out.result.upstream_code = result["code"].as_str().map(str::to_owned);
        if category != ExecutionCategory::Succeeded {
            return Ok(out);
        }
        fn s(v: &Value, k: &str) -> Result<String, Status> {
            v[k].as_str()
                .map(str::to_owned)
                .ok_or_else(|| Status::internal("missing host output"))
        }
        fn money(v: &Value) -> Result<Option<Money>, Status> {
            Ok(Some(Money {
                amount: s(&v["money"], "amount")?,
                currency: s(&v["money"], "currency")?,
            }))
        }
        fn payment_status(v: &Value) -> Result<i32, Status> {
            Ok(match v["status"].as_str() {
                Some("paid") => PaymentStatus::Paid,
                Some("closed") => PaymentStatus::Closed,
                Some("pending") => PaymentStatus::Pending,
                Some("failed") => PaymentStatus::Failed,
                Some("unknown") => PaymentStatus::Unknown,
                _ => return Err(Status::internal("invalid payment status")),
            } as i32)
        }
        fn time(v: &Value) -> Result<Option<prost_types::Timestamp>, Status> {
            v.as_str()
                .map(|s| {
                    kaivo_upstream_sdk::time::parse(s)
                        .map(|(seconds, n)| prost_types::Timestamp {
                            seconds,
                            nanos: n as i32,
                        })
                        .ok_or_else(|| Status::internal("invalid time"))
                })
                .transpose()
        }
        let mut e = Encoder::default();
        let bytes = if let Some(v) = result.get("payment") {
            let p = PaymentOutput {
                order_id: s(v, "order_id")?,
                upstream_id: s(v, "upstream_id")?,
                money: money(v)?,
                status: payment_status(v)?,
                url: v["url"].as_str().map(str::to_owned),
                qrcode: v["qrcode"].as_str().map(str::to_owned),
                paid_at: time(&v["paid_at"])?,
                expires_at: time(&v["expires_at"])?,
            };
            e.payment(&p);
            p.encode_to_vec()
        } else if let Some(v) = result.get("refund") {
            let status = match v["status"].as_str() {
                Some("pending") => RefundStatus::Pending,
                Some("succeeded") => RefundStatus::Succeeded,
                Some("failed") => RefundStatus::Failed,
                Some("unknown") => RefundStatus::Unknown,
                _ => return Err(bad()),
            };
            let p = RefundOutput {
                order_id: s(v, "order_id")?,
                refund_id: s(v, "refund_id")?,
                upstream_refund_id: s(v, "upstream_refund_id")?,
                money: money(v)?,
                status: status.into(),
            };
            e.refund(&p);
            p.encode_to_vec()
        } else if let Some(v) = result.get("route") {
            let p = RouteCallbackOutput {
                order_id: s(v, "order_id")?,
            };
            e.string(&p.order_id);
            p.encode_to_vec()
        } else {
            let v = &result["callback"];
            let ack = &v["ack"];
            let heads: BTreeMap<String, Vec<String>> =
                serde_json::from_value(ack["headers"].clone()).map_err(|_| bad())?;
            let p = CallbackOutput {
                event_id: s(v, "event_id")?,
                order_id: s(v, "order_id")?,
                upstream_id: s(v, "upstream_id")?,
                money: money(v)?,
                status: payment_status(v)?,
                ack: Some(HttpResponse {
                    status: ack["status"].as_u64().ok_or_else(bad)? as u32,
                    headers: heads
                        .into_iter()
                        .map(|(name, values)| HttpHeader { name, values })
                        .collect(),
                    body: BASE64_STANDARD.decode(s(ack, "body")?).map_err(|_| bad())?,
                }),
            };
            e.verified(&p);
            p.encode_to_vec()
        };
        out.output = Some(bytes);
        out.canonical = Some(e.0);
        Ok(out)
    }
}
