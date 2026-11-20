use crate::{
    engine::{Host, Input, Loaded, Metric},
    environment::{Cancellation, Environment},
    http::{self, Check},
    json::{object, projected_len},
    package::{media, token},
    state::State,
    types::*,
};
use base64::prelude::*;
use kaivo_upstream_sdk::{time, valid_money};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, sync::Arc, time::Instant};
#[derive(Default, Clone, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub category: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    pub requests: usize,
    pub responses: usize,
    pub steps: usize,
    #[serde(skip)]
    pub metrics: Vec<Metric>,
    #[serde(skip)]
    pub elapsed: std::time::Duration,
}
impl Execution {
    fn failed(&mut self, c: &str) {
        self.category = if self.requests > 0 {
            "unknown"
        } else {
            "not_sent"
        }
        .into();
        self.error_code = Some(c.into());
        self.result = None
    }
}
pub(crate) fn headers_value(h: &Headers) -> Value {
    json!(h.iter().cloned().collect::<BTreeMap<_, _>>())
}
pub(crate) fn headers_from(v: &Value) -> Option<Headers> {
    Some(
        serde_json::from_value::<BTreeMap<String, Vec<String>>>(v.clone())
            .ok()?
            .into_iter()
            .collect(),
    )
}
pub(crate) fn request_value(r: &HttpRequest) -> Value {
    json!({"method":r.method,"url":r.url,"headers":headers_value(&r.headers),"body":BASE64_STANDARD.encode(&r.body)})
}
pub(crate) fn response_value(r: &HttpResponse) -> Value {
    json!({"status":r.status,"headers":headers_value(&r.headers),"body":BASE64_STANDARD.encode(&r.body)})
}
pub(crate) fn only(v: &Value, fields: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.keys().all(|k| fields.contains(&k.as_str())))
}
pub(crate) fn input_schema(op: &str, v: &Value) -> Check<()> {
    let mut fields = Vec::new();
    let callback = op.ends_with("callback");
    if callback {
        fields.extend(["method", "headers", "body", "raw_query", "source_ip"])
    }
    if op != "route_callback" {
        fields.extend(["order_id", "money"]);
        if !v["order_id"].as_str().is_some_and(http::id)
            || !only(&v["money"], &["amount", "currency"])
        {
            return Err("input_json");
        }
        let m: Money = serde_json::from_value(v["money"].clone()).map_err(|_| "input_json")?;
        if !valid_money(&m.amount, &m.currency) || m.amount == "0" {
            return Err("input_json");
        }
    }
    if op == "create_payment" {
        fields.extend(["method", "callback_url", "bank_mode", "instruction"]);
        if ["method", "callback_url"]
            .iter()
            .any(|k| v[k].as_str().is_none_or(str::is_empty))
        {
            return Err("input_json");
        }
    }
    if op.contains("refund") {
        fields.push("refund_id");
        if !v["refund_id"].as_str().is_some_and(http::id) {
            return Err("input_json");
        }
    }
    if !only(v, &fields) || v.as_object().unwrap().values().any(Value::is_null) {
        return Err("input_json");
    }
    if callback {
        for k in ["body", "raw_query"] {
            if let Some(b) = v.get(k) {
                BASE64_STANDARD
                    .decode(b.as_str().ok_or("input_json")?)
                    .map_err(|_| "input_json")?;
            }
        }
        if !v["method"].is_string()
            || !v["body"].is_string()
            || headers_from(&v["headers"]).is_none()
            || v.get("source_ip").is_some_and(|s| !s.is_string())
        {
            return Err("input_json");
        }
    }
    if ["bank_mode", "instruction"]
        .iter()
        .any(|k| v.get(k).is_some_and(|x| !x.is_string()))
    {
        return Err("input_json");
    }
    Ok(())
}
fn input(op: &str, v: &Value, s: &State) -> Check<Input> {
    input_schema(op, v)?;
    if op.ends_with("callback") {
        let method = v["method"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("input_json")?
            .to_owned();
        let bytes = |k: &str| -> Check<Vec<u8>> {
            BASE64_STANDARD
                .decode(v[k].as_str().ok_or("input_json")?)
                .map_err(|_| "input_json")
        };
        let raw_query = if v.get("raw_query").is_some() {
            bytes("raw_query")?
        } else {
            Vec::new()
        };
        let body = bytes("body")?;
        if s.scan.bytes(&body) || s.scan.bytes(&raw_query) {
            return Err("secret_leak");
        }
        if body.len() > 65536 || raw_query.len() > 16384 {
            return Err("input_json");
        }
        let rules = s.m.callback.as_ref().ok_or("callback_request")?;
        if !rules.methods.contains(&method) || !rules.allow_query && !raw_query.is_empty() {
            return Err("callback_request");
        }
        let headers = http::normalize(&headers_from(&v["headers"]).ok_or("callback_headers")?)
            .ok_or("callback_headers")?;
        if !http::values(&headers, "Content-Type")
            .first()
            .and_then(|s| media(s))
            .is_some_and(|s| rules.content_types.contains(&s))
        {
            return Err("callback_content_type");
        }
        let source_ip = v
            .get("source_ip")
            .map(|v| v.as_str().map(String::from).ok_or("input_json"))
            .transpose()?;
        let raw = RouteCallbackInput {
            method,
            raw_query,
            headers,
            body,
            source_ip,
        };
        return Ok(if op == "route_callback" {
            Input::Route(raw)
        } else {
            Input::Callback(CallbackInput {
                order_id: v["order_id"].as_str().unwrap().into(),
                money: serde_json::from_value(v["money"].clone()).unwrap(),
                raw,
            })
        });
    }
    match op {
        "create_payment" => serde_json::from_value(v.clone()).map(Input::Create),
        "query_payment" | "close_payment" => serde_json::from_value(v.clone()).map(Input::Payment),
        _ => serde_json::from_value(v.clone()).map(Input::Refund),
    }
    .map_err(|_| "input_json")
}
fn result_value(r: &OperationResult) -> Check<Value> {
    let (outcome, code, value) = match r {
        OperationResult::Error(c) => ("error", c.as_deref(), None),
        OperationResult::Unknown(c) => ("unknown", c.as_deref(), None),
        OperationResult::Rejected(c) => ("rejected", Some(c.as_str()), None),
        OperationResult::Completed(c) => ("completed", c.code.as_deref(), Some(&c.value)),
    };
    let mut v = json!({"outcome":outcome});
    if let Some(c) = code.filter(|c| !c.is_empty()) {
        v["code"] = json!(c)
    }
    if let Some(o) = value {
        match o {
            Output::Route(p) => v["route"] = json!(p),
            Output::Callback(p) => {
                let mut x = json!({"event_id":p.event_id,"order_id":p.order_id,"upstream_id":p.upstream_id,"money":p.money});
                x["status"] = json!(
                    serde_json::to_value(p.status)
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_ascii_lowercase()
                );
                x["ack"] = response_value(&p.ack);
                v["callback"] = x
            }
            Output::Refund(p) => {
                let mut x = json!(p);
                x["status"] = json!(
                    serde_json::to_value(p.status)
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_ascii_lowercase()
                );
                v["refund"] = x
            }
            Output::Payment(p) => {
                let mut x = json!(p);
                x["status"] = json!(
                    serde_json::to_value(p.status)
                        .unwrap()
                        .as_str()
                        .unwrap()
                        .to_ascii_lowercase()
                );
                for (k, t) in [("paid_at", p.paid_at), ("expires_at", p.expires_at)] {
                    if let Some(t) = t {
                        x[k] = json!(time::format((t.seconds, t.nanos)).ok_or("output_time")?)
                    }
                }
                x.as_object_mut().unwrap().retain(|_, v| !v.is_null());
                v["payment"] = x
            }
        }
    }
    Ok(v)
}
fn scan_headers(s: &State, h: &Headers) -> bool {
    h.iter()
        .any(|(k, vs)| s.scan.bytes(k.as_bytes()) || vs.iter().any(|v| s.scan.bytes(v.as_bytes())))
}
// Close the measurement on early errors as well as on successful validation.
struct StepTimer<'a> {
    start: Instant,
    elapsed: &'a mut std::time::Duration,
}
impl Drop for StepTimer<'_> {
    fn drop(&mut self) {
        *self.elapsed = self.start.elapsed()
    }
}
impl Host {
    pub fn execute(
        &self,
        l: &Loaded,
        op: &str,
        raw: &[u8],
        env: Arc<dyn Environment>,
        cancel: Cancellation,
    ) -> Execution {
        let started = Instant::now();
        let mut out = Execution::default();
        let mut s = State::new(l.manifest.clone(), env, cancel, op);
        let run = (|| -> Check<()> {
            if l.manifest.r#type != self.options.plugin_type
                || !l.manifest.capabilities.iter().any(|x| x == op)
                || !l.belongs_to(self)
            {
                return Err("unsupported_operation");
            }
            if raw.len() > 1 << 20 {
                return Err("input_limit");
            }
            s.prepare()?;
            if s.scan.bytes(raw) {
                return Err("secret_leak");
            }
            let mut value = object(raw).map_err(|_| "input_json")?;
            let i = input(op, &value, &s)?;
            match &i {
                Input::Route(r) => value["headers"] = headers_value(&r.headers),
                Input::Callback(c) => value["headers"] = headers_value(&c.raw.headers),
                _ => {}
            }
            let mut responses = vec![];
            let mut history = vec![];
            for step in 1..=5 {
                out.steps = step;
                let permit = self.admission.acquire(&s.cancel)?;
                let start = Instant::now();
                if projected_len(&json!({"input":value,"responses":history})) > 1 << 20 {
                    return Err("input_limit");
                }
                let placeholder =
                    State::new(l.manifest.clone(), s.env.clone(), s.cancel.clone(), op);
                let old = std::mem::replace(&mut s, placeholder);
                let (state, result, metric) = self.call(l, old, start, &i, &responses);
                s = state;
                out.metrics.push(metric);
                let timer = StepTimer {
                    start,
                    elapsed: &mut out.metrics.last_mut().unwrap().elapsed,
                };
                let next = result?;
                match next {
                    Step::Request(mut r) => {
                        if s.scan.bytes(r.url.as_bytes())
                            || s.scan.bytes(&r.body)
                            || scan_headers(&s, &r.headers)
                            || s.scan.bytes(r.method.as_bytes())
                        {
                            return Err("secret_leak");
                        }
                        let projection = json!({"request":request_value(&r)});
                        if s.scan.value(&projection) {
                            return Err("secret_leak");
                        }
                        if projected_len(&projection) > 1 << 20 {
                            return Err("output_limit");
                        }
                        if op.ends_with("callback") {
                            return Err("callback_network_forbidden");
                        }
                        if step == 5 {
                            return Err("step_limit");
                        }
                        if r.body.len() > 262144 {
                            return Err("request_limit");
                        }
                        if !token(&r.method) || r.method != r.method.to_ascii_uppercase() {
                            return Err("request_method");
                        }
                        let host = http::url(&r.url, self.options.test_only_allow_http)?;
                        if !s.m.domains.iter().any(|x| x == host) {
                            return Err("domain_forbidden");
                        }
                        if r.url.contains("{{secret:")
                            || memchr::memmem::find(&r.body, b"{{secret:").is_some()
                        {
                            return Err("secret_placeholder");
                        }
                        let template = r.clone();
                        let transport = s.env.transport().ok_or("transport_unavailable")?;
                        r.headers = http::expand(&s.m, &r.headers, |n| {
                            String::from_utf8(s.secrets.get(n)?.to_vec()).ok()
                        })?;
                        s.check()?;
                        drop(timer);
                        drop(permit);
                        let mut deadline = Instant::now() + self.options.request_timeout;
                        if let Some(d) = s.cancel.deadline {
                            deadline = deadline.min(d)
                        }
                        out.requests += 1;
                        let sent = transport.send(&template, &r, deadline, &s.cancel);
                        for (_, vs) in &mut r.headers {
                            for v in vs {
                                zeroize::Zeroize::zeroize(v)
                            }
                        }
                        let incoming = sent.map_err(|err| {
                            if s.cancel.cancelled() {
                                "cancelled"
                            } else if err.is::<crate::environment::MissingResponse>() {
                                "transport_response"
                            } else {
                                "transport_error"
                            }
                        })?;
                        let mut body = Vec::new();
                        incoming
                            .body
                            .take(262145)
                            .read_to_end(&mut body)
                            .map_err(|_| {
                                if s.cancel.cancelled() {
                                    "cancelled"
                                } else {
                                    "transport_error"
                                }
                            })?;
                        if s.scan.bytes(&body) || scan_headers(&s, &incoming.headers) {
                            return Err("secret_leak");
                        }
                        if s.cancel.cancelled() {
                            return Err("cancelled");
                        }
                        if Instant::now() >= deadline {
                            return Err("transport_error");
                        }
                        if body.len() > 262144 {
                            return Err("response_limit");
                        }
                        if !(100..600).contains(&incoming.status) {
                            return Err("response_status");
                        }
                        if (300..400).contains(&incoming.status) {
                            return Err("redirect_forbidden");
                        }
                        let headers =
                            http::normalize(&incoming.headers).ok_or("response_headers")?;
                        let response = HttpResponse {
                            status: incoming.status,
                            headers,
                            body,
                        };
                        let rv = response_value(&response);
                        if s.scan.value(&rv) {
                            return Err("secret_leak");
                        }
                        history.push(rv);
                        responses.push(response);
                        out.responses += 1;
                    }
                    Step::Result(r) => {
                        if let OperationResult::Completed(c) = &r
                            && let Output::Callback(p) = &c.value
                            && (s.scan.bytes(&p.ack.body) || scan_headers(&s, &p.ack.headers))
                        {
                            return Err("secret_leak");
                        }
                        if !matches!(&r,OperationResult::Completed(c) if matches!(c.value,Output::Callback(_)))
                            && s.scan.value(&json!(&r))
                        {
                            return Err("secret_leak");
                        }
                        let v = result_value(&r)?;
                        if s.scan.value(&v) {
                            return Err("secret_leak");
                        }
                        if projected_len(&json!({"result":v})) > 1 << 20 {
                            return Err("output_limit");
                        }
                        if v["code"].as_str().is_some_and(|c| {
                            c.len() > 128
                                || c.chars().any(|ch| ch.is_whitespace() || ch.is_control())
                        }) {
                            return Err("output_structure");
                        }
                        match r {
                            OperationResult::Error(_) => return Err("plugin_error"),
                            OperationResult::Unknown(_) => return Err("upstream_unknown"),
                            OperationResult::Rejected(code) => {
                                if responses.is_empty() {
                                    return Err("unsubstantiated_rejection");
                                }
                                if code.is_empty() {
                                    return Err("output_structure");
                                }
                                out.category = "rejected".into()
                            }
                            OperationResult::Completed(c) => {
                                self.validate(&s, &c.value, &value)?;
                                if !op.ends_with("callback") && responses.is_empty() {
                                    return Err("unsubstantiated_result");
                                }
                                out.category = "completed".into()
                            }
                        }
                        s.check()?;
                        out.result = Some(v);
                        return Ok(());
                    }
                }
            }
            Err("step_limit")
        })();
        if let Err(c) = run {
            out.failed(c);
        }
        if run == Err("secret_leak") {
            s.env.alert("secret_leak");
        } else {
            for event in &s.logs {
                s.env.log(event)
            }
        }
        out.elapsed = started.elapsed();
        out
    }
    fn validate(&self, s: &State, o: &Output, i: &Value) -> Check<()> {
        let order = i["order_id"].as_str().unwrap_or("");
        let m = match (s.op.as_str(), o) {
            ("route_callback", Output::Route(r)) => {
                return if http::id(&r.order_id) {
                    Ok(())
                } else {
                    Err("output_identity")
                };
            }
            ("verify_callback", Output::Callback(c)) => {
                if c.order_id != order || c.event_id.is_empty() || c.upstream_id.is_empty() {
                    return Err("output_identity");
                }
                if json!(c.money) != i["money"] {
                    return Err("amount_mismatch");
                }
                let rule = s.m.callback.as_ref().ok_or("callback_ack")?;
                let h = http::normalize(&c.ack.headers).ok_or("callback_ack")?;
                if c.ack.status != rule.ack_status
                    || c.ack.body != rule.ack_body.as_bytes()
                    || http::values(&h, "Content-Type")
                        != std::slice::from_ref(&rule.ack_content_type)
                {
                    return Err("callback_ack");
                }
                &c.money
            }
            ("refund" | "query_refund", Output::Refund(r)) => {
                if r.order_id != order
                    || i["refund_id"] != r.refund_id
                    || r.upstream_refund_id.is_empty()
                {
                    return Err("output_identity");
                }
                &r.money
            }
            ("create_payment" | "query_payment" | "close_payment", Output::Payment(p)) => {
                if p.order_id != order || p.upstream_id.is_empty() {
                    return Err("output_identity");
                }
                if json!(p.money) != i["money"] {
                    return Err("amount_mismatch");
                }
                let pending =
                    s.op == "create_payment" && matches!(p.status, PaymentStatus::Pending);
                let guide = p.url.is_some() || p.qrcode.is_some();
                if p.url.is_some() && p.qrcode.is_some()
                    || pending && !guide
                    || p.qrcode.as_ref().is_some_and(String::is_empty)
                    || p.url.as_ref().is_some_and(|u| {
                        !http::instruction_url(u, self.options.test_only_allow_http)
                    })
                {
                    return Err("output_instruction");
                }
                if p.paid_at
                    .is_some_and(|t| !time::valid((t.seconds, t.nanos)))
                {
                    return Err("output_time");
                }
                if let Some(t) = p.expires_at {
                    let now = s
                        .env
                        .now(s.deadline, &s.cancel)
                        .map_err(|_| "host_service")?;
                    let t = (t.seconds, t.nanos);
                    if !pending
                        || !guide
                        || !time::valid(t)
                        || !time::valid(now)
                        || t <= now
                        || t > (now.0 + 86400, now.1)
                    {
                        return Err("output_time");
                    }
                }
                &p.money
            }
            _ => return Err("output_structure"),
        };
        if json!(m) != i["money"] {
            return Err("amount_mismatch");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{engine::Options, imports::UtcTime, package::Manifest};
    struct Clock;
    impl Environment for Clock {
        fn now(&self, _: Instant, _: &Cancellation) -> anyhow::Result<time::Timestamp> {
            Ok((0, 123))
        }
    }
    #[test]
    fn payment_time_and_instruction_boundaries() {
        let host = Host::new(Options::production("payment")).unwrap();
        let m = Manifest::parse(&crate::json::canonical(&crate::tests::manifest())).unwrap();
        let s = State::new(
            Arc::new(m),
            Arc::new(Clock),
            Default::default(),
            "create_payment",
        );
        let input = json!({"order_id":"test","money":{"amount":"12","currency":"CNY"}});
        let payment = PaymentOutput {
            order_id: "test".into(),
            upstream_id: "upstream".into(),
            money: Money {
                amount: "12".into(),
                currency: "CNY".into(),
            },
            status: PaymentStatus::Pending,
            url: Some("https://Cashier.example/pay".into()),
            qrcode: None,
            paid_at: None,
            expires_at: None,
        };
        let check = |p| host.validate(&s, &Output::Payment(p), &input);
        for (t, expected) in [
            ((0, 122), Err("output_time")),
            ((0, 123), Err("output_time")),
            ((0, 124), Ok(())),
            ((86400, 123), Ok(())),
            ((86400, 124), Err("output_time")),
            ((1, 1_000_000_000), Err("output_time")),
        ] {
            let mut p = payment.clone();
            p.expires_at = Some(UtcTime {
                seconds: t.0,
                nanos: t.1,
            });
            assert_eq!(check(p), expected)
        }
        let mut p = payment.clone();
        p.qrcode = Some("qr".into());
        assert_eq!(check(p), Err("output_instruction"));
        let mut p = payment.clone();
        p.url = None;
        assert_eq!(check(p), Err("output_instruction"));
        let mut p = payment.clone();
        p.money.amount = "012".into();
        assert_eq!(check(p), Err("amount_mismatch"));
        let mut p = payment;
        p.paid_at = Some(UtcTime {
            seconds: 253402300800,
            nanos: 0,
        });
        assert_eq!(check(p), Err("output_time"));
    }
}
