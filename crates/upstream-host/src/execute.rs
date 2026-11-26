use crate::{
    engine::{Host, Input, Loaded, Metric},
    environment::{AddressForbidden, Cancellation, CapturedResponse, Dispatch, Environment},
    http::{self, Check},
    json::{object, projected_len},
    package::{media, token},
    state::{Scanner, State},
    types::*,
};
use base64::prelude::*;
use kaivo_upstream_sdk::{time, valid_money};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{collections::BTreeMap, io::Read, sync::Arc, time::Instant};
use zeroize::Zeroizing;
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
        fields.extend([
            "method",
            "callback_url",
            "bank_mode",
            "instruction",
            "client_ip",
            "device",
        ]);
        if ["method", "callback_url"]
            .iter()
            .any(|k| v[k].as_str().is_none_or(str::is_empty))
            || v.get("client_ip")
                .is_some_and(|v| !v.as_str().is_some_and(http::valid_client_ip))
            || v.get("device")
                .is_some_and(|v| !v.as_str().is_some_and(http::valid_device))
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
        // Query-only GET notifications such as EPay V1 can omit the media type.
        let allowed = match http::values(&headers, "Content-Type").first() {
            Some(value) => media(value).is_some_and(|s| rules.content_types.contains(&s)),
            None => method == "GET" && body.is_empty(),
        };
        if !allowed {
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
fn exchange(
    s: &State,
    out: &mut Execution,
    template: &HttpRequest,
    request: Zeroizing<HttpRequest>,
    transport: &dyn crate::environment::Transport,
    deadline: Instant,
) -> Check<HttpResponse> {
    let connection = transport
        .open(template, deadline, &s.cancel)
        .map_err(|err| {
            if s.cancel.cancelled() {
                "cancelled"
            } else if err.is::<AddressForbidden>() {
                "address_forbidden"
            } else {
                "transport_connect"
            }
        })?;
    let number = out.requests + 1;
    let sent = match s.env.authorize_dispatch(number, template) {
        Dispatch::Denied(code) => return Err(code),
        Dispatch::Unconfirmed => {
            out.requests = number;
            drop(connection);
            Err("dispatch_unconfirmed")
        }
        Dispatch::Granted => {
            out.requests = number;
            connection
                .send_wire(template, &request, deadline, &s.cancel)
                .map_err(|err| {
                    if s.cancel.cancelled() {
                        "cancelled"
                    } else if err.is::<crate::environment::MissingResponse>() {
                        "transport_response"
                    } else {
                        "transport_error"
                    }
                })
        }
    };
    drop(request);
    let mut captured = None;
    let result = (|| {
        let incoming = sent?;
        let mut body = Vec::new();
        let read = incoming.body.take(262145).read_to_end(&mut body);
        let oversized = body.len() > 262144;
        let leaked = s.scan.bytes(&body)
            || incoming
                .headers
                .iter()
                .any(|(k, vs)| s.scan.bytes(k.as_bytes()) || vs.iter().any(|v| s.scan.bytes(v)));
        body.truncate(262144);
        // A reflected field can contain the entire expanded URL or body. Keep only
        // the status in the quarantined receipt for packages declaring these fields.
        if leaked && s.m.secret_fields.is_some() {
            captured = Some(CapturedResponse {
                status: incoming.status,
                headers: vec![],
                body: vec![],
                complete: false,
            });
            return Err("secret_leak");
        }
        let raw = captured.insert(CapturedResponse {
            status: incoming.status,
            headers: incoming.headers,
            body,
            complete: read.is_ok() && !oversized,
        });
        if leaked {
            return Err("secret_leak");
        }
        if s.cancel.cancelled() {
            return Err("cancelled");
        }
        if read.is_err() || Instant::now() >= deadline {
            return Err("transport_error");
        }
        if oversized {
            return Err("response_limit");
        }
        if !(100..600).contains(&raw.status) {
            return Err("response_status");
        }
        if (300..400).contains(&raw.status) {
            return Err("redirect_forbidden");
        }
        let headers: Option<Headers> = raw
            .headers
            .iter()
            .map(|(k, vs)| {
                let values = vs
                    .iter()
                    .map(|v| String::from_utf8(v.clone()).ok())
                    .collect::<Option<_>>()?;
                Some((k.clone(), values))
            })
            .collect();
        let response = HttpResponse {
            status: raw.status,
            headers: http::normalize(&headers.ok_or("response_headers")?)
                .ok_or("response_headers")?,
            body: raw.body.clone(),
        };
        if s.scan.value(&response_value(&response)) {
            return Err("secret_leak");
        }
        Ok(response)
    })();
    let code = result.as_ref().err().copied().unwrap_or("");
    if s.env
        .record_attempt(number, template, captured.as_ref(), code)
        .is_err()
        && code != "secret_leak"
    {
        return Err("host_service");
    }
    result
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
        let mut private_logs = Scanner::default();
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
                Input::Create(c) => {
                    for field in [c.client_ip.as_deref(), c.device.as_deref()]
                        .into_iter()
                        .flatten()
                    {
                        private_logs.add(field.as_bytes());
                    }
                }
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
                    Step::Request(r) => {
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
                        if r.body.len() > http::REQUEST_BODY_LIMIT {
                            return Err("request_limit");
                        }
                        if !token(&r.method) || r.method != r.method.to_ascii_uppercase() {
                            return Err("request_method");
                        }
                        let host = http::url(&r.url, self.options.test_only_allow_http)?;
                        if !s.m.domains.iter().any(|x| x == host) {
                            return Err("domain_forbidden");
                        }
                        let template = r;
                        let fields = http::RequestTemplate::validate(
                            &s.m,
                            &template,
                            self.options.test_only_allow_http_secret_fields,
                        )?;
                        let transport = s.env.transport().ok_or("transport_unavailable")?;
                        let request = fields
                            .expand(http::REQUEST_BODY_LIMIT, |n| s.secrets.get(n).cloned())?;
                        s.check()?;
                        drop(timer);
                        drop(permit);
                        let mut deadline = Instant::now() + self.options.request_timeout;
                        if let Some(d) = s.cancel.deadline {
                            deadline = deadline.min(d)
                        }
                        let response =
                            exchange(&s, &mut out, &template, request, transport, deadline)?;
                        history.push(response_value(&response));
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
                            value["client_ip"].as_str().is_some_and(|ip| c.contains(ip))
                                || c.len() > 128
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
            s.flush_logs(&private_logs);
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
    fn buyer_metadata_stays_out_of_plugin_logs() {
        use crate::imports::Host as _;
        #[derive(Default)]
        struct Events(std::sync::Mutex<Vec<Value>>);
        impl Environment for Events {
            fn log(&self, event: &Value) {
                self.0.lock().unwrap().push(event.clone());
            }
        }
        let events = Arc::new(Events::default());
        let manifest = Manifest::parse(&crate::json::canonical(&crate::tests::manifest())).unwrap();
        let mut state = State::new(
            Arc::new(manifest),
            events.clone(),
            Default::default(),
            "create_payment",
        );
        state.deadline = Instant::now() + std::time::Duration::from_secs(5);
        let mut private = Scanner::default();
        private.add(b"1.2.3.4");
        private.add(b"pc");
        state.log("info".into(), "ready".into(), vec![]).unwrap();
        state.flush_logs(&private);
        assert_eq!(events.0.lock().unwrap().len(), 1);
        for piece in ["1.2.", "3.4"] {
            state
                .log(
                    "info".into(),
                    "progress".into(),
                    vec![("detail".into(), piece.into())],
                )
                .unwrap();
        }
        state.flush_logs(&private);
        assert_eq!(events.0.lock().unwrap().len(), 1);
    }

    #[test]
    fn create_validates_json_before_passing_buyer_fields_to_wit() {
        let manifest = Manifest::parse(&crate::json::canonical(&crate::tests::manifest())).unwrap();
        let state = State::new(
            Arc::new(manifest),
            Arc::new(Clock),
            Default::default(),
            "create_payment",
        );
        let base = json!({"order_id":"order","money":{"amount":"1","currency":"CNY"},"method":"alipay","callback_url":"http://localhost/cb"});
        for (ip, device) in [
            (None, None),
            (Some("1.2.3.4"), Some("pc")),
            (Some("2001:db8::1"), Some("a1_b")),
        ] {
            let mut v = base.clone();
            if let Some(ip) = ip {
                v["client_ip"] = json!(ip);
            }
            if let Some(device) = device {
                v["device"] = json!(device);
            }
            let Input::Create(i) = input("create_payment", &v, &state).unwrap() else {
                panic!("expected create")
            };
            assert_eq!(i.client_ip.as_deref(), ip);
            assert_eq!(i.device.as_deref(), device);
        }
        for (field, bad) in [
            ("client_ip", json!("2001:DB8::1")),
            ("client_ip", json!("::ffff:1.2.3.4")),
            ("client_ip", json!("1.2.3.4:80")),
            ("client_ip", json!("")),
            ("client_ip", json!(7)),
            ("device", json!("PC")),
            ("device", json!("")),
            ("device", json!("a".repeat(33))),
            ("device", Value::Null),
        ] {
            let mut v = base.clone();
            v[field] = bad;
            assert_eq!(input_schema("create_payment", &v), Err("input_json"));
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

#[cfg(test)]
mod dispatch_tests;

#[cfg(test)]
mod callback_input_tests {
    use super::*;
    use crate::{environment::SystemEnvironment, package::Manifest};

    #[test]
    fn media_type_exception_requires_an_allowed_bodyless_get() {
        for op in ["route_callback", "verify_callback"] {
            for (method, allow_get, body, ct, error) in [
                ("GET", true, "", None, None),
                (
                    "GET",
                    true,
                    "",
                    Some("application/x-www-form-urlencoded; charset=utf-8"),
                    None,
                ),
                (
                    "GET",
                    true,
                    "",
                    Some("text/plain"),
                    Some("callback_content_type"),
                ),
                ("GET", true, "", Some(""), Some("callback_content_type")),
                ("GET", true, "eA==", None, Some("callback_content_type")),
                ("HEAD", true, "", None, Some("callback_content_type")),
                ("POST", true, "", None, Some("callback_content_type")),
                ("GET", false, "", None, Some("callback_request")),
            ] {
                let mut m: Manifest = serde_json::from_value(crate::tests::manifest()).unwrap();
                let rules = m.callback.as_mut().unwrap();
                rules.methods.push("HEAD".into());
                if allow_get {
                    rules.methods.push("GET".into());
                }
                let state = State::new(
                    Arc::new(m),
                    Arc::new(SystemEnvironment),
                    Default::default(),
                    op,
                );
                let mut value = json!({"method":method, "body":body, "headers":{}});
                if let Some(ct) = ct {
                    value["headers"]["content-type"] = json!([ct]);
                }
                if op == "verify_callback" {
                    value["order_id"] = json!("order");
                    value["money"] = json!({"amount":"1", "currency":"CNY"});
                }
                assert_eq!(input(op, &value, &state).err(), error, "{op} {value}");
            }
        }
    }
}
