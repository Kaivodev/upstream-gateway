//! In-memory limits for simulator HTTP exchanges and callbacks.
use super::*;
const MAX_ID: usize = 100;
const BODY: usize = 256 << 10;
const CALLBACK_BODY: usize = 64 << 10;
const HEADERS: usize = 16 << 10;

fn pad_headers(f: &mut Fixture) -> Result<()> {
    let headers = headers_from(&f.input["headers"]).context("callback headers")?;
    let used: usize = headers
        .iter()
        .flat_map(|(k, vs)| vs.iter().map(move |v| k.len() + v.len()))
        .sum();
    let padding = HEADERS
        .checked_sub(used + "X-Pad".len())
        .context("callback header budget")?;
    f.input["headers"]["X-Pad"] = json!(["p".repeat(padding)]);
    Ok(())
}

fn oversized_callback(f: &mut Fixture, keys: &dyn TestCredentials) -> Result<()> {
    let raw = BASE64_STANDARD.decode(f.input["body"].as_str().context("callback body")?)?;
    let order = "o".repeat(MAX_ID);
    let verify = f.operation == "verify_callback";
    let variant = if verify { "callback" } else { "route" };
    let expected = &mut f.expected.result.as_mut().context("callback expectation")?[variant];
    expected["order_id"] = json!(order);
    if verify {
        f.input["order_id"] = json!(order);
    }

    if raw.is_empty()
        && let Some(encoded) = f.input["raw_query"].as_str()
    {
        let query = BASE64_STANDARD.decode(encoded)?;
        let mut fields = form::parse(&query).context("invalid callback query")?;
        form::set(&mut fields, "out_trade_no", &order);
        form::set(&mut fields, "sign", &"0".repeat(32));
        form::set(&mut fields, "padding", "");
        let mut query = form::encode_bytes(&fields);
        // Extend the padding value to the host query limit before the normal re-sign step.
        let padding = (16_usize << 10)
            .checked_sub(query.len())
            .context("callback query budget")?;
        form::set(&mut fields, "padding", &"p".repeat(padding));
        query = form::encode_bytes(&fields);
        f.input["raw_query"] = json!(BASE64_STANDARD.encode(query));
        return pad_headers(f);
    }

    let (body, event) = if f.input["headers"]["Content-Type"][0] == "application/json" {
        let mut v = json::object(&raw)?;
        v["order_id"] = json!(order);
        v["upstream_id"] = json!("u".repeat(MAX_ID));
        v["amount"] = json!(i64::MAX);
        v["sequence"] = json!(i64::MAX);
        if verify {
            f.input["money"]["amount"] = json!(i64::MAX.to_string());
            expected["money"]["amount"] = f.input["money"]["amount"].clone();
            expected["upstream_id"] = v["upstream_id"].clone();
        }
        v["event_id"] = json!("");
        let event = "e".repeat(CALLBACK_BODY - serde_json::to_vec(&v)?.len());
        v["event_id"] = json!(event);
        let body = serde_json::to_vec(&v)?;
        // Size padding against the actual in-memory signature, including on route.
        // Verify recordings also pass through the usual protected re-signing path.
        f.input["headers"]["X-Signature"] =
            json!([keys.callback_signature("application/json", &body)?]);
        (body, event)
    } else {
        let mut v = form::parse(&raw).context("invalid callback form")?;
        form::set(&mut v, "order_id", &order);
        form::set(&mut v, "event_id", "");
        if verify {
            form::set(&mut v, "sign", &"0".repeat(32));
        }
        let event = "e".repeat(CALLBACK_BODY - form::encode_bytes(&v).len());
        form::set(&mut v, "event_id", &event);
        (form::encode_bytes(&v), event)
    };
    ensure!(body.len() == CALLBACK_BODY, "wrong callback width");
    if verify {
        expected["event_id"] = json!(event);
    }
    f.input["body"] = json!(BASE64_STANDARD.encode(body));
    pad_headers(f)
}

// Rebuild only the synthetic request. The ordinary replay always compares the
// untouched recording's raw bytes. JSON uses the Go struct's declared field order.
enum ExpectedRequest {
    Json(Value),
    Form(form::Values),
}
impl ExpectedRequest {
    fn read(x: &WireRequest) -> Result<Self> {
        let body = BASE64_STANDARD.decode(&x.body)?;
        Ok(
            if x.headers
                .get("Content-Type")
                .is_some_and(|v| v == &["application/json"])
            {
                Self::Json(json::object(&body)?)
            } else {
                Self::Form(form::parse(&body).context("invalid form")?)
            },
        )
    }
    fn set(&mut self, key: &str, value: &str) {
        match self {
            Self::Form(v) => form::set(v, key, value),
            Self::Json(v) => v[key] = json!(value),
        }
    }
    fn max_amount(&mut self) {
        match self {
            Self::Form(v) if v.contains_key(b"amount".as_slice()) => {
                form::set(v, "amount", &i64::MAX.to_string())
            }
            Self::Json(v) if v.get("amount").is_some() => v["amount"] = json!(i64::MAX),
            _ => {}
        }
    }
    fn encode(&self) -> Result<Vec<u8>> {
        let v = match self {
            Self::Form(v) => return Ok(form::encode_bytes(v)),
            Self::Json(v) => v,
        };
        use serde::ser::{SerializeMap, Serializer};
        let mut out = Vec::new();
        let mut serializer = serde_json::Serializer::new(&mut out);
        let mut map = serializer.serialize_map(None)?;
        for key in [
            "account_id",
            "operation",
            "order_id",
            "amount",
            "currency",
            "method",
            "bank_mode",
            "instruction",
            "callback_url",
            "refund_id",
        ] {
            if let Some(value) = v.get(key) {
                map.serialize_entry(key, value)?;
            }
        }
        map.end()?;
        Ok(String::from_utf8(out)?
            .replace('&', "\\u0026")
            .replace('<', "\\u003c")
            .replace('>', "\\u003e")
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029")
            .into_bytes())
    }
}

fn oversized_exchange(f: &mut Fixture) -> Result<()> {
    let x = &mut f.exchanges[0];
    let r = x.response.as_mut().context("missing recorded response")?;
    let mut body = json::object(&BASE64_STANDARD.decode(&r.body)?)?;
    let mut req = ExpectedRequest::read(&x.request)?;
    let refund = f.operation.contains("refund");
    let variant = if refund { "refund" } else { "payment" };
    let row = &mut body[if refund { "refund" } else { "order" }];
    let expected = &mut f.expected.result.as_mut().context("expected response")?[variant];
    for key in if refund {
        &["order_id", "refund_id"][..]
    } else {
        &["order_id"][..]
    } {
        let key = *key;
        let id = if key == "refund_id" { "r" } else { "o" }.repeat(MAX_ID);
        f.input[key] = json!(id);
        req.set(key, &id);
        row[key] = json!(id);
        expected[key] = json!(id);
        if key == "refund_id" {
            expected["upstream_refund_id"] = json!(id);
        }
    }
    f.input["money"]["amount"] = json!(i64::MAX.to_string());
    expected["money"]["amount"] = f.input["money"]["amount"].clone();
    row["amount"] = json!(i64::MAX);
    req.max_amount();
    if f.operation == "create_payment" {
        req.set("method", "");
        let len = req.encode()?.len();
        let sent_len = if matches!(req, ExpectedRequest::Form(_)) {
            len - MARK.len() + 32
        } else {
            len
        };
        let method = "m".repeat(BODY - sent_len);
        req.set("method", &method);
        f.input["method"] = json!(method);
    }
    x.request.body = BASE64_STANDARD.encode(req.encode()?);
    if !refund {
        body["order"]["method"] = json!("");
        body["order"]["method"] = json!(" ".repeat(BODY - serde_json::to_vec(&body)?.len()));
    }
    let mut encoded = serde_json::to_vec(&body)?;
    encoded.resize(BODY, b' ');
    r.body = BASE64_STANDARD.encode(encoded);
    Ok(())
}
#[derive(Default)]
pub struct Calibration {
    pub operations: BTreeMap<String, OperationMaxima>,
    pub total_fuel: u128,
    pub total_wall_ns: u128,
}
#[derive(Default)]
pub struct OperationMaxima {
    pub accepted: Option<Peak>,
    pub boundary: Option<Peak>,
}
pub struct Peak {
    pub fuel: u64,
    pub step: usize,
    pub case: String,
    pub wall_ns: u128,
}
impl Calibration {
    fn observe(&mut self, op: &str, name: &str, boundary: bool, metrics: &[crate::engine::Metric]) {
        let maxima = self.operations.entry(op.to_owned()).or_default();
        let peak = if boundary {
            &mut maxima.boundary
        } else {
            &mut maxima.accepted
        };
        for (i, m) in metrics.iter().enumerate() {
            self.total_fuel += u128::from(m.fuel);
            self.total_wall_ns += m.elapsed.as_nanos();
            if peak.as_ref().is_none_or(|p| m.fuel > p.fuel) {
                *peak = Some(Peak {
                    fuel: m.fuel,
                    step: i + 1,
                    case: name.into(),
                    wall_ns: m.elapsed.as_nanos(),
                });
            }
        }
    }
    pub fn fuel_per_ms(&self) -> f64 {
        if self.total_wall_ns == 0 {
            return 0.0;
        }
        self.total_fuel as f64 * 1_000_000.0 / self.total_wall_ns as f64
    }
}
impl Replay {
    pub fn calibrate(&self) -> Result<Calibration> {
        let keys: Arc<dyn TestCredentials> = Arc::new(Ephemeral::new(self.loaded.manifest())?);
        let mut report = Calibration::default();
        for (_, f) in self.cases.values() {
            let mut cases = vec![(f.clone(), f.name.clone(), false)];
            if f.name.ends_with("/success") {
                let mut large = f.clone();
                if f.operation.ends_with("callback") {
                    oversized_callback(&mut large, &*keys)?
                } else {
                    oversized_exchange(&mut large)?
                }
                if f.operation == "create_payment" {
                    let mut boundary = large.clone();
                    boundary.input["method"] = json!("m");
                    let size =
                        crate::json::projected_len(&json!({"input":boundary.input,"responses":[]}));
                    boundary.input["method"] = json!("m".repeat((1 << 20) - size + 1));
                    boundary.exchanges.clear();
                    boundary.expected = Execution {
                        category: "not_sent".into(),
                        error_code: Some("host_io_limit".into()),
                        steps: 1,
                        ..Execution::default()
                    };
                    cases.push((boundary, format!("{}/maximum_call", f.operation), true));
                }
                cases.push((large, format!("{}/maximum_accepted", f.operation), false));
            }
            for (case, name, boundary) in cases {
                let (e, ok) = self.case(case, keys.clone())?;
                ensure!(ok, "calibration case {name} failed ({:?})", e.error_code);
                report.observe(&f.operation, &name, boundary, &e.metrics);
            }
        }
        Ok(report)
    }
}
