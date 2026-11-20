//! In-memory boundary cases for the two form simulators. Their longest accepted
//! history is one upstream response, or zero responses for a callback.
use super::*;
fn oversized_callback(f: &mut Fixture) -> Result<()> {
    let headers = headers_from(&f.input["headers"]).context("callback headers")?;
    let used: usize = headers
        .iter()
        .flat_map(|(k, vs)| vs.iter().map(move |v| k.len() + v.len()))
        .sum();
    f.input["headers"]["X-Pad"] = json!(["p".repeat(16384 - used - "X-Pad".len())]);
    let raw = BASE64_STANDARD.decode(f.input["body"].as_str().context("callback body")?)?;
    let mut v = form::parse(&raw).context("invalid callback")?;
    let order = "o".repeat(100);
    form::set(&mut v, "order_id", &order);
    let verify = f.operation == "verify_callback";
    if verify {
        f.input["order_id"] = json!(order);
        f.expected.result.as_mut().unwrap()["callback"]["order_id"] = json!(order);
    } else {
        f.expected.result.as_mut().unwrap()["route"]["order_id"] = json!(order);
    }
    form::set(&mut v, "event_id", "");
    // Synthetic signed callbacks use the actual MD5 output width.
    if verify {
        form::set(&mut v, "sign", &"0".repeat(32))
    }
    let event = "e".repeat(65536 - form::encode(&v).len());
    form::set(&mut v, "event_id", &event);
    if verify {
        f.expected.result.as_mut().unwrap()["callback"]["event_id"] = json!(event);
    }
    f.input["body"] = json!(BASE64_STANDARD.encode(form::encode(&v)));
    Ok(())
}
fn oversized_exchange(f: &mut Fixture) -> Result<()> {
    let x = &mut f.exchanges[0];
    let r = x.response.as_mut().context("missing recorded response")?;
    let mut body = json::object(&BASE64_STANDARD.decode(&r.body)?)?;
    let mut req = form::parse(&BASE64_STANDARD.decode(&x.request.body)?).context("invalid form")?;
    let refund = f.operation.contains("refund");
    let variant = if refund { "refund" } else { "payment" };
    let row = &mut body[if refund { "refund" } else { "order" }];
    let expected = &mut f.expected.result.as_mut().unwrap()[variant];
    for key in if refund {
        vec!["order_id", "refund_id"]
    } else {
        vec!["order_id"]
    } {
        let id = if key == "refund_id" { "r" } else { "o" }.repeat(100);
        f.input[key] = json!(id);
        form::set(&mut req, key, &id);
        row[key] = json!(id);
        expected[key] = json!(id);
        if key == "refund_id" {
            expected["upstream_refund_id"] = json!(id)
        }
    }
    f.input["money"]["amount"] = json!(i64::MAX.to_string());
    expected["money"]["amount"] = f.input["money"]["amount"].clone();
    row["amount"] = json!(i64::MAX);
    if req.contains_key(b"amount".as_slice()) {
        form::set(&mut req, "amount", &i64::MAX.to_string())
    }
    if f.operation == "create_payment" {
        // Leave exactly enough room for the regenerated signature in the actual request.
        form::set(&mut req, "method", "");
        let len = form::encode(&req).len() - MARK.len() + 32;
        let method = "m".repeat(262144 - len);
        form::set(&mut req, "method", &method);
        f.input["method"] = json!(method);
    }
    x.request.body = BASE64_STANDARD.encode(form::encode(&req));
    let mut encoded = serde_json::to_vec(&body)?;
    if !refund {
        // Exercise string decoding across the full 256 KiB, with valid JSON escapes.
        body["order"]["method"] = json!(" ".repeat(262144 - encoded.len()));
        encoded = serde_json::to_vec(&body)?;
    }
    encoded.resize(262144, b' ');
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
                    oversized_callback(&mut large)?
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
