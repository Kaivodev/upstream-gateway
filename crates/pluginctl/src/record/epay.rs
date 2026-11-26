use super::{
    CaptureEnv, Evidence, Listener, SEED,
    http::{Callback, FORM, Simulator},
};
use anyhow::{Context, Result, ensure};
use base64::prelude::*;
use kaivo_upstream_sdk::{form, time};
use md5::{Digest, Md5};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use upstream_host::{
    engine::{Host, Options},
    execute::Execution,
    package::{Package, hex},
    replay::{MARK, Scanner, SeedStream, SignedQuery, TestCredentials},
};
use zeroize::Zeroizing;

pub(super) const PRODUCT: &str = "Kaivo 测试商品";
pub(super) struct Account {
    pub pid: String,
    pub key: Zeroizing<Vec<u8>>,
}
impl TestCredentials for Account {
    fn shared(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        ensure!(name == "merchant_key", "unknown recording credential");
        Ok(self.key.clone())
    }
}

// The purchase request is signed independently of the host replay implementation.
fn signature(fields: &BTreeMap<&str, &str>, key: &[u8]) -> String {
    let canonical = fields
        .iter()
        .filter(|(k, v)| !matches!(**k, "sign" | "sign_type") && !v.is_empty())
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    hex(&Md5::new()
        .chain_update(canonical.as_bytes())
        .chain_update(key)
        .finalize())
}
impl Account {
    pub fn fetch(sim: &Simulator, token: &str) -> Result<Self> {
        let response = sim.request("GET", "/__test/credentials", Some(token), None, &[])?;
        ensure!(response.status == 200, "test credentials unavailable");
        let credentials = upstream_host::json::object(&response.body)?;
        let account = &credentials["epay-demo"];
        let pid = account["pid"]
            .as_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .context("invalid test pid")?;
        let key = account["shared_secret"]
            .as_str()
            .filter(|s| (16..=16384).contains(&s.len()))
            .context("invalid test credential")?;
        Ok(Self {
            pid: pid.into(),
            key: Zeroizing::new(key.as_bytes().to_vec()),
        })
    }
    pub fn pay(
        &self,
        sim: &Simulator,
        token: &str,
        notify: &str,
        order: &str,
        scenario: &str,
        protected: &mut Scanner,
    ) -> Result<()> {
        let settings = match scenario {
            "signature_error" => json!({"callback_invalid_signature":true}),
            "amount_mismatch" => json!({"callback_amount":12346}),
            _ => json!({}),
        };
        let path = format!("/__test/scenarios/epay-demo/{order}");
        let response = sim.request(
            "PUT",
            &path,
            Some(token),
            Some("application/json"),
            &serde_json::to_vec(&settings)?,
        )?;
        ensure!(
            (200..300).contains(&response.status),
            "test scenario setup failed"
        );
        let mut fields = BTreeMap::from([
            ("pid", self.pid.as_str()),
            ("type", "alipay"),
            ("out_trade_no", order),
            ("notify_url", notify),
            ("name", PRODUCT),
            ("money", "123.45"),
            ("clientip", "127.0.0.1"),
            ("sign_type", "MD5"),
        ]);
        let sig = signature(&fields, &self.key);
        protected.add(sig.as_bytes());
        fields.insert("sign", &sig);
        let mut form = form::Values::new();
        for (k, v) in fields {
            form::set(&mut form, k, v);
        }
        let response = sim.request(
            "POST",
            "/mapi.php",
            None,
            Some(FORM),
            &form::encode_bytes(&form),
        )?;
        ensure!(response.status == 200, "simulator purchase failed");
        let result = upstream_host::json::object(&response.body)?;
        ensure!(result["code"] == 1, "simulator rejected purchase");
        let path = sim.pay_target(
            result["payurl"]
                .as_str()
                .context("missing simulator pay URL")?,
        )?;
        ensure!(
            sim.request("POST", path, None, Some(FORM), &[])?.status == 200,
            "simulator payment failed"
        );
        Ok(())
    }
}

pub(super) struct Case {
    pub input: Value,
    pub sanitized: Vec<u8>,
    pub source: &'static str,
    pub resign: bool,
}
impl Case {
    pub fn from_notification(
        op: &str,
        scenario: &str,
        order: &str,
        callback: &Callback,
        protected: &mut Scanner,
    ) -> Result<Self> {
        ensure!(
            callback.method == "GET" && callback.body.is_empty(),
            "unexpected notification method or body"
        );
        let query = SignedQuery::parse(&callback.query)?;
        let sig = query.signature();
        ensure!(!sig.is_empty(), "empty simulator signature");
        protected.add(sig);
        let mut headers = json!({});
        if !callback.media.is_empty() {
            headers["Content-Type"] = json!(callback.media);
        }
        let raw = if scenario == "malformed" {
            b"malformed%"
        } else {
            callback.query.as_slice()
        };
        let mut input = json!({"method":callback.method, "headers":headers, "raw_query":BASE64_STANDARD.encode(raw), "body":""});
        if op == "verify_callback" {
            input["order_id"] = json!(order);
            input["money"] = json!({"amount":"12345","currency":"CNY"});
        }
        let (sanitized, source) = match scenario {
            "malformed" => (
                raw.to_vec(),
                "recorded_callback_with_constructed_malformed_query",
            ),
            "signature_error" => (
                query.replace_signature(&"0".repeat(32)),
                "recorded_upstream_sim_loopback_with_constructed_invalid_signature",
            ),
            _ => (
                query.replace_signature(MARK),
                "recorded_upstream_sim_loopback",
            ),
        };
        Ok(Self {
            input,
            sanitized,
            source,
            resign: op == "verify_callback" && scenario != "signature_error",
        })
    }
    pub fn check_result(&self, scenario: &str, execution: &Execution) -> Result<()> {
        let ok = match scenario {
            "success" => execution.category == "completed",
            "malformed" => {
                execution.category == "not_sent"
                    && execution.error_code.as_deref() == Some("plugin_error")
            }
            "signature_error" => execution.category == "not_sent",
            "amount_mismatch" => {
                execution.category == "not_sent"
                    && execution.error_code.as_deref() == Some("amount_mismatch")
            }
            _ => false,
        };
        ensure!(ok, "unexpected execution for {scenario}");
        Ok(())
    }
}

pub(super) fn record(
    p: &mut Package,
    sim: &Simulator,
    origin: &str,
    token: &str,
    protected: &mut Scanner,
) -> Result<()> {
    ensure!(
        p.manifest
            .capabilities
            .iter()
            .all(|op| matches!(op.as_str(), "route_callback" | "verify_callback")),
        "unsupported recording capability"
    );
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let timestamp = (now.as_secs().try_into()?, now.subsec_nanos());
    let time = time::format(timestamp).context("invalid recording time")?;
    let stamp = format!(
        "{}{:09}",
        time[..19].replace(['-', 'T', ':'], ""),
        timestamp.1
    );
    let account = Arc::new(Account::fetch(sim, token)?);
    protected.add(&account.key);
    let config = BTreeMap::from([
        ("gateway".into(), origin.to_owned()),
        ("pid".into(), account.pid.clone()),
        ("product_name".into(), PRODUCT.into()),
    ]);
    let host = Host::new(Options::replay(&p.manifest.r#type))?;
    let loaded = host.load(p)?;
    let listener = Listener::start()?;
    for operation in &p.manifest.capabilities {
        for &scenario in upstream_host::replay::required_scenarios(operation) {
            let order = format!("test_{stamp}_{operation}_{scenario}");
            listener.expect(&order);
            account.pay(sim, token, &listener.url, &order, scenario, protected)?;
            let callback = listener.wait()?;
            let mut case =
                Case::from_notification(operation, scenario, &order, &callback, protected)?;
            let env = CaptureEnv {
                config: config.clone(),
                keys: account.clone(),
                now: timestamp,
                random: Mutex::new(SeedStream::new(
                    BASE64_STANDARD
                        .decode(SEED)?
                        .try_into()
                        .expect("32-byte recording seed"),
                )),
            };
            let execution = host.execute(
                &loaded,
                operation,
                &serde_json::to_vec(&case.input)?,
                Arc::new(env),
                Default::default(),
            );
            case.check_result(scenario, &execution)?;
            case.input["raw_query"] = json!(BASE64_STANDARD.encode(case.sanitized));
            let fixture = Evidence {
                name: format!("{operation}/{scenario}"),
                source: case.source,
                operation,
                input: case.input,
                config: &config,
                time: &time,
                random_seed: SEED,
                test_only_resign_callback: case.resign,
                exchanges: [],
                expected: execution,
            };
            let mut raw = serde_json::to_vec_pretty(&fixture)?;
            raw.push(b'\n');
            p.fixtures
                .insert(format!("fixtures/{operation}_{scenario}.json"), raw);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_epay_signature_and_wire_replacement() {
        let fields = BTreeMap::from([
            ("name", "茶 shop"),
            ("sign", "old"),
            ("sign_type", "MD5"),
            ("empty", ""),
            ("Z", "a/b"),
            ("_key", "0"),
        ]);
        assert_eq!(
            signature(&fields, b"vector-secret"),
            "57ca3bd3c13fae53be240e4de17a1b9e"
        );
        let query = SignedQuery::parse(b"z=%2f+&%73ign=abc%3D%3D&sign_type=MD5").unwrap();
        assert_eq!(
            query.replace_signature("replacement"),
            b"z=%2f+&%73ign=replacement&sign_type=MD5"
        );
    }
}
