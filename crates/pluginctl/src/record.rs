//! Capture expected executions with simulator credentials, then replay with fresh keys.
mod epay;
mod http;

use anyhow::{Context, Result, ensure};
use base64::prelude::*;
use http::{Callback, Simulator, TIMEOUT};
use kaivo_upstream_sdk::{form, time};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    env, fs, io,
    net::TcpListener,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use upstream_host::{
    environment::{Cancellation, Environment},
    execute::Execution,
    package::{Package, entry_path},
    replay::{Fixture, Replay, Scanner, SeedStream, TestCredentials},
};
use zeroize::Zeroizing;

const SEED: &str = "b25seS10ZXN0LXJlY29yZGVkLWVudHJvcHktMzJieXQ=";

struct Listener {
    url: String,
    callbacks: mpsc::Receiver<Result<Callback>>,
    expected_order: Arc<Mutex<Option<String>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Listener {
    fn start() -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let url = format!("http://{}/callback", listener.local_addr()?);
        let (tx, callbacks) = mpsc::sync_channel(1);
        let expected_order = Arc::new(Mutex::new(None::<String>));
        let current = expected_order.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let worker = thread::spawn(move || {
            while !done.load(Ordering::Acquire) {
                let result = match listener.accept() {
                    Ok((stream, _)) => {
                        let Ok(callback) = http::accept(stream) else {
                            continue;
                        };
                        let Some(fields) = form::parse(&callback.query) else {
                            continue;
                        };
                        let mut order = current.lock().unwrap();
                        if !order
                            .as_deref()
                            .is_some_and(|id| form::get(&fields, "out_trade_no") == Some(id))
                        {
                            continue;
                        }
                        order.take();
                        Ok(callback)
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => Err(e.into()),
                };
                if tx.try_send(result).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            url,
            callbacks,
            expected_order,
            stop,
            worker: Some(worker),
        })
    }
    fn expect(&self, order: &str) {
        *self.expected_order.lock().unwrap() = Some(order.into());
    }

    fn wait(&self) -> Result<Callback> {
        self.callbacks
            .recv_timeout(TIMEOUT)
            .context("callback unavailable")?
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

struct CaptureEnv {
    config: BTreeMap<String, String>,
    keys: Arc<dyn TestCredentials>,
    now: time::Timestamp,
    random: Mutex<SeedStream>,
}
impl Environment for CaptureEnv {
    fn config(&self, _: &Cancellation) -> BTreeMap<String, String> {
        self.config.clone()
    }
    fn secret(&self, name: &str, _: &Cancellation) -> Result<Zeroizing<Vec<u8>>> {
        self.keys.shared(name)
    }
    fn now(&self, _: Instant, _: &Cancellation) -> Result<time::Timestamp> {
        Ok(self.now)
    }
    fn random(&self, b: &mut [u8], _: Instant, _: &Cancellation) -> Result<()> {
        self.random.lock().unwrap().fill(b);
        Ok(())
    }
}

#[derive(Serialize)]
struct Evidence<'a> {
    name: String,
    source: &'a str,
    operation: &'a str,
    input: Value,
    config: &'a BTreeMap<String, String>,
    time: &'a str,
    random_seed: &'a str,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    test_only_resign_callback: bool,
    exchanges: [Value; 0],
    expected: Execution,
}

// Scan both the serialized evidence and the wire data carried inside Base64 fields.
fn check_evidence(bytes: &[u8], protected: &Scanner) -> Result<()> {
    ensure!(!protected.bytes(bytes), "protected data in fixture");
    let fixture = Fixture::decode(bytes)?;
    for key in ["raw_query", "body"] {
        let raw = BASE64_STANDARD.decode(
            fixture.input[key]
                .as_str()
                .context("missing callback data")?,
        )?;
        ensure!(!protected.bytes(&raw), "protected data in callback");
        if key == "raw_query"
            && let Some(fields) = form::parse(&raw)
        {
            for (key, values) in fields {
                ensure!(
                    !protected.bytes(&key) && values.iter().all(|v| !protected.bytes(v)),
                    "protected callback field"
                );
            }
        }
    }
    Ok(())
}

fn empty_output(out: &Path) -> Result<()> {
    if out.try_exists()? {
        ensure!(
            fs::read_dir(out)?.next().is_none(),
            "output directory must be empty"
        );
    }
    Ok(())
}
fn publish(p: &Package, out: &Path) -> Result<()> {
    let parent = out.parent().context("missing output parent")?;
    fs::create_dir_all(parent)?;
    let stage = tempfile::tempdir_in(parent)?;
    for (path, raw) in &p.fixtures {
        let name = path
            .strip_prefix("fixtures/")
            .context("invalid fixture path")?;
        ensure!(
            name.ends_with(".json") && !name.contains('/'),
            "invalid recording name"
        );
        fs::write(stage.path().join(name), raw)?;
    }
    empty_output(out)?;
    fs::rename(stage.path(), out)?;
    for path in p.fixtures.keys() {
        println!("{}", &path["fixtures/".len()..]);
    }
    println!("fixtures_sha256 {}", p.fixture_hash());
    Ok(())
}

pub fn run(plugin: &Path, origin: &str, out: &Path) -> Result<()> {
    let sim = Simulator::parse(origin)?;
    let out = entry_path(out)?;
    empty_output(&out)?;
    let token = Zeroizing::new(
        env::var("UPSTREAM_SIM_CONTROL_TOKEN")
            .ok()
            .context("missing simulator control token")?,
    );
    ensure!(
        token.len() >= 16 && token.bytes().all(|b| b.is_ascii_graphic()),
        "invalid simulator control token"
    );
    let mut p = crate::build::recording_component(plugin)?;
    let mut protected = Scanner::default();
    protected.add(token.as_bytes());
    match p.manifest.code.as_str() {
        "epay_v1" => epay::record(&mut p, &sim, origin, &token, &mut protected)?,
        _ => anyhow::bail!("no recording recipe"),
    }
    for bytes in p.fixtures.values() {
        check_evidence(bytes, &protected)?;
    }
    ensure!(
        Replay::new(&p)?.run()?["passed"] == true,
        "recorded fixtures failed ephemeral replay"
    );
    publish(&p, &out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use upstream_host::package::hex;

    #[test]
    fn listener_ignores_other_orders_and_accepts_a_fragmented_request() {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        let listener = Listener::start().unwrap();
        listener.expect("selected");
        let addr = listener
            .url
            .strip_prefix("http://")
            .unwrap()
            .strip_suffix("/callback")
            .unwrap();
        for id in ["unrelated", "selected"] {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.set_read_timeout(Some(TIMEOUT)).unwrap();
            stream.write_all(b"GET /callback?out_trade_no=").unwrap();
            thread::sleep(Duration::from_millis(20));
            write!(stream, "{id}&sign=x HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            let mut reply = String::new();
            stream.read_to_string(&mut reply).unwrap();
            assert!(reply.starts_with("HTTP/1.1 200 OK") && reply.ends_with("\r\n\r\nsuccess"));
        }
        assert_eq!(
            listener.wait().unwrap().query,
            b"out_trade_no=selected&sign=x"
        );
    }

    #[test]
    fn evidence_rejects_raw_hex_base64_and_embedded_callback_secrets() {
        let mut secret = [0; 24];
        getrandom::fill(&mut secret).unwrap();
        let secret = hex(&secret);
        let mut scan = Scanner::default();
        scan.add(secret.as_bytes());
        let raw = include_bytes!(
            "../../../guest/plugins/sim_form_md5/fixtures/verify_callback_success.json"
        );
        let mut f: Value = serde_json::from_slice(raw).unwrap();
        f["input"]["raw_query"] = json!("");
        check_evidence(&serde_json::to_vec(&f).unwrap(), &scan).unwrap();
        for value in [
            secret.clone(),
            hex(secret.as_bytes()),
            BASE64_STANDARD.encode(&secret),
        ] {
            f["source"] = json!(value);
            assert!(check_evidence(&serde_json::to_vec(&f).unwrap(), &scan).is_err());
            f["source"] = json!("test");
            f["input"]["raw_query"] = json!(BASE64_STANDARD.encode(format!("q={value}&sign=x")));
            assert!(check_evidence(&serde_json::to_vec(&f).unwrap(), &scan).is_err());
            f["input"]["raw_query"] = json!("");
        }
    }
}
