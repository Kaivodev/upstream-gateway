use anyhow::{Result, ensure};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tempfile::tempdir;
use upstream_host::{
    engine::{Host, Options},
    environment::{Cancellation, Environment, Incoming, Transport},
    package::{Package, hex},
    replay::Replay,
    types::HttpRequest,
};
use zeroize::Zeroizing;
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}
fn cli(args: &[&str], paths: &[&Path]) -> Result<()> {
    let mut c = Command::new(env!("CARGO_BIN_EXE_pluginctl"));
    for (i, arg) in args.iter().enumerate() {
        c.arg(arg);
        if let Some(path) = i.checked_sub(1).and_then(|j| paths.get(j)) {
            c.arg(path);
        }
    }
    let o = c.output()?;
    ensure!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    Ok(())
}
fn build(src: &Path, out: &Path) -> Result<Package> {
    cli(&["build", "--plugin", "--out"], &[src, out])?;
    Package::read(out)
}
#[test]
fn rejects_an_unpinned_interpreter_before_validating_inputs() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempdir()?;
    let python = tmp.path().join("python3");
    fs::write(
        &python,
        b"#!/bin/sh\n[ \"$1\" = -I ] && [ \"$2\" = --version ] || exit 2\necho 'Python 3.14.0'\n",
    )?;
    fs::set_permissions(&python, fs::Permissions::from_mode(0o755))?;
    let output = Command::new(env!("CARGO_BIN_EXE_pluginctl"))
        .args(["build", "--plugin"])
        .arg(root().join("guest/plugins/sim_json_rsa"))
        .arg("--out")
        .arg(tmp.path().join("unused"))
        .env("PATH", tmp.path())
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr)?.contains("wrong Python release: Python 3.14.0"));
    Ok(())
}
#[test]
fn real_packages_replay_and_verify() -> Result<()> {
    let tmp = tempdir()?;
    let root = root();
    for (name, count) in [
        ("sim_form_md5", 30),
        ("sim_form_md5_verify", 10),
        ("sim_json_rsa", 30),
        ("sim_json_rsa_verify", 10),
    ] {
        let out = tmp.path().join(name);
        let p = build(&root.join("guest/plugins").join(name), &out)?;
        let r = Replay::new(&p)?;
        let a = r.run()?;
        assert_eq!(a["passed"], true);
        assert_eq!(a["cases"].as_array().unwrap().len(), count);
        assert_eq!(a, r.run()?);
        if name.ends_with("_verify") {
            let mut broken = Package::read(&out)?;
            for (scenario, change) in [
                ("success", "mismatch"),
                ("rejected", "missing"),
                ("signature_error", "extra"),
            ] {
                let raw = broken
                    .fixtures
                    .get_mut(&format!("fixtures/query_payment_{scenario}.json"))
                    .unwrap();
                let mut fixture: Value = serde_json::from_slice(raw)?;
                let x = fixture["exchanges"].as_array_mut().unwrap();
                match change {
                    "mismatch" => x[0]["request"]["url"] = json!("https://example.test/mismatch"),
                    "missing" => x.clear(),
                    _ => x.push(x[0].clone()),
                };
                *raw = serde_json::to_vec(&fixture)?;
            }
            let report = Replay::new(&broken)?.run()?;
            assert_eq!(report["passed"], false);
            assert_eq!(
                report["cases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|c| c["passed"] == false)
                    .count(),
                3
            );
        }
        if p.manifest.build.source_commit == "uncommitted" {
            assert!(cli(&["verify", "--dir", "--repo"], &[&out, &root]).is_err())
        }
    }
    // Source, package, fixture and output paths all cross an alias outside the tree.
    let physical = tmp.path().join("physical");
    fs::create_dir(&physical)?;
    let alias = tmp.path().join("external alias");
    std::os::unix::fs::symlink(&physical, &alias)?;
    let repo = alias.join("source checkout");
    fs::create_dir(&repo)?;
    fn copy(p: &Path, q: &Path) -> Result<()> {
        if p.is_dir() {
            fs::create_dir_all(q)?;
            for e in fs::read_dir(p)? {
                let e = e?;
                if e.file_name() != "target" {
                    copy(&e.path(), &q.join(e.file_name()))?
                }
            }
        } else {
            fs::copy(p, q)?;
        }
        Ok(())
    }
    for name in [
        "guest",
        "wit",
        "scripts",
        "rust-toolchain.toml",
        "build-config.json",
        ".gitignore",
    ] {
        copy(&root.join(name), &repo.join(name))?;
    }
    let git = |args: &[&str]| -> Result<()> {
        let o = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args([
                "-c",
                "user.name=Fixture Builder",
                "-c",
                "user.email=fixture@localhost",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=.git/disabled-hooks",
            ])
            .args(args)
            .output()?;
        ensure!(o.status.success(), "temporary repository setup failed");
        Ok(())
    };
    git(&["init", "-q"])?;
    git(&["add", "-f", "."])?;
    git(&["commit", "-qm", "Synthetic source snapshot"])?;
    let out = alias.join("committed");
    let p = build(&repo.join("guest/plugins/sim_form_md5_verify"), &out)?;
    assert_ne!(p.manifest.build.source_commit, "uncommitted");
    cli(&["verify", "--dir", "--repo"], &[&out, &repo])?;
    let linked_out = alias.join("linked-package");
    std::os::unix::fs::symlink(&out, &linked_out)?;
    assert!(Package::read(&linked_out).is_err());
    assert!(cli(&["package", "--dir", "--out"], &[&out, &linked_out]).is_err());
    let plugin = repo.join("guest/plugins/sim_form_md5_verify");
    let linked_plugin = plugin.with_file_name("linked-plugin");
    std::os::unix::fs::symlink(&plugin, &linked_plugin)?;
    let err = cli(
        &["build", "--plugin", "--out"],
        &[&linked_plugin, &alias.join("unused")],
    )
    .unwrap_err();
    assert!(err.to_string().contains("symbolic link"), "{err}");
    fs::remove_file(linked_plugin)?;
    let closure_link = repo.join("guest/sdk/src/uncompiled.rs");
    std::os::unix::fs::symlink(repo.join("guest/sdk/src/lib.rs"), &closure_link)?;
    let err = cli(
        &["build", "--plugin", "--out"],
        &[&plugin, &alias.join("unused")],
    )
    .unwrap_err();
    assert!(err.to_string().contains("symbolic link"), "{err}");
    fs::remove_file(closure_link)?;
    fs::write(repo.join("dirty"), b"changed")?;
    assert!(cli(&["verify", "--dir", "--repo"], &[&out, &repo]).is_err());
    fs::remove_file(repo.join("dirty"))?;
    let mut wasm = fs::read(out.join("plugin.wasm"))?;
    wasm.push(0);
    fs::write(out.join("plugin.wasm"), wasm)?;
    assert!(cli(&["verify", "--dir", "--repo"], &[&out, &repo]).is_err());
    Ok(())
}
struct Services {
    mode: String,
    material: Zeroizing<Vec<u8>>,
    offset: Mutex<usize>,
    alerts: AtomicUsize,
    resolutions: AtomicUsize,
    logs: AtomicUsize,
}
impl Services {
    fn new(mode: &str) -> Arc<Self> {
        let mut bytes = Zeroizing::new([0; 16]);
        getrandom::fill(&mut *bytes).unwrap();
        Arc::new(Self {
            mode: mode.into(),
            material: Zeroizing::new(hex(bytes.as_slice()).into_bytes()),
            offset: Mutex::new(0),
            alerts: 0.into(),
            resolutions: 0.into(),
            logs: 0.into(),
        })
    }
}
impl Environment for Services {
    fn config(&self, _: &Cancellation) -> BTreeMap<String, String> {
        BTreeMap::from([("mode".into(), self.mode.clone())])
    }
    fn secret(&self, _: &str, _: &Cancellation) -> Result<Zeroizing<Vec<u8>>> {
        self.resolutions.fetch_add(1, Ordering::Relaxed);
        Ok(self.material.clone())
    }
    fn random(&self, b: &mut [u8], _: Instant, _: &Cancellation) -> Result<()> {
        if b.len() == 16 {
            let mut i = self.offset.lock().unwrap();
            b.copy_from_slice(&self.material[*i..*i + 16]);
            *i = (*i + 16) % 32
        } else {
            b.fill(0)
        }
        Ok(())
    }
    fn alert(&self, c: &str) {
        assert_eq!(c, "secret_leak");
        self.alerts.fetch_add(1, Ordering::Relaxed);
    }
    fn log(&self, _: &Value) {
        self.logs.fetch_add(1, Ordering::Relaxed);
    }
    fn transport(&self) -> Option<&dyn Transport> {
        Some(self)
    }
}
impl Transport for Services {
    fn send(
        &self,
        _: &HttpRequest,
        _: &HttpRequest,
        _: Instant,
        c: &Cancellation,
    ) -> Result<Incoming> {
        if self.mode == "missing_response" {
            return Err(upstream_host::environment::MissingResponse.into());
        }
        assert_eq!(
            self.logs.load(Ordering::Relaxed),
            0,
            "logs delivered before dispatch"
        );
        let mut body = Vec::new();
        if self.mode == "reflect" {
            body.extend(&*self.material);
            c.cancel()
        }
        Ok(Incoming {
            status: 200,
            headers: vec![],
            body: Box::new(Cursor::new(body)),
        })
    }
}
#[test]
fn sandbox_boundaries() -> Result<()> {
    let tmp = tempdir()?;
    let p = build(
        &root().join("guest/testdata/abi_probe"),
        &tmp.path().join("probe"),
    )?;
    // Invoke the undeclared entry directly through the component ABI. The default
    // SDK path needs no imports, so any host access here is also a test failure.
    {
        use upstream_host::{trade::TradePlugin, types::*};
        use wasmtime::{
            Engine, Store,
            component::{Component, Linker},
        };
        let engine = Engine::default();
        let component = Component::new(&engine, &p.wasm)?;
        let mut linker = Linker::<()>::new(&engine);
        linker.define_unknown_imports_as_traps(&component)?;
        let mut store = Store::new(&engine, ());
        let guest = TradePlugin::instantiate(&mut store, &component, &linker)?;
        let step = guest.kaivo_upstream_trade().call_close_payment(
            &mut store,
            &PaymentCall {
                input: PaymentInput {
                    order_id: "probe".into(),
                    money: Money {
                        amount: "1".into(),
                        currency: "CNY".into(),
                    },
                },
                responses: vec![],
            },
        )?;
        assert!(
            matches!(step,Step::Result(OperationResult::Error(Some(code))) if code=="unsupported_operation")
        );
    }
    let h = Host::new(Options::replay("payment"))?;
    let l = h.load(&p)?;
    assert!(Arc::ptr_eq(&l, &h.load(&p)?));
    let input =
        serde_json::to_vec(&json!({"order_id":"probe","money":{"amount":"12","currency":"CNY"}}))?;
    for (mode, code, requests) in [
        ("loop", "fuel_exhausted", 0),
        ("memory", "memory_limit", 0),
        ("calls", "host_call_limit", 0),
        ("random", "random_limit", 0),
        ("random_total", "random_limit", 0),
        ("log_level", "log_level", 0),
        ("log_count", "log_rate_limit", 0),
        ("log_size", "log_limit", 0),
        ("leak_log", "secret_leak", 0),
        ("split_log", "secret_leak", 0),
        ("leak_url", "secret_leak", 0),
        ("leak_header", "secret_leak", 0),
        ("leak_body", "secret_leak", 0),
        ("leak_step", "secret_leak", 0),
        ("reflect", "secret_leak", 1),
        ("missing_response", "transport_response", 1),
        ("undeclared", "undeclared_config", 0),
        ("clock", "sandbox_trap", 0),
        ("fifth", "step_limit", 4),
        ("complete", "unsubstantiated_result", 0),
        ("rejected", "unsubstantiated_rejection", 0),
        ("after_request", "plugin_error", 1),
    ] {
        let env = Services::new(mode);
        let e = h.execute(&l, "query_payment", &input, env.clone(), Default::default());
        assert_eq!(e.error_code.as_deref(), Some(code), "{mode}");
        assert_eq!(e.requests, requests);
        assert_eq!(
            e.category,
            if requests == 0 { "not_sent" } else { "unknown" }
        );
        assert!(e.result.is_none());
        assert_eq!(
            env.alerts.load(Ordering::Relaxed),
            usize::from(code == "secret_leak")
        );
        let delivered = match mode {
            "log_count" => 32,
            "after_request" => 1,
            _ => 0,
        };
        assert_eq!(env.logs.load(Ordering::Relaxed), delivered, "{mode}");
    }
    let e = h.execute(
        &l,
        "query_payment",
        &input,
        Services::new("fresh"),
        Default::default(),
    );
    assert_eq!(e.category, "completed");
    assert_eq!(e.steps, 2);
    for (mode, code) in [
        ("crypto", "route_crypto_forbidden"),
        ("http", "callback_network_forbidden"),
    ] {
        let env = Services::new(mode);
        let raw=br#"{"method":"POST","headers":{"Content-Type":["application/x-www-form-urlencoded"]},"body":""}"#;
        let e = h.execute(&l, "route_callback", raw, env.clone(), Default::default());
        assert_eq!(e.error_code.as_deref(), Some(code));
        assert_eq!(env.resolutions.load(Ordering::Relaxed), 0);
    }
    let e = h.execute(
        &l,
        "close_payment",
        &input,
        Services::new("fresh"),
        Default::default(),
    );
    assert_eq!(e.error_code.as_deref(), Some("unsupported_operation"));
    assert_eq!(e.steps, 0);
    let mut options = Options::production("payment");
    options.test_only_allow_uncommitted = true;
    options.fuel_per_step = u64::MAX;
    let slow = Host::new(options)?;
    let l = slow.load(&p)?;
    let start = Instant::now();
    let e = slow.execute(
        &l,
        "query_payment",
        &input,
        Services::new("loop"),
        Default::default(),
    );
    assert_eq!(e.error_code.as_deref(), Some("sandbox_timeout"));
    assert!(start.elapsed() < Duration::from_secs(10));
    Ok(())
}

#[test]
fn reject_unsafe_package_inputs() -> Result<()> {
    use std::os::unix::fs::symlink;
    use upstream_host::package::fixtures;
    let root = tempdir()?;
    let dir = root.path().join("fixtures");
    fs::create_dir(&dir)?;
    fs::write(dir.join("ok.json"), b"{}")?;
    assert_eq!(fixtures(root.path())?.len(), 1);
    fs::hard_link(dir.join("ok.json"), dir.join("alias.json"))?;
    assert!(fixtures(root.path()).is_err());
    fs::remove_file(dir.join("alias.json"))?;
    symlink(dir.join("ok.json"), dir.join("linked.json"))?;
    assert!(fixtures(root.path()).is_err());
    fs::remove_file(dir.join("linked.json"))?;
    let nested = dir.join("subdirectory");
    fs::create_dir(&nested)?;
    symlink(&nested, dir.join("linked-dir"))?;
    assert!(fixtures(root.path()).is_err());
    fs::remove_file(dir.join("linked-dir"))?;
    fs::rename(&dir, root.path().join("real-fixtures"))?;
    symlink(root.path().join("real-fixtures"), &dir)?;
    assert!(fixtures(root.path()).is_err());
    fs::remove_file(&dir)?;
    fs::rename(root.path().join("real-fixtures"), &dir)?;
    fs::write(dir.join("bad:name.json"), b"{}")?;
    assert!(fixtures(root.path()).is_err());
    Ok(())
}
