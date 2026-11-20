mod build;
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use upstream_host::{
    json,
    package::{Package, digest},
    replay::Replay,
};
fn main() {
    if let Err(e) = run() {
        eprintln!("pluginctl: {e:#}");
        std::process::exit(1)
    }
}
fn run() -> Result<()> {
    let mut args = env::args().skip(1);
    let cmd = args.next().context("expected a subcommand")?;
    let mut opts = BTreeMap::new();
    while let Some(k) = args.next() {
        ensure!(
            k.starts_with("--")
                && opts
                    .insert(k, args.next().context("missing option value")?)
                    .is_none(),
            "invalid or duplicate option"
        )
    }
    let mut path = |k: &str| -> Result<PathBuf> {
        Ok(PathBuf::from(
            opts.remove(k).with_context(|| format!("missing {k}"))?,
        ))
    };
    if cmd == "build" {
        let plugin = path("--plugin")?;
        let out = path("--out")?;
        ensure!(opts.is_empty(), "unknown option");
        return build::build(&plugin, &out);
    }
    let dir = path("--dir")?;
    let p = Package::read(&dir)?;
    match cmd.as_str() {
        "verify" => {
            let repo = opts.remove("--repo").unwrap_or_else(|| ".".into());
            ensure!(opts.is_empty(), "unknown option");
            build::verify(&p, Path::new(&repo))?
        }
        "package" => {
            let out = path("--out")?;
            ensure!(opts.is_empty(), "unknown option");
            build::write(&p, &out, &dir)?
        }
        "replay" => {
            let out = path("--out")?;
            ensure!(opts.is_empty(), "unknown option");
            let report = Replay::new(&p)?.run()?;
            let bytes = json::canonical(&report);
            fs::write(out, &bytes)?;
            println!("regression_sha256 {}", digest(&bytes));
            ensure!(report["passed"] == true, "fixture regression failed");
        }
        "calibrate" => {
            ensure!(opts.is_empty(), "unknown option");
            let package = &p.manifest.code;
            let report = Replay::for_calibration(&p)?.calibrate()?;
            for (op, maxima) in &report.operations {
                for (group, peak) in [
                    ("accepted", &maxima.accepted),
                    ("boundary", &maxima.boundary),
                ] {
                    if let Some(p) = peak {
                        println!(
                            "{package} {op} {group} fuel {} step {} case {} wall_ns {}",
                            p.fuel, p.step, p.case, p.wall_ns
                        );
                    } else {
                        println!("{package} {op} {group} none")
                    }
                }
            }
            println!(
                "{package} aggregate total_fuel {} total_wall_ns {} fuel_per_ms {:.2}",
                report.total_fuel,
                report.total_wall_ns,
                report.fuel_per_ms()
            );
        }
        "bench" => {
            let n = number(&mut opts, "--iterations", 100)?;
            ensure!(opts.is_empty(), "unknown option");
            let r = Replay::new(&p)?;
            let name = if p.manifest.r#type == "payment" {
                "verify_callback/success"
            } else {
                "query_payment/success"
            };
            let mut samples = BTreeMap::<usize, Vec<u128>>::new();
            let mut durations = Vec::with_capacity(n);
            let mut peak = 0;
            for _ in 0..n {
                let e = r.measure(name)?;
                durations.push(e.elapsed.as_nanos());
                for (i, m) in e.metrics.iter().enumerate() {
                    samples.entry(i + 1).or_default().push(m.elapsed.as_nanos());
                    peak = peak.max(m.memory)
                }
            }
            durations.sort_unstable();
            println!(
                "{name} operation p50_ns {} p99_ns {} peak_bytes {peak}",
                durations[(n * 50).div_ceil(100) - 1],
                durations[(n * 99).div_ceil(100) - 1]
            );
            for (i, mut v) in samples {
                v.sort_unstable();
                println!(
                    "{name} step {i} p50_ns {} p99_ns {} peak_bytes {peak}",
                    v[(n * 50).div_ceil(100) - 1],
                    v[(n * 99).div_ceil(100) - 1]
                )
            }
        }
        "stress" => {
            let threads = number(&mut opts, "--threads", 4)?;
            let rounds = number(&mut opts, "--rounds", 4)?;
            ensure!(opts.is_empty(), "unknown option");
            let r = Arc::new(Replay::for_concurrency(&p, threads.try_into()?)?);
            let base = r.run()?;
            if base["passed"] != true {
                let fixtures = p
                    .fixtures
                    .iter()
                    .map(|(path, raw)| Ok((path.as_str(), json::object(raw)?["expected"].clone())))
                    .collect::<Result<BTreeMap<_, _>>>()?;
                bail!("baseline failed{}", case_differences(&fixtures, &base));
            }
            let expected = base["cases"]
                .as_array()
                .context("missing baseline cases")?
                .iter()
                .map(|c| {
                    (
                        c["path"].as_str().expect("replay case path"),
                        c["actual"].clone(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let hash = digest(&json::canonical(&base));
            std::thread::scope(|scope| -> Result<()> {
                let mut workers = Vec::new();
                for _ in 0..threads {
                    let r = &r;
                    let hash = &hash;
                    let expected = &expected;
                    workers.push(scope.spawn(move || -> Result<()> {
                        for _ in 0..rounds {
                            let report = r.run()?;
                            ensure!(
                                &digest(&json::canonical(&report)) == hash,
                                "report mismatch{}",
                                case_differences(expected, &report)
                            )
                        }
                        Ok(())
                    }))
                }
                for w in workers {
                    w.join().map_err(|_| anyhow::anyhow!("worker failed"))??
                }
                Ok(())
            })?;
            println!("{} identical reports {hash}", threads * rounds)
        }
        _ => bail!("unknown subcommand"),
    }
    Ok(())
}
fn number(opts: &mut BTreeMap<String, String>, key: &str, default: usize) -> Result<usize> {
    let n = opts
        .remove(key)
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(default);
    ensure!((1..=100000).contains(&n), "invalid {key}");
    Ok(n)
}

fn case_differences(
    expected: &BTreeMap<&str, serde_json::Value>,
    report: &serde_json::Value,
) -> String {
    use std::fmt::Write;
    let mut differences = String::new();
    let mut missing: std::collections::BTreeSet<_> = expected.keys().copied().collect();
    for case in report["cases"].as_array().into_iter().flatten() {
        let path = case["path"].as_str().unwrap_or("?");
        let actual = &case["actual"];
        missing.remove(path);
        let prior = expected.get(path).unwrap_or(&serde_json::Value::Null);
        if actual != prior || case["passed"] != true {
            write!(
                differences,
                "\n{path}: expected category={} error_code={}, actual category={} error_code={}",
                prior["category"].as_str().unwrap_or("-"),
                prior["error_code"].as_str().unwrap_or("-"),
                actual["category"].as_str().unwrap_or("-"),
                actual["error_code"].as_str().unwrap_or("-")
            )
            .unwrap();
        }
    }
    for path in missing {
        let prior = &expected[path];
        write!(
            differences,
            "\n{path}: expected category={} error_code={}, actual case missing",
            prior["category"].as_str().unwrap_or("-"),
            prior["error_code"].as_str().unwrap_or("-")
        )
        .unwrap();
    }
    differences
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn stress_identifies_each_differing_case_without_dumping_results() {
        let expected = BTreeMap::from([
            ("one", json!({"category":"completed"})),
            (
                "two",
                json!({"category":"not_sent","error_code":"plugin_error"}),
            ),
        ]);
        let actual = json!({"cases":[{"path":"one","passed":false,"actual":{"category":"unknown","error_code":"sandbox_timeout"}},{"path":"two","passed":false,"actual":{"category":"not_sent","error_code":"cancelled"}}]});
        let msg = case_differences(&expected, &actual);
        assert!(msg.contains("one: expected category=completed error_code=-, actual category=unknown error_code=sandbox_timeout"));
        assert!(msg.contains("two: expected category=not_sent error_code=plugin_error, actual category=not_sent error_code=cancelled"));
    }
}
