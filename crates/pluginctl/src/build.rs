//! Locked component build, source-closure hashing and clean-commit verification.
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Component, Path, PathBuf},
    process::{Command, Output},
};
use tempfile::{TempDir, tempdir_in};
use upstream_host::{
    engine::{Host, Options},
    json as wire,
    package::{Manifest, Package, entry_path, file, fixtures, hex, safe_path},
};
fn checked(c: &mut Command) -> Result<Output> {
    let o = c
        .output()
        .with_context(|| format!("starting {:?}", c.get_program()))?;
    ensure!(
        o.status.success(),
        "{:?} failed: {}",
        c.get_program(),
        String::from_utf8_lossy(&o.stderr)
    );
    Ok(o)
}
fn output(c: &mut Command) -> Result<String> {
    Ok(String::from_utf8(checked(c)?.stdout)?.trim_end().into())
}
fn git(root: &Path, args: &[&str]) -> Result<String> {
    output(Command::new("git").arg("-C").arg(root).args(args))
}
fn source_commit(root: &Path) -> Result<String> {
    ensure!(
        git(root, &["rev-parse", "--show-toplevel"])? == root.to_str().context("checkout path")?,
        "repository root mismatch"
    );
    ensure!(
        git(root, &["status", "--porcelain=v1", "--untracked-files=all"])?.is_empty(),
        "dirty sources"
    );
    git(root, &["rev-parse", "--verify", "HEAD^{commit}"])
}
fn relative<'a>(p: &'a Path, root: &Path) -> Result<&'a str> {
    let rel = p.strip_prefix(root)?.to_str().context("non-UTF-8 source")?;
    ensure!(
        !rel.is_empty()
            && !rel.contains(['\\', ':'])
            && rel.split('/').all(|s| !matches!(s, "" | "." | "..")),
        "unsafe closure path"
    );
    Ok(rel)
}
fn strings(v: &Value) -> Result<Vec<&str>> {
    v.as_array()
        .context("expected array")?
        .iter()
        .map(|v| v.as_str().context("expected string"))
        .collect()
}
struct Closure {
    digest: String,
    ids: BTreeSet<String>,
    registry_features: BTreeMap<String, Value>,
    files: BTreeSet<PathBuf>,
}
struct Builder {
    root: PathBuf,
    plugin: PathBuf,
    cfg: Value,
    sysroot: PathBuf,
    system_path: Vec<PathBuf>,
    tools: PathBuf,
    scratch: TempDir,
    host: String,
    name: String,
    world: String,
}
impl Builder {
    fn new(plugin: &Path) -> Result<Self> {
        ensure!(
            !plugin.components().any(|c| c == Component::ParentDir),
            "parent traversal"
        );
        let supplied = std::path::absolute(plugin)?;
        let plugin = &supplied;
        let guest = plugin
            .parent()
            .and_then(Path::parent)
            .context("invalid plugin path")?;
        ensure!(
            guest.file_name().is_some_and(|n| n == "guest")
                && plugin
                    .parent()
                    .and_then(Path::file_name)
                    .is_some_and(|n| n == "plugins" || n == "testdata"),
            "expected guest plugin member"
        );
        let checkout = guest.parent().context("missing checkout root")?;
        let root = checkout.canonicalize()?;
        let plugin = root.join(plugin.strip_prefix(checkout)?);
        safe_path(&root, &plugin)?;
        let guest = root.join("guest");
        // Use the validator embedded in this host binary when checking untrusted checkouts.
        let validator = include_str!("../../../scripts/check-build-inputs.py");
        ensure!(
            file(&root, &root.join("scripts/check-build-inputs.py"), 65536)?
                == validator.as_bytes(),
            "unrecognized build validator"
        );
        checked(
            Command::new("python3")
                .env_remove("PYTHONPATH")
                .args(["-I", "-B", "-c", validator])
                .arg(&root)
                .arg(&plugin),
        )?;
        let cfg = wire::object(&file(&root, &root.join("build-config.json"), 65536)?)?;
        ensure!(
            cfg == serde_json::from_str::<Value>(include_str!("../../../build-config.json"))?,
            "build configuration differs from pinned builder"
        );
        let rust = output(Command::new("rustc").arg("-vV").current_dir(&root))?;
        let field = |k: &str| {
            rust.lines()
                .find_map(|l| l.strip_prefix(k))
                .context("invalid rustc -vV")
        };
        ensure!(
            cfg["rust_version"] == field("release: ")?,
            "wrong Rust release"
        );
        let host = field("host: ")?.to_string();
        ensure!(
            strings(&cfg["hosts"])?.contains(&host.as_str()),
            "unapproved build host"
        );
        let sysroot = PathBuf::from(output(
            Command::new("rustc")
                .args(["--print", "sysroot"])
                .current_dir(&root),
        )?)
        .canonicalize()?;
        let tools = env::split_paths(&env::var_os("PATH").context("missing PATH")?)
            .map(|p| p.join("wasm-tools"))
            .find(|p| p.is_file())
            .context("wasm-tools missing")?
            .canonicalize()?;
        ensure!(
            output(Command::new(&tools).arg("--version"))?
                == format!("wasm-tools {}", cfg["wasm_tools_version"].as_str().unwrap()),
            "wrong wasm-tools version"
        );
        let source = wire::object(&file(&root, &plugin.join("manifest.json"), 65536)?)?;
        ensure!(
            source.get("build").is_none(),
            "source manifest contains build"
        );
        let world = match source["type"].as_str() {
            Some("payment") => "trade-plugin",
            Some("verification") => "verification-plugin",
            _ => bail!("invalid plugin role"),
        }
        .into();
        let name = source["code"]
            .as_str()
            .context("missing plugin code")?
            .to_owned();
        ensure!(
            plugin.file_name().unwrap() == name.as_str(),
            "plugin code/path mismatch"
        );
        let scratch = tempdir_in(env::temp_dir().canonicalize()?)?;
        fs::create_dir(scratch.path().join("home"))?;
        fs::create_dir(scratch.path().join("tmp"))?;
        ensure!(
            !scratch.path().starts_with(guest),
            "temporary build directory inside guest workspace"
        );
        let system_path =
            env::split_paths(&output(Command::new("getconf").arg("PATH"))?).collect::<Vec<_>>();
        ensure!(
            !system_path.is_empty() && system_path.iter().all(|p| p.is_absolute()),
            "invalid system tool search path"
        );
        Ok(Self {
            system_path,
            root,
            plugin,
            cfg,
            sysroot,
            tools,
            scratch,
            host,
            name,
            world,
        })
    }
    fn cmd(&self, p: &Path) -> Result<Command> {
        let mut c = Command::new(p);
        let tmp = self.scratch.path();
        let bin = self.sysroot.join("bin");
        // Invoke the actual pinned compiler and Cargo. Rustup proxies would need user configuration.
        let path = env::join_paths(std::iter::once(&bin).chain(&self.system_path))?;
        c.env_clear()
            .env("PATH", path)
            .env("HOME", tmp.join("home"))
            .env("CARGO_HOME", tmp.join("home"))
            .env("CARGO_TARGET_DIR", tmp.join("target"))
            .env("TMPDIR", tmp.join("tmp"))
            .env("RUSTC", bin.join("rustc"))
            .env("LC_ALL", "C")
            .current_dir(&self.plugin);
        let mut flags = Vec::new();
        for f in strings(&self.cfg["rustflags"])? {
            flags.push(
                f.replace("$WORKSPACE", self.root.to_str().unwrap())
                    .replace(
                        "$TOOLCHAIN",
                        self.sysroot.to_str().context("toolchain path")?,
                    )
                    .replace("$BUILD", tmp.to_str().context("scratch path")?),
            )
        }
        c.env("CARGO_ENCODED_RUSTFLAGS", flags.join("\x1f"));
        Ok(c)
    }
    fn cargo(&self, verb: &str) -> Result<Command> {
        let mut c = self.cmd(&self.sysroot.join("bin/cargo"))?;
        c.arg(verb).args([
            "--manifest-path",
            "Cargo.toml",
            "--locked",
            "--offline",
            "--no-default-features",
        ]);
        let features = strings(&self.cfg["features"])?;
        if !features.is_empty() {
            c.args(["--features", &features.join(",")]);
        }
        Ok(c)
    }
    fn metadata(&self, triple: &str) -> Result<Value> {
        let mut c = self.cargo("metadata")?;
        Ok(serde_json::from_slice(
            &checked(c.args(["--format-version", "1", "--filter-platform", triple]))?.stdout,
        )?)
    }
    fn tree(&self) -> Result<Closure> {
        let target = self.cfg["target"]
            .as_str()
            .context("missing build target")?;
        let metas = [self.metadata(target)?, self.metadata(&self.host)?];
        let find = |side: usize, table: &str, id: &str| -> Result<&Value> {
            let items = if table == "nodes" {
                &metas[side]["resolve"]["nodes"]
            } else {
                &metas[side]["packages"]
            };
            items
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["id"] == id)
                .context("unresolved dependency")
        };
        let root_id = metas[0]["resolve"]["root"]
            .as_str()
            .context("no root package")?;
        let mut queue = vec![(root_id.to_owned(), 0usize)];
        let mut seen = BTreeSet::new();
        let mut files = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut registry_features = BTreeMap::new();
        for path in strings(&self.cfg["inputs"])? {
            let p = self.root.join(path);
            relative(&p, &self.root)?;
            files.insert(p);
        }
        while let Some((id, side)) = queue.pop() {
            if !seen.insert((id.clone(), side)) {
                continue;
            }
            ids.insert(id.clone());
            let pkg = find(side, "packages", &id)?;
            let node = find(side, "nodes", &id)?;
            let manifest = PathBuf::from(pkg["manifest_path"].as_str().unwrap());
            let dir = manifest.parent().unwrap();
            let rel = relative(dir, &self.root)?;
            let src = &pkg["source"];
            if src.is_null() {
                ensure!(
                    metas[side]["workspace_members"]
                        .as_array()
                        .unwrap()
                        .contains(&json!(id))
                        && rel.starts_with("guest/"),
                    "external path dependency"
                );
                files.insert(manifest.clone());
                walk(&self.root, &dir.join("src"), &mut files)?;
                for t in pkg["targets"].as_array().unwrap() {
                    let path = Path::new(t["src_path"].as_str().unwrap());
                    ensure!(
                        path.starts_with(dir.join("src"))
                            || files.contains(path)
                            || path == dir.join("build.rs"),
                        "undeclared target input"
                    );
                    ensure!(
                        t["kind"] != json!(["proc-macro"]),
                        "workspace proc-macros require a new admission review"
                    );
                    if t["kind"] == json!(["custom-build"]) {
                        ensure!(
                            strings(&self.cfg["workspace_build_scripts"])?
                                .contains(&relative(path, &self.root)?),
                            "unreviewed workspace build script"
                        )
                    }
                    files.insert(path.into());
                }
            } else {
                let name = pkg["name"].as_str().unwrap();
                let pin = self.cfg["registry_crates"]
                    .get(name)
                    .context("unapproved registry crate")?;
                let index = file(&self.root, &dir.join(".cargo-checksum.json"), 1 << 20)?;
                ensure!(
                    pin["vendor_index_sha256"] == upstream_host::package::digest(&index),
                    "vendor checksum index differs from release configuration"
                );
                let checksum = wire::object(&index)?;
                ensure!(
                    src == "registry+https://github.com/rust-lang/crates.io-index"
                        && pin["version"] == pkg["version"]
                        && pin["checksum"] == checksum["package"],
                    "unapproved registry dependency"
                );
                registry_features.insert(id.clone(), pin["features"].clone());
                ensure!(
                    rel == format!(
                        "guest/vendor/{}-{}",
                        pkg["name"].as_str().unwrap(),
                        pkg["version"].as_str().unwrap()
                    ),
                    "unexpected vendor path"
                );
                let mut vendor_files = BTreeSet::new();
                walk(&self.root, dir, &mut vendor_files)?;
                let expected = checksum["files"]
                    .as_object()
                    .context("invalid vendor checksum index")?;
                ensure!(
                    vendor_files.len() == expected.len() + 1,
                    "vendor file set changed"
                );
                for path in &vendor_files {
                    let name = relative(path, dir)?;
                    if name != ".cargo-checksum.json" {
                        let bytes = file(&self.root, path, usize::MAX - 1)?;
                        ensure!(
                            expected.get(name)
                                == Some(&json!(upstream_host::package::digest(&bytes))),
                            "vendor file checksum mismatch"
                        );
                    }
                }
                files.extend(vendor_files);
            }
            for dep in node["deps"].as_array().unwrap() {
                let child = dep["pkg"].as_str().unwrap();
                let proc_macro = find(side, "packages", child)?["targets"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|t| t["kind"].as_array().unwrap().contains(&json!("proc-macro")));
                for edge in dep["dep_kinds"].as_array().unwrap() {
                    if edge["kind"] == "dev" {
                        continue;
                    }
                    let host = side == 1 || proc_macro || edge["kind"] == "build";
                    queue.push((child.to_owned(), usize::from(host)))
                }
            }
        }
        let config = json!({"crate":relative(&self.plugin.join("Cargo.toml"),&self.root)?,"world":format!("kaivo:upstream/{}@3.0.0",self.world),"target":target,"host":self.host,"rust_version":self.cfg["rust_version"],"wasm_tools_version":self.cfg["wasm_tools_version"],"features":self.cfg["features"],"default_features":false,"profile":self.cfg["profile"],"rustflags":self.cfg["rustflags"],"component_args":self.cfg["component_args"]});
        let mut h = Sha256::new();
        let mut lp = |b: &[u8]| {
            h.update((b.len() as u64).to_be_bytes());
            h.update(b)
        };
        lp(b"kaivo.plugin.source-closure.v3");
        lp(&wire::canonical(&config));
        let mut paths = BTreeMap::new();
        for p in &files {
            paths.insert(relative(p, &self.root)?, p);
        }
        for (rel, p) in paths {
            lp(b"file");
            lp(rel.as_bytes());
            lp(&file(&self.root, p, usize::MAX - 1)?);
        }
        Ok(Closure {
            digest: hex(&h.finalize()),
            ids,
            registry_features,
            files,
        })
    }
    fn selected_features(&self) -> Result<BTreeSet<(String, String)>> {
        let mut c = self.cargo("tree")?;
        let raw = output(c.args([
            "-p",
            &self.name,
            "--target",
            self.cfg["target"].as_str().unwrap(),
            "-e",
            "normal,build",
            "--prefix",
            "none",
            "--no-dedupe",
            "--format",
            "{p}|{f}",
        ]))?;
        raw.lines()
            .map(|l| {
                let (package, features) = l.rsplit_once('|').context("invalid compilation unit")?;
                Ok((
                    package
                        .split_whitespace()
                        .next()
                        .context("missing crate name")?
                        .replace('-', "_"),
                    features.into(),
                ))
            })
            .collect()
    }
    fn check_compiler_inputs(&self, core: &Path, files: &BTreeSet<PathBuf>) -> Result<()> {
        // Cargo's cdylib dep-info includes compiler-discovered include! and include_bytes!
        // transitive inputs. Paths may contain Make-escaped spaces.
        let dep = String::from_utf8(file(
            self.scratch.path(),
            &core.with_extension("d"),
            usize::MAX - 1,
        )?)?;
        let (_, list) = dep
            .lines()
            .next()
            .context("empty compiler dep-info")?
            .split_once(": ")
            .context("invalid compiler dep-info")?;
        let mut word = String::new();
        let mut escaped = false;
        for c in list.chars().chain([' ']) {
            if escaped {
                word.push(c);
                escaped = false;
                continue;
            }
            if c == '\\' {
                escaped = true;
                continue;
            }
            if c != ' ' {
                word.push(c);
                continue;
            }
            if word.is_empty() {
                continue;
            }
            let path = PathBuf::from(std::mem::take(&mut word));
            let root = if path.starts_with(&self.root) {
                &self.root
            } else {
                self.scratch.path()
            };
            safe_path(root, &path)?;
            let generated = path.starts_with(self.scratch.path().join("target"))
                && path.components().any(|c| c.as_os_str() == "out");
            ensure!(
                files.contains(&path) || generated,
                "compiler read an undeclared source input"
            );
        }
        Ok(())
    }
    fn build(&self, commit: String) -> Result<Package> {
        let closure = self.tree()?;
        if commit != "uncommitted" && self.root.join(".git").exists() {
            let tracked = checked(
                Command::new("git")
                    .arg("-C")
                    .arg(&self.root)
                    .args(["ls-files", "-z"]),
            )?
            .stdout;
            let tracked: BTreeSet<_> = tracked.split(|b| *b == 0).collect();
            for p in &closure.files {
                ensure!(
                    tracked.contains(relative(p, &self.root)?.as_bytes()),
                    "ignored or untracked closure input"
                )
            }
        }
        // Build from a fresh snapshot containing the declared files. Cargo also needs
        // manifests for other workspace members and lock-only registry packages to
        // resolve the workspace, but their source code is never copied or compiled.
        let stage = self.scratch.path().join("checkout");
        let copy = |p: &Path| -> Result<()> {
            let dest = stage.join(relative(p, &self.root)?);
            fs::create_dir_all(dest.parent().unwrap())?;
            fs::write(dest, file(&self.root, p, usize::MAX - 1)?)?;
            Ok(())
        };
        for p in &closure.files {
            copy(p)?;
        }
        let meta = self.metadata(self.cfg["target"].as_str().unwrap())?;
        for pkg in meta["packages"].as_array().unwrap() {
            if !pkg["source"].is_null() {
                continue;
            }
            let path = Path::new(pkg["manifest_path"].as_str().unwrap());
            if closure.files.contains(path) {
                continue;
            }
            copy(path)?;
            for t in pkg["targets"].as_array().unwrap() {
                let src = Path::new(t["src_path"].as_str().unwrap());
                let dest = stage.join(relative(src, &self.root)?);
                fs::create_dir_all(dest.parent().unwrap())?;
                fs::write(dest, [])?;
            }
        }
        for entry in fs::read_dir(self.root.join("guest/vendor"))? {
            let dir = entry?.path();
            let manifest = dir.join("Cargo.toml");
            if !closure.files.contains(&manifest) {
                copy(&manifest)?;
                copy(&dir.join(".cargo-checksum.json"))?;
            }
        }
        copy(&self.plugin.join("manifest.json"))?;
        let staged = Builder::new(&stage.join(relative(&self.plugin, &self.root)?))?;
        let snapshot = staged.tree()?;
        ensure!(
            snapshot.digest == closure.digest,
            "source changed while taking snapshot"
        );
        staged.compile(commit, snapshot, fixtures(&self.plugin)?)
    }
    fn compile(
        &self,
        commit: String,
        closure: Closure,
        recordings: upstream_host::package::Fixtures,
    ) -> Result<Package> {
        let units = self.selected_features()?;
        let target = self.cfg["target"].as_str().unwrap();
        let mut cmd = self.cargo("build")?;
        let o = checked(cmd.args([
            "--lib",
            "--release",
            "--target",
            target,
            "--message-format=json",
        ]))?;
        let mut actual = BTreeSet::new();
        let mut core = None;
        for line in o.stdout.split(|b| *b == b'\n').filter(|b| !b.is_empty()) {
            let v: Value = serde_json::from_slice(line)?;
            if v["reason"] != "compiler-artifact" {
                continue;
            }
            let id = v["package_id"].as_str().unwrap();
            actual.insert(id.to_string());
            if let Some(pin) = closure.registry_features.get(id) {
                ensure!(pin == &v["features"], "unreviewed registry features")
            }
            let features = strings(&v["features"])?.join(",");
            ensure!(
                units.contains(&(
                    v["target"]["name"].as_str().unwrap().replace('-', "_"),
                    features.clone()
                )) || v["target"]["kind"] == json!(["custom-build"]),
                "unexplained compilation features"
            );
            if v["target"]["name"] == self.name {
                core = strings(&v["filenames"])?
                    .into_iter()
                    .find(|s| s.ends_with(".wasm"))
                    .map(PathBuf::from)
            }
        }
        ensure!(
            actual == closure.ids,
            "metadata and compiled package sets differ"
        );
        let core = core.context("missing cdylib")?;
        self.check_compiler_inputs(&core, &closure.files)?;
        // Rehash after compilation to detect edits made while the build was running.
        ensure!(
            self.tree()?.digest == closure.digest,
            "source changed during compilation"
        );
        let comp = self.scratch.path().join("plugin.wasm");
        let args = strings(&self.cfg["component_args"])?;
        ensure!(
            args == ["component", "new", "$CORE", "-o", "$COMPONENT"],
            "unexpected component build command"
        );
        checked(
            self.cmd(&self.tools)?
                .args(["component", "new"])
                .arg(core)
                .arg("-o")
                .arg(&comp),
        )?;
        checked(
            self.cmd(&self.tools)?
                .args(["validate", "--features", "component-model"])
                .arg(&comp),
        )?;
        let wit = output(self.cmd(&self.tools)?.args(["component", "wit"]).arg(&comp))?;
        let interface = self.world.trim_end_matches("-plugin");
        ensure!(
            wit.contains(&format!("export kaivo:upstream/{interface}@3.0.0;")),
            "wrong component world"
        );
        let mut m = wire::object(&file(
            &self.root,
            &self.plugin.join("manifest.json"),
            65536,
        )?)?;
        m["build"] = json!({"rust_version":self.cfg["rust_version"],"target":target,"wasm_tools_version":self.cfg["wasm_tools_version"],"source_commit":commit,"source_tree_sha256":closure.digest});
        let p = Package {
            manifest: Manifest::parse(&wire::canonical(&m))?,
            wasm: file(self.scratch.path(), &comp, 4 << 20)?,
            fixtures: recordings,
        };
        Host::new(Options::replay(&p.manifest.r#type))?.load(&p)?;
        Ok(p)
    }
}
fn walk(root: &Path, p: &Path, files: &mut BTreeSet<PathBuf>) -> Result<()> {
    safe_path(root, p)?;
    for e in fs::read_dir(p)? {
        let e = e?;
        if e.file_type()?.is_dir() {
            walk(root, &e.path(), files)?
        } else {
            files.insert(e.path());
        }
    }
    Ok(())
}
pub fn build(plugin: &Path, out: &Path) -> Result<()> {
    let b = Builder::new(plugin)?;
    let dest = entry_path(out)?;
    ensure!(
        !["guest", "crates", "scripts", "wit", ".git"]
            .iter()
            .any(|d| dest.starts_with(b.root.join(d))),
        "package output overlaps source tree"
    );
    let before = source_commit(&b.root).unwrap_or_else(|_| "uncommitted".into());
    let p = b.build(before.clone())?;
    ensure!(
        before == "uncommitted" || source_commit(&b.root)? == before,
        "checkout changed during build"
    );
    write(&p, out, &b.plugin)
}
pub fn write(p: &Package, out: &Path, src: &Path) -> Result<()> {
    let abs = entry_path(out)?;
    let out = abs.as_path();
    let src = src.canonicalize()?;
    ensure!(
        !abs.starts_with(&src) && !src.starts_with(&abs),
        "source overlaps output"
    );
    if out.exists() {
        for e in fs::read_dir(out)? {
            let e = e?;
            match e.file_name().to_str() {
                Some("manifest.json") => {
                    file(out, &e.path(), 65536)?;
                }
                Some("plugin.wasm") => {
                    file(out, &e.path(), 4 << 20)?;
                }
                Some("fixtures") => {
                    fixtures(out)?;
                }
                _ => bail!("unexpected package output entry"),
            }
        }
    }
    let parent = abs.parent().context("missing output parent")?;
    fs::create_dir_all(parent)?;
    let temp = tempfile::tempdir_in(parent)?;
    let next = temp.path().join("next");
    fs::create_dir(&next)?;
    fs::write(
        next.join("manifest.json"),
        wire::canonical(&serde_json::to_value(&p.manifest)?),
    )?;
    fs::write(next.join("plugin.wasm"), &p.wasm)?;
    for (k, b) in &p.fixtures {
        let path = next.join(k);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, b)?
    }
    let old = temp.path().join("old");
    if out.exists() {
        fs::rename(out, &old)?
    }
    if let Err(e) = fs::rename(&next, out) {
        if old.exists() {
            fs::rename(old, out)?
        }
        return Err(e.into());
    }
    println!(
        "package_sha256 {}\nfixtures_sha256 {}",
        p.hash(),
        p.fixture_hash()
    );
    Ok(())
}
pub fn verify(p: &Package, repo: &Path) -> Result<()> {
    let commit = &p.manifest.build.source_commit;
    ensure!(commit != "uncommitted", "uncommitted package");
    let repo = repo.canonicalize()?;
    source_commit(&repo)?;
    ensure!(
        git(
            &repo,
            &["rev-parse", "--verify", &format!("{commit}^{{commit}}")]
        )? == *commit,
        "unverifiable commit"
    );
    let tmp = tempdir_in(env::temp_dir().canonicalize()?)?;
    let archive = tmp.path().join("source.tar");
    let checkout = tmp.path().join("checkout");
    fs::create_dir(&checkout)?;
    checked(
        Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["archive", "--format=tar", "-o"])
            .arg(&archive)
            .arg(commit),
    )?;
    checked(
        Command::new("tar")
            .arg("-xf")
            .arg(archive)
            .arg("-C")
            .arg(&checkout),
    )?;
    let b = Builder::new(&checkout.join("guest/plugins").join(&p.manifest.code))?;
    let rebuilt = b.build(commit.clone())?;
    ensure!(
        rebuilt.wasm == p.wasm
            && serde_json::to_value(&rebuilt.manifest)? == serde_json::to_value(&p.manifest)?
            && rebuilt.hash() == p.hash()
            && rebuilt.fixtures == p.fixtures,
        "clean-commit rebuild differs"
    );
    println!("verified {}", p.hash());
    Ok(())
}
