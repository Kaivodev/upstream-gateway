use crate::json;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};
pub const OPS: [&str; 7] = [
    "create_payment",
    "query_payment",
    "close_payment",
    "refund",
    "query_refund",
    "route_callback",
    "verify_callback",
];
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    pub r#type: String,
    pub required: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Callback {
    pub methods: Vec<String>,
    pub allow_query: bool,
    pub content_types: Vec<String>,
    pub ack_status: u16,
    pub ack_content_type: String,
    pub ack_body: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Build {
    pub rust_version: String,
    pub target: String,
    pub wasm_tools_version: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub r#type: String,
    pub code: String,
    pub version: String,
    pub abi_version: u32,
    pub domains: Vec<String>,
    pub secrets: BTreeMap<String, String>,
    pub public_keys: Vec<String>,
    pub config: BTreeMap<String, Field>,
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback: Option<Callback>,
    pub build: Build,
}
// SemVer places no fixed-width integer limit on numeric components.
fn valid_version(s: &str) -> bool {
    let numeric = |p: &str| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
    let canonical_number = |p: &str| numeric(p) && (p == "0" || !p.starts_with('0'));
    let identifiers = |s: &str, pre: bool| {
        s.split('.').all(|p| {
            !p.is_empty()
                && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && (!pre || !numeric(p) || canonical_number(p))
        })
    };
    let (version, build) = s.split_once('+').map_or((s, None), |(v, b)| (v, Some(b)));
    let (core, pre) = version
        .split_once('-')
        .map_or((version, None), |(v, p)| (v, Some(p)));
    core.split('.').count() == 3
        && core.split('.').all(canonical_number)
        && pre.is_none_or(|p| identifiers(p, true))
        && build.is_none_or(|p| identifiers(p, false))
}
pub fn domain(s: &str) -> bool {
    s.len() <= 253
        && s.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn unique(v: &[String]) -> bool {
    v.iter().collect::<BTreeSet<_>>().len() == v.len()
}
pub fn token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_\x60|~".contains(&b))
}
pub fn media(raw: &str) -> Option<String> {
    if raw.bytes().any(|b| b != 9 && (b < 32 || b == 127)) {
        return None;
    }
    let (base, mut rest) = raw.split_once(';').unwrap_or((raw, ""));
    let base = base.trim();
    let (a, b) = base.split_once('/')?;
    if !token(a) || !token(b) {
        return None;
    }
    let mut seen = BTreeSet::new();
    while !rest.trim().is_empty() {
        let (k, v) = rest.trim().split_once('=')?;
        if !token(k.trim()) || !seen.insert(k.trim().to_ascii_lowercase()) {
            return None;
        }
        let v = v.trim_start();
        if let Some(q) = v.strip_prefix('"') {
            let mut escaped = false;
            let end = q
                .char_indices()
                .find(|(_, c)| {
                    if escaped {
                        escaped = false;
                        false
                    } else if *c == '\\' {
                        escaped = true;
                        false
                    } else {
                        *c == '"'
                    }
                })?
                .0;
            let tail = q[end + 1..].trim_start();
            rest = if tail.is_empty() {
                ""
            } else {
                tail.strip_prefix(';')?
            };
        } else {
            let (value, tail) = v.split_once(';').unwrap_or((v, ""));
            if !token(value.trim()) {
                return None;
            }
            rest = tail
        }
    }
    Some(base.to_ascii_lowercase())
}
pub fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        write!(s, "{x:02x}").unwrap()
    }
    s
}
fn lower_hex(v: &str) -> bool {
    v.bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
}
impl Manifest {
    pub fn parse(b: &[u8]) -> Result<Self> {
        ensure!(b.len() <= 65536, "manifest size limit");
        let v = json::object(b)?;
        ensure!(
            v.get("callback").is_none_or(|c| c.is_object()),
            "invalid callback"
        );
        let m: Self = serde_json::from_value(v)?;
        m.validate()?;
        Ok(m)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.r#type.as_str(), "payment" | "verification") && self.abi_version == 3,
            "invalid plugin type/ABI"
        );
        ensure!(
            (2..=32).contains(&self.code.len())
                && self
                    .code
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "invalid code"
        );
        ensure!(valid_version(&self.version), "invalid semantic version");
        ensure!(
            (1..=32).contains(&self.domains.len())
                && unique(&self.domains)
                && self.domains.iter().all(|d| domain(d)),
            "invalid domains"
        );
        let ops = &self.capabilities;
        let has = |s: &str| ops.iter().any(|v| v == s);
        ensure!(
            !ops.is_empty() && unique(ops) && ops.iter().all(|x| OPS.contains(&x.as_str())),
            "invalid capabilities"
        );
        ensure!(
            self.r#type != "verification"
                || (ops.len() == 2 && has("query_payment") && has("query_refund")),
            "invalid verification capabilities"
        );
        ensure!(
            !has("verify_callback") || has("route_callback"),
            "callback requires routing"
        );
        ensure!(
            self.callback.is_some() == has("route_callback"),
            "callback rules mismatch"
        );
        if let Some(c) = &self.callback {
            ensure!(
                !c.methods.is_empty()
                    && unique(&c.methods)
                    && c.methods.iter().all(|x| matches!(
                        x.as_str(),
                        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
                    )),
                "invalid callback methods"
            );
            ensure!(
                !c.content_types.is_empty()
                    && c.content_types.iter().all(|s| media(s).as_ref() == Some(s))
                    && media(&c.ack_content_type).is_some()
                    && (200..300).contains(&c.ack_status)
                    && (1..=1024).contains(&c.ack_body.len()),
                "invalid callback rules"
            );
        }
        ensure!(
            self.secrets.len() <= 32 && self.public_keys.len() <= 32 && self.config.len() <= 64,
            "too many fields"
        );
        let mut names = BTreeSet::new();
        for n in self
            .config
            .keys()
            .chain(self.secrets.keys())
            .chain(&self.public_keys)
        {
            ensure!(
                (1..=64).contains(&n.len())
                    && n.as_bytes()[0].is_ascii_lowercase()
                    && n.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    && names.insert(n),
                "invalid credential/config name"
            )
        }
        ensure!(
            self.secrets
                .values()
                .all(|s| matches!(s.as_str(), "shared" | "rsa-private"))
                && self.config.values().all(|f| f.r#type == "string"),
            "invalid field definition"
        );
        let b = &self.build;
        ensure!(
            b.rust_version == "1.99.1"
                && b.wasm_tools_version == "1.263.0"
                && b.target == "wasm32-unknown-unknown"
                && b.source_tree_sha256.len() == 64
                && lower_hex(&b.source_tree_sha256)
                && (b.source_commit == "uncommitted"
                    || matches!(b.source_commit.len(), 40 | 64) && lower_hex(&b.source_commit)),
            "invalid build provenance"
        );
        Ok(())
    }
}
/// Resolve an externally supplied entry relative to its trusted parent. Existing
/// ancestors of the parent can be OS aliases. The entry itself cannot be a link.
pub fn entry_path(path: &Path) -> Result<PathBuf> {
    ensure!(
        !path.as_os_str().is_empty() && !path.components().any(|c| c == Component::ParentDir),
        "invalid entry path"
    );
    let absolute = std::path::absolute(path)?;
    let parent = absolute.parent().context("missing entry parent")?;
    // Outputs may introduce subdirectories. Resolve the nearest existing parent
    // before comparing overlapping paths or creating any directories.
    let mut existing = parent;
    loop {
        match fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                existing = existing.parent().context("missing directory ancestor")?
            }
            Err(e) => return Err(e.into()),
        }
    }
    let root = existing.canonicalize()?;
    let entry = root.join(absolute.strip_prefix(existing)?);
    safe_path(&root, &entry)?;
    Ok(entry)
}

/// Both paths are anchored at the same previously resolved root. Inspect only
/// its descendants, preserving the distinction between a link and its target.
pub fn safe_path(root: &Path, p: &Path) -> Result<()> {
    let rel = p.strip_prefix(root).context("path outside trusted root")?;
    ensure!(
        rel.components().all(|c| matches!(c, Component::Normal(_))),
        "invalid relative path"
    );
    let mut path = root.to_path_buf();
    for part in rel.components() {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(m) => ensure!(!m.is_symlink(), "symbolic link"),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
pub fn file(root: &Path, p: &Path, max: usize) -> Result<Vec<u8>> {
    safe_path(root, p)?;
    let m = fs::symlink_metadata(p)?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.len() <= max as u64,
        "unsafe file or size"
    );
    let mut b = Vec::new();
    let opened = fs::File::open(p)?;
    let actual = opened.metadata()?;
    ensure!(
        actual.is_file()
            && actual.dev() == m.dev()
            && actual.ino() == m.ino()
            && actual.nlink() == 1,
        "file changed during open"
    );
    opened.take(max as u64 + 1).read_to_end(&mut b)?;
    ensure!(b.len() <= max, "file size limit");
    Ok(b)
}
pub type Fixtures = BTreeMap<String, Vec<u8>>;
pub fn fixtures(root: &Path) -> Result<Fixtures> {
    read_fixtures(&entry_path(root)?)
}
fn read_fixtures(root: &Path) -> Result<Fixtures> {
    fn walk(root: &Path, d: &Path, out: &mut Fixtures, total: &mut usize) -> Result<()> {
        safe_path(root, d)?;
        for e in fs::read_dir(d)? {
            let e = e?;
            let p = e.path();
            let rel = p
                .strip_prefix(root)?
                .to_str()
                .context("invalid UTF-8 path")?;
            ensure!(!rel.contains(['\\', ':']), "invalid fixture path");
            if e.file_type()?.is_dir() {
                walk(root, &p, out, total)?
            } else {
                ensure!(
                    rel.ends_with(".json") && out.len() < 256,
                    "invalid fixture name/count"
                );
                let b = file(root, &p, 1 << 20)?;
                *total += b.len();
                ensure!(*total <= 3 << 20, "fixture size limit");
                out.insert(rel.to_owned(), b);
            }
        }
        Ok(())
    }
    let mut out = Fixtures::new();
    walk(root, &root.join("fixtures"), &mut out, &mut 0)?;
    ensure!(!out.is_empty(), "empty fixture set");
    Ok(out)
}
pub struct Package {
    pub manifest: Manifest,
    pub wasm: Vec<u8>,
    pub fixtures: Fixtures,
}
impl Package {
    pub fn validate_fixtures(&self) -> Result<()> {
        ensure!(
            (1..=256).contains(&self.fixtures.len()),
            "invalid fixture count"
        );
        let mut total = 0;
        for (k, b) in &self.fixtures {
            ensure!(
                k.starts_with("fixtures/")
                    && k.ends_with(".json")
                    && !k.contains(['\\', ':'])
                    && k.split('/').all(|s| !matches!(s, "" | "." | "..")),
                "invalid fixture path"
            );
            total += b.len();
            ensure!(b.len() <= 1 << 20 && total <= 3 << 20, "fixture size limit")
        }
        Ok(())
    }
    pub fn read(dir: &Path) -> Result<Self> {
        let dir = entry_path(dir)?;
        for entry in fs::read_dir(&dir)? {
            ensure!(
                matches!(
                    entry?.file_name().to_str(),
                    Some("plugin.wasm" | "manifest.json" | "fixtures")
                ),
                "unexpected package entry"
            )
        }
        let raw = file(&dir, &dir.join("manifest.json"), 65536)?;
        let manifest = Manifest::parse(&raw)?;
        ensure!(
            raw == json::canonical(&serde_json::to_value(&manifest)?),
            "packaged manifest must be canonical"
        );
        let wasm = file(&dir, &dir.join("plugin.wasm"), 4 << 20)?;
        ensure!(!wasm.is_empty(), "empty component");
        Ok(Self {
            manifest,
            wasm,
            fixtures: read_fixtures(&dir)?,
        })
    }
    pub fn hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(json::canonical(
            &serde_json::to_value(&self.manifest).unwrap(),
        ));
        h.update(&self.wasm);
        hex(&h.finalize())
    }
    pub fn fixture_hash(&self) -> String {
        let mut h = Sha256::new();
        let mut lp = |b: &[u8]| {
            h.update((b.len() as u32).to_be_bytes());
            h.update(b)
        };
        lp(b"aipay.plugin.fixtures.v1");
        for (p, b) in &self.fixtures {
            lp(p.as_bytes());
            lp(b)
        }
        hex(&h.finalize())
    }
}
