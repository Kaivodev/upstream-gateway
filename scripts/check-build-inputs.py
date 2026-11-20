"""Validate the reviewed Cargo configuration before running Cargo or build scripts."""
import json
import sys
import tomllib
from pathlib import Path

root, plugin = map(Path, sys.argv[1:])
guest = root / "guest"

def read(path):
    if (not path.is_relative_to(root) or path.resolve(strict=True) != path
            or not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError("unsafe build configuration file")
    return tomllib.loads(path.read_text(encoding="utf-8"))

def require(condition, message):
    if not condition:
        raise ValueError(message)

cfg = json.loads((root / "build-config.json").read_bytes())
vendor = {"source": {"crates-io": {"replace-with": "vendored-sources"},
                     "vendored-sources": {"directory": "vendor"}}}
require(read(guest / ".cargo/config.toml") == vendor, "unexpected guest Cargo configuration")
for directory in [plugin, *plugin.parents]:
    for name in ("config", "config.toml"):
        p = directory / ".cargo" / name
        if p != guest / ".cargo/config.toml":
            require(not p.exists() and not p.is_symlink(), "ambient Cargo configuration")
ws = read(guest / "Cargo.toml")
require(ws.get("profile") == {"release": cfg["profile"]}, "unexpected release profile")
pin = read(root / "rust-toolchain.toml")["toolchain"]
require(pin["channel"] == cfg["rust_version"] and pin["targets"] == [cfg["target"]],
        "toolchain configuration mismatch")
for manifest in [guest / "Cargo.toml", *(p for pattern in ws["workspace"]["members"]
                                          for d in guest.glob(pattern) for p in [d / "Cargo.toml"])]:
    require(manifest.resolve() == manifest and manifest.is_relative_to(guest),
            "workspace member outside guest tree")
    m = read(manifest)
    require("patch" not in m and "replace" not in m, "unreviewed source override")
