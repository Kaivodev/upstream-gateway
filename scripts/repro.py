"""Build the same source snapshot in two independent paths and compare packages."""
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
ctl = root / "target/debug/pluginctl"
plugins = ("sim_form_md5", "sim_form_md5_verify")
clean = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=root,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
clean = clean and not subprocess.check_output(["git", "status", "--porcelain"], cwd=root)

def generated(directory, entries):
    p = Path(directory)
    omitted = {".local", ".git", "dist", "target"} if p == root else {"target"} if p == root / "guest" else set()
    return omitted.intersection(entries)


with tempfile.TemporaryDirectory() as scratch:
    outputs = []
    for name in ("first", "different-source-directory"):
        checkout = Path(scratch) / name
        if clean:
            subprocess.run(["git", "init", "-q", checkout], check=True)
            # --depth 1: the rebuild needs only the snapshot, and a shallow source
            # (actions/checkout defaults to depth 1) rejects a full-history fetch.
            subprocess.run(["git", "fetch", "-q", "--depth", "1", str(root), "HEAD"], cwd=checkout, check=True)
            subprocess.run(["git", "reset", "-q", "--hard", "FETCH_HEAD"], cwd=checkout, check=True)
        else:
            # A development snapshot has no commit identity, including in copied directories.
            shutil.copytree(root, checkout, symlinks=True, ignore=generated)
        packages = {}
        for plugin in plugins:
            out = checkout / "dist" / plugin
            subprocess.run([ctl, "build", "--plugin", checkout / "guest/plugins" / plugin,
                            "--out", out], cwd=checkout, check=True)
            packages[plugin] = {str(p.relative_to(out)): p.read_bytes()
                                for p in out.rglob("*") if p.is_file()}
        outputs.append(packages)
    if outputs[0] != outputs[1]:
        raise SystemExit("two-path rebuild differs")
print("Both packages reproduced byte for byte")
