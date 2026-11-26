import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FILES = ("aipay/upstream/v1/upstream_service.proto", "aipay/authz/v1/policy.proto")


def read_tagged_files(checkout, version):
    git = ["git", "-C", checkout]
    tag = f"refs/tags/{version}"
    if subprocess.run([*git, "show-ref", "--verify", "--quiet", tag]).returncode:
        raise SystemExit(f"cannot resolve protobuf tag {version}")
    files = {}
    for name in FILES:
        result = subprocess.run([*git, "show", f"{tag}:proto/{name}"], stdout=subprocess.PIPE)
        if result.returncode:
            raise SystemExit(f"cannot read proto/{name} from protobuf tag {version}")
        files[name] = result.stdout
    return files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("sync", "check"))
    args = parser.parse_args()
    checkout = os.environ.get("PROTOBUF_DIR")
    source_json = ROOT / "source.json"
    if args.action == "sync":
        version = os.environ.get("PROTOBUF_VERSION")
        if not checkout or not version:
            parser.error("proto-sync requires PROTOBUF_DIR and PROTOBUF_VERSION")
    else:
        recorded = json.loads(source_json.read_text())
        version = recorded.get("version") if isinstance(recorded, dict) else None
    if not isinstance(version, str) or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", version):
        parser.error("protobuf version must match vMAJOR.MINOR.PATCH")

    tagged = read_tagged_files(checkout, version) if checkout else {}
    hashes = {}
    for name in FILES:
        target = ROOT / name
        if args.action == "sync":
            data = tagged[name]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        else:
            data = target.read_bytes()
            if checkout and data != tagged[name]:
                parser.error(f"{name} differs from protobuf tag {version}")
        hashes[name] = hashlib.sha256(data).hexdigest()
    metadata = {"module": "github.com/Kaivodev/protobuf", "version": version, "files": hashes}
    if args.action == "sync":
        source_json.write_text(json.dumps(metadata, indent=2) + "\n")
    elif recorded != metadata:
        parser.error("vendored contract differs from source.json")


if __name__ == "__main__":
    main()
