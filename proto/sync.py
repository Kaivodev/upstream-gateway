import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FILES = ("aipay/upstream/v1/upstream_service.proto", "aipay/authz/v1/policy.proto")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("sync", "check"))
    args = parser.parse_args()
    checkout = os.environ.get("PROTOBUF_DIR")
    if args.action == "sync" and not checkout:
        parser.error("proto-sync requires PROTOBUF_DIR")
    hashes = {}
    for name in FILES:
        target = ROOT / name
        if checkout:
            source = (Path(checkout) / "proto" / name).read_bytes()
            if args.action == "sync":
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source)
            elif source != target.read_bytes():
                parser.error(f"{name} differs from source checkout")
        hashes[name] = hashlib.sha256(target.read_bytes()).hexdigest()
    metadata = {"module": "github.com/Kaivodev/protobuf", "version": "unpublished", "files": hashes}
    source_json = ROOT / "source.json"
    if args.action == "sync":
        source_json.write_text(json.dumps(metadata, indent=2) + "\n")
    elif json.loads(source_json.read_text()) != metadata:
        parser.error("vendored contract differs from source.json")


if __name__ == "__main__":
    main()
