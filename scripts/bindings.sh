#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
version=$(python3 -c 'import json; print(json.load(open("build-config.json"))["wit_bindgen_cli_version"])')
test "$(wit-bindgen --version)" = "wit-bindgen-cli $version"
for world in trade verification; do
    wit-bindgen rust wit --world "$world-plugin" --generate-all --pub-export-macro \
        --export-macro-name "export_generated_$world" --out-dir guest/sdk/src --format
done
