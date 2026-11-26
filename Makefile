PLUGINS = sim_form_md5 sim_form_md5_verify sim_json_rsa sim_json_rsa_verify epay_v1
PROTOCOLS = sim-form-md5-protocol sim-json-rsa-protocol
CTL = target/debug/pluginctl
RELEASE_CTL = target/release/pluginctl
VET_FLAGS ?= --locked
DENY_CHECKS ?= advisories bans licenses sources
DENY_FLAGS ?= --locked
.PHONY: fmt check bindings ctl release-ctl plugins package replay repro bench calibrate stress deny vet vendor
fmt:
	cargo fmt --all
	cd guest && cargo fmt --all
check: proto-check
	cargo fmt --all -- --check
	cd guest && cargo fmt --all -- --check
	cargo clippy --locked --workspace --all-targets -- -D warnings
	cargo test --locked --workspace
	cd guest && cargo test --locked -p kaivo-upstream-sdk --features trade
	cd guest && cargo test --locked -p epay_v1
	cd guest && set -e; for p in $(PLUGINS); do cargo clippy --locked --target wasm32-unknown-unknown -p $$p -p kaivo-upstream-sdk -- -D warnings; done
	cd guest && cargo clippy --locked --target wasm32-unknown-unknown -p abi_probe -- -D warnings
	cd guest && set -e; for p in $(PROTOCOLS); do for w in trade verification; do cargo clippy --locked --target wasm32-unknown-unknown -p $$p --features $$w -- -D warnings; cargo test --locked -p $$p --features $$w; done; done
bindings:
	sh scripts/bindings.sh
ctl:
	cargo build --locked -p pluginctl
release-ctl:
	cargo build --release --locked -p pluginctl
plugins: ctl
	@set -e; for p in $(PLUGINS); do $(CTL) build --plugin guest/plugins/$$p --out dist/build/$$p; done
package: plugins
	@set -e; for p in $(PLUGINS); do $(CTL) package --dir dist/build/$$p --out dist/packages/$$p; done
replay: package
	@mkdir -p dist/reports
	@set -e; for p in $(PLUGINS); do $(CTL) replay --dir dist/packages/$$p --out dist/reports/$$p.json; done
repro: ctl
	python3 scripts/repro.py
bench calibrate stress: package release-ctl
	@set -e; for p in $(PLUGINS); do $(RELEASE_CTL) $@ --dir dist/packages/$$p; done
deny:
	cargo deny $(DENY_FLAGS) check $(DENY_CHECKS)
	cd guest && cargo deny $(DENY_FLAGS) check $(DENY_CHECKS)
vet:
	cd guest && cargo vet $(VET_FLAGS)
vendor:
	cd guest && cargo vendor --locked --versioned-dirs vendor

.PHONY: proto-sync proto-check integration
export PROTOBUF_DIR PROTOBUF_VERSION
proto-sync:
	python3 proto/sync.py sync
proto-check:
	python3 proto/sync.py check
.PHONY: integration-env
integration-env:
	@test -n "$$AIPAY_TEST_DATABASE_URL" || { echo "integration requires AIPAY_TEST_DATABASE_URL" >&2; exit 1; }
integration: integration-env package
	cargo test --locked -p upstream-gateway --lib -- --ignored --test-threads=2
	cargo test --release --locked -p upstream-gateway --test edge -- --ignored --nocapture --test-threads=2
