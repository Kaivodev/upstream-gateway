PLUGINS = sim_form_md5 sim_form_md5_verify
CTL = target/debug/pluginctl
RELEASE_CTL = target/release/pluginctl
VET_FLAGS ?= --locked
DENY_CHECKS ?= advisories bans licenses sources
DENY_FLAGS ?= --locked
.PHONY: fmt check bindings ctl release-ctl plugins package replay repro bench calibrate stress deny vet vendor
fmt:
	cargo fmt --all
	cd guest && cargo fmt --all
check:
	cargo fmt --all -- --check
	cd guest && cargo fmt --all -- --check
	cargo clippy --locked --workspace --all-targets -- -D warnings
	cargo test --locked --workspace
	cd guest && cargo test --locked -p kaivo-upstream-sdk --features trade
	cd guest && set -e; for p in $(PLUGINS); do cargo clippy --locked --target wasm32-unknown-unknown -p $$p -p kaivo-upstream-sdk -p sim-form-md5-protocol -- -D warnings; done
	cd guest && cargo clippy --locked --target wasm32-unknown-unknown -p abi_probe -- -D warnings
	cd guest && set -e; for w in trade verification; do cargo test --locked -p sim-form-md5-protocol --features $$w; done
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
