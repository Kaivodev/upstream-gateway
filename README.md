# Kaivo upstream gateway pilot

The Rust host executes ABI v3 payment and verification components in fresh Wasmtime instances. The two form/MD5 simulators use separate worlds and credentials. The pilot runs offline recordings and has no default network transport.

Install the Rust toolchain in `rust-toolchain.toml`, wasm-tools 1.263.0 and wit-bindgen-cli 0.63.0. The builder also uses Python 3.11+, Git and tar. Run `cargo fetch --locked` for the host. Guest sources and generated bindings are included. Run `make check plugins replay repro` to test, package, replay and compare two independent builds. Reports are under `dist/reports/`. Run `make bench calibrate stress` for measurements and `make deny vet` for admission checks.

Use `target/debug/pluginctl verify --dir PACKAGE --repo CHECKOUT` to verify a committed package. Host callers provide a role, credentials and a deadline-aware transport. See [PILOT_NOTES.md](PILOT_NOTES.md) for measured limits, audit status and remaining work.
