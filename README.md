# Kaivo upstream gateway pilot

The Rust host executes ABI v3 payment and verification components in fresh Wasmtime instances. The form/MD5 and JSON/RSA simulators use separate worlds and credentials. The EPay V1 payment plugin creates payments through `mapi.php`, queries orders with `api.php?act=order`, and routes and verifies GET notifications. The `epay_v1_verify` plugin exposes only order queries. With owner approval under A136 ③, the verification instance can separately seal the same merchant key as the trading instance. This release excludes refunds. EPay V1 has no refund-query or close-payment interface. Creating an EPay payment requires a canonical buyer IP and accepts an optional device type. The pilot runs offline recordings and has no default network transport.

Install the Rust toolchain in `rust-toolchain.toml`, wasm-tools 1.263.0 and wit-bindgen-cli 0.63.0. The builder also uses Python 3.14.7, Git and tar. Run `cargo fetch --locked` for the host. Guest sources and generated bindings are included. Run `make check plugins replay repro` to test, package, replay and compare two independent builds. Reports are under `dist/reports/`. Run `make bench calibrate stress` for measurements and `make deny vet` for admission checks.

To record EPay V1 fixtures, start upstream-sim in its test environment and export its control token as `UPSTREAM_SIM_CONTROL_TOKEN` (at least 16 bytes). Run `target/debug/pluginctl record --plugin guest/plugins/epay_v1 --sim http://127.0.0.1:9080 --out TRADE_FIXTURES` with the simulator's actual loopback port. Repeat with `guest/plugins/epay_v1_verify` and a separate output directory. Each directory must be empty or new. The recorder captures four creates, six queries and five callback cases for trading, and six queries with the verification host. Query cases cover paid, missing order, invalid key, transport timeout, amount mismatch and timeout-inferred closure. Both plugins require `unpaid_timeout_seconds` as a decimal string from 1 to 2592000. Each component HTTP exchange has a two-second deadline and can reach only the selected simulator socket. Before publishing, the recorder scans the fixtures for credentials and signatures and replays them with fresh keys. The recorded query URL retains the merchant key placeholder. After installing both fixture sets, run `make check plugins replay repro deny vet` and `make bench calibrate stress`.

To refresh the vendored contract, set `PROTOBUF_DIR` to a protobuf checkout and run `PROTOBUF_VERSION=v0.18.0 make proto-sync`. Run `make proto-check` to verify the digests in `proto/source.json`. With `PROTOBUF_DIR` set, it also compares both files with the recorded tag.

Use `target/debug/pluginctl verify --dir PACKAGE --repo CHECKOUT` to verify a committed package. Host callers provide a role, credentials and a deadline-aware transport. See [PILOT_NOTES.md](PILOT_NOTES.md) for measured limits, audit status and remaining work.

## Gateway service

Run one gateway instance per role. Give each instance its own database or PostgreSQL schema, KEK, service certificate and outbound network policy. The gateway returns protocol facts, dispatch counts and encrypted exchange evidence. Payment and reconciliation own approval, settlement and order state.

| Role | Local SPIFFE service name | Sole client | Business RPCs | Package world |
| --- | --- | --- | --- | --- |
| `trade` | `upstream-gateway-trade` | `payment` | CreatePayment, QueryPayment, ClosePayment, Refund, QueryRefund, RouteCallback, VerifyCallback | `payment` |
| `verification` | `upstream-gateway-verification` | `reconciliation` | QueryPayment, QueryRefund | `verification` |

Both roles expose ReplayPackage, RegisterPackage, RevokePackage, StoreCredentials and GetExchange. Use TLS 1.3 and HTTP/2. The listener requires a trusted client chain and exactly one URI SAN of the form `spiffe://<trust_domain>/service/<name>`. The server certificate must identify its configured role and support server authentication. Clients should verify the server chain, hostname and expected service URI. The gateway rejects any `x-aipay-assertion` with Unauthenticated. Missing method policy or a caller outside its descriptor rules returns PermissionDenied. The server validates raw protobuf messages recursively before typed decoding, with a 16 MiB limit in both directions. The service then enforces its role, package world and object ownership.

### Development configuration

Copy [the TOML example](config/development.example.toml) and replace its file references. Relative paths resolve against the configuration file's directory. Set the environment variable named by `database_url_env` to a PostgreSQL connection string for this instance. The database principal must be able to migrate its schema. The database adapter currently uses a private, trusted connection without database TLS. Supply a randomly generated, persistent 32-byte KEK file with owner-only read or read/write permissions. Keep the KEK available across restarts.

| Setting | Meaning |
| --- | --- |
| `role`, `allowed_peers` | Required role and its one-element client allowlist from the table above. |
| `mode`, `listen` | Use `development` and an explicit IP socket address. Production requires a production KMS adapter, which is pending. |
| `tls.trust_domain`, `tls.ca_file`, `tls.cert_file`, `tls.key_file` | SPIFFE trust domain, PEM trust bundle, server leaf followed by intermediates, and matching PEM private key. |
| `database_url_env`, `local_kek_file` | Name of the environment variable containing the DSN, and development KEK path. |
| `allow_loopback_http`, `allow_uncommitted` | Explicit development exceptions for cleartext HTTP and loopback egress, and packages built from uncommitted sources. Both default to false. Production rejects enabled exceptions and the local KMS. |
| `egress_ca_file`, `egress_proxy` | Optional outbound PEM trust bundle and CONNECT proxy socket address. The default uses Mozilla roots and direct connections. |
| `timing.heartbeat_ms`, `timing.fence_ms` | Defaults of 3,000 and 30,000 ms. Heartbeats accept 50–60,000 ms. The fence threshold must be at least three heartbeats and at most 600,000 ms. |

For verification, set `role = "verification"` and `allowed_peers = ["reconciliation"]`. Use its verification certificate, independent storage, KEK and listener address. Start either instance with the same command.

```sh
cargo build --locked --release -p upstream-gateway
target/release/upstream-gateway --config path/to/instance.toml
```

Startup validates configuration and TLS identity, applies migrations, registers an executor, starts maintenance, and loads registered components before binding the listener. TLS files are reread every 30 seconds. A changed bundle must validate as a whole and preserve its authentication usages before new handshakes adopt it. Established connections keep their original peer identity.

SIGTERM closes admission and allows up to 75 seconds for active RPCs and detached journal workers to finish. Once the executor requires restart, new requests receive Unavailable while the listener drains, and the process exits unsuccessfully. Run under a supervisor that starts a new process identity on failure. The new executor seals a previously dispatched, interrupted operation as UNKNOWN with `dispatch_interrupted`. An operation without a dispatch marker can execute when its owner retries the original key.

StoreCredentials returns an immutable reference and a digest. RegisterPackage requires the approved digests computed by replay. GetExchange returns authenticated evidence to the original caller. Callback screening fingerprints all stored credential values, including registered public keys. A callback reflecting one of these values can therefore produce `secret_leak` and quarantined evidence. The caller still receives the exchange ID and digest.

Run `make integration` with `AIPAY_TEST_DATABASE_URL` in the environment for PostgreSQL-backed service tests and real-process mTLS acceptance. The tests use disposable schemas, generated certificates and keys, and loopback HTTP simulators.
