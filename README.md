# Kaivo upstream gateway pilot

The Rust host executes ABI v3 payment and verification components in fresh Wasmtime instances. The form/MD5 and JSON/RSA simulators use separate worlds and credentials. The EPay V1 payment plugin creates payments through `mapi.php`, queries orders with `api.php?act=order`, and routes and verifies GET notifications. The `epay_v1_verify` plugin exposes only order queries. With owner approval under A136 ③, the verification instance can separately seal the same merchant key as the trading instance. This release excludes refunds. EPay V1 has no refund-query or close-payment interface. Creating an EPay payment requires a canonical buyer IP and accepts an optional device type. The pilot runs offline recordings and has no default network transport.

Install the Rust toolchain in `rust-toolchain.toml`, wasm-tools 1.263.0 and wit-bindgen-cli 0.63.0. The builder also uses Python 3.14.7, Git and tar. Run `cargo fetch --locked` for the host. Guest sources and generated bindings are included. Run `make check plugins replay repro` to test, package, replay and compare two independent builds. Reports are under `dist/reports/`. Run `make bench calibrate stress` for measurements and `make deny vet` for admission checks.

To record EPay V1 fixtures, start upstream-sim in its test environment and export its control token as `UPSTREAM_SIM_CONTROL_TOKEN` (at least 16 bytes). Run `target/debug/pluginctl record --plugin guest/plugins/epay_v1 --sim http://127.0.0.1:9080 --out TRADE_FIXTURES` with the simulator's actual loopback port. Repeat with `guest/plugins/epay_v1_verify` and a separate output directory. Each directory must be empty or new. The recorder captures four creates, six queries and five callback cases for trading, and six queries with the verification host. Query cases cover paid, missing order, invalid key, transport timeout, amount mismatch and timeout-inferred closure. Both plugins require `unpaid_timeout_seconds` as a decimal string from 1 to 2592000. Each component HTTP exchange has a two-second deadline and can reach only the selected simulator socket. Before publishing, the recorder scans the fixtures for credentials and signatures and replays them with fresh keys. The recorded query URL retains the merchant key placeholder. After installing both fixture sets, run `make check plugins replay repro deny vet` and `make bench calibrate stress`.

To refresh the vendored contract, set `PROTOBUF_DIR` to a protobuf checkout and run `PROTOBUF_VERSION=v0.18.0 make proto-sync`. Run `make proto-check` to verify the digests in `proto/source.json`. With `PROTOBUF_DIR` set, it also compares both files with the recorded tag.

Use `target/debug/pluginctl verify --dir PACKAGE --repo CHECKOUT` to verify a committed package. Host callers provide a role, credentials and a deadline-aware transport. See [PILOT_NOTES.md](PILOT_NOTES.md) for measured limits, audit status and remaining work.

## Gateway service

Run one gateway instance per role. Give each instance its own database or PostgreSQL schema, KEK, service identity and outbound network policy. The gateway returns protocol facts, dispatch counts and encrypted exchange evidence. On QueryPayment, a REJECTED result with upstream code `not_found` means the upstream explicitly reported that the order does not exist. Payment and reconciliation own approval, settlement and order state.

| Role | Service name | Sole client | Business RPCs | Package world |
| --- | --- | --- | --- | --- |
| `trade` | `upstream-gateway-trade` | `payment` | CreatePayment, QueryPayment, ClosePayment, Refund, QueryRefund, RouteCallback, VerifyCallback | `payment` |
| `verification` | `upstream-gateway-verification` | `reconciliation` | QueryPayment, QueryRefund | `verification` |

Both roles expose ReplayPackage, RegisterPackage, RevokePackage, StoreCredentials and GetExchange. The default mTLS transport uses TLS 1.3 and HTTP/2. Its listener requires a trusted client chain and exactly one URI SAN of the form `spiffe://<trust_domain>/service/<name>`. The server certificate must identify its configured role and support server authentication. Clients should verify the server chain, hostname and expected service URI. The gateway rejects any `x-aipay-assertion` with Unauthenticated. Missing method policy or a caller outside its descriptor rules returns PermissionDenied. The server validates raw protobuf messages recursively before typed decoding, with a 16 MiB limit in both directions. The service then enforces its role, package world and object ownership.

### Gateway configuration

Choose the [mTLS example](config/development.example.toml) or the [Kubernetes plaintext example](config/kubernetes.example.toml) and supply the referenced files. Relative paths resolve against the configuration file's directory. Set the environment variable named by `database_url_env` to a PostgreSQL connection string for this instance. The database principal must be able to migrate its schema.

| Setting or command | Meaning |
| --- | --- |
| `role`, `allowed_peers` | Required role and its one-element client allowlist from the table above. |
| `mode`, `listen` | Select `development` or `production` and an explicit IP socket address. Development requires exactly one of `local_kek_file` and `[kms]`. Production requires `[kms]`. |
| `transport` | Defaults to `mtls` and requires `[tls]`. Kubernetes uses `plaintext` for HTTP/2 prior knowledge (h2c) with `[service_token]`. Configuring both identity mechanisms fails startup. |
| `service_token.jwks_file` | Required in plaintext mode. Mount the issuer's public JWKS. The gateway rereads it every 30 seconds. Failed reloads retain the last valid set. An invalid initial set prevents startup. |
| `service_token.issuer`, `service_token.issuer_file` | Set exactly one in plaintext mode. Supply the exact issuer inline or point to the ConfigMap's `issuer` file. Startup reads the regular file once, accepts up to 1 KiB of UTF-8, trims surrounding ASCII whitespace, and requires a nonempty issuer without internal whitespace. Restart the gateway after an issuer change. |
| `service_token.service_namespaces` | Map ServiceAccount names to namespaces, including this role's sole caller. Clients send one projected token in `x-kaivo-service-token` with audience `kaivo:upstream-gateway-trade` or `kaivo:upstream-gateway-verification`. Use a 600-second projection. The gateway strips the header before dispatch. |
| gRPC health probe | Use `grpc.health.v1.Health/Check` or `Watch` with the empty service name and the configured listener port. The gateway reports SERVING after initialization and NOT_SERVING on drain or executor retirement. Probes bypass token and method authorization. The mTLS listener still requires the role's client certificate. |
| `tls.trust_domain`, `tls.ca_file`, `tls.cert_file`, `tls.key_file` | SPIFFE trust domain, PEM trust bundle, server leaf followed by intermediates, and matching PEM private key. |
| `database_url_env`, `database_ca_file` | Name of the environment variable containing the DSN and optional path to the PostgreSQL CA bundle in PEM format. Production requires the bundle. |
| `database_max_connections` | Size of the shared connection pool for requests, journal workers and maintenance. Defaults to 16 and accepts 4–64. Lower it for managed databases with small connection limits. |
| `local_kek_file` | Optional development-only path to a persistent 32-byte KEK with owner-only read or read/write permissions. |
| `kms.key` | Unversioned Cloud KMS symmetric CryptoKey resource, for example `projects/kaivokms/locations/asia-southeast1/keyRings/test-business/cryptoKeys/upstream-gateway-trade-kek`. |
| `kms.wrapped_key_file` | Path to the role's `kaivo.sealing.v1` JSON file. Mount it from a ConfigMap. Startup requires one current key with purpose `sealing`. |
| `kms.credentials_file` | GCP `external_account` JSON with an absolute file source for a projected Kubernetes JWT and a service account impersonation URL. The source format defaults to `text`. |
| `wrap-kek --config <path> [--version <n>]` | Generate and round-trip verify a fresh KEK. Writes the compact wrapped key file to stdout. The default version is 1. |
| `kms.egress_proxy` | Optional trusted `host:port` CONNECT proxy for the Google APIs. DNS names, IPv4 and bracketed IPv6 addresses are supported. |
| `allow_loopback_http`, `allow_private_http` | Development switches, both default false. The first permits direct loopback connections. The second permits RFC 1918 IPv4 and unique-local IPv6 destinations, including the staging simulator. Either switch enables HTTP and declared HTTP secret fields. Direct cleartext connections require an enabled destination range. Other reserved addresses remain blocked. |
| `allow_uncommitted` | Permits development packages built from uncommitted sources. Defaults to false. Production rejects enabled development switches and the local KMS. |
| `egress_ca_file`, `egress_proxy` | Optional plugin HTTPS trust bundle and trusted plugin CONNECT proxy in `host:port` form. Both proxy settings accept Kubernetes Service DNS names, IPv4 and bracketed IPv6. The gateway resolves the proxy at connection time and permits private proxy addresses. With a proxy, the gateway sends `CONNECT <URL hostname>:<explicit or default port>`. The proxy owns DNS resolution, host allowlisting and destination address policy. TLS still verifies the URL hostname. Direct connections use local DNS and check every returned address before connecting. The default trust store uses Mozilla roots. |
| `timing.heartbeat_ms`, `timing.fence_ms` | Defaults of 3,000 and 30,000 ms. Heartbeats accept 50–60,000 ms. The fence threshold must be at least three heartbeats and at most 600,000 ms. |

For verification, set `role = "verification"` and `allowed_peers = ["reconciliation"]`. Give it independent storage, a KEK and a listener address. Configure its verification certificate for mTLS or map the reconciliation ServiceAccount to its namespace for plaintext. Start either instance with the same command.

```sh
cargo build --locked --release -p upstream-gateway
target/release/upstream-gateway --config path/to/instance.toml
```

### PostgreSQL TLS

Set `sslmode` in the database URL. For a managed database, mount the provider CA bundle, set the top-level `database_ca_file` to its path, and use `?sslmode=require`. For CloudNativePG, mount the cluster's server CA and connect using a Service DNS name covered by its certificate.

| Database CA file | URL `sslmode` | Development | Production |
| --- | --- | --- | --- |
| Set | `require` | Verify chain and host | Verify chain and host |
| Set | Absent, `prefer`, or `disable` | Startup error | Startup error |
| Omitted | `require` | TLS without certificate verification | Startup error |
| Omitted | Absent, `prefer`, or `disable` | Plaintext | Startup error |

Database TLS requires a single TCP host and uses TLS 1.2 or 1.3. With a CA file, the gateway trusts only that bundle and verifies the URL host against the certificate's DNS or IP subject alternative names (libpq `verify-full` semantics). The gateway loads the bundle at startup. The connector reports no PostgreSQL channel binding.

### Container image

Build from the repository root with BuildKit.

```sh
docker build -t upstream-gateway:0.7.0 .
```

The builder installs wasm-tools 1.263.0, fetches the locked host dependencies, and compiles the release binary with network access disabled. The shared deploy workflow may supply the `COMMIT` build argument and the optional `aipay_modules_token` secret. Neither is used.

The image runs `/app/upstream-gateway --config /run/kaivo/inputs/gateway.toml` as UID and GID 65532. Mount the configuration and referenced files read-only with permissions that allow this user to read them. Supply the database URL through the configured environment variable. A read-only root filesystem requires no writable volume. Wasmtime compiles components in memory and its disk cache is disabled. Persistent gateway state lives in PostgreSQL.

### Provisioning and loading a wrapped KEK

Run the following command once for a new role and database. The provisioning identity needs permission to encrypt and decrypt with the configured CryptoKey. The running service needs decrypt permission. Both identities use workload identity federation with service account impersonation.

```sh
target/release/upstream-gateway wrap-kek --config path/to/instance.toml --version 1 > kek.json
```

The version defaults to 1. The command reads the role and KMS access settings, generates a random 32-byte KEK in memory, encrypts it with role, purpose and version as AAD, and decrypts it to verify the result before writing the wrapped JSON to stdout. Ship the resulting file at `kms.wrapped_key_file` and retain it across restarts.

Allow HTTPS to `sts.googleapis.com`, `iamcredentials.googleapis.com` and `cloudkms.googleapis.com` on port 443 at startup and during provisioning. With `kms.egress_proxy`, the proxy receives `CONNECT <Google hostname>:443`. TLS validates the Google hostname against Mozilla roots. Startup exchanges the projected token, impersonates the configured service account, and unwraps the KEK once. Record encryption and decryption then use the in-memory KEK.

Cloud KMS primary key-version rotation requires no file change. Keep the KMS version that produced the ciphertext enabled for decryption. Replacing the gateway KEK itself requires a versioned sealed-record format and migration first. Existing records have no KEK version, so startup rejects multi-key files. Generating a fresh KEK for an existing database would make its records unreadable.

### Service lifecycle

Startup validates configuration and the selected identity material, applies migrations, registers an executor, starts maintenance, and loads registered components before binding the listener. Listener mTLS files are reread every 30 seconds. A changed bundle must validate as a whole and preserve its authentication usages before new handshakes adopt it. Established connections keep their original peer identity.

SIGTERM closes admission and allows up to 75 seconds for active RPCs and detached journal workers to finish. Once the executor requires restart, new requests receive Unavailable while the listener drains, and the process exits unsuccessfully. Run under a supervisor that starts a new process identity on failure. The new executor seals a previously dispatched, interrupted operation as UNKNOWN with `dispatch_interrupted`. An operation without a dispatch marker can execute when its owner retries the original key.

The gateway opens the upstream connection before it journals a dispatch. A URL or address rejected by egress policy returns `address_forbidden`. DNS, TCP, CONNECT tunnel and TLS setup failures return `transport_connect`. Cancellation during setup returns `cancelled`. If no earlier request was dispatched, the terminal result is NOT_SENT with zero requests and responses. Repeating the same idempotency key returns that sealed result. If an earlier request was dispatched, a later connection failure returns UNKNOWN and preserves the count. After a grant, a peer that closes before returning a complete HTTP response head yields UNKNOWN with `transport_error` and the dispatch counted.

StoreCredentials returns an immutable reference and a digest. RegisterPackage requires the approved digests computed by replay. GetExchange returns authenticated evidence to the original caller. Callback screening fingerprints all stored credential values, including registered public keys. A callback reflecting one of these values can therefore produce `secret_leak` and quarantined evidence. The caller still receives the exchange ID and digest.

Run `make integration` with `AIPAY_TEST_DATABASE_URL` in the environment for PostgreSQL-backed service tests and real-process mTLS and projected-token acceptance. The tests use disposable schemas, generated certificates and keys, and loopback HTTP simulators.
