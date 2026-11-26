# UG-2 pilot notes

## Status

| Milestone | Local result |
| --- | --- |
| Toolchain, WIT, SDK and components | Both worlds built, validated and matched the complete reference interface. Regeneration preserved the checked-in binding bytes. |
| Host and offline replay | All 30 payment and 10 independent verification recordings passed with exact Execution values and exchange consumption. |
| Sandbox conformance | The real probe component exercised traps, limits, leak alerts, routing, SDK defaults, dispatch and fresh state. Component admission rejected wrong or additional interfaces. |
| Build and CLI | Build, package, replay, verify, bench, calibrate and stress ran locally. Different build paths produced identical components, manifests and fixture sets. A disposable committed repository exercised clean-commit verification. |
| Dependency admission | The reviewer refreshed the vendor tree and audit imports from the network. The guest vet store imports Bytecode Alliance, Google and Mozilla audits and trusts the crates.io publishers dtolnay and BurntSushi for safe-to-deploy until 2027-11-20. All 12 locked guest packages are fully audited with no exemptions. |

The two delivered packages have development provenance. The working repository is on its original unborn main branch. The CI workflow is prepared for Ubuntu. All validation reported here ran locally on Apple Silicon.

## Toolchain and design decisions

- Rust and Cargo 1.99.1, Rust commit 58cf8f9c35b355199727627d07ae34a4e2846d67, LLVM 23.1.1, edition 2024, rustfmt 1.10.0-stable and Clippy 0.1.99. Guests target wasm32-unknown-unknown. The accepted build hosts are aarch64-apple-darwin and x86_64-unknown-linux-gnu. The actual triple contributes to the closure digest.
- Wasmtime 48.0.10 with runtime, cranelift, component-model, pooling-allocator, std and anyhow integration. The root lockfile has 160 registry packages. Host tools include wasm-tools 1.263.0, wit-bindgen-cli 0.63.0, cargo-vet 0.10.3 and cargo-deny 0.22.0. Build configuration validation uses Python 3.11+ tomllib. Local tools included Python 3.14.7, Git 2.54.0, GNU Make 3.81 and the system tar.
- The host directly uses anyhow 1.0.104, serde 1.0.229 with derive, serde_json 1.0.154, sha2 0.11.1, md-5 0.11.0, sha1 0.11.0, hmac 0.13.0, rsa 0.10.0, base64 0.23.1, subtle 2.6.1, zeroize 1.9.2 and getrandom 0.4.3. The memchr 2.8.3 dependency provides byte-oriented substring search for the leak scanner. pluginctl uses tempfile 3.27.0 for isolated builds, atomic directory staging and verification. Host tests use wat 1.263.0 for component admission cases.
- The guest workspace owns its own manifest, release profile, registry replacement, lockfile and vendor tree. The root workspace depends on the featureless SDK for strict JSON, form, money and timestamp utilities. Guest builds select a single world per Cargo invocation. The SDK retains all seven host entry points through linker roots. The release profile preserved the required component type metadata without a strip workaround.
- Source manifests omit the build object. Packaged manifests include the complete object and must already match canonical bytes. The WIT matches the ABI document verbatim. All 40 fixture files match the prototype at ed8f177 byte for byte.
- A reference component for each world is generated from the WIT at host build time. Registration compares structural types, signatures and exact member sets before creating the typed InstancePre. The in-memory cache belongs to one role and engine. The default pool has 32 component slots. Options::max_concurrent_steps defaults to available CPU parallelism, capped by pool_slots. The sandbox reported 10 available CPUs. Each admitted step has capacity for 16 core instances, eight memories and eight tables. Each memory slot reserves 32 MiB of virtual address space plus a 64 KiB guard. A separate growth limiter enforces 32 MiB summed per step. Component transfer fuel bounds host allocations during lift. A single 5 ms epoch ticker serves each engine. Blocking service adapters receive the operation cancellation handle and the applicable deadline. The step clock starts after admission. It covers instantiation, guest execution, host calls, automatic post-return and validation. Options::step_wall_clock defaults to 200 ms in production and five seconds in offline replay. A queued caller observes cancellation and its operation deadline. The permit is released before HTTP dispatch. Ordinary failures still deliver buffered logs after the operation. A secret leak discards all buffered logs and raises one trusted alert.
- Environments provide synchronous, bounded services. Egress receives both the header template and the expanded request for one dispatch. The adapter owns validated DNS/IP/TLS connections, header limits and deadline-aware body reads. The core has no network default. The offline signer generates independent shared or RSA credentials as required by the manifest. Test RSA keys stay in typed memory.
- The closure uses the guest workspace root files. The host Cargo.lock and other plugins' sources are outside the compiled guest closure. The builder walks target and native metadata, compares the actual compiled packages and selected features, checks compiler dep-info, and compares the snapshot digest before and after compilation. Cargo receives a fresh home, target directory and a snapshot containing closure files plus the manifests and empty entry points needed to resolve inactive members. The builder checks every vendored file against the pinned index before compiling. Workspace build scripts and procedural macros require explicit review. Only the five registry build scripts in serde, serde_core, serde_json, wit-bindgen and zmij execute for these packages.

### Local tool fingerprints

These SHA-256 values identify the executables used in the Apple Silicon pilot. The compiler driver also depends on its sysroot and shared libraries.

| Executable | SHA-256 |
| --- | --- |
| rustc | `1ba7bb8e273bd64125f4048d2ecce530e0a6470e565ab1b3aecf0b82b532f7b1` |
| cargo | `6d576d8058f8ca643e8fce55b64ee3c614ba64c9da2e536bae843e6a2e1f3951` |
| wasm-tools | `c205049c2228820ff9f4bff92c4d44f28f418823810ce7da6600909580597504` |
| wit-bindgen | `ad0f01f3dcd886f3db385cacf380b94ff58ec54b646a4fb063fdedc5bbf7754a` |
| cargo-deny | `632077350728d2c6ce4601e6620d8bc5b230eafef84cbbad703c75e4abebbedb` |
| cargo-vet | `8c85a1a2b31cfe29a9a3286d599ae94683ec80f64b51974e342a69e607bef5ac` |

## Guest dependency inventory

The following packages compile for both plugins. Registry checksums are the Cargo.lock package checksums.

| Crate | Version | Features | Purpose | Checksum |
| --- | --- | --- | --- | --- |
| itoa | 1.0.19 | none | Integer formatting | `3bd1574e617a9a6c1f8f8181bd7e841e1f20e4277607ef28945765188d6284d4` |
| memchr | 2.8.3 | alloc, std | JSON byte search | `cf8baf1c55e62ffcace7a9f06f4bd9cd3f0c4beb022d3b367256b91b87513d98` |
| serde | 1.0.229 | default, std | Visitor and deserializer traits | `4148590afebada386688f18773da617792bf2ef03ffc1e4cbd2b1d45b023e0ba` |
| serde_core | 1.0.229 | result, std | Serialization data model | `67dca2c9c51e58a4791a4b1ed58308b39c64224d349a935ab5039aa360942a48` |
| serde_json | 1.0.154 | default, std | Strict upstream JSON and Value | `e7e9cc8b1b85264074fbcc02a88680c4096b1e47df8f739dceb03bf482f04bd6` |
| wit-bindgen | 0.63.0 | realloc | Canonical ABI runtime and realloc | `b85a987ab61d365382d25c7d47e26edd48941b3bf6e3fbf76eff918bc71dab06` |
| zmij | 1.0.23 | none | Transitive number formatting used by serde_json | `29666d0abbfad1e3dc4dcf6144730dd3a3ab225bbbdac83319345b1b44ccfc1b` |

Cargo also resolves the following packages for inactive target or optional derive paths. Cargo vendor copies the full lockfile. Neither guest enables derive or links a procedural macro. The target-specific cargo-deny allow-list includes only the seven compiled registry crates.

| Lock-only crate | Version | Checksum |
| --- | --- | --- |
| proc-macro2 | 1.0.107 | `985e7ec9bb745e6ce6535b544d84d6cd6f7ad8bd711c398938ae983b91a766d9` |
| quote | 1.0.47 | `1fbf4db142a473a8d80c26bbf18454ed458bf8d26c8219c331daecfdbd079001` |
| serde_derive | 1.0.229 | `e7a5d71263a5a7d47b41f6b3f06ba276f10cc18b0931f1799f710578e2309348` |
| syn | 3.0.10 | `4ae9ccbea3a7b0b09443036490c8f34a8b1b760fd345e5c0dae0aac718faea79` |
| unicode-ident | 1.0.27 | `a2c754d6c33795a1c324727428e5a7dedb5b06195f9890bdbcba760d3e246563` |

## Replay evidence

The Go sizes come from the existing Go artifacts. Both round 2 sandbox runs reproduced the following component bytes, canonical manifests, fixtures and reports.

| Package | Go bytes | Rust bytes | Cases passed |
| --- | ---: | ---: | ---: |
| sim_form_md5 | 5,428,141 | 124,539 | 30 |
| sim_form_md5_verify | 5,428,213 | 94,792 | 10 |

**sim_form_md5**

- Package SHA-256 `3876ec6504ba577f515063b5a264b38790233f7fe0fe53ea4a0c2ac7d5aa0d01`
- Fixture set SHA-256 `6fa220ad2cc0ca5787c6a9ad07e480e227172f715d24687ac664cf05fdd3104f`
- Regression SHA-256 `20af2184deb4aab0491acebca13cf292d20501062c2182657b56205822ee8a59`
- Source closure SHA-256 `7a3a99b4de622506db9222e2c323df40b5c0cff3149f6ef2580b755655a78c1b`

**sim_form_md5_verify**

- Package SHA-256 `5389a2e0b7470550ce0fea73108712cea8743d7b94d2e09cdd4280e7ec1463ce`
- Fixture set SHA-256 `fe1720960f3109f0dca94972b4645e6c25b0bcebed537285bc850a7cd4dcf5c0`
- Regression SHA-256 `56324b8eea6982cbc8f51c8157fa0464f5511b25462415a1cbaa5d9a9fcea679`
- Source closure SHA-256 `3d58623ee2aa985a51a7c7f249e26a8a1152b6526a008a8c5f456b47dc60e261`

## Round 2 review

The builder now checks paths relative to canonical package, checkout, scratch and output roots. Tests exercise an external directory alias and reject links inside each protected tree. Form escaping now copies literal byte runs and writes escaped bytes into a shared output buffer. The protocol reuses the signed byte buffer for the HTTP body. All 40 original recordings passed. A separate Go net/url comparison matched the Rust output byte for byte for the full byte range, UTF-8 path escaping, the original canonical MD5 form vector, repeated and empty values, malformed pairs and a long literal run.

## Timing and calibration

All timings below are from the Apple Silicon sandbox with a release pluginctl and release guests. Each column is a separate run of the same packages. The first inherited the macOS temporary directory. The second used a temporary directory inside the workspace. Bench used 100 iterations of each shape. Calibration ran all 40 recordings and synthetic maximums under the normal replay fuel limit.

| Benchmark | macOS temp p50 / p99 ns | Workspace temp p50 / p99 ns | Peak bytes |
| --- | ---: | ---: | ---: |
| verify_callback operation | 70,375 / 108,583 | 70,167 / 130,625 | 1,179,648 |
| verify_callback step 1 | 56,958 / 90,166 | 56,625 / 115,375 | 1,179,648 |
| query_payment operation | 101,666 / 162,833 | 103,541 / 121,291 | 1,179,648 |
| query_payment step 1 | 50,125 / 86,917 | 51,042 / 62,250 | 1,179,648 |
| query_payment step 2 | 30,000 / 52,167 | 30,709 / 37,750 | 1,179,648 |

The accepted group includes all cases matching their expected outcome under normal limits. Its winning cases are the maximum accepted inputs. These include 100-byte IDs, signed 64-bit simulator amounts, a 256 KiB JSON response, a 256 KiB create request or a 64 KiB callback form with the 16 KiB header budget. HTTP operations accept one response and callbacks accept zero. The boundary group contains the 1 MiB create Call that terminates with host_io_limit before dispatch. Every other operation has zero host-limit boundary cases.

| Role | Operation | Group | Winning case | Step | Fuel | macOS temp wall ns | Workspace temp wall ns |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: |
| Payment | close_payment | accepted | close_payment/maximum_accepted | 2 | 2,260,908 | 426,167 | 443,708 |
| Payment | create_payment | accepted | create_payment/maximum_accepted | 1 | 6,081,943 | 1,882,125 | 1,941,292 |
| Payment | create_payment | boundary | create_payment/maximum_call | 1 | 24,154,643 | 4,257,250 | 4,357,208 |
| Payment | query_payment | accepted | query_payment/maximum_accepted | 2 | 2,260,857 | 398,833 | 422,791 |
| Payment | query_refund | accepted | query_refund/maximum_accepted | 2 | 7,651,384 | 580,416 | 622,291 |
| Payment | refund | accepted | refund/maximum_accepted | 2 | 7,651,384 | 580,459 | 636,583 |
| Payment | route_callback | accepted | route_callback/maximum_accepted | 1 | 2,967,409 | 189,792 | 214,042 |
| Payment | verify_callback | accepted | verify_callback/maximum_accepted | 1 | 4,766,255 | 593,833 | 605,542 |
| Verification | query_payment | accepted | query_payment/maximum_accepted | 2 | 2,260,828 | 414,750 | 468,834 |
| Verification | query_refund | accepted | query_refund/maximum_accepted | 2 | 7,651,358 | 588,083 | 587,917 |

Aggregate rates divide the sum of fuel by the sum of measured step wall time over all cases. Timing starts at admission, includes instantiation, host imports, post-return and validation, and excludes permit waits and transport.

| Role | Total fuel | macOS temp fuel/ms | Workspace temp fuel/ms |
| --- | ---: | ---: | ---: |
| Payment | 62,662,415 | 5,156,143.42 | 4,938,536.27 |
| Verification | 10,743,109 | 5,266,222.16 | 4,980,576.74 |
| Both | 73,405,524 | 5,171,965.41 | 4,944,644.63 |

The largest accepted step used 7,651,384 fuel. The create boundary used 24,154,643 fuel, down from the previous 95,388,535. Multiplying the larger maximum by two and rounding up to the next ten million yields the provisional **50,000,000 fuel per step**. This corresponds to **9.67 ms** at the first combined rate and **10.11 ms** at the second, or **4.8%** and **5.1%** of the 200 ms production fallback. These are empirical estimates for this mix of guest code and native validation. The four-package calibration in UG-3 will set the release budget.

## Commands and results

The following acceptance commands passed twice in the sandbox, first with the macOS default temporary directory and then with a workspace-local temporary directory. The shell supplied a disposable Cargo home, a private vet cache, and offline mode. The full deny runs used the cached crates.io index and RustSec database from the reviewer's connected checks.

```sh
make bindings
make check plugins replay repro deny vet calibrate stress bench
cargo deny --locked --offline check licenses bans sources
(cd guest && cargo deny --locked --offline check licenses bans sources)
```

- Compared binding SHA-256 values before and after both regenerations. Verified every indexed vendor file against its on-disk checksum, refreshed the seven active vendor index pins, and verified all three cargo-vet store files against their original bytes. The 12 registry package checksums in the guest inventory still match Cargo.lock.
- Formatting, Clippy with warnings denied, host tests, guest tests and CLI integration tests passed. The tests used an external directory symlink for a clean checkout and its outputs, and rejected symlinked plugin entries, closure inputs, package directories, output directories, fixture directories and fixture files. A held permit exercised cancellation and caller deadlines. An occupied Wasmtime pool exercised the host_service fallback. Log tests verified deferred delivery after an ordinary failure and suppression across an alert.
- The two paths in each reproduction test yielded identical packages. Independent SHA-256 calculations verified canonical manifest and report bytes, fixture file hashes, both fixture-set digests and both package digests. Comparing the outputs of the two temporary-directory profiles also yielded identical bytes.
- All four cargo-deny checks passed in both workspaces using the local RustSec snapshot at `074ea9a7ed619f511b5b7374c7a97e98d1e98be4` and a populated crates.io index. Host duplicate-version warnings remain. The separate offline license, ban and source commands passed. Locked, frozen cargo-vet then reported two fully audited and ten exempted. After the owner chose publisher trust, the reviewer's locked cargo-vet run reported **12 fully audited** with no exemptions.
- The release CLI ran bench, calibrate and stress for both packages. At four workers and four rounds, every report digest equaled the single-thread baseline. CI now runs release calibration and stress. The Ubuntu workflow was prepared locally.
- Independently ran release stress at 64 and 128 workers, one round per worker per package, first without additional load and then with 20 concurrent CPU busy loops. All 192 reports per package in each experiment matched its single-thread SHA-256. Every background load process was stopped and reaped after measurement.

## Spec deviations

Line references below refer to the normative UG-1 edition of upstream-gateway-abi.md.

- **Wall-clock fallback, lines 133–144.** The reviewer observed timeouts at 64–128 replay workers on a 10-core machine with 20 CPU busy loops. Steps normally taking approximately 50 µs sometimes timed out after one dispatch and returned unknown. Up to 32 workers were stable in that experiment. Offline replay, approval evidence, bench, calibration and stress now use five seconds. Production retains 200 ms. Fuel and the recorded inputs remain the primary replay controls.
- **Execution budget, lines 133–144.** The ABI calls for four simulator packages to freeze fuel and component-size limits. This milestone supplies provisional values from two. Repeat with the two JSON/RSA components and the deployed engine before freezing them.
- **Reproducible builds and dependencies, lines 196–215, and source closure, lines 216–230.** The local pilot fixes releases, compilation options, target, host policy and vendored inputs. It has no immutable release-image identifier or independently verified per-host tool binary checksums. The clean environment and source snapshot constrain Cargo inputs. A nested OS filesystem sandbox could not be installed in the test environment. The outer build worker must enforce network and filesystem isolation for native tools and build scripts. Compiler dep-info covers compiler-observed inputs and cannot attest arbitrary native system calls.
- **Third-party admission, lines 212–215.** The reviewer fetched live audits and ran all four cargo-deny checks. By the owner's decision the guest store imports only Bytecode Alliance, Google and Mozilla audits and trusts two publishers: dtolnay (itoa, proc-macro2, serde, serde_core, serde_derive, serde_json, syn, unicode-ident, zmij) and BurntSushi (memchr). wit-bindgen is covered by the Bytecode Alliance wildcard audit and quote by Google and Mozilla audits. The publisher trust entries expire on 2027-11-20 and need renewal. Narrowing trust to fewer crates would require new audits or exemptions.
- **Operations and validation, lines 96–114.** The typed v3 SDK must reject unrepresentable upstream enum values and malformed timestamp strings inside the simulator. Such data produce plugin_error. The v2 JSON boundary could carry the invalid strings through to host output_identity or output_time. All 40 recorded outcomes and business bytes are preserved.

## Connected follow-up and UG-3

The reviewer performed the connected vendor and audit refresh and full advisory checks. Keep those sources current during future release reviews.

Run the prepared Ubuntu workflow on a committed checkout. Use pluginctl verify on that checkout's committed packages. The two-path development run here used uncommitted snapshots. The clean-commit verification test used its own temporary Git repository.

UG-3 owns the immutable release builder, production DNS/IP/TLS transport, credential storage, gRPC, operation journal, encrypted exchange evidence and service deployment. Consider a persistent native code cache keyed by engine, target, configuration and package digest when deployment requires it.

## UG-3 four-package calibration and release limits

Measured on 2026-11-22 with macOS 27.2.1 arm64, `aarch64-apple-darwin`, Rust/Cargo 1.99.1, LLVM 23.1.1, wasm-tools 1.263.0 and Wasmtime 48.0.10 (Cranelift). The release pluginctl exercised release guests built with the pinned fat-LTO profile. The local packages carry `uncommitted` development provenance on top of `214a007dc2eee74183589cca59cca502febae35a`.

### Protocol, fixtures and package evidence

The new `sim-json-rsa-protocol` guest has separate trade and verification features. It signs the ordered Go JSON bytes with the role's declared private key reference. Callback verification authenticates the raw body, then checks its schema and identity. Routing reads only the untrusted order clue. Simulator wire decoding checks exact field names, nested duplicates, integer widths and trailing data. Go scalar nulls decode to their zero values. The typed ABI continues to require representable status and time values.

The Go 1.27.4 encoder and the Rust encoder test produced identical bytes for an all-fields vector using the original wireRequest definition, an i64 maximum, HTML characters, Unicode separators, quotes and control characters. The 243-byte vector's SHA-256 is `276035d4f36a4612ca09a7ab65420383229b7ede0df0915bbe67bbedf8514f37`. The two source manifests are compact canonical v3 bytes, version 0.3.0, with explicit collections and build provenance supplied at packaging. The three new workspace members use the existing registry inventory and vendor tree.

| Package | Component bytes | Component SHA-256 | Package SHA-256 |
| --- | --- | --- | --- |
| sim_form_md5 | 124,539 | 4d3c1eb92666bc7a1f2b3bbbee744160919a09f7d75ac7221ab198cf5eeadb04 | b802186e4f991737c6e930aa1d9c06b9c823906543a3c3458b45156c03e79b75 |
| sim_form_md5_verify | 94,792 | 92c010ddf91fcee86d6d2f38a49710e160913d4c4a3ce39e1fb86cbbf150844d | ba3a675141ef7c7b05052e93db37c721e1994fa5be4c3061584c0fd0a0584b78 |
| sim_json_rsa | 115,300 | 79fa78fc06a4dcef5f09ed7923b7f9058c4fc6b57234193119a9ae770772ac4e | 59de07aa5df3761383a5f4faccdaddb3d9246f190b77b249a95f2456b39f0426 |
| sim_json_rsa_verify | 93,537 | 5b19c1390c96b01835c9cacc1b733cedd9e425b9c66d72dc57bd6fb79ea825a6 | eabab0e2acbd7dfb660c844d326f384397ebebfaa41f7823356178c56bd3e3c2 |

| Package | Fixtures matched | Fixture-set SHA-256 | Regression SHA-256 |
| --- | --- | --- | --- |
| sim_form_md5 | 30/30 | 6fa220ad2cc0ca5787c6a9ad07e480e227172f715d24687ac664cf05fdd3104f | b0a29a08908ff761f3589c686c7c4c72a0d0d065e366c443eeb4c71ed6fe4257 |
| sim_form_md5_verify | 10/10 | fe1720960f3109f0dca94972b4645e6c25b0bcebed537285bc850a7cd4dcf5c0 | b785a58f4ca6307930d52b6716c3ef37caeae21a68f888a222fe8263221b91aa |
| sim_json_rsa | 30/30 | 0825720e59c8a58ec16fa62dd84fdeaf5f09de287905f269ae750b92440a50f4 | 67f3209d8344119d03cd84a316fae2981f732973fbf1a24a7e91cc86b3945006 |
| sim_json_rsa_verify | 10/10 | ea422021b85216fa141fe26337158f0d39278b9a77b64460dfe143186b58d262 | 8a7c7343de1f306421b9e6b415f2abb71efe20db156003633259b1abdd7ad916 |

For every path in the four Go fixture trees at `ed8f1779766c38cda2fb023a6f6e613d0fab3e8b`, an independent check compared the source Git blob, guest file and packaged bytes, and checked the report's individual SHA-256 against the blob. All 40 newly copied JSON/RSA fixtures matched. The 40 existing form fixtures also matched. All 80 actual Execution objects equaled their individual expected objects and replay exhausted each recording. The fixture-set column hashes the ABI length-prefixed paths and original bytes. The regression column hashes the canonical report bytes, including package identity.

### Per-operation maxima and frozen limits

Each row is the maximum single guest step across all recordings and synthetic cases in that operation and group. The accepted group includes normal terminal outcomes. The two `maximum_call` rows are the pre-dispatch `host_io_limit` group. Each group was checked against its expected Execution before its metrics were counted.

| Package | Operation | Winning case | Step | Fuel |
| --- | --- | --- | --- | --- |
| sim_form_md5 | close_payment | close_payment/maximum_accepted | 2 | 2,260,746 |
| sim_form_md5 | create_payment | create_payment/maximum_accepted | 1 | 6,081,943 |
| sim_form_md5 | create_payment | create_payment/maximum_call | 1 | 24,154,643 |
| sim_form_md5 | query_payment | query_payment/maximum_accepted | 2 | 2,260,874 |
| sim_form_md5 | query_refund | query_refund/maximum_accepted | 2 | 7,651,384 |
| sim_form_md5 | refund | refund/maximum_accepted | 2 | 7,651,384 |
| sim_form_md5 | route_callback | route_callback/maximum_accepted | 1 | 2,967,409 |
| sim_form_md5 | verify_callback | verify_callback/maximum_accepted | 1 | 4,766,255 |
| sim_form_md5_verify | query_payment | query_payment/maximum_accepted | 2 | 2,260,845 |
| sim_form_md5_verify | query_refund | query_refund/maximum_accepted | 2 | 7,651,358 |
| sim_json_rsa | close_payment | close_payment/maximum_accepted | 2 | 2,260,870 |
| sim_json_rsa | create_payment | create_payment/maximum_accepted | 1 | 4,750,034 |
| sim_json_rsa | create_payment | create_payment/maximum_call | 1 | 18,896,615 |
| sim_json_rsa | query_payment | query_payment/maximum_accepted | 2 | 2,260,998 |
| sim_json_rsa | query_refund | query_refund/maximum_accepted | 2 | 7,651,487 |
| sim_json_rsa | refund | refund/maximum_accepted | 2 | 7,651,487 |
| sim_json_rsa | route_callback | route_callback/maximum_accepted | 1 | 603,496 |
| sim_json_rsa | verify_callback | verify_callback/maximum_accepted | 1 | 681,890 |
| sim_json_rsa_verify | query_payment | query_payment/maximum_accepted | 2 | 2,260,943 |
| sim_json_rsa_verify | query_refund | query_refund/maximum_accepted | 2 | 7,651,439 |

The HTTP cases use 100-byte identifiers, the maximum positive signed 64-bit amount and one 256 KiB JSON response. The largest accepted create request has a 256 KiB body. The boundary create fills the 1 MiB Call projection and stops during the projected signing import before sending any request. Synthetic JSON callbacks use 64 KiB of body and 16 KiB of headers, including the actual base64 signature width. Their signers and signatures exist only in replay memory.

**Fuel is frozen at 50,000,000 per step.** The local high-water mark is 24,154,643. Multiplying by two gives 48,309,286 and rounding upward in units of 10,000,000 gives 50,000,000. The winning form create boundary also won UG-2. The JSON/RSA create boundary consumed 18,896,615. The highest accepted step across all four guests was 7,651,487. Production and replay use the frozen fuel with their respective 200 ms and five-second wall clocks.

**Component size is frozen at 4 MiB (4,194,304 bytes).** The largest component was the 124,539-byte form payment guest. All four fall below the 1 MiB review threshold. Recalibrate both approved hosts when the engine, target/compiler, profile, component bytes, ABI projections, limits or calibration workload changes. Use the largest single step across both hosts and both groups with the same factor and rounding. The first Linux measurement for these exact sources is pending CI. If the two-host result crosses the rounding boundary, revise the default and its regression assertion together.

### Component identity on different build hosts

Release and approval rebuilds use `x86_64-unknown-linux-gnu`. The reviewed closure includes the actual build host in its configuration. An approved macOS builder can produce development and comparison evidence. Given a committed package and a clean repository, `pluginctl verify` rebuilds the named commit on its current host and compares component bytes, manifest, package digest and fixtures. Rebuilding on the other approved triple changes the closure digest in the manifest and fails with `clean-commit rebuild differs`, even if component bytes match. Development packages fail earlier with `uncommitted package`.

Cargo 1.99.1 commit `5f94df4789f005f9a352888e8355ffc645b7ed0e` excludes the `host:` line of stable `rustc -vV` for explicit target units. Native units hash that line. Cargo then feeds the sorted dependency metadata hashes into each dependent unit's `-C metadata`. This lets the five native build scripts influence symbols in the Wasm dependency graph. The hypothesis that each Wasm unit directly hashes the complete host version string is false for this Cargo release. [Pinned Cargo version-hash code](https://github.com/rust-lang/cargo/blob/5f94df4789f005f9a352888e8355ffc645b7ed0e/src/compiler/build_runner/compilation_files.rs#L902-L916) and [dependency hash code](https://github.com/rust-lang/cargo/blob/5f94df4789f005f9a352888e8355ffc645b7ed0e/src/compiler/build_runner/compilation_files.rs#L844-L851).

An offline `cargo build -v --locked --no-default-features --release --lib --target wasm32-unknown-unknown -p sim_form_md5` on macOS emitted native build-script metadata `465aa0e432f6563c` for serde_core. The Wasm serde_core unit received `df51a9a8912ea334`, the SDK `77ea3ce5bdd73e8d`, and the final cdylib `e08aee6e44d00ea0`. The last command used `-C lto=fat -C codegen-units=1` and stripped symbols.

In a separate same-host sensitivity test, two otherwise identical builds added stable target flags `-Cmetadata=ug3_a` and `-Cmetadata=ug3_b`. Their core Wasm **code sections** measured 98,603 and 98,972 bytes (SHA-256 `1254c1beab4db44b1a47845d496c21e1fc8a903899b9d12f678daaf6bb12d624` and `eedf7e6c065988b3411c8a00c0d4ad6db17f84c75681c29240261d5963891644`). The component digests were `4d3c1eb92666bc7a1f2b3bbbee744160919a09f7d75ac7221ab198cf5eeadb04` and `a76cb51e1d71c8665ada0709dea28d14abe6c126299238d70133a7f569009796`. Release calibration of the two experimental components measured 7,651,384 and 7,650,408 fuel for the maximum accepted query_refund step. Both create boundaries consumed 24,154,643. This establishes metadata sensitivity after LTO on one machine. Attribution of the historical Linux fuel difference still requires paired evidence.

The matrix builds all four guests natively, prints the verbose metadata for the form guest, reproduces packages on two paths on each host and uploads one component/fuel manifest per host. Its comparison job reports cross-host component differences and prints the combined budget. Missing or mislabeled measurements fail the comparison. The ABI binds release identity to the approved build host, so cross-host component inequality is informational. No host-detection wrapper or metadata override participates in packaging. The release worker image and tool binary attestations remain separate release-engineering work.

### Validator and acceptance

The builder compares build-config.json with the copy embedded in pluginctl. That file is an explicit closure input and now pins Python 3.14.7. The builder checks `python3 -I --version` before invoking the embedded validator with `-I -B`, isolating it from user site packages and PYTHON* environment variables. A regression test supplies 3.14.0 and verifies rejection before validator execution. A separate build with invalid PYTHONHOME and PYTHONPATH reproduced the JSON verification package digest. CI installs the same patch release. Checkout, setup-python and both artifact actions use full commit pins and Node 24.

| Local acceptance | Result |
| --- | --- |
| `make bindings` and binding drift check | Both regenerated bindings matched the original SHA-256 and the Git tree. |
| `make check` | Formatting, Clippy with warnings denied, host/CLI/SDK tests, and each guest protocol feature passed. The CLI tests covered a disposable committed checkout and repeat replay using fresh in-memory credentials. |
| `make plugins replay` | Four packages built and all 80 recorded cases passed. |
| `make repro` | Four packages reproduced byte for byte in two independent build paths. |
| `make deny vet` | Both workspaces passed advisories, bans, licenses and sources. The host emitted duplicate-version warnings. RustSec checkout `d1fe6ac3eba823a3515e849045f36dc34543885d`. All 12 locked guest registry packages were fully audited. |
| `make calibrate stress bench` | Release calibration completed on all four packages. Four workers × four rounds produced 16 reports per package identical to each single-thread baseline. Each benchmark ran 100 samples. |
| CI workflow | actionlint 1.7.12 passed locally. The comparison script accepted complete synthetic host pairs, reported differing hashes and rejected missing evidence. Both hosted jobs await execution. |

| Package | Operation | p50 (ns) | p99 (ns) | Peak linear memory (bytes) |
| --- | --- | --- | --- | --- |
| sim_form_md5 | verify_callback | 80,083 | 120,584 | 1,179,648 |
| sim_form_md5_verify | query_payment | 118,125 | 175,458 | 1,179,648 |
| sim_json_rsa | verify_callback | 122,125 | 323,750 | 1,179,648 |
| sim_json_rsa_verify | query_payment | 1,227,958 | 2,510,584 | 1,179,648 |

## UG-3 gateway service

The host workspace contains the twelve library RPCs and the upstream contract released in protobuf v0.18.0 (commit `fd769b1`). The PostgreSQL journal fences executors, commits each request before transport, and seals the terminal response and exchange in one transaction. Immutable credential versions use instance-specific envelope encryption. Routing checks write-time credential fingerprints without opening the credential envelope. The live HTTP/1.1 transport pins the validated destination through direct TLS and CONNECT.

Phase one acceptance used Rust 1.99.1 and PostgreSQL 18.7.

- `make proto-sync` and `make proto-check` compared both files with the protobuf checkout. The embedded descriptors retained every method policy. Running `make bindings` on a temporary copy of the binding inputs produced byte-identical trade and verification bindings.
- `make check` passed formatting, Clippy, host, guest and CLI checks. The gateway passed nine database-independent tests, including canonical vectors, descriptor checks, local KMS permissions, TLS, proxy targeting, limits, deadlines and cancellation. The host passed fifteen unit tests.
- `make integration` passed thirteen tests in independent temporary schemas. The tests covered original-key response bytes, both revocation orders, package publication, pre-dispatch fencing, an in-flight fenced sender, a lost dispatch acknowledgement, cancellation, credential binding, routing without credential decryption, quarantined echoes and ciphertext integrity. All seven trade operations ran with the real component. The verification package ran with its independent role and credential reference. The test database contained zero temporary gateway schemas after the run.
- `make plugins replay` passed all 40 cases. The development report hashes were `20af2184deb4aab0491acebca13cf292d20501062c2182657b56205822ee8a59` and `56324b8eea6982cbc8f51c8157fa0464f5511b25462415a1cbaa5d9a9fcea679`. Replaying the original clean-source packages also reproduced both original report files byte for byte. Their hashes were `b86859d4cb5b655bf613ee9be14469d34d78a9eccacbd56bda3aef534ab97f28` and `aba414ab86a7996ca885aa566e1ce71ae9b837d99e01fc32d51e1762c4129af6`.
- `make repro` reproduced both packages in independent directories. `make deny` passed advisories, bans, licenses and sources in both workspaces. The host reported duplicate-version warnings. `make vet` reported 12 fully audited guest dependencies.
- `make bench calibrate stress` passed. Release operation p99 was 84,333 ns for verification of a callback and 170,708 ns for a payment query. The recorded aggregate fuel totals were 62,662,415 and 10,743,109. Sixteen concurrent reports per package matched their respective serial baselines.

### Phase two service boundary

The binary uses the vendored descriptor extension to authorize each method before decoding its body. TLS 1.3 validates the chain, the sole SPIFFE URI and the instance's single peer during the handshake. The connected stream carries the verified name. Every inbound message passes recursive wire validation before prost can discard a tag. The server uses the 16 MiB limit for requests and responses.

Migration 002 adds database-clock operation creation, completion, dispatch-marker and response-receipt times. Existing events with unknown times retain NULL. An attempt with no captured response has no receipt time. The evidence encoding and its digest exclude all four timestamps. During duplicate waits the database query takes no operation row lock. A released operation still requires a transactional claim.

The executor heartbeat and fence threshold are configurable. A retryable storage failure uses exponential backoff, starting at 25 ms and capped at 500 ms, within a ten-second budget per retryable journal step. Each attempt's receipt is reused on retry. An ambiguous dispatch authorization still sends zero requests. A terminal commit with uncertain acknowledgement can recover the stored immutable response. Callback credential fingerprints cover public keys as well as secrets, so a reflected public key can quarantine an exchange.

Local phase two acceptance ran on Apple Silicon with Rust 1.99.1 and PostgreSQL 18.7.

- `make bindings` preserved both generated files byte for byte. `make proto-check` also matched the designated protobuf checkout. `make check` passed formatting, Clippy, host, SDK, guest and CLI checks, including 10 database-independent gateway tests and 15 host tests.
- `make plugins replay repro deny vet` passed. All 80 recordings succeeded, all four packages reproduced byte for byte across build directories, and both workspaces passed all four deny checks. The guest vet store reported 12 fully audited packages. Local vet used a writable temporary cache.
- `make integration` passed 14 database service tests and 13 release-binary end-to-end tests. The final schema count was zero. Both roles completed their allowed paths with independent stored credentials. Loopback simulators verified each live signed request. Tests covered rejected handshakes, assertion and method policy ordering, malformed nested fields, the 16 MiB boundary, isolated storage, idempotency conflicts, revocation, evidence retrieval and credential echo quarantine.
- The pre-dispatch SIGKILL test held the attempt insertion behind a database lock. Upstream count was zero at process death and one after the owner's retry. The completed response recorded one request and one response. The post-dispatch test withheld the upstream response after receiving the first complete request. Recovery returned UNKNOWN with `dispatch_interrupted`, one request and zero responses. The upstream count stayed at one across restart and repeated retrieval. Both tests used the ordinary gateway binary.
- SIGTERM closed the listener and allowed an active request to commit its successful terminal. An external fence during a separate live request produced a durable interrupted terminal before the binary exited unsuccessfully. Across two scheduled TLS reloads, a partial bundle retained the previous material. Valid replacement of the CA, certificate and key admitted the new client, rejected new handshakes from the old CA, and kept the established connection usable.
- `make calibrate stress bench` passed for all four packages. The peak single-step fuel was 24,154,643. Each package produced 16 reports matching its serial digest. The 100-iteration offline operation p99 values were 0.436 ms and 0.573 ms for form trade and verification, and 0.517 ms and 4.463 ms for JSON trade and verification, respectively.

The following release measurements each cover one 64 KiB callback from the gRPC client through terminal persistence and back. The signed payload and its credentials were generated in memory.

| Package | RouteCallback | VerifyCallback |
| --- | ---: | ---: |
| sim_form_md5 | 8.209 ms | 9.168 ms |
| sim_json_rsa | 9.107 ms | 10.752 ms |

All four observations were below the 50 ms review threshold. The fingerprint implementation was retained.

The current contract defines enums only in response trees. A real enum descriptor rejected an unknown category. Submitting those same bytes over gRPC exercised wire-type rejection at the request boundary. Production startup still requires a production KMS adapter. The PostgreSQL 18 integration workflow passed actionlint locally. Hosted CI and deployment verification remain outstanding.

## UG-3 reviewer verification

On 2026-11-22 the reviewer reran the full acceptance suite on the merged working tree, on Apple Silicon with PostgreSQL 18.7:

- `make bindings` regenerated both bindings without drift. `make proto-check` matched both vendored files byte for byte against the `ug3-upstream-contract` branch based on protobuf v0.16.0.
- `make check plugins replay repro deny vet` passed. Replay passed 30, 10, 30 and 10 cases. All four packages reproduced byte for byte in two paths. Both workspaces passed all four cargo-deny checks. cargo vet reported 12 fully audited guest packages.
- `make integration` passed 14 database tests and 13 binary end-to-end tests, including both SIGKILL cases.
- `make calibrate stress bench` passed. The maximum step remained 24,154,643 fuel. Each package produced 16 identical stress reports.

At B0, `proto/source.json` recorded the released protobuf tag v0.17.0 (commit `8442a37`). For B0, `make proto-sync` preserved both files byte for byte, and `make proto-check` passed locally and against the tag. Temporary copies rejected invalid versions, a one-byte change and a missing tag. Both bindings regenerated without drift, and `make check` passed. In UG-4, payment and reconciliation ran the full stage 2 demo through a trade and a verification instance on the local mTLS stack. Hosted CI, including the two-host component comparison and the PostgreSQL job, has not run yet.

## UG-7 EPay V1 callbacks

The host accepts a callback without Content-Type when its manifest allows GET, the request method is GET and the body is empty. An explicit media type must match the manifest. Both callback operations retain their method, query, size, header and secret checks.

For EPay replay, a marked callback with an empty body, nonempty query and absent Content-Type uses the manifest's single shared secret. The re-signer decodes form bytes, rejects malformed escapes, empty keys and duplicates, and requires a sign field. It omits sign, sign_type and empty values, joins the remaining decoded fields in bytewise key order and appends the key directly before computing lowercase MD5. Only the signature value changes on the wire. The output scanner also protects the regenerated signature. Calibration exercises the 16 KiB query limit with both callback operations.

The recorder uses the authenticated test control endpoint on an explicit IPv4 or IPv6 loopback socket. Each HTTP/1.1 request uses a fresh connection with five-second timeouts and a 1 MiB response limit. Control credentials stay in memory. The recorder independently signs a simulator purchase, checks the payment URL's origin, acknowledges the raw notification, and runs the component with the simulator key to obtain its expected execution. It scans the full fixture set for credentials and signatures, including their hex and Base64 encodings and the decoded wire data. It publishes the JSON files to an empty or new directory after strict fixture decoding and offline replay with ephemeral keys.

In UG-7, EPay V1 0.1.0 declared route_callback and verify_callback. Payment creation depended on adding the buyer IP to WIT. An EPay urlscheme has no mapping to the URL instruction.

The trial and source fixture sets each passed all five cases on Apple Silicon. Both success cases completed. Malformed routing and invalid-signature verification returned `not_sent/plugin_error`. The signed amount mismatch returned `not_sent/amount_mismatch`. Every case used one host step and zero exchanges. Both simulator processes were stopped after capture.

| Local artifact | Value |
| --- | --- |
| EPay component size | 117,826 bytes |
| Component SHA-256 | `888e18769f2798bc593c4d76a2e63fcbaf47fa1f32c7cb734d498d6cfcde00ea` |
| Trial fixture set SHA-256 | `7fb3f6d375e1f3a6dab83291f0f105210fbe4a387648396fcbec948a705da1d7` |
| Source fixture set SHA-256 | `5dc6104d9636750fbb684ddbe5e403c107c220060486ecf7d110f976723b1ef1` |

- `make bindings` on a temporary copy of the pinned inputs reproduced both SDK files byte for byte. Both workspaces passed `cargo fmt --all -- --check` and the host workspace passed `cargo clippy --locked --workspace --all-targets -- -D warnings`.
- Guest Clippy passed for epay_v1 and the SDK on wasm32-unknown-unknown and for all native epay_v1 targets. All 16 epay_v1 unit tests passed, including the payment creation tests. Python hashlib independently produced the fixed query signature used by both Rust implementations.
- Replaying the four original packaged components with the updated host reproduced all four saved report files byte for byte (80 cases).
- `cargo test --locked -p upstream-host -p pluginctl` passed 17 host tests, seven CLI unit tests and four CLI integration tests. The listener test delivered an unrelated order and then the selected order using fragmented writes. The first trial encountered an intermittent callback read failure. The final listener explicitly sets accepted sockets to blocking mode before its bounded reads.
- `make check` passed the contract digest check, workspace checks and guest checks. The ordinary workspace test command skipped its 27 explicitly ignored gateway integration tests.
- `make plugins replay repro` built all five packages, passed all 85 cases and reproduced the complete packages byte for byte in two independent source directories. For the four rebuilt simulator packages, the reports differed from the prior files only in package SHA-256. Their build manifests carried the updated source-tree digest, and their case arrays were identical. The EPay replay report SHA-256 was `15f2143f41294c11d1ec50e901a0c3bfdf56391af654554c76a4b5fbe562782a`.
- `make deny vet` ran offline with the cached advisory database, `cargo deny --locked --offline` and `cargo vet --locked --frozen` with a temporary cache. Both workspaces passed advisories, bans, licenses and sources. The host reported duplicate-version warnings. Guest vet reported 12 fully audited packages.
- `make bench calibrate stress` passed for all five packages. In this local 100-iteration release run, EPay verification took 197,792 ns at p50 and 357,916 ns at p99 with 1,179,648 peak guest bytes. The highest EPay calibration step used 835,791 fuel on the maximum accepted verification query. Each package produced 16 concurrent reports identical to its serial baseline.

## UG-6 buyer IP and device

The gateway vendors protobuf v0.18.0 (`fd769b1`). Compared with v0.17.0, only the two optional fields and their comments in CreatePaymentInput changed. The authorization policy is byte-identical. WIT adds client-ip and device after instruction. The package stays at kaivo:upstream@3.0.0 because v3 has not entered production. Both worlds export the types interface. All five previous components were tested with the new host and rejected with `component does not match declared WIT world`.

The gateway and host share the buyer-field validators. A present buyer IP must round-trip byte for byte through the standard IP parser and formatter. IPv4-mapped IPv6, ports and zone identifiers are invalid. A present device contains 1–32 lowercase ASCII letters, digits or underscores. Absent fields are omitted from host JSON. The WIT call preserves both options. Validation errors contain fixed codes. The host screens buffered guest log messages and fields for buyer metadata before forwarding them. Alert codes and numeric execution metrics carry no input values.

The canonical CreatePayment request appends field 7 and then field 8. Each absent field contributes one zero byte. Each present field contributes one byte of value 1 followed by the big-endian u32 byte length and UTF-8 bytes. Even with both absent, the new encoding adds two zero bytes. Retrying a pre-upgrade order under its existing idempotency key can therefore conflict with its stored request digest. Exchange evidence includes that digest and the journal's actual HTTP request. An independent Python encoder produced the SHA-256 vector `e1c772272dfcc13838f85da9d19fcfc8ffb1b17d2c53b5a7ec1a7796dba579b1` for the two-field example in `create_buyer_fields_validate_and_bind_the_request_digest`.

EPay V1 0.1.0 requires client_ip to sign and dispatch a mapi purchase and sends device when present. The recorded success response supplies a payment URL and the plugin reports pending. EPay returns no amount in this response, so the payment output echoes the input amount. Admission requires success, rejected, signature_error and timeout for create_payment. Supplied amount_mismatch cases still undergo expectation checks and replay. Output amount checks still apply to every plugin.

The recorder installs each order's test scenario, executes the real component with the simulator key and records the exchange. It captures the four creates before the five callback cases. Its mapi transport accepts a form POST to the selected HTTP loopback socket, opens a fresh connection, sends Connection: close, and reads at most 1 MiB of response body within a two-second deadline. The signature-error case changes only the outgoing form signature to 32 zeroes. The captured request uses replay's signature marker. A three-second simulator delay produces a timeout exchange. The pre-publication scan covers the simulator token, key, generated request and callback signatures, headers, and decoded wire bodies. Strict decoding and replay with ephemeral keys run before publication.

| Operation | Scenario | Category | Host error | Upstream code |
| --- | --- | --- | --- | --- |
| create_payment | success | completed (pending, URL) | — | — |
| create_payment | rejected | rejected | — | epay_code_-1 |
| create_payment | signature_error | rejected | — | epay_code_-1 |
| create_payment | timeout | unknown | transport_error | — |
| route_callback | success | completed | — | — |
| route_callback | malformed | not_sent | plugin_error | — |
| verify_callback | success | completed | — | — |
| verify_callback | signature_error | not_sent | plugin_error | — |
| verify_callback | amount_mismatch | not_sent | amount_mismatch | — |

The final temporary capture and installed source set matched byte for byte. Both simulator runs stopped after capture. The four simulator fixture directories have no changes. The three relaxations tracked under A136, EPay order queries and refunds, and epay_v1_verify remain open.

| Package | Component bytes | Component SHA-256 | Fixture-set SHA-256 |
| --- | ---: | --- | --- |
| epay_v1 | 129,546 | `e87ebb57f612a26ff6547ec9ed1809f393042bcce94033c6bdff5a0b4c842cc5` | `a5002eaaf1312ce942acacbc7c1b58d8454a2d137902676164ca0241bd9c54d0` |
| sim_form_md5 | 124,760 | `4576b180aee36d2a6d0e68602dbaf7d3901bfc79c28217c3af620d80ddd4d6a9` | `6fa220ad2cc0ca5787c6a9ad07e480e227172f715d24687ac664cf05fdd3104f` |
| sim_form_md5_verify | 94,830 | `32ff97d5f420bfdb65da48b1f491c3972ba54f6a2569e2dc763f60d6dd795513` | `fe1720960f3109f0dca94972b4645e6c25b0bcebed537285bc850a7cd4dcf5c0` |
| sim_json_rsa | 115,515 | `65319b01b15532c9f38a24cb58e8172c8d380222f7c15cee8eeb8d9ecb064a9b` | `0825720e59c8a58ec16fa62dd84fdeaf5f09de287905f269ae750b92440a50f4` |
| sim_json_rsa_verify | 93,575 | `2faeb40d9c46ca8fe3234b33a08159824a7aeb455ea61cdd836e61b1205901db` | `ea422021b85216fa141fe26337158f0d39278b9a77b64460dfe143186b58d262` |

- `make proto-sync` and `make proto-check` passed against the local v0.18.0 tag. The digest-only check also passed. Repeating `make bindings` reproduced both updated SDK source files byte for byte.
- `make check` passed both workspaces' checks, including 11 database-independent gateway tests, 19 host tests, 11 CLI unit tests, four CLI integration tests and 16 EPay protocol tests. The gateway digest tests compare six presence/value combinations against independently computed SHA-256 vectors.
- `make plugins replay` built all five components and passed 89 cases. The four simulator packages' 80 case records matched their previous reports exactly. The installed EPay fixture-set hash matched the final temporary recording. Its replay report SHA-256 was `1584aaf509bf43f8aafab9bfc5e836ebe779022d8218ae7d0490a8836d18b28b`.
- The first EPay calibration of the 1 MiB call exhausted the guest fuel budget while scanning the callback URL. A byte search for the ASCII query and fragment delimiters preserved URL validation and let the final component reach the expected pre-dispatch `host_io_limit`. The accepted synthetic EPay create has a 39-byte canonical IPv6 address, a 32-byte device and a 256 KiB request and response. All nine recordings were repeated with this component.
- `make integration` stopped at the environment check with `integration requires AIPAY_TEST_DATABASE_URL`. The 14 PostgreSQL tests and 13 release-binary tests remain unverified in this run.
- `make repro` reproduced all five complete packages byte for byte across two independent source and build paths. Offline `make deny` passed advisories, bans, licenses and sources in both workspaces, with duplicate-version warnings in the host workspace. Frozen `make vet` reported 12 fully audited guest packages.
- `make bench calibrate stress` passed for all five packages on aarch64-apple-darwin. The EPay verify_callback benchmark recorded 102,958 ns at p50 and 140,041 ns at p99 over 100 iterations, with 1,179,648 peak guest bytes. EPay's highest single step used 12,621,226 fuel on the pre-dispatch create boundary. The highest across all packages was 24,152,683 for sim_form_md5. Each package produced 16 concurrent reports identical to its serial baseline.

## v0.3.0 (UG-6) declared secret fields and query-only verification

A manifest declaring `secret_fields` must supply at least one of `query` or `form` and declare a shared secret. Each supplied array contains 1–16 distinct, case-sensitive names of 1–64 ASCII letters, digits, underscores, hyphens or dots. Omitting the object preserves the canonical manifest bytes used in the package digest.

The host validates the guest's request and exact egress domain before it resolves placeholders for transport. Without `secret_fields`, it checks the URL and body for the literal `{{secret:` prefix and rejects it with `secret_placeholder`. It forwards query and form bytes unchanged, including repeated keys and malformed percent escapes.

With `secret_fields`, the host decodes query pairs and form pairs separately. Form bodies require exactly one Content-Type value with base media type `application/x-www-form-urlencoded`. A repeated declared name in the same location, an undecodable pair, a misplaced placeholder or ambiguous braces in a declared value fails with `secret_placeholder`. Undeclared field names may repeat. An allowed field accepts a whole decoded `{{secret:NAME}}` value referencing a declared shared credential. Substitution copies the original bytes around each value and uses the SDK encoder for the credential bytes. Header and field substitutions share the control-byte policy, including the horizontal tab exception. The expanded URL fits the gateway transport's 65,534-byte URI limit and the expanded body fits 256 KiB.

Production requires HTTPS. The host rejects query or form substitution over HTTP with `https_required` before expansion unless HTTP field substitution is explicitly enabled. The development gateway enables it only with `allow_loopback_http` and sends cleartext requests only when every resolved address is loopback. Offline replay and the loopback recorder enable the exception with test credentials.

Dispatch authorization, attempt evidence and fixture capture receive the original request template. Only the trusted transport receives the expanded request. Replay expands the recorded template with the current test credentials before comparison. For exchanges with field substitution, the recorder and replay mask a separate form signature in place. This preserves surrounding wire bytes and also permits the declared credential field itself to be named `sign`. Existing recordings retain their signature projection. Before publishing fixtures, the recorder scans decoded request URL fields as well as decoded wire bodies. Response scanning covers raw header names, header values and body bytes, including the encoded credential sent on the wire. When a response leaks a credential for a manifest declaring secret fields, the host stops with `secret_leak` and retains only its status in the quarantined response receipt. This prevents an echoed request from entering the evidence.

Inspection of gateway egress, its service and journal callers, and the server event sink found no complete outbound URL or request body in logs, metrics or public errors. There were no gateway log or error message changes. The replay diagnostic for an invalid recorded template now reads `invalid recorded request template` and carries no request data.

For an approved upstream that cannot issue independent read-only credentials, the verification instance can seal the same merchant key as the trading instance and declare only `query_payment`. The owner approves this credential arrangement. The gateway enforces the manifest, role and egress policy. A verifier can also declare both query operations in either order. Replay requires scenarios for the declared capabilities, and an undeclared entry returns `unsupported_operation` before the first step.

The requirement to declare at least one group matches payment commit `cbe32ce`. Remaining integration work includes EPay V1 order queries and refunds, the epay_v1_verify component, and acceptance of `secret_fields` by the reconciliation manifest parser.

Verification on aarch64-apple-darwin with Rust 1.99.1:

- `make bindings` reproduced both checked-in SDK bindings byte for byte.
- `make check` passed workspace formatting, Clippy, contract digests, host and guest tests. The host passed 26 tests, the gateway passed 13 database-independent tests, and pluginctl passed 12 unit and four integration tests. Coverage includes empty declarations, raw and encoded placeholders, malformed escapes and repeated fields in both query and form data. A loopback transport test observed the original repeated query and `%zz` on the wire. Gateway tests covered the field substitution switch in production and both development settings, as well as the resolved-address policy for HTTP and HTTPS. The query-payment-only verifier passed all five required scenarios and rejected query_refund with zero steps and zero requests.
- The recorder's loopback test observed expanded bytes on the socket and placeholders in the captured query and body. Tests rejected fixture publication for encoded credentials in either position. Replay matched a signed form with a wire body exactly 256 KiB, detected non-secret byte changes, and preserved a placeholder in a field named `sign`.
- The 14 PostgreSQL tests and 13 release-binary tests are outside `make check`. The earlier `make integration` attempt stopped at the environment check for `AIPAY_TEST_DATABASE_URL`. This review used offline fixtures and local test sockets.
- `make plugins replay repro` rebuilt all five packages and passed all 89 cases. For each simulator, the trade and verification reports covered 30 and 10 cases respectively. EPay V1 covered nine. A direct `cmp` against the five reports saved before these review changes found all five byte-identical. The independent two-path build also reproduced all five packages byte for byte.
- Offline `make deny vet` passed advisories, bans, licenses and sources in both workspaces. The host workspace reported duplicate-version warnings. Frozen guest vet reported 12 fully audited packages.
- `make bench calibrate stress` passed for all five packages. Across 100 release iterations, EPay verify_callback took 314,292 ns at p50 and 5,770,292 ns at p99. A standalone repeat measured 77,917 ns at p50 and 112,459 ns at p99. Both runs used 1,179,648 peak guest bytes. EPay peaked at 12,621,226 fuel in the create_payment boundary case. The highest single step overall was 24,152,683 fuel for sim_form_md5. For each package, four workers ran four replays apiece. All 16 reports matched the serial baseline.

## UG-6 EPay V1 order query and verifier

The trading component `epay_v1` 0.2.0 and the query-only `epay_v1_verify` 0.1.0 share `epay-v1-protocol`. Both issue a bodyless GET to `api.php` with `act=order`, the configured PID, the merchant order ID and a form-encoded merchant key placeholder. Both manifests declare the query field `key`. The host expands its value only for transport. The verifier requires just `gateway` and `pid`. Under A136 ③, the verification instance separately seals the trading instance's merchant key. The owner must approve this credential arrangement.

After HTTP 200, the plugin parses the JSON object, accepting a UTF-8 BOM, surrounding whitespace and PHP-style escapes. An integer or decimal-string code other than 1 yields an upstream rejection. For success, the plugin checks the PID and merchant order ID and requires a nonempty upstream trade number. It converts the response's yuan string to integer CNY minor units. The host compares this amount with the input. Status 0 yields pending and 1 yields paid. For paid orders, a present, nonempty `endtime` must be a valid civil date and time to the second. The plugin interprets it as Asia/Shanghai at fixed UTC+8 and reports UTC. Missing, null and empty paid times are omitted. Malformed identity, amount, status or time yields an unknown outcome. Query responses carry no payment instruction or expiry.

Refunds are outside the initial EPay V1 release. The upstream provides neither a refund query nor a close-payment interface. UG-8 still needs the manual refund procedure. Payment owns the outstanding decision on handling EPay orders when the upstream cannot close them.

Both sets below were recorded in temporary directories against one local test simulator. For queries, the recorder created and paid the setup orders directly through the simulator and skipped creation for the missing-order case. Each role used its corresponding host. The invalid-key case changed only the outgoing encoded key value to equally many zeroes. All query recordings retained the placeholder. Independent inspection confirmed the simulator's distinct missing-order and invalid-key responses, the 123.46 CNY mismatch, and the UTC conversion for both paid results. The 3,000 ms simulator fault exceeded the two-second transport deadline. The recorder checked all fixtures for protected values and expanded URLs before publication and replayed them with fresh credentials. The installed files matched the temporary sets byte for byte. The simulator was stopped.

| Operation | Scenario | Trading | Verification | Host error | Upstream code |
| --- | --- | --- | --- | --- | --- |
| create_payment | success | completed (pending, URL) | — | — | — |
| create_payment | rejected | rejected | — | — | epay_code_-1 |
| create_payment | signature_error | rejected | — | — | epay_code_-1 |
| create_payment | timeout | unknown | — | transport_error | — |
| query_payment | success | completed (paid, paid_at) | completed (paid, paid_at) | — | — |
| query_payment | rejected | rejected | rejected | — | epay_code_-1 |
| query_payment | signature_error | rejected | rejected | — | epay_code_-1 |
| query_payment | timeout | unknown | unknown | transport_error | — |
| query_payment | amount_mismatch | unknown | unknown | amount_mismatch | — |
| route_callback | success | completed | — | — | — |
| route_callback | malformed | not_sent | — | plugin_error | — |
| verify_callback | success | completed | — | — | — |
| verify_callback | signature_error | not_sent | — | plugin_error | — |
| verify_callback | amount_mismatch | not_sent | — | amount_mismatch | — |

All nine pre-existing cases matched `7747c9a` in category, host error, upstream code and counts of steps, requests and responses.

On aarch64-apple-darwin with Rust 1.99.1, two independent checkout and build paths reproduced all six complete packages byte for byte. The table gives the component file size and digest, and the package-format digest over fixture paths and bytes.

| Component | Bytes | Component SHA-256 | Fixture-set SHA-256 |
| --- | ---: | --- | --- |
| epay_v1 | 139,838 | `52b0848cf7f1594a4feec352fd45b4c170bac60bbe983a108960aa4b9a3f853d` | `15a2251f71df8a3317acaf3d849eb142cdde34d1851b947aacd798d370d02250` |
| epay_v1_verify | 108,715 | `7a6741b4607ae05b7a5205c7c6c547fab306d1d55584d275e1b39071815843e4` | `1c5ec88b43c2326d816305e610ec8ba3e00ddadb7ff459f1d4495edf54e3fa91` |
| sim_form_md5 | 124,760 | `4576b180aee36d2a6d0e68602dbaf7d3901bfc79c28217c3af620d80ddd4d6a9` | `6fa220ad2cc0ca5787c6a9ad07e480e227172f715d24687ac664cf05fdd3104f` |
| sim_form_md5_verify | 94,830 | `32ff97d5f420bfdb65da48b1f491c3972ba54f6a2569e2dc763f60d6dd795513` | `fe1720960f3109f0dca94972b4645e6c25b0bcebed537285bc850a7cd4dcf5c0` |
| sim_json_rsa | 115,515 | `65319b01b15532c9f38a24cb58e8172c8d380222f7c15cee8eeb8d9ecb064a9b` | `0825720e59c8a58ec16fa62dd84fdeaf5f09de287905f269ae750b92440a50f4` |
| sim_json_rsa_verify | 93,575 | `2faeb40d9c46ca8fe3234b33a08159824a7aeb455ea61cdd836e61b1205901db` | `ea422021b85216fa141fe26337158f0d39278b9a77b64460dfe143186b58d262` |

- `make bindings` reproduced the checked-in SDK bindings. The SDK diff was empty.
- `make check` passed contract checks, formatting, Clippy and tests. EPay passed 22 tests with the trade feature (16 original and six query tests) and six query tests with verification. The host passed 26 tests, the gateway passed 13 database-independent tests, and pluginctl passed 13 unit and four integration tests. A recorder test observed the expanded GET and its corrupted variant on a loopback socket and checked their saved templates.
- `make plugins replay repro` built six components, replayed all 99 cases and reproduced the packages. All 80 case records from the four simulator packages matched the reports saved before the change.
- `make deny` passed advisories, bans, licenses and sources for both workspaces, with duplicate-version warnings in the host workspace. The aggregate make command stopped at `vet` because the sandbox denied the default cache lock. Rerunning `make vet` with a writable temporary cache and the same locked audits passed with 12 fully audited packages.
- `make integration` stopped at its environment check for `AIPAY_TEST_DATABASE_URL`. The 14 PostgreSQL tests and 13 release-binary tests remain unverified in this run.
- `make bench calibrate stress` passed for all six packages. Over 100 release iterations, EPay trading's verify_callback measured 125,458 ns at p50 and 246,833 ns at p99. The verifier's query_payment measured 173,500 ns at p50 and 285,458 ns at p99. Both used 1,179,648 peak guest bytes. The EPay query calibration exercised a 100-byte order ID, the maximum signed 64-bit minor-unit amount and a 256 KiB response, reaching 7,550,518 fuel for trading and 7,549,297 for verification. Each package's 16 concurrent replay reports matched its serial baseline.

## v0.4.0 (A140) EPay V1 timeout-inferred closure

The trading plugin `epay_v1` moves from 0.2.0 to 0.3.0 and the query-only verifier `epay_v1_verify` from 0.1.0 to 0.2.0. Both manifests require the string `unpaid_timeout_seconds`. Add it to each existing trading channel and verification account before activating the new packages. The shared parser accepts ASCII decimal integers from 1 through 2592000 seconds (30 days), without signs, whitespace or leading zeroes. An invalid value fails configuration validation before dispatch.

Both roles validate the EPay response code, identity and amount as before. For numeric status 0 they interpret `addtime` as Shanghai civil time to the second (`YYYY-MM-DD HH:MM:SS`, UTC+08:00). A missing, null or invalid value, or a value more than 300 seconds ahead of the host clock, leaves the payment pending. A future timestamp within the tolerance also stays pending until its full timeout elapses. At or after `addtime + unpaid_timeout_seconds`, the result is completed with payment status `closed`, no `paid_at` and completion code `timeout_inferred_close`. Status 1 continues to report paid under the existing `endtime` rules. Other statuses yield `response_status` in the guest.

The code denotes a local inference. EPay continues to report unpaid and provides no confirmation of upstream closure. The exchange retains the raw response, including status 0 and `addtime`. The approved channel or verification configuration supplies the threshold. The gateway carries the completion code in `ExecutionResult.upstream_code` and the canonical evidence. After committing a new successful query with this code and a closed payment, the gateway emits the fixed event `gateway completion timeout_inferred_close`. Log-based metrics can count this reason separately from ordinary closure, paid results and transport timeouts.

### Recorded EPay cases

Both roles were recorded against a test simulator bound to IPv4 loopback, with an in-memory control token. Each `unpaid_closed` case created an order, left it unpaid, waited two seconds and queried it with the recorded threshold `"1"`. Relative to the raw Shanghai creation time, the recorded host clocks were 2.192179 seconds later for trading and 2.073358 seconds later for verification. The other 19 cases were re-recorded with `"2400"` (the 10-minute instruction lifetime plus the 30-minute late-payment window). Their categories, codes and step, request and response counts matched the preceding release. All 21 installed fixtures matched the recorder output byte for byte. The simulator was stopped after recording.

Replay accepts `query_payment/unpaid_closed` as an optional scenario because the policy is specific to upstreams that infer unpaid closure. It requires a response, a completed closed payment without a paid time, and the inference code. The two columns below cover 15 trading and six verification cases. Codes are present only where shown.

| Operation | Scenario | Trading | Verification | Host error | Result code |
| --- | --- | --- | --- | --- | --- |
| create_payment | success | completed (pending, URL) | — | — | — |
| create_payment | rejected | rejected | — | — | epay_code_-1 |
| create_payment | signature_error | rejected | — | — | epay_code_-1 |
| create_payment | timeout | unknown | — | transport_error | — |
| query_payment | success | completed (paid) | completed (paid) | — | — |
| query_payment | unpaid_closed | completed (closed) | completed (closed) | — | timeout_inferred_close |
| query_payment | rejected | rejected | rejected | — | epay_code_-1 |
| query_payment | signature_error | rejected | rejected | — | epay_code_-1 |
| query_payment | timeout | unknown | unknown | transport_error | — |
| query_payment | amount_mismatch | unknown | unknown | amount_mismatch | — |
| route_callback | success | completed | — | — | — |
| route_callback | malformed | not_sent | — | plugin_error | — |
| verify_callback | success | completed | — | — | — |
| verify_callback | signature_error | not_sent | — | plugin_error | — |
| verify_callback | amount_mismatch | not_sent | — | amount_mismatch | — |

### Owner follow-up

Payment still owns scheduling queries, skipping an unsupported `close_payment` operation and registering a system cancellation intent against the current hold and version. The owner must approve the per-channel threshold and enforce a lower bound of the instruction lifetime plus the late-payment window. Payment uses the configured hard upper bound for that window and reconciliation checks the actual window. Reconciliation still requires two observations separated by at least the late-payment window before authorizing cancellation. A payment received after cancellation follows UG-8 for manual seller refund and platform review.

### Components and fixture digests

Measured on aarch64-apple-darwin with Rust 1.99.1. The fixture digest covers length-prefixed package-relative paths and file bytes in package order.

| Component | Bytes | Component SHA-256 | Fixture-set SHA-256 |
| --- | ---: | --- | --- |
| epay_v1 | 140,265 | `f76b82e3879bb17836948119847c8aca4cead1aec72a261ab3a149cff8ca1853` | `0e4140f90ed8d2e8531a8fb3c72eed4543e18ea83cd4714fef904e2f70e0e2db` |
| epay_v1_verify | 109,205 | `6fb367138f1e0f03a3896ede2f1022dffe9bb7861bcaf67bb75582d1613679d7` | `e31b807c72512335a99e845f2772be733aa9df841587117ec35cd730a1ab7882` |
| sim_form_md5 | 124,760 | `4576b180aee36d2a6d0e68602dbaf7d3901bfc79c28217c3af620d80ddd4d6a9` | `6fa220ad2cc0ca5787c6a9ad07e480e227172f715d24687ac664cf05fdd3104f` |
| sim_form_md5_verify | 94,830 | `32ff97d5f420bfdb65da48b1f491c3972ba54f6a2569e2dc763f60d6dd795513` | `fe1720960f3109f0dca94972b4645e6c25b0bcebed537285bc850a7cd4dcf5c0` |
| sim_json_rsa | 115,515 | `65319b01b15532c9f38a24cb58e8172c8d380222f7c15cee8eeb8d9ecb064a9b` | `0825720e59c8a58ec16fa62dd84fdeaf5f09de287905f269ae750b92440a50f4` |
| sim_json_rsa_verify | 93,575 | `2faeb40d9c46ca8fe3234b33a08159824a7aeb455ea61cdd836e61b1205901db` | `ea422021b85216fa141fe26337158f0d39278b9a77b64460dfe143186b58d262` |

### Verification

- `make bindings` regenerated both SDK bindings. `git diff --exit-code -- guest/sdk/src` passed.
- `make check` passed the pinned contract digest check, formatting, Clippy and tests. The EPay protocol passed 25 tests with the trade feature and nine with verification. Tests cover the second before, at and after expiry, invalid and future timestamps, paid precedence and invalid configuration before dispatch. The host passed 27 tests, the gateway passed 14 database-independent tests, and pluginctl passed 13 unit and four integration tests. The new host test rejects incorrect optional-scenario expectations. The gateway test checks projection of the recorded completion code and distinguishes inferred closure from an ordinary closure or a paid result.
- `make plugins replay repro` built all six components, passed all 101 replays (21 EPay and 80 simulator cases), and reproduced all six complete packages byte for byte in two independent source and build directories. The packaged fixtures matched the source fixture paths and bytes.
- The default aggregate command stopped at `deny` because the sandbox denied the advisory database lock. A separate default `make vet` also encountered a read-only cache lock. The offline `make deny vet` rerun passed advisories, bans, licenses and sources in both workspaces and reported 12 fully audited guest packages. Deny used each workspace's policy and the default cached RustSec checkout at `d1fe6ac3eba823a3515e849045f36dc34543885d`, with its lock in a temporary directory. The host reported duplicate dependency versions. Vet used `--locked --frozen` with its default cache. All runs used the default Cargo home.
- `make integration` stopped at the environment check for `AIPAY_TEST_DATABASE_URL`. The sandbox denied the shared-memory allocation needed to initialize isolated PostgreSQL 17 and 18 instances. The 14 database tests and 13 release-binary tests were skipped. The post-commit event was not exercised against a live database in this run.
- Two additional offline replay variants per role used the recorded unpaid response. With a 2400-second threshold the query returned pending with no completion code. With the one-second threshold and a mismatched input amount the host returned unknown with `amount_mismatch` and no completion result.
- `make bench calibrate stress` passed for all six components. In 100 release benchmark iterations, EPay trading's verify_callback measured 119,000 ns at p50 and 329,917 ns at p99. The verification query measured 158,000 ns at p50 and 222,000 ns at p99. Both used 1,179,648 peak guest bytes. The maximum accepted query step used 7,552,678 fuel for trading and 7,551,476 for verification. The highest single step across all packages was 24,152,683 fuel for sim_form_md5. Each component produced 16 concurrent replay reports identical to its serial baseline.

## v0.5.0 (UG-4b part 1) Kubernetes identity and staging egress

In plaintext mode each listener checks its role-specific audience and ServiceAccount namespace mapping. The token header is stripped at the RPC boundary. Health Check and Watch share the executor lifecycle with admission and shutdown. Direct egress checks the full DNS answer. A configured CONNECT proxy receives the original hostname and owns resolution and destination address checks.

- A temporary Go module ran servicekit's `verify.go` and `jwks.go` from `origin/main` at `1266cf162fc472ed466f57065bd265fb5b81ae5e`. Rust and Go agreed on 118 token/admission decisions and 70 JWKS decisions, including reason ordering, both signature algorithms, cross-instance denial and skew boundaries. With `UG4B_VECTOR_DIR` set to a temporary directory, `cargo test --locked -p upstream-gateway --lib service_token::tests` emitted synthetic vectors. The comparison ran with `GOPROXY=off go test -count=1 -v ./internal/servicetoken` in the temporary module.
- Ring verifies RSA moduli up to 8192 bits. Rust rejects an entire JWKS containing a larger modulus. A separate 8200-bit case confirmed that Go admits that set. The gateway uses the requested lowercase gRPC message `service authentication required`. Servicekit capitalizes its first letter.
- `make bindings` and `git diff --exit-code -- guest/sdk/src` passed. `make plugins replay repro` reproduced all six packages byte for byte in separate build trees. All 101 packaged fixtures matched the checked-in bytes and passed replay. `make bench calibrate stress` passed with 16 identical concurrent reports for each plugin.
- `make check` passed. The gateway passed 21 database-independent tests. The h2c wire test observed SERVING followed by NOT_SERVING and a clean Watch close during drain. The boundary tests checked the fixed rejection message, event contents, header removal and descriptor policy. Local CONNECT tests verified the hostname, default and explicit ports, and TLS server name through a proxy serving a DNS-inaccessible target.
- `cargo test --release --locked -p upstream-gateway --test edge --no-run` compiled the real-process suite, including the projected-token StoreCredentials call and the health checks on both transports. `AIPAY_TEST_DATABASE_URL` was absent, so the PostgreSQL 18 run of `make integration` is pending in CI.
- The default deny and vet runs encountered read-only cache locks. Frozen runs with the existing RustSec snapshot at `d1fe6ac3eba823a3515e849045f36dc34543885d` passed advisories, bans, licenses and sources for both workspaces and all 12 guest audits. The complete `make check plugins replay repro deny vet` retry passed with `VET_FLAGS='--locked --frozen'` and `DENY_FLAGS='--frozen --config "$$UG4B_CHECK_DIR/$$(basename "$$PWD").toml"'`. Each temporary policy retained its workspace rules and redirected the advisory lock directory.

Development packages below were built on aarch64-apple-darwin with Rust 1.99.1 and uncommitted provenance. Fixture-set digests match the v0.4.0 table above.

| Plugin | Version | Cases | Component SHA-256 | Package SHA-256 | Replay SHA-256 |
| --- | --- | ---: | --- | --- | --- |
| sim_form_md5 | 0.3.1 | 30 | `308169a050fe34660ee58c85f538f10d1369b250171476ed8e727bbecdd03db1` | `a3babb04f728b83e1e3e5d8f7117a0fad54bfdb7b717cea6798e9049c8ef75a2` | `ce10b9787d97e109927af92097edf5195c5cc8303d5d791e26dee99f50dfe92c` |
| sim_form_md5_verify | 0.3.1 | 10 | `32ff97d5f420bfdb65da48b1f491c3972ba54f6a2569e2dc763f60d6dd795513` | `3a8b1ae8d79678fb5233f2c3aef7c304f178c8fdca6612694c97d6d086173695` | `a8fd9473835e4e8a3e766515889fa5028226d79e708cf08b8ffbdb8bc9c76a6c` |
| sim_json_rsa | 0.3.1 | 30 | `65319b01b15532c9f38a24cb58e8172c8d380222f7c15cee8eeb8d9ecb064a9b` | `5cd3084d348c1343f897fc6a0e82d67bbccf8a164a28a89d6e1724381c6926e1` | `9c595c9503c566ca471a0ba0abcfe25719143c663a91f5214b66ee38ac03994f` |
| sim_json_rsa_verify | 0.3.1 | 10 | `00bd464344627cc311d08d1a010d5cbced238e0b823b47edc66d9a09f6eb5fb2` | `2157a7351b0ab752e88eeca48ab6e3f9b76cebf2997c778efb421f81172c8a82` | `8f70e8e5942c514ba39e6495dc7e03569b2b23b273039ebd3b5634be42fed3df` |
| epay_v1 | 0.3.1 | 15 | `6b758e5e1816f4c71a776aac78b4766a04f517e8027154ea04a0fb41aba4e329` | `6055deeb965b4ab2847b24b078389b8132f1e648741d2a26c0beb09085fdb61e` | `dbf8ed3590e6dc80d0e2978d17c322e51984e47f472d31aecb2c8de376e7eb7a` |
| epay_v1_verify | 0.2.1 | 6 | `70832c0133981640ee201b5b3e1cb28112ff74c417f46140da437feab0695efd` | `06c37fd970d28dc763c71ebc5a9b408d25a11e3a26c15e55639e5db82045107b` | `ce3ab5bbf0cd26aa12a227933918ce9b14c88ad2a23b38653aec348b1c2f7cfd` |

## v0.5.0 (UG-4b part 2) Cloud KMS wrapping for gateway KEKs

Production startup exchanges the projected Kubernetes JWT at STS, impersonates the configured service account, and decrypts the role's KEK with Cloud KMS. The record path uses the existing AES-GCM vault with that in-memory key. The wrapped file accepts one current KEK because sealed records carry no KEK version. The provisioning command verifies an encrypt/decrypt round trip before emitting the file.

- `make bindings` and `git diff --exit-code -- guest/sdk/src` passed with Rust 1.99.1. `make check` passed, including 28 gateway library tests and the CLI argument test. Loopback HTTPS tests used generated certificates and credentials. They checked SNI, CONNECT by hostname, form and JSON bodies, bearer headers, the CRC32C fields, the 32-byte key length and exact output bytes. Failure cases covered redirects, non-retryable errors, bounded retries, oversized responses, invalid wrapped files and credential configurations, and redacted errors and events.
- `cargo build --locked -p upstream-gateway` built the service binary. A local CONNECT proxy returned 403 to the real `wrap-kek` command and to production startup. Each made one CONNECT, exited unsuccessfully, wrote zero bytes to stdout and reported the STS step and status on stderr. Both read a credential file with more than 64 KiB of ignored metadata. Production startup rejected a multi-key file before connecting.
- An offline `go test -v ./sealing` with the servicekit sources from `origin/main` at `1266cf162fc472ed466f57065bd265fb5b81ae5e` compared the gateway's golden file with Go's `NewKeyFile` plus a newline. The bytes matched, Go parsed the file, and the version-7 trade AAD matched the HTTPS test.
- `make plugins replay repro` passed all 101 cases across six components and reproduced the six packages byte for byte. `make bench calibrate stress` completed for every component. Each produced 16 concurrent replay reports identical to its serial report.
- `make deny vet` passed offline. Deny used frozen copies of the two workspace policies with the advisory lock in a temporary directory and the cached RustSec snapshot at `c9f6c91a44dbad9d71742329e9df061279f9c4be`. Both workspaces passed advisories, bans, licenses and sources. The host reported duplicate-version warnings. Vet used `--locked --frozen` and reported 12 fully audited guest packages. The lockfile adds direct gateway references to two already locked crates.
- Google IAM permissions, cluster egress and live KMS decryption remain deployment checks. All KMS traffic in verification was local. The separate PostgreSQL and real-service integration suite requires `AIPAY_TEST_DATABASE_URL`, which was absent.

## v0.5.0 (UG-4b part 3) Database TLS, projected issuer and gateway image

Production requires a PostgreSQL CA bundle and `sslmode=require`. The ring-backed connector verifies the chain against the configured bundle and the DNS name or IP SAN against the database host. Development also supports encryption without certificate verification and plaintext. The connector reports `ChannelBinding::none()`. The Kubernetes example reads the ServiceAccount issuer once from the projected ConfigMap, independently of JWKS reloads.

- `make bindings` and `git diff --exit-code -- guest/sdk/src` passed. The gateway tests exercised the mode/CA/URL matrix and PostgreSQL SSLRequest on loopback with generated CAs. TLS 1.2 and TLS 1.3 both accepted matching DNS and IP SANs. They rejected wrong DNS and IP SANs and an unrelated CA. The development encryption-only case accepted the unrelated server identity. Issuer coverage includes both configuration forms, both/neither errors, projected-volume symlinks, the 1 KiB boundary, invalid UTF-8, whitespace, and key reload after the issuer file is removed.
- `make check plugins replay repro deny vet bench calibrate stress` passed offline. The final `make check` also passed with 32 gateway library tests and one CLI test. All 101 replay cases passed, all six packages reproduced byte for byte, and each stress run produced 16 identical reports. Deny passed advisories, bans, licenses and sources in both workspaces with `--frozen`, the repository policies and a writable lock directory for the cached RustSec snapshot at `c9f6c91a44dbad9d71742329e9df061279f9c4be`. Vet passed with `--locked --frozen` and reported 12 fully audited guest packages.
- Five invocations of the native release binary with a projected issuer and synthetic DSNs confirmed the startup diagnostics for a missing CA, a weak SSL mode, multiple hosts, a Unix socket, and a malformed CA. Each failed before KMS access with empty stdout and the expected redacted error on stderr.
- Docker was unavailable. The exact source paths copied by the Dockerfile passed `cargo fetch --locked --offline` and `cargo build --release --locked --offline -p upstream-gateway` with Rust 1.99.1 on the native host. Source inspection confirmed that the host caches components in memory, disables Wasmtime's filesystem cache feature, and uses anonymous memory images on Linux. Building the Linux image and running it with a read-only root filesystem remain unverified.
- `cargo test --release --locked -p upstream-gateway --test edge --no-run` compiled the real-process suite. The PostgreSQL-backed integration tests remain configured for plaintext. No test DSN was supplied, and local PostgreSQL 18 initialization stopped when the sandbox denied shared-memory allocation.

## v0.6.0 (A144 ①) Connection failures before dispatch

The gateway opens the connection with the request template before authorizing an attempt. A first open failure leaves both counters at zero. A later open failure preserves the earlier dispatch count. The opened connection checks the expanded request’s scheme, host and effective port before writing it.

- `make bindings` and `git diff --exit-code -- guest/sdk/src` passed with Rust 1.99.1. Loopback tests covered direct and tunneled setup, TLS authentication, deadline and cancellation, origin changes and truncated responses.
- `make check` passed, including all six host dispatch tests and all 14 gateway egress tests, including a TCP handshake that never completes. `make plugins replay` passed all 101 cases. The six components, six manifests and 101 fixtures matched an unmodified archive of `f80dd81` byte for byte with the same uncommitted build provenance. `make repro` independently reproduced all six packages. All 17 recorded timeouts retained UNKNOWN with one request. A temporary replay copy with a recorded `transport_error` also passed that expectation.
- Default deny and vet stopped on read-only cache locks. Frozen checks passed advisories, bans, licenses and sources in both workspaces using the cached RustSec snapshot `c9f6c91a44dbad9d71742329e9df061279f9c4be` and a writable lock directory. Vet reported 12 fully audited guest packages.
- `make bench calibrate stress` passed for all six plugins. Across 100 release iterations per plugin, operation p50 ranged from 74,625 to 1,347,042 ns and p99 from 109,750 to 1,520,625 ns. Peak guest memory was 1,179,648 bytes for every plugin. The largest calibrated step used 24,152,683 fuel. Each plugin produced 16 reports identical to its serial baseline with four workers and four rounds.
- `make integration` against a disposable local PostgreSQL 18 passed 15 database-backed service tests and 15 real-binary edge tests. They include CreatePayment and QueryPayment open failures sealed as NOT_SENT with zero attempts and idempotent replay, a refused port classified NOT_SENT and a peer closing after the request classified UNKNOWN, and both SIGKILL cases.

## v0.7.0 (A144 ②) EPay V1 order not found

Both EPay plugins returned `rejected("not_found")` for the recorded missing-order query. Each fixture differed from HEAD only in its expected code. Both invalid-key recordings and the synthetic create response with the same missing-order message retained `epay_code_-1`.

- `make bindings` and `git diff --exit-code -- guest/sdk/src` passed on aarch64-apple-darwin with Rust 1.99.1.
- `make check` passed. The EPay protocol ran 29 trade tests and 12 verification tests. They covered raw and escaped messages, string codes, BOM and whitespace, ambiguous messages, non-200 status and malformed JSON. The gateway fixture test verified the fixed event label and its method, category and code conditions.
- `make plugins replay repro` passed all 101 cases and reproduced all six packages byte for byte across two build paths.
- Compared with an archive of HEAD `341f2a8`, the four simulator components, four source manifests and 80 fixtures matched byte for byte. With both builds marked `uncommitted`, each packaged simulator manifest differed only in `build.source_tree_sha256`. The source closure hashes the entire guest lockfile, including the three updated EPay versions.
- Default deny and vet encountered read-only cache locks. Frozen deny passed advisories, bans, licenses and sources for both workspaces with their existing policies, a temporary advisory lock directory and RustSec snapshot `c9f6c91a44dbad9d71742329e9df061279f9c4be`. The host reported duplicate-version warnings. Guest vet passed with `--locked --frozen` and 12 fully audited packages.
- `make bench calibrate stress` passed for all six plugins. Across 100 iterations, EPay trade callback and verification query p99 were 145,500 ns and 249,292 ns respectively. Both peaked at 1,179,648 bytes. Their maximum calibrated steps used 12,622,328 and 7,553,889 fuel. All six plugins produced 16 reports identical to their serial replay.
- The separate PostgreSQL integration target was outside this run. The standard suite skipped its 15 database-backed service tests and 15 real-process edge tests.

The following SHA-256 digests identify the local packages with `uncommitted` build provenance.

| Plugin | Package | Component | Fixture set |
| --- | --- | --- | --- |
| epay_v1 0.4.0 | `565aa4489e943df602cb736d0668f1250177aa27d89e6b964168c872d67c840d` | `d57a4bdded2fe2d00a4fc19962c8bfa4f7c2d4e779da2b39b658c6b59ec3ea3f` | `d89cfbe559ff030c4f0f7186074378470eab79fe6b924d0675fa598d1d66ee0d` |
| epay_v1_verify 0.3.0 | `ccb6095344226d4dd812acecdc212855ff5d8a5f603fa75246edef75f22d0032` | `a8a42bfd1ba7d894411808b434af51b969ce448bc425d6efe5862f1537731db5` | `1c0d9669ff7025629d37be02117f98003c4664c831134a1bc749628b0302d4ba` |

## v0.8.0 (A138) Schema migration Job

The owner runs `upstream-gateway migrate --config <path> --app-role <name>`. The Job uses the database DSN and its TLS trust configuration. Schema version 2 and the v0.7.0 fingerprint envelope format are retained. The application login checks the version and initializes or opens the singleton fingerprint key. Both development examples explicitly enable startup migration.

- `make bindings` and `git diff --exit-code -- guest/sdk/src` passed using Rust 1.99.1. `make check` passed, including the serve, wrap-kek and migration CLI tests, the production configuration guard and the migration binary's database TLS checks.
- `make plugins replay repro` passed all 101 replay cases and reproduced all six packages byte for byte. `make bench calibrate stress` passed for all six plugins. The highest calibrated step used 24,152,683 fuel. Each stress run returned 16 reports identical to its serial replay.
- Both workspaces passed frozen `make deny` for advisories, bans, licenses and sources using cached RustSec revision `c9f6c91a44dbad9d71742329e9df061279f9c4be`. The default advisory lock location was read-only. The successful run used the existing policies with a writable advisory lock directory. The host emitted duplicate-version warnings. `make vet VET_FLAGS='--locked --frozen'` passed with 12 fully audited guest packages.
- `cargo test --locked -p upstream-gateway --no-run` and `cargo test --release --locked -p upstream-gateway --test edge --no-run` compiled the PostgreSQL suites. No PostgreSQL 18 test URL was provided, so the 17 ignored service tests and 17 ignored edge tests await execution with `make integration`. New cases cover schema mismatches, repeated migrations and grant repair, a restricted login serving RPCs, denied DDL and DML, concurrent identity creation and preservation of a v0.7.0 identity.
- Deployment requires a pre-existing non-owner application login and a successful owner migration Job for each gateway schema. Configure both DSNs to select the same schema, mount the PostgreSQL CA for both workloads, and retain the existing runtime KEK and identity material.

## v0.8.0 upgrade note (2026-11-26)

- A local development stack database reported schema version 1 when v0.8.0 first started, so the gateway refused it with the "run upstream-gateway migrate" message. The README upgrade section now requires running the migration (or `migrate_on_start` in development) before the first v0.8.0 start. servicekit's native and Compose gateway configs set `migrate_on_start = true`.
