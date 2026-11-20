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
