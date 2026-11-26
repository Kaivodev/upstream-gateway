ARG COMMIT
FROM rust:1.99.1-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS build
WORKDIR /build
# upstream-host/build.rs embeds the WIT worlds using the pinned component CLI.
RUN cargo install --locked wasm-tools@1.263.0
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY guest/sdk/ guest/sdk/
COPY wit/ wit/
COPY proto/ proto/
RUN cargo fetch --locked
RUN --network=none cargo build --release --locked --offline -p upstream-gateway

FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8
COPY --from=build /build/target/release/upstream-gateway /app/upstream-gateway
USER 65532:65532
ENTRYPOINT ["/app/upstream-gateway"]
CMD ["--config", "/run/kaivo/inputs/gateway.toml"]
