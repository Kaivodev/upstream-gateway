use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    let upstream = root.join("aipay/upstream/v1/upstream_service.proto");
    println!("cargo:rerun-if-changed={}", upstream.display());
    println!(
        "cargo:rerun-if-changed={}",
        root.join("aipay/authz/v1/policy.proto").display()
    );
    let mut compiler = protox::Compiler::new([&root])?;
    compiler.include_imports(true).open_file(upstream)?;
    // Encoding through prost_types discards custom method options.
    let descriptor = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("upstream.bin");
    fs::write(descriptor, compiler.encode_file_descriptor_set())?;
    let mut config = tonic_prost_build::Config::new();
    config.enable_type_names();
    tonic_prost_build::configure()
        .codec_path("crate::wire::StrictCodec")
        .build_client(false)
        .build_transport(false)
        .compile_fds_with_config(compiler.file_descriptor_set(), config)?;
    println!("cargo:rerun-if-changed=health.proto");
    tonic_prost_build::configure()
        .build_client(false)
        .build_transport(false)
        .compile_fds(protox::compile(["health.proto"], ["."])?)?;
    Ok(())
}
