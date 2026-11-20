// Materialize the reference component types for structural admission checks.
use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=../../wit/kaivo-upstream.wit");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    for world in ["trade-plugin", "verification-plugin"] {
        let core = out.join("reference.core.wasm");
        let component = out.join(format!("{world}.wasm"));
        assert!(
            Command::new("wasm-tools")
                .args([
                    "component",
                    "embed",
                    "../../wit",
                    "--world",
                    world,
                    "--dummy",
                    "-o"
                ])
                .arg(&core)
                .status()
                .unwrap()
                .success()
        );
        assert!(
            Command::new("wasm-tools")
                .args(["component", "new"])
                .arg(core)
                .arg("-o")
                .arg(component)
                .status()
                .unwrap()
                .success()
        );
    }
}
