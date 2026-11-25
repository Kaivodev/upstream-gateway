fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!(
        "cargo:rustc-env=PLUGINCTL_TRIPLE={}",
        std::env::var("TARGET").unwrap()
    );
}
