use rustc_version::version;

fn main() {
    // Get the version of Rust used to compile, this gets set as the
    // build_info metric.
    let v = version().unwrap();
    println!("cargo:rustc-env=RUSTC_VERSION={v}");
}
