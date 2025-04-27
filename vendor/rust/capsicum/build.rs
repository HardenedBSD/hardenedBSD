use std::env;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(nightly)");
    if env::var("CARGO_CFG_TARGET_OS").unwrap() != "freebsd" {
        panic!("This is a FreeBSD only crate. It will not compile for other operating systems.");
    }
    if version_check::is_feature_flaggable() == Some(true) {
        println!("cargo:rustc-cfg=nightly")
    }
}
