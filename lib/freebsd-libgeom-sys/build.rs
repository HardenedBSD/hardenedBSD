// vim: tw=80

#[cfg(target_os = "freebsd")]
fn main() {
    use std::{env, path::PathBuf};

    println!("cargo::rustc-check-cfg=cfg(crossdocs)");
    println!("cargo:rerun-if-env-changed=LLVM_CONFIG_PATH");
    println!("cargo:rustc-link-lib=geom");
    let bindings = bindgen::Builder::default()
        .header("/usr/include/libgeom.h")
        .header("/usr/include/sys/devicestat.h")
        .allowlist_function("geom_.*")
        .allowlist_function("gctl_.*")
        .allowlist_function("g_.*")
        .allowlist_type("devstat_trans_flags")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

#[cfg(not(target_os = "freebsd"))]
fn main() {
    println!("cargo::rustc-check-cfg=cfg(crossdocs)");
    // If we're building not on FreeBSD, there's no way the build can succeed.
    // This probably means we're building docs on docs.rs, so set this config
    // variable.  We'll use it to stub out the crate well enough that
    // freebsd-libgeom's docs can build.
    println!("cargo:rustc-cfg=crossdocs");
}
