extern crate regex;

#[cfg(target_os = "freebsd")]
fn main() {
    use regex::Regex;
    use std::{env, fs::File, io::Write, path::PathBuf};

    println!("cargo:rerun-if-env-changed=LLVM_CONFIG_PATH");
    println!("cargo:rustc-link-lib=nv");
    let autobindings = bindgen::Builder::default()
        .header("/usr/include/sys/nv.h")
        .allowlist_function("nvlist_.*")
        .allowlist_function("FreeBSD_nvlist_.*")
        .allowlist_type("nvlist_t")
        .allowlist_type("FreeBSD_nvlist_t")
        .blocklist_type("size_t")
        .blocklist_type("__size_t")
        .blocklist_type("__uint64_t")
        .opaque_type("FILE")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings")
        .to_string();
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // libnv.so.1 prepends a "FreeBSD_" to the names of all public symbols, but
    // achieves backwards-compatibility by #define'ing the old name to the new.
    // That allows libnv.so.1 to be linked to an application that also links to
    // libnvpair.so.  That wasn't possible with libnv.so.0.  However, bindgen
    // doesn't understand #define, so we have to post-process its output by
    // removing the "FreeBSD_" from public symbols.
    let mut fixed_bindings = String::new();
    let mut prev_index = 0;
    let re = Regex::new("pub (fn|type) FreeBSD_([a-zA-Z0-9_]+)").unwrap();
    for cap in re.captures_iter(&autobindings) {
        let index = cap.get(0).unwrap().start();
        fixed_bindings.push_str(&autobindings[prev_index..index]);
        let new_fragment = match cap.get(1).unwrap().as_str() {
            "fn" => {
                let funcname = cap.get(2).unwrap().as_str();
                fixed_bindings.push_str(&format!("#[link_name = \"FreeBSD_{}\"]\n", funcname));
                format!("pub fn {}", funcname)
            },
            "type" => {
                let typename = cap.get(2).unwrap().as_str();
                fixed_bindings
                    .push_str(&format!("pub type FreeBSD_{} = {};\n", typename, typename));
                format!("pub type {}", typename)
            },
            _ => unreachable!(),
        };
        fixed_bindings.push_str(&new_fragment);
        prev_index = index + new_fragment.len() + "FreeBSD_".len();
    }
    fixed_bindings.push_str(&autobindings[prev_index..]);

    File::create(out_path.join("bindings.rs"))
        .unwrap()
        .write_all(fixed_bindings.as_bytes())
        .expect("Couldn't write bindings!");
}

#[cfg(not(target_os = "freebsd"))]
fn main() {
    // If we're building not on FreeBSD, there's no way the build can succeed.
    // This probably means we're building docs on docs.rs, so set this config
    // variable.  We'll use it to stub out the crate well enough that
    // libnv's docs can build.
    println!("cargo:rustc-cfg=crossdocs");
}
