#[cfg(target_os = "freebsd")]
fn main() {
    use std::{env, process::Command};

    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_OS");
    println!("cargo::rustc-check-cfg=cfg(have_fspacectl)");

    // When self-compiling, enable fspacectl if the build host is FreeBSD 14+
    // This is easier than using bindgen, which pulls in tons of dependencies.
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "freebsd" {
        let output = Command::new("freebsd-version")
            .arg("-u")
            .output()
            .expect("Failed to execute freebsd-version");
        let v = String::from_utf8_lossy(&output.stdout);
        if let Some((major, _)) = v.split_once('.') {
            if let Ok(major) = major.parse::<i32>() {
                if major >= 14 {
                    println!("cargo:rustc-cfg=have_fspacectl");
                }
            }
        }
    }
}

// When cross-compiling, never enable fspacectl
#[cfg(not(target_os = "freebsd"))]
fn main() {
    println!("cargo::rustc-check-cfg=cfg(have_fspacectl)");
}
