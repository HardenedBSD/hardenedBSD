// vim: tw=80

fn main() {
    use std::{env, path::PathBuf};

    let bindings = bindgen::Builder::default()
        .header("/usr/include/sys/param.h")
        .header("/usr/include/sys/mount.h")
        .header("/usr/include/sys/time.h")
        .header("/usr/include/nfs/nfsproto.h")
        .header("/usr/include/nfsclient/nfs.h")
        .header("/usr/include/nfsserver/nfs.h")
        .header("/usr/include/nfs/nfssvc.h")
        .header("/usr/include/fs/nfs/nfsport.h")
        .header("/usr/include/unistd.h")
        .allowlist_function("nfssvc")
        .allowlist_type("nfsstatsv1")
        .allowlist_var("NFS.*")
        .derive_default(true)
        .generate()
        .expect("Unable to generate bindings");
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
