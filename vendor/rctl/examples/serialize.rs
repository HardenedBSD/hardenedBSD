extern crate libc;
extern crate rctl;

#[cfg(feature = "serialize")]
extern crate serde_json;

#[cfg(feature = "serialize")]
fn main() {
    let uid = unsafe { libc::getuid() };

    let subject = rctl::Subject::user_id(uid);

    let serialized = serde_json::to_string(&subject).expect("Could not serialize RCTL subject.");

    println!("{}", serialized);
}

#[cfg(not(feature = "serialize"))]
fn main() {
    println!("Run `cargo build --features=serialize` to enable this example");
}
