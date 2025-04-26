extern crate libc;
extern crate rctl;

fn main() {
    println!("RCTL is {}", rctl::State::check());

    let uid = unsafe { libc::getuid() };

    let subject = rctl::Subject::user_id(uid);

    let usage = subject.usage().expect("Could not get RCTL usage");

    println!("{:#?}", usage);
}
