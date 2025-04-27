use jail::process::Jailed;
use std::process::Command;

fn main() {
    let jail = jail::StoppedJail::new("/rescue")
        .name("testjail_defer_cleanup")
        .start()
        .expect("could not start jail");

    let mut child = Command::new("/sleep")
        .arg("3")
        .jail(&jail)
        .spawn()
        .expect("Failed to execute command");

    jail.defer_cleanup().expect("could not defer cleanup");

    child.wait().expect("Could not wait for child.");

    jail.kill().expect_err("Jail should be dead by now.");
}
