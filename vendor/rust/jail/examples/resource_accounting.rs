use jail::process::Jailed;
use std::process::{Command, Stdio};
use std::{thread, time};

fn main() {
    if !rctl::State::check().is_enabled() {
        // If we don't have RCTL, let's just skip this test.
        panic!("Need RCTL for this example!");
    }

    let stopped = jail::StoppedJail::new("/").name("example_racct");

    let running = stopped.start().expect("Failed to start jail");

    println!("created new jail with JID {}", running.jid);

    println!("Let's run a command that burns CPU cycles in the jail!");
    Command::new("/usr/bin/yes")
        .jail(&running)
        .stdout(Stdio::null())
        .spawn()
        .expect("Failed to execute command in jail");

    for _ in 1..10 {
        thread::sleep(time::Duration::from_millis(1000));
        match running.racct_statistics() {
            Ok(stats) => println!("Resource accounting statistics: {:#?}", stats),
            Err(jail::JailError::RctlError(rctl::Error::InvalidKernelState(state))) => {
                println!("Resource accounting is reported as {}", state)
            }
            Err(e) => {
                println!("Other Error: {}", e);
                break;
            }
        };
    }

    running.kill().expect("Could not kill jail");
}
