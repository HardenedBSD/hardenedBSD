use jail::param;
use jail::process::Jailed;
use log::{error, info, warn};
use std::process::Command;

fn main() {
    pretty_env_logger::init();

    let mut stopped = jail::StoppedJail::new("/rescue")
        .name("example_basic")
        .ip("127.0.1.1".parse().expect("couldn't parse IP Addr"))
        .ip("fe80::2".parse().expect("couldn't parse IP Addr"))
        .param(
            "osrelease",
            param::Value::String("FreeBSD 42.23".to_string()),
        )
        .param("allow.raw_sockets", param::Value::Int(1))
        .param("allow.sysvipc", param::Value::Int(1));

    stopped.hostname = Some("testjail.example.org".to_string());

    let running = stopped.start().expect("Failed to start jail");

    info!("created new jail with JID {}", running.jid);

    info!(
        "the jail's path is {:?}",
        running.path().expect("could not get path")
    );

    info!(
        "the jail's jailname is '{}'",
        running.name().expect("could not get name")
    );

    info!(
        "the jail's IP addresses are: {:?}",
        running.ips().expect("could not get ip addresses")
    );

    info!("Other parameters: {:#?}", running.params().unwrap());

    info!("Let's run a command in the jail!");
    let output = Command::new("/hostname")
        .jail(&running)
        .output()
        .expect("Failed to execute command in jail");

    info!("output: {}", String::from_utf8_lossy(&output.stdout));

    match running.racct_statistics() {
        Ok(stats) => info!("Resource accounting statistics: {:#?}", stats),
        Err(jail::JailError::RctlError(rctl::Error::InvalidKernelState(state))) => {
            warn!("Resource accounting is reported as {}", state)
        }
        Err(e) => error!("Other Error: {}", e),
    };
    info!("jid before restart: {}", running.jid);
    let running = running.restart().unwrap();
    info!("jid after restart: {}", running.jid);

    running.kill().expect("Failed to stop Jail");
}
