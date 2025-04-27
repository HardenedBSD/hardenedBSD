#[cfg(feature = "serialize")]
use log::info;

#[cfg(feature = "serialize")]
use jail::param;

#[cfg(feature = "serialize")]
use std::str::FromStr;

#[cfg(feature = "serialize")]
fn main() {
    pretty_env_logger::init();

    let mut stopped = jail::StoppedJail::new("/rescue")
        .name("example_serializing")
        .ip("127.0.1.1".parse().expect("couldn't parse IP Addr"))
        .ip("fe80::2".parse().expect("couldn't parse IP Addr"))
        .param(
            "osrelease",
            param::Value::String("FreeBSD 42.23".to_string()),
        )
        .param("allow.raw_sockets", param::Value::Int(1))
        .param("allow.sysvipc", param::Value::Int(1));

    if rctl::State::check().is_enabled() {
        // skip setting limits when racct is not enabled
        stopped = stopped.limit(
            rctl::Resource::from_str("maxproc").expect("couldn't parse Resource name"),
            rctl::Limit::from_str("1000").expect("couldn't parse resource Limit"),
            rctl::Action::Signal(rctl::Signal::SIGTERM),
        );
    }

    stopped.hostname = Some("testjail.example.org".to_string());

    let running = stopped.start().expect("Failed to start jail");

    info!("created new jail with JID {}", running.jid);

    let stopped = running.stop().expect("Failed to stop jail");

    let serialized = serde_json::to_string_pretty(&stopped).expect("Failed to serialize jail");

    println!("{}", serialized);
}

#[cfg(not(feature = "serialize"))]
fn main() {
    println!("Run `cargo build --features=serialize` to enable this example.");
}
