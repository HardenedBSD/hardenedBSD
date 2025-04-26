use crate::param;
use crate::process::Jailed;
use crate::running::RunningJail;
use crate::stopped::StoppedJail;
use rctl;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

#[cfg(feature = "serialize")]
#[test]
fn test_serializing_jail() {
    let rctl_enabled = rctl::State::check().is_enabled();

    let mut stopped = StoppedJail::new("/")
        .name("testjail_serializing")
        .ip("127.0.1.1".parse().expect("couldn't parse IP Addr"))
        .param(
            "osrelease",
            param::Value::String("FreeBSD 42.23".to_string()),
        );

    if rctl_enabled {
        // Skip setting limits if racct is disabled.
        stopped = stopped.limit(
            rctl::Resource::Wallclock,
            rctl::Limit::amount(1),
            rctl::Action::Signal(rctl::Signal::SIGKILL),
        );
    }

    let serialized = serde_json::to_string(&stopped).expect("could not serialize jail");

    let output: serde_json::Value =
        serde_json::from_str(&serialized).expect("could not parse serialized string");

    assert_eq!(output["name"], "testjail_serializing");
    assert_eq!(output["ips"][0], "127.0.1.1");
    assert_eq!(
        output["params"]["osrelease"]["String"]
            .as_str()
            .expect("could not read jails parameter value"),
        "FreeBSD 42.23"
    );

    if rctl_enabled {
        let limits = &output["limits"][0];
        assert_eq!(limits[0], "Wallclock");
        assert_eq!(limits[1]["amount"], 1);
        assert_eq!(limits[2]["Signal"], "SIGKILL")
    }
}

#[test]
fn test_rctl_yes() {
    if !rctl::State::check().is_enabled() {
        // If we don't have RCTL, let's just skip this test.
        return;
    }

    let running = StoppedJail::new("/")
        .name("testjail_rctl_yes")
        .limit(
            rctl::Resource::Wallclock,
            rctl::Limit::amount(1),
            rctl::Action::Signal(rctl::Signal::SIGKILL),
        )
        .start()
        .expect("Could not start Jail");

    // this should hang until killed by the limit
    let output = Command::new("/usr/bin/yes")
        .jail(&running)
        .output()
        .expect("Failed to start yes command");

    assert!(output.status.code() == None);
    assert!(output.status.signal() == Some(9));

    println!("{:?}", output);

    running.stop().expect("Could not stop Jail");
}

#[test]
fn test_name_nonexistent_jail() {
    // Assume Jail 424242 is not running
    let r: RunningJail = RunningJail::from_jid_unchecked(424242);

    r.name()
        .expect_err("Could get name for jail 424242 which should not be running.");
}

#[test]
fn test_params_nonexistent_jail() {
    // Assume Jail 424242 is not running
    let r: RunningJail = RunningJail::from_jid_unchecked(424242);

    r.params()
        .expect_err("Could get name for jail 424242 which should not be running.");
}

#[test]
fn test_vnet_jail() {
    use sysctl::{Ctl, CtlValue::String, Sysctl};

    let ctl = Ctl::new("kern.osrelease")
        .expect("Failed to read kern.osrelease sysctl")
        .value()
        .expect("Failed to parse kern.osrelease sysctl");

    let version = match ctl {
        String(value) => value[0..2].parse::<u32>(),
        _ => Ok(0),
    }
    .unwrap_or(0);

    if version < 12 {
        // Earlier versions do not support vnet flag, skipping.
        return;
    }

    let running = StoppedJail::new("/")
        .name("vnet_jail")
        .param("vnet", param::Value::Int(1))
        .start()
        .expect("Could not start Jail");

    running.stop().expect("Could not stop Jail");
}
