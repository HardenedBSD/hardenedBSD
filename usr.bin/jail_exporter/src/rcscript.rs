// rcscript: Handle dumping the rc script
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use std::io::{
    self,
    Write,
};
use tracing::debug;

const RC_SCRIPT: &str = include_str!("../rc.d/jail_exporter.in");

pub fn output() {
    debug!("Dumping rc(8) script to stdout");

    // The script we included is the one that we use for the ports tree, so
    // we need to replace %%PREFIX%% with a reasonable prefix.
    let output = RC_SCRIPT.replace("%%PREFIX%%", "/usr/local");

    io::stdout().write_all(output.as_bytes()).expect("writable stdout");
}
