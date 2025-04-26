//!
//! `jail_exporter`
//!
//! An exporter for Prometheus, exporting jail metrics as reported by rctl(8).
//!
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::redundant_field_names)]
use tracing::debug;
use uzers::UsersCache;

#[cfg(feature = "auth")]
use std::path::PathBuf;

mod cli;
mod errors;
mod exporter;
mod file;
mod httpd;
mod racctrctl;
mod rctlstate;
mod user;

#[macro_use]
mod macros;

#[cfg(feature = "bcrypt_cmd")]
mod bcrypt;

#[cfg(feature = "rc_script")]
mod rcscript;

use errors::ExporterError;
use exporter::Exporter;
use file::{
    FileExporter,
    FileExporterOutput,
};

#[cfg(feature = "auth")]
use httpd::auth::BasicAuthConfig;

#[tokio::main]
async fn main() -> Result<(), ExporterError> {
    // We do as much as we can without checking if we're running as root.
    tracing_subscriber::fmt::init();

    // Parse the commandline arguments.
    let matches = cli::parse_args();

    #[cfg(feature = "rc_script")]
    // If we have been asked to dump the rc(8) script, do that, and exit.
    if matches.get_flag("RC_SCRIPT") {
        rcscript::output();

        ::std::process::exit(0);
    }

    #[cfg(feature = "bcrypt_cmd")]
    // If we have the auth feature, we can bcrypt passwords for the user.
    if let Some(subcmd) = matches.subcommand_matches("bcrypt") {
        bcrypt::generate_from(subcmd)?;

        ::std::process::exit(0);
    }

    // Root is required beyond this point.
    // Check that we're running as root.
    user::is_running_as_root(&mut UsersCache::new())?;

    // Check if RACCT/RCTL is available and if it's not, exit.
    racctrctl::is_available()?;

    // If an output file was specified, we do that. We will never launch the
    // HTTPd when we're passed an OUTPUT_FILE_PATH.
    if let Some(output_path) = matches.get_one::<FileExporterOutput>("OUTPUT_FILE_PATH") {
        debug!("output.file-path: {}", output_path);

        let exporter = FileExporter::new(output_path.clone());

        return exporter.export();
    }

    // Get the bind_address for the httpd::Server below.
    // We shouldn't hit the error conditions here after the validation of the
    // CLI arguments passed.
    let bind_address = matches.get_one::<String>("WEB_LISTEN_ADDRESS")
        .ok_or_else(|| {
            ExporterError::ArgNotSet("web.listen-address".to_owned())
        })?.clone();
    debug!("web.listen-address: {}", bind_address);

    // Get the WEB_TELEMETRY_PATH and turn it into an owned string for moving
    // into the httpd::Server below.
    // We shouldn't hit the error conditions here after the validation of the
    // CLI arguments passed.
    let telemetry_path = matches.get_one::<String>("WEB_TELEMETRY_PATH")
        .ok_or_else(|| {
            ExporterError::ArgNotSet("web.telemetry-path".to_owned())
        })?.clone();

    debug!("web.telemetry-path: {}", telemetry_path);

    // Start configuring HTTP server.
    // unused_mut here silences a warning if the crate is compiled without auth
    // support.
    #[allow(unused_mut)]
    let mut server = httpd::Server::new()
        .bind_address(bind_address)
        .telemetry_path(telemetry_path);

    #[cfg(feature = "auth")]
    // Set the configuration file for HTTP Basic Auth
    if let Some(path) = matches.get_one::<PathBuf>("WEB_AUTH_CONFIG") {
        let config = BasicAuthConfig::from_yaml(path)?;

        server = server.auth_config(config);
    }

    let exporter = Exporter::new();
    server.run(exporter).await?;

    Ok(())
}
