// cli: Command line interface parsing
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use clap::{
    crate_description,
    crate_name,
    crate_version,
    Arg,
    ArgAction,
    ArgMatches,
    Command,
};
use tracing::debug;

mod validator;

// Create a clap app
fn create_app() -> Command {
    debug!("Creating clap app");

    let app = Command::new(crate_name!())
        .version(crate_version!())
        .about(crate_description!())
        .term_width(80)
        .arg(
            Arg::new("OUTPUT_FILE_PATH")
                .action(ArgAction::Set)
                .env("OUTPUT_FILE_PATH")
                .hide_env_values(true)
                .long("output.file-path")
                .value_name("FILE")
                .help("File to output metrics to.")
                .value_parser(validator::is_valid_output_file_path)
        )
        .arg(
            Arg::new("WEB_LISTEN_ADDRESS")
                .action(ArgAction::Set)
                .default_value("127.0.0.1:9452")
                .env("WEB_LISTEN_ADDRESS")
                .help("Address on which to expose metrics and web interface.")
                .hide_env_values(true)
                .long("web.listen-address")
                .value_name("[ADDR:PORT]")
                .value_parser(validator::is_valid_socket_addr)
        )
        .arg(
            Arg::new("WEB_TELEMETRY_PATH")
                .action(ArgAction::Set)
                .default_value("/metrics")
                .env("WEB_TELEMETRY_PATH")
                .help("Path under which to expose metrics.")
                .hide_env_values(true)
                .long("web.telemetry-path")
                .value_name("PATH")
                .value_parser(validator::is_valid_telemetry_path)
        );

    #[cfg(feature = "auth")]
    let app = app.arg(
        Arg::new("WEB_AUTH_CONFIG")
            .action(ArgAction::Set)
            .env("WEB_AUTH_CONFIG")
            .help("Path to HTTP Basic Authentication configuration")
            .hide_env_values(true)
            .long("web.auth-config")
            .value_name("CONFIG")
            .value_parser(validator::is_valid_basic_auth_config_path)
    );

    #[cfg(feature = "bcrypt_cmd")]
    let app = {
        let bcrypt = Command::new("bcrypt")
            .about("Returns bcrypt encrypted passwords suitable for HTTP Basic Auth")
            .arg(
                Arg::new("COST")
                    .action(ArgAction::Set)
                    .default_value("12")
                    .help("Computes the hash using the given cost")
                    .long("cost")
                    .short('c')
                    .value_name("COST")
                    .value_parser(validator::is_valid_bcrypt_cost)
            )
            .arg(
                Arg::new("LENGTH")
                    .action(ArgAction::Set)
                    .default_value("32")
                    .help("Specify the random password length")
                    .long("length")
                    .short('l')
                    .value_parser(validator::is_valid_length)
            )
            .arg(
                Arg::new("RANDOM")
                    .action(ArgAction::SetTrue)
                    .help("Generate a random password instead of having to \
                           specify one")
                    .long("random")
                    .short('r')
            )
            .arg(
                Arg::new("PASSWORD")
                    .action(ArgAction::Set)
                    .help("The password to hash using bcrypt, a prompt is \
                           provided if this is not specified")
                    .value_name("PASSWORD")
                    .value_parser(validator::is_valid_password)
            );

        app.subcommand(bcrypt)
    };

    #[cfg(feature = "rc_script")]
    let app = app
        .arg(
            Arg::new("RC_SCRIPT")
                .action(ArgAction::SetTrue)
                .help("Dump the jail_exporter rc(8) script to stdout")
                .long("rc-script")
        );

    app
}

// Parses the command line arguments and returns the matches.
pub fn parse_args() -> ArgMatches {
    debug!("Parsing command line arguments");

    create_app().get_matches()
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use parking_lot::Mutex;
    use pretty_assertions::assert_eq;
    use std::env;
    use std::panic;

    // Used during env_tests
    static LOCK: Lazy<Mutex<i8>> = Lazy::new(|| Mutex::new(0));

    // Wraps setting and unsetting of environment variables
    fn env_test<T>(key: &str, var: &str, test: T) -> ()
    where T: FnOnce() -> () + panic::UnwindSafe {
        // This ensures that only one test can be manipulating the environment
        // at a time.
        let _locked = LOCK.lock();

        env::set_var(key, var);

        let result = panic::catch_unwind(|| {
            test()
        });

        env::remove_var(key);

        assert!(result.is_ok())
    }

    #[test]
    fn default_web_listen_address() {
        // Must lock since we're still testing env vars here even though we're
        // not setting one.
        let _locked = LOCK.lock();

        let argv = vec!["jail_exporter"];
        let matches = create_app().get_matches_from(argv);
        let listen_address = matches.get_one::<String>("WEB_LISTEN_ADDRESS");

        assert_eq!(listen_address, Some(&"127.0.0.1:9452".into()));
    }

    #[test]
    fn default_web_telemetry_path() {
        // Must lock since we're still testing env vars here even though we're
        // not setting one.
        let _locked = LOCK.lock();

        let argv = vec!["jail_exporter"];
        let matches = create_app().get_matches_from(argv);
        let telemetry_path = matches.get_one::<String>("WEB_TELEMETRY_PATH");

        assert_eq!(telemetry_path, Some(&"/metrics".into()));
    }

    #[test]
    fn cli_set_web_listen_address() {
        let argv = vec![
            "jail_exporter",
            "--web.listen-address=127.0.1.2:9452",
        ];

        let matches = create_app().get_matches_from(argv);
        let listen_address = matches.get_one::<String>("WEB_LISTEN_ADDRESS");

        assert_eq!(listen_address, Some(&"127.0.1.2:9452".into()));
    }

    #[test]
    fn cli_override_env_web_listen_address() {
        env_test("WEB_LISTEN_ADDRESS", "127.0.1.2:9452", || {
            let argv = vec![
                "jail_exporter",
                "--web.listen-address=127.0.1.3:9452",
            ];

            let matches = create_app().get_matches_from(argv);
            let listen_address = matches.get_one::<String>("WEB_LISTEN_ADDRESS");

            assert_eq!(listen_address, Some(&"127.0.1.3:9452".into()));
        });
    }

    #[test]
    fn cli_override_env_web_telemetry_path() {
        env_test("WEB_TELEMETRY_PATH", "/envvar", || {
            let argv = vec![
                "jail_exporter",
                "--web.telemetry-path=/clioverride",
            ];

            let matches = create_app().get_matches_from(argv);
            let listen_address = matches.get_one::<String>("WEB_TELEMETRY_PATH");

            assert_eq!(listen_address, Some(&"/clioverride".into()));
        });
    }

    #[test]
    fn cli_set_web_telemetry_path() {
        let argv = vec![
            "jail_exporter",
            "--web.telemetry-path=/test",
        ];

        let matches = create_app().get_matches_from(argv);
        let telemetry_path = matches.get_one::<String>("WEB_TELEMETRY_PATH");

        assert_eq!(telemetry_path, Some(&"/test".into()));
    }

    #[test]
    fn env_set_web_listen_address() {
        env_test("WEB_LISTEN_ADDRESS", "127.0.1.2:9452", || {
            let argv = vec!["jail_exporter"];
            let matches = create_app().get_matches_from(argv);
            let listen_address = matches.get_one::<String>("WEB_LISTEN_ADDRESS");

            assert_eq!(listen_address, Some(&"127.0.1.2:9452".into()));
        });
    }

    #[test]
    fn env_set_web_telemetry_path() {
        env_test("WEB_TELEMETRY_PATH", "/test", || {
            let argv = vec!["jail_exporter"];
            let matches = create_app().get_matches_from(argv);
            let telemetry_path = matches.get_one::<String>("WEB_TELEMETRY_PATH");

            assert_eq!(telemetry_path, Some(&"/test".into()));
        });
    }
}
