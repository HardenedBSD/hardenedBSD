# `jail_exporter`

## v0.17.0

  - Update MSRV to 1.70.0
  - Implement `axum::response::IntoResponse` for `HttpdError`
  - Updated FreeBSD versions for CI runs, now run on 14.0 and 13.2
  - Switch from [users] crate to [uzers]

## v0.16.1

  - Switch from [log] and [env_logger] to [tracing] and [tracing-subscriber]
  - Bump crate versions

## v0.16.0

  - Update all crate versions, and disable some unused crate features
  - Add FreeBSD 12.3 to the test matrix
  - Move `rc_script` functionality to its own file
  - Move `bcrypt` command functionality to its own file
  - Remove [mime] crate dependency
  - Replace dev-dependency [lazy-static] with [once_cell]
  - Bump MSRV to 1.64.0
  - Move to official [prometheus-client] Rust crate
  - Update to [clap] 4.2
  - Change exposition format to [OpenMetrics] 1.0.0
  - Mutexes now use [parking_lot]
  - Switch from [actix-web] to [axum]

## v0.15.1

  - Remove FreeBSD 11.4 from CI configuration as its no longer supported
  - Update to [prometheus] 0.13.0
  - Update to [pretty-assertions] 1.0
  - Fixed a typo in the man page (thanks, Schueni1)
  - Use the new custom registry macros from [prometheus] and remove our own
    versions

## v0.15.0

  - Add FreeBSD 13.0 as a build environment in CI.
  - Bump all dependency versions.
  - Bump MSRV to 1.51.0
  - Set `resolver` version to `2` in `Cargo.toml`, we may as well since
    dependencies have bumped our MSRV to 1.51.0.
  - Update [jail] and [rctl] crates to 0.2.0.
  - Resolve various clippy issues.

## v0.14.0

  - Update dependencies.
  - The MSRV has been bumped to 1.44.0 as required by dependencies.
  - Fix some minor [clippy] issues.
  - exporter: Remove a clone from metric bookkeeping.
  - exporter: Avoid using clone when creating exporter metrics struct.
  - Change environment variables, removing the `JAIL_EXPORTER_` prefix.
  - Added `rc_script` feature, enabling a `--rc-script` CLI flag which outputs
    the `jail_exporter` [`rc(8)`] script on stdout.
  - Added `auth` feature, enabling HTTP Basic authentication.
    - Configuration for the HTTP Basic authentication is via a YAML
      configuration file, the location of the configuration is specified via
      the `--web.auth-config` CLI argument.
  - Added `bcrypt` subcommand when compiled with the `auth` feature.
    - This is to assist users when they're enabling HTTP Basic Authentication
      as they may not have tools installed for generating bcrypt hashes.

## v0.13.0

  - Update to [prometheus] 0.9.0.
  - The MSRV (minimum supported Rust version) has been bumped to 1.40.0, as
    `cargo msrv` shows some dependencies now require this.
  - Added a `rustversion` label to the `jail_exporter_build_info` time series,
    showing which version of Rust was used to compile Jail Exporter.

## v0.12.0

  - Update to [prometheus] 0.8.0.
  - Remove [FreeBSD] 12.0 image from the test matrix, as it is EOL.
  - Update to [users] 0.10.0.

## v0.11.0

  - Switch from [failure] crate to [thiserror].
  - Minimum Rust version bumped to 1.39.0 as we use:
    - `enum` type aliases
    - `async`/`await` for `actix-web` 2.0
  - Added basic [Grafana] dashboard example.
  - Update to [actix-web] 2.0.
  - Update [FreeBSD] images used for CI testing.
  - Simplified template error handling.

## v0.10.0

  - Update to [prometheus] 0.7.0.
  - Update to [actix-web] 1.0.8.
  - Update to [jail] 0.1.1.
  - Bump minimum version of Rust to 1.34.0 in README, due to actix-web update.
  - Add `output.file-path` argument which allows writing metrics to either a
    file or stdout.
  - Internals: Move CLI parsing functions to `cli.rs`.

## v0.9.10

  - No code changes.
  - Added `exporter_build_info` metric to man page.
  - `rc.d` script is now a `.in` file, suitable for use in ports.
  - Fixes to `rc.d` script.
  - Tighten permissions on `.pid` file in `rc.d` script, matching permission
    of other daemons that run as root.

## v0.9.9

  - No code changes.
  - Changes to `Cargo.toml` for publishing on [crates.io].

## v0.9.8

  - Added [pretty-assertions] for tests.
  - Use [Cirrus CI] to run `cargo test` on push.
  - Update [prometheus] crate to 0.6.0.
  - Move to using a local metrics registry, which makes testing much more
    reliable.
  - Implement local macros for registering metrics with local registry.
  - Simplify `dead_jails` method in `Exporter` and add test.
  - Add test for `reap` method in `Exporter`.
  - Add locking around environment tests to fix race conditions.
  - Improve CLI testing by passing our own argv in a few cases.
  - Use [mime] crate for ContentTypes in HTTP handlers.
  - Update [jail] to 0.1.0.

## v0.9.7

  - Additional testing around CLI argument environment variables.
  - Additional testing around HTTP handling.
  - Minor style clean up.
  - Version bumps in `Cargo.lock`.
  - Fixing of some incorrect comments.
  - Updated to [askama] 0.8.
  - Updated to [users] 0.9.1.
  - Add testing for `is_running_as_root()` function.
  - Break out various parts of `httpd` module into sub-modules.
    - `handlers`: Route handlers used by the server.
    - `templates`: Renders templates used elsewhere.

## v0.9.6

  - Improvements to error handling in `lib.rs` which should allow an "Internal
    Server Error" to be generated in `httpd.rs` the event of any issues.
  - Minor documentation improvements.
  - Simplify handling of `bind_address` in `httpd` module.
  - Noted in `README.md` that minimum version of Rust is now 1.32.
  - Add `Cargo.lock` to repository.

## v0.9.5

  - Attempts at taking care of some [clippy] warnings.
  - Change templating library from [handlebars] to [askama].
  - Move exporter into the `AppState` struct, removing the requirement for
    [lazy_static] in the release binaries.
  - Created a `jail_exporter(8)` man page.
  - Move some helper code out of `main` into their own functions.
  - Moved HTTP related code out to `httpd` module, simplifying `main` function.
  - `jail_exporter::Metrics` is now `#[derive(Clone)]`
  - Fixed a bug where Metrics would attempt initialization once per Actix Web
    thread.
  - Added Actix Web Logger middleware to HTTP server.
  - `jail_exporter` now attempts to ensure that it's running as `root` before
    starting.
  - Updated to version 0.5 of the [prometheus] crate.
  - Now using a builder pattern for the HTTP server instead of multiple
    arguments to a run function.
  - Added a validator for the `web.telemetry-path` setting.
  - Moved to using [failure] crate and removed explicit `exit` calls on error
    conditions by using `Result` return on `main` function.

## v0.9.0

  - Implemented landing page at HTTP web root which simply links to the
    `--web.telemetry-path`. This makes viewing exporter output from a browser
    a slightly more friendly experience.
  - Declare `#![forbid(unsafe_code)]` as we aren't implementing any `unsafe`
    blocks directly.
  - Update to `env_logger` 0.6 and `lazy_static` 1.2.

## v0.8.0

  - Added `CHANGELOG.md`
  - Updated to Rust 1.31 and 2018 edition.
  - Added [FreeBSD] `rc.d` script.
  - Switched from [warp] to [actix-web] for HTTP related functions.
  - Update to [jail] 0.0.6 and [rctl] 0.0.5.
  - Deal with errors if HTTP server can't bind to address.
  - Simplify metrics HTTP response handler.
  - Provided more metadata in `Cargo.toml`.

<!-- links -->
[actix-web]: https://crates.io/crates/actix-web
[askama]: https://crates.io/crates/askama
[axum]: https://crates.io/crates/axum
[clap]: https://crates.io/crates/clap
[clippy]: https://github.com/rust-lang/rust-clippy
[crates.io]: https://crates.io/
[env_logger]: https://crates.io/crates/env_logger
[failure]: https://crates.io/crates/failure
[handlebars]: https://crates.io/crates/handlebars
[jail]: https://crates.io/crates/jail
[lazy_static]: https://crates.io/crates/lazy_static
[log]: https://crates.io/crates/log
[mime]: https://crates.io/crates/mime
[once_cell]: https://crates.io/crates/once_cell
[parking_lot]: https://crates.io/crates/parking_lot
[pretty-assertions]: https://crates.io/crates/pretty-assertions
[prometheus]: https://crates.io/crates/prometheus
[prometheus-client]: https://crates.io/crates/prometheus-client
[rctl]: https://crates.io/crates/rctl
[thiserror]: https://github.com/dtolnay/thiserror
[tracing]: https://crates.io/crates/tracing
[tracing-subscriber]: https://crates.io/crates/tracing-subscriber
[users]: https://crates/io/crates/users
[uzers]: https://crates/io/crates/uzers
[warp]: https://crates.io/crates/warp
[Cirrus CI]: https://cirrus-ci.org/
[FreeBSD]: https://www.freebsd.org/
[Grafana]: https://grafana.com/grafana/
[OpenMetrics]: https://github.com/OpenObservability/OpenMetrics/blob/main/specification/OpenMetrics.md
[`rc(8)`]: https://man.freebsd.org/rc(8)
