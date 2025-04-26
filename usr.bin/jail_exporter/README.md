# Jail Exporter

[![Build Status]](https://cirrus-ci.com/github/phyber/jail_exporter)

## Description

Jail Exporter is a [Prometheus] exporter for [FreeBSD] jail metrics as reported
by [`rctl(8)`].

The exporter is written in [Rust] and uses the [jail] and [rctl] crates to
discover jails and obtain metrics.

## Installation

### `pkg(8)` and Ports

`jail_exporter` is available in the FreeBSD ports tree as
`sysutils/jail_exporter`. It can be installed by either the binary package with
`pkg install jail_exporter`, or by compiling the package yourself in the ports
tree.

### Cargo Install

The crate is also available via [crates.io], and can be installed using the
`cargo install` command. However, it is heavily recommended to install the
exporter via `pkg(8)` or the ports tree.

```shell
$ cargo install jail_exporter
```

When installing via this method, you may want to move the installed binary to
`/usr/local/sbin` and obtain an appropriate [`rc(8)`] to start the exporter on
system boot. You can do this as follows:

```shell
# Performed as root.
$ mv ~/.cargo/bin/jail_exporter /usr/local/sbin/
$ chown root:wheel /usr/local/sbin/jail_exporter
$ jail_exporter --rc-script | tee /usr/local/etc/rc.d/jail_exporter
$ chmod 755 /usr/local/etc/rc.d/jail_exporter
```

### Enabling at System Boot

You can enable `jail_exporter` to start at system boot via [`rc.conf(5)`].

```shell
# Either edit /etc/rc.conf directly or use the following command
sysrc jail_exporter_enable=YES
```

## Building

At a minimum, building Jail Exporter should require:

  - Rust v1.74.1 (MSRV)
  - Cargo

A BSD [`make(1)`] Makefile is provided for convenience, if you already have
Rust and Cargo available, executing `make` will build a debug release of Jail
Exporter at `target/debug/jail_exporter`. `make release` will build a release
version at `target/release/jail_exporter`.

If you don't wish to use `make(1)`, the usual `cargo build` command should work
just fine.

## Configuration

Configuration can be performed either via command line arguments or environment
variables.  If both an environment variable and a command line argument are
provided for the same option, the configuration will be taken from the command
line argument.

### Command Line Arguments

Argument               | Default          | Purpose
-----------------------|------------------|--------
`--output.file-path`   | N/A              | Output metrics to a file instead of running an HTTPd.
`--rc-script`          | N/A              | Output an appropriate rc.d script
`--web.auth-config`    | N/A              | HTTP Basic authentication configuration file.
`--web.listen-address` | `127.0.0.1:9452` | Address on which to expose metrics and web interface.
`--web.telemetry-path` | `/metrics`       | Path under which to expose metrics.

### Environment variables

Variable             | Equivalent Argument
---------------------|--------------------
`OUTPUT_FILE_PATH`   | `output.file-path`
`WEB_AUTH_CONFIG  `  | `web.auth-config`
`WEB_LISTEN_ADDRESS` | `web.listen-address`
`WEB_TELEMETRY_PATH` | `web.telemetry-path`

### HTTP Basic Authentication

HTTP Basic Authentication is available when the crate is compiled with the
`auth` feature. This feature is enabled by default.

The configuration file format is the same as specified in [`exporter-toolkit`].

```yaml
---
basic_auth_users:
    username: 'bcrypt hashed secret'
    another_user: 'bcrypt hashed secret'
```

If no configuration is specified, or the configuration is specified but
contains no users, authentication will be disabled.

While loading the configuration, usernames will be checked for compliance with
[RFC7617]. If any invalid usernames are detected, `jail_exporter` will error
out and refuse to start.

User passwords are [bcrypt] hashed secrets, which can be generated with the
`bcrypt` subcommand if `jail_exporter` was compiled with the `bcrypt_cmd`
feature (enabled by default).

```shell
# Generate a password by specifying it on the CLI 
$ jail_exporter bcrypt foobar
Hash: $2b$12$kSOSps7NIQaEQi2CXb.Ll.qYQZ3pCK7NDWKUH7QvHzprUyLHL6tsq

# Generate a password via an interactive prompt
# The password will be prompted for and then confirmed
$ jail_exporter bcrypt
Password: [hidden]
Hash: $2b$12$/5ghhZFShmhrq5W4tE1hnubk/xgGH0MmixxQeKwSGx0g7kjDFL2hq

# Generate a random password
# The random plaintext password will also be output.
$ jail_exporter bcrypt --random
Password: TiFRz4rg6JHdRunnIFm2aB3uNa0OnlU7
Hash: $2b$12$dyK2iA1Yq1ToA9AWtjg96exmvLABj05DuB1V5a4haUOZvu2.Hvbo2
```

The cost for the password hashing can be controlled with the `--cost` argument
to the `bcrypt` subcommand and defaults to `12`. This default it taken from the
bcrypt crate and should be tuned for the computer the hashing will be running
on, as this cost will be paid each time a connection is authenticated.

## Running

The exporter needs to run as `root` in order to have enough permission to
execute the [`rctl_get_racct(2)`] calls.  If it is not run as `root`, it will
complain and exit.

As jails may come and go during the lifetime of the exporter, so to will the
time series that the exporter exports.  If you wish to account for resource
usage for jails that have disappeared, you may wish to make use of the
Prometheus [recording rules] to track total resource usage across all jails.

The exporter can be run in two different ways. The default way is to run a
persistent network daemon for Prometheus to scrape. The exporter will not
daemonize itself, instead, it is recommended to use a tool such as
[`daemon(8)`].  See the included [`rc.d/jail_exporter.in`] for an example of
this.

The second way is to simply output the scraped metrics to a text file. This
mode is designed to be paired with the [`node_exporter`] [Textfile Collector].

No port is available yet, but it should happen soon.

## Exposed Metrics

This exporter was developed under FreeBSD 11.1 and currently exports all
resources listed under the `RESOURCES` section of [`rctl(8)`].

The `id` and `num` time series are calculated based on other information and do
not come from [`rctl(8)`] directly. Metric names have their units appended
where appropriate, based on the Prometheus best practice for [metric and label
naming].

All exported metrics are prefixed with `jail` and have a `name` label
representing the name of the jail. As such, jail names are expected to be
unique.

Descriptions of metrics are taken from the [`rctl(8)`] man page where
applicable.

### `rctl(8)` Metrics

Metric                    | `rctl(8)` name    | Description
--------------------------|-------------------|------------
`coredumpsize_bytes`      | `coredumpsize`    | core dump size, in bytes
`cputime_seconds_total`   | `cputime`         | CPU time, in seconds
`datasize_bytes`          | `datasize`        | data size, in bytes
`maxproc`                 | `maxproc`         | number of processes
`memorylocked_bytes`      | `memorylocked`    | locked memory, in bytes
`memoryuse_bytes`         | `memoryuse`       | resident set size, in bytes
`msgqqueued`              | `msgqqueued`      | number of queued SysV messages
`msgqsize_bytes`          | `msgqsize`        | SysV message queue size, in bytes
`nmsgq`                   | `nmsgq`           | number of SysV message queues
`nsem`                    | `nsem`            | number of SysV semaphores
`nsemop`                  | `nsemop`          | number of SysV semaphores modified in a single semop(2) call
`nshm`                    | `nshm`            | number of SysV shared memory segments
`nthr`                    | `nthr`            | number of threads
`openfiles`               | `openfiles`       | file descriptor table size
`pcpu_used`               | `pcpu`            | %CPU, in percents of a single CPU core
`pseudoterminals`         | `pseudoterminals` | number of PTYs
`readbps`                 | `readbps`         | filesystem reads, in bytes per second
`readiops`                | `readiops`        | filesystem reads, in operations per second
`shmsize_bytes`           | `shmsize`         | SysV shared memory size, in bytes
`stacksize_bytes`         | `stacksize`       | stack size, in bytes
`swapuse_bytes`           | `swapuse`         | swap space that may be reserved or used, in bytes
`vmemoryuse_bytes`        | `vmemoryuse`      | address space limit, in bytes
`wallclock_seconds_total` | `wallclock`       | wallclock time, in seconds
`writebps`                | `writebps`        | filesystem writes, in bytes per second
`writeiops`               | `writeiops`       | filesystem writes, in operations per second

### Non-`rctl(8)` Metrics

Metric                | Description
----------------------|------------
`exporter_build_info` | The version of Rust used to build the exporter, and the version of the exporter.
`id`                  | ID of the named jail
`num`                 | Current number of running jails

## Crate Features

Feature      | Default | Description
-------------|---------|------------
`auth`       | `true`  | Enables HTTP Basic Authentication
`bcrypt_cmd` | `true`  | Enables a `bcrypt` subcommand to assist with hashing passwords for HTTP Basic Authentication
`rc_script`  | `true`  | Enables the `--rc-script` CLI flag to dump the [`rc(8)`] script to stdout

## Notes

The `rc_script` feature is enabled by default for the benefit of users
installing via `cargo install`. It is disabled by default in the FreeBSD port
as the [`rc(8)`] script is supplied in the ports tree.

[Build Status]: https://api.cirrus-ci.com/github/phyber/jail_exporter.svg
[FreeBSD]: https://www.freebsd.org/
[Prometheus]: https://prometheus.io/
[RFC7617]: https://tools.ietf.org/html/rfc7617
[Rust]: https://www.rust-lang.org/
[Textfile Collector]: https://github.com/prometheus/node_exporter#textfile-collector
[bcrypt]: https://en.wikipedia.org/wiki/Bcrypt
[crates.io]: https://crates.io/crates/jail_exporter
[jail]: https://crates.io/crates/jail
[metric and label naming]: https://prometheus.io/docs/practices/naming/
[rctl]: https://crates.io/crates/rctl
[recording rules]: https://prometheus.io/docs/prometheus/latest/configuration/recording_rules/
[`daemon(8)`]: https://www.freebsd.org/cgi/man.cgi?query=daemon&sektion=8
[`exporter-toolkit`]: https://github.com/prometheus/exporter-toolkit
[`make(1)`]: https://www.freebsd.org/cgi/man.cgi?query=make&sektion=1
[`node_exporter`]: https://github.com/prometheus/node_exporter
[`rc(8)`]: https://man.freebsd.org/rc(8)
[`rc.conf(5)`]: https://man.freebsd.org/rc.conf(5)
[`rc.d/jail_exporter.in`]: rc.d/jail_exporter.in
[`rctl(8)`]: https://www.freebsd.org/cgi/man.cgi?query=rctl&sektion=8
[`rctl_get_racct(2)`]: https://www.freebsd.org/cgi/man.cgi?query=rctl_get_racct&sektion=2
