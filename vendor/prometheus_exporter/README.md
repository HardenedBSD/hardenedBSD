# prometheus_exporter

[![Build Status](https://github.com/AlexanderThaller/prometheus_exporter/workflows/Rust/badge.svg?branch=master)](https://github.com/AlexanderThaller/prometheus_exporter/actions?query=workflow%3ARust)
[![crates.io](https://img.shields.io/crates/v/prometheus_exporter.svg)](https://crates.io/crates/prometheus_exporter)
[![docs.rs](https://docs.rs/prometheus_exporter/badge.svg)](https://docs.rs/prometheus_exporter)

Helper libary to export prometheus metrics using tiny-http. It's intended to
help writing prometheus exporters without the need to setup and maintain a http
webserver. If the program also uses a http server for other purposes this
package is probably not the best way and
[rust-prometheus](https://github.com/pingcap/rust-prometheus) should be used
directly.

It uses [rust-prometheus](https://github.com/pingcap/rust-prometheus) for
collecting and rendering the prometheus metrics and
[tiny-http](https://github.com/tiny-http/tiny-http) for exposing the metrics
through http.

**NOTICE:** You have to use the same prometheus crate version that is used by
this crate. This crate currently uses the metrics stored in the global registry.
A different prometheus crate will register to a different global registry. This
means that the macros used to register new metrics do not expose metrics to this
exporter.

This crate re-exports the prometheus crate to make it easier to keep versions in
sync (see examples). Currently this crate uses prometheus version `0.13`.

For information on how to migrate from an older crate version follow
[MIGRATION](/MIGRATION.md).

**NOTICE** Version `0.8.0` used a vulnerable version of `tiny_http` please update
to version `0.8.1` or higher. See issue
[#18](https://github.com/AlexanderThaller/prometheus_exporter/issues/18) for
more information.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
prometheus_exporter = "0.8"
```

The most basic way to use this crate is to run the following:
```rust
prometheus_exporter::start("0.0.0.0:9184".parse().expect(
"failed to parse binding",
))
.expect("failed to start prometheus exporter");
```

This will start the exporter and bind the http server to `0.0.0.0:9184`. After
that you can just update the metrics how you see fit. As long as those metrics
are put into the global prometheus registry the changed metrics will be
exported.

Another way to use the crate is like this:

```rust
let exporter = prometheus_exporter::start("0.0.0.0:9184".parse().expect(
"failed to parse binding",
))
.expect("failed to start prometheus exporter");

let guard = exporter.wait_request()
```

This will block the current thread until a request has been received on the http
server. It also returns a guard which will make the http server wait until the
guard is dropped. This is useful to always export consistent metrics as all of
the metrics can be updated before they get exported.

See the [documentation](https://docs.rs/prometheus_exporter) and the
[examples](/examples) for more information on how to use this crate.

## Basic Example

You will need the following in your Cargo.toml
```rust
[dependencies]
prometheus_exporter = "0.8"
env_logger = "0.9"
log = "0.4"
reqwest = { version = "0.11",features = ["blocking"] }
```

A very simple example looks like this (from
[`examples/simple.rs`](/examples/simple.rs)):

```rust
// Will create an exporter with a single metric that does not change

use env_logger::{
    Builder,
    Env,
};
use log::info;
use prometheus_exporter::prometheus::register_gauge;
use std::net::SocketAddr;

fn main() {
    // Setup logger with default level info so we can see the messages from
    // prometheus_exporter.
    Builder::from_env(Env::default().default_filter_or("info")).init();

    // Parse address used to bind exporter to.
    let addr_raw = "0.0.0.0:9184";
    let addr: SocketAddr = addr_raw.parse().expect("can not parse listen addr");

    // Create metric
    let metric = register_gauge!("simple_the_answer", "to everything")
        .expect("can not create gauge simple_the_answer");

    metric.set(42.0);

    // Start exporter
    prometheus_exporter::start(addr).expect("can not start exporter");

    // Get metrics from exporter
    let body = reqwest::blocking::get(&format!("http://{}/metrics", addr_raw))
        .expect("can not get metrics from exporter")
        .text()
        .expect("can not body text from request");

    info!("Exporter metrics:\n{}", body);
}
```
