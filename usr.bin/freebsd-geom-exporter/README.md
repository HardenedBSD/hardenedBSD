# FreeBSD GEOM statistics exporter for Prometheus

[![Build Status](https://api.cirrus-ci.com/github/asomers/gstat-rs.svg)](https://cirrus-ci.com/github/asomers/gstat-rs)
[![Crates.io](https://img.shields.io/crates/v/freebsd-geom-exporter.svg)](https://crates.io/crates/freebsd-geom-exporter)
[![FreeBSD port](https://repology.org/badge/version-for-repo/freebsd/geom-exporter.svg)](https://repology.org/project/geom-exporter/versions)

## Overview

The is a [Prometheus](http://prometheus.io) exporter for
[FreeBSD's](http://www.freebsd.org) GEOM statistics.  These are the same
underlying statistics reported by gstat(8).

In terms of accuracy, accessing these metrics via Prometheus is less accurate
than using gstat directly, for two reasons:

* Prometheus records all metrics as 64-bit floating point values.  But gstat
  uses devstat(3), which uses `long double` internally.

* Prometheus timestamps data points according to the time that they are
  ingested into the database.  So computing rates with Prometheus will suffer
  due to the jitter involved in ingesting the data.  But devstat(3) uses
  timestamps that are recorded by the kernel at the moment the kernel generates
  a devstat snapshot.  So those rate computations are much more accurate.

## Usage

```
cargo install freebsd-geom-exporter
daemon geom-exporter
```

Note that the FreeBSD port of this exporter
([net-mgmt/geom-exporter](https://www.freshports.org/net-mgmt/geom-exporter))
comes with an rc(8) service script.

# Minimum Supported Rust Version (MSRV)

freebsd-geom-exporter does not guarantee any specific MSRV.  Rather, it
guarantees compatibility with the oldest rustc shipped in the latest quarterly
branch of the FreeBSD ports collection.

* https://www.freshports.org/lang/rust/

# License

`freebsd-geom-exporter` is primarily distributed under the terms of both the
MIT license and the Apache License (Version 2.0).
