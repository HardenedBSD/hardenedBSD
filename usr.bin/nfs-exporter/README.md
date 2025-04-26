# FreeBSD NFS statistics exporter for Prometheus

[![Build Status](https://api.cirrus-ci.com/github/Axcient/freebsd-nfs-exporter.svg)](https://cirrus-ci.com/github/Axcient/freebsd-nfs-exporter)
[![crates.io](https://img.shields.io/crates/v/freebsd-nfs-exporter.svg)](https://crates.io/crates/freebsd-nfs-exporter)
[![FreeBSD port](https://repology.org/badge/version-for-repo/freebsd/nfs-exporter.svg)](https://repology.org/project/nfs-exporter/versions)

## Overview

The is a [Prometheus](http://prometheus.io) exporter for
[FreeBSD's](http://www.freebsd.org) NFS statistics.  Currently only the server
statistics are supported; client stats will come later.

## Usage

```
cargo install freebsd-nfs-exporter
daemon nfs-exporter
```

Note that the FreeBSD port of this exporter
([net-mgmt/nfs-exporter](https://www.freshports.org/net-mgmt/nfs-exporter))
comes with an rc(8) service script.

# Minimum Supported Rust Version (MSRV)

freebsd-nfs-exporter does not guarantee any specific MSRV.  Rather, it
guarantees compatibility with the oldest rustc shipped in the latest quarterly
branch of the FreeBSD ports collection.

* https://www.freshports.org/lang/rust/

# License

`freebsd-nfs-exporter` is primarily distributed under the terms of both the MIT
license and the Apache License (Version 2.0).

See LICENSE-APACHE, and LICENSE-MIT for details
