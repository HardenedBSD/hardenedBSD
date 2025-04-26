# gstat-rs

An enhanced replacement for FreeBSD's gstat(8) utility.

[![Build Status](https://api.cirrus-ci.com/github/asomers/gstat-rs.svg)](https://cirrus-ci.com/github/asomers/gstat-rs)
[![Crates.io](https://img.shields.io/crates/v/gstat.svg)](https://crates.io/crates/gstat)

## Overview

`gstat` is awesome, but it has some limitations that come into play on larger
systems.  `gstat-rs` is designed to work better even on servers with hundreds of
disks.  The key differences are:

* gstat-rs supports sorting the disks using the '+', '-', and 'r' keys, and the
  "--sort" and "-r" command line options.
* gstat-rs can enable/disable columns at any time using the insert and
  delete keys.  gstat can only do that at startup, and only for certain
  infrequently used columns.
* If the screen has enough space, gstat-rs will display multiple disks side by
  side.
* gstat-rs can pause the display without exiting the program.
* gstat-rs's settings are automatically persisted to a config file.
* gstat-rs does not support batch mode (`-bBC`) output.  If you want that kind
  of information, use iostat(8) instead.
* gstat-rs does not display GEOM consumers (`-c`), but it can easily be
  added if there's any demand for that feature.

# Screenshot

gstat-rs demonstrating side-by-side mode, sorting by %busy.
![Screenshot 1](https://raw.githubusercontent.com/asomers/gstat-rs/master/gstat/doc/demo.gif)

# Minimum Supported Rust Version (MSRV)

gstat-rs does not guarantee any specific MSRV.  Rather, it guarantees
compatibility with the oldest rustc shipped in the current FreeBSD ports tree.

* https://www.freshports.org/lang/rust/

# License

`gstat-rs` is primarily distributed under the terms of the BSD 2-clause license.

See LICENSE for details.

# Sponsorship

gstat-rs is sponsored by Axcient, inc.
