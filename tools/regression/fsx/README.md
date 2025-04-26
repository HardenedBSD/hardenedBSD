# File System eXerciser

Test file system I/O routines for correctness, with random input.

[![Build Status](https://api.cirrus-ci.com/github/asomers/fsx-rs.svg)](https://cirrus-ci.com/github/asomers/fsx-rs)
[![Crates.io](https://img.shields.io/crates/v/fsx.svg)](https://crates.io/crates/fsx)

# Overview

`fsx` generates a pseudorandom sequence of file modifications and applies them
to the file system under test.  On every read, it verifies the expected data.
It's highly configurable, and the test sequence is 100% reproducible according
to a seed value.

# History

The first version of FSX was written in C at Apple Computer, beginning in 1998,
by Avadis Tevanian Jr.  It was imported into FreeBSD 5.0 by Jordan Hubbard, but
only as a development tool.  It was never installed as part of any release.
It's had occasional enhancements since then.

FSX was independently imported into Linux in 2001 by user robbiew, and has
occasionally merged in features from the FreeBSD version.

A tool by the same name was included in DEC Unix 4.0, but I don't think it
shared any code.

This version is a full rewrite in Rust, by Alan Somers.

# Usage

First, create the file system under test and ensure that the current user can
write to it.  Then run

`fsx [OPTIONS] /path/to/filesystem/testfile`

The default settings test the lowest-common denominator of most file systems.
To tweak the test parameters, such as by enabling additional operations, create
an fsx.toml file.  See the example for a description of the allowed settings.

## Migration

fsx-rs version 0.1.1 is fully compatible with The C-based fsx.  Given the same
seed, the two implementations will produce exactly the same sequence of file
system operations.  Some of the options are slightly different.  If migrating
from the C-based FSX, adapt like so:

| C-based FSX option | fsx-rs equivalent                          |
| ------------------ | ------------------------------------------ |
| -d                 | `env RUST_LOG=debug`                       |
| -d -q              | `env RUST_LOG=info`                        |
| -m                 | `env RUST_LOG=warn fsx -m xxx`             |
| -p N               | `fsx ... 2>&1 \| awk '$3 % N == 0{print}'` |
| -s                 | no equivalent                              |
| -L                 | -B -P ...                                  |
| -D N               | `fsx ... 2>&1 \| awk '$3 >= N {print}`     |

Later versions of fsx-rs are not byte-for-byte compatible.  That is, fsx-rs
will no longer produce exactly the same sequence of operations as the original,
even when configured identically.  It also takes many of its options in a
config file instead of on the command line.  If migrating from the C-based FSX
to fsx-rs version 0.2.0 or later, these config file settings are equivalent to
the original's command line flags:

| C-based FSX option | fsx.toml equivalent                        |
| ------------------ | ------------------------------------------ |
| -c                 | `weights.close_open`                       |
| -d                 | -vv                                        |
| -d -q              | -v                                         |
| -i                 | `weights.invalidate`                       |
| -l                 | `flen`                                     |
| -n                 | `nosizechecks`                             |
| -o                 | `opsize.max`                               |
| -r                 | `opsize.align`                             |
| -t                 | `opsize.align`                             |
| -w                 | `opsize.align`                             |
| -L                 | `blockmode`                                |
| -O                 | `opsize.max` and `opsize.min`              |
| -W                 | `weights.write`                            |
| -R                 | `weights.read`                             |
| -U                 | `nomsyncafterwrite`                        |

# Minimum Supported Rust Version (MSRV)

fsx does not guarantee any specific MSRV.  Rather, it guarantees compatibility
with the oldest rustc shipped in the package collection of each supported
operating system.

* https://www.freshports.org/lang/rust/

# License

`fsx` is distributed under the Apple Public Source License version 2.0.  See
LICENSE for details.
