# mdconfig

Rust bindings to FreeBSD's [md(4)] driver.

`md` devices are memory disks, that can be backed by RAM, swap, or a file.  They can be useful
for temporary storage, and they're very useful for working with disk images as
files.  This crate provides bindings to `md` that are equivalent to what the
[mdconfig(8)] utility provides, but Rustier.

![Build Status](https://api.cirrus-ci.com/github/asomers/mdconfig.svg)
[![Crates.io](https://img.shields.io/crates/v/mdconfig.svg)](https://crates.io/crates/mdconfig)

[Documentation](https://docs.rs/crate/mdconfig)

[md(4)]: https://man.freebsd.org/cgi/man.cgi?query=md
[mdconfig(8)]: https://man.freebsd.org/cgi/man.cgi?query=mdconfig

# Usage

See the examples in the API docs.  The general idea is to create a `Builder`
struct, set various options, and then construct the `Md` device from that.  Most
applications will then open the `Md` device's path with the standard file system
API.  When complete, the `Md` object will tell the kernel to deallocate the `md`
device upon Drop.

# Platforms

This crate only works on FreeBSD.  Similarly named drivers in NetBSD and
DragonflyBSD actually have very different APIs.

# Minimum Supported Rust Version (MSRV)

`mdconfig` does not guarantee any specific MSRV.  Rather, it guarantees
compatibility with the oldest rustc shipped in the FreeBSD package collection.

* https://www.freshports.org/lang/rust/

# License

`mdconfig` is primarily distributed under the terms of both the MIT license and
the Apache License (Version 2.0).

See LICENSE-APACHE, and LICENSE-MIT for details.


