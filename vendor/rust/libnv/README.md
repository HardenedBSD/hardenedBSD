![libnv](libnv.png)

[![Crates.io](https://img.shields.io/crates/v/libnv.svg)](https://crates.io/crates/libnv)
> Rust bindings to libnv and nbpairs.

## What's that?
This library is safe rust bindings to FreeBSD's Name/value pairs library ([`libnv`](man)). It's poor's man `Map<&str,T>` where `T` could one of [a few lucky types](types).

FreeBSD's `libnv` is not the same as `libnvpair` from zfs project and hey aren't binary compatible. This library supports both. I have no intention of having 1:1 mapping with either of the libraries - I only implement what I need in `libzetta`, however, if you need something feel free to open an issue or send a PR.

## Installation
If you have FreeBSD you already have library available in base system. On linux, you will have to figure it out on your own.

`libnv` is available on crates.io and can be included in your Cargo enabled project like this:

```
[dependencies]
libnv= "0.4.2"
```
## Usage
Read the [docs](https://docs.rs/libnv).


[man]: https://www.freebsd.org/cgi/man.cgi?query=nv
[types]: https://docs.rs/libnv/0.2.2/libnv/enum.NvType.html#variants
