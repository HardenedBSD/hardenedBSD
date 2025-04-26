// vim: tw=80
//! Rust FFI bindings for FreeBSD's libgeom library
//!
//! These are raw, `unsafe` FFI bindings.  Here be dragons!  You probably
//! shouldn't use this crate directly.  Instead, you should use the
//! [`freebsd-libgeom`](https://crates.io/crates/freebsd-libgeom) crate.
#![cfg_attr(crossdocs, doc = "")]
#![cfg_attr(crossdocs, doc = "These docs are just stubs!  Don't trust them.")]
// bindgen generates some unconventional type names
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

#[cfg(not(crossdocs))]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(crossdocs)]
mod fakes;
#[cfg(crossdocs)]
pub use fakes::*;
