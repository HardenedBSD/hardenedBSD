// vim: tw=80
//! Rust FFI bindings for FreeBSD's libnv library
//!
//! These are raw, `unsafe` FFI bindings.  Here be dragons!  You probably
//! shouldn't use this crate directly.  Instead, you should use the
//! [`libnv`](https://crates.io/crates/libnv) crate.
#![cfg_attr(crossdocs, doc = "")]
#![cfg_attr(crossdocs, doc = "These docs are just stubs!  Don't trust them.")]
// bindgen generates some unconventional type names
#![allow(non_camel_case_types)]

#[cfg(not(crossdocs))]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(crossdocs)]
mod fakes;
#[cfg(crossdocs)]
pub use fakes::*;
