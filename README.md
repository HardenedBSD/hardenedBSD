FreeBSD, with Rust
==================

The FreeBSD source tree, enhanced with components written in Rust.

How to Use
==========

Building
--------

To build everything, including C and Rust programs, do `env
OPTIONAL_TOOLCHAINS=rust-cargo make buildworld` like usual.

To build just a single Rust program, cd into its subdirectory and do
`env OPTIONAL_TOOLCHAINS=rust-cargo make build`

How to Develop
==============

Updating an existing Rust crate
-------------------------------

* First make any changes to the crate.  Edit files locally, copy the source
  from github, or whatever.
* If there are any changes to the crate's dependencies:
  - Comment out the vendor-related lines in .cargo/config.toml
  - Run `mv vendor vendor.bak`
  - Run `cargo vendor-filterer`
  - Test your changes
  - Run `rm -r vendor.bak`
  - Commit everything

Updating a dependency
---------------------

*

Adding a new Rust crate
-----------------------

Status
======
[✓] Add at least one Rust executable
[✓] Add at least one Rust library
[ ] Add at least one Rust dynamic library
[✓] Vendor all Rust dependencies
[✓] Add a new program, wholly written in Rust
[ ] Add a program that uses a private interface in base.
[✓] Rewrite an existing program in Rust, with enhanced features
[✓] Tweak each crate's dependencies, so as to prevent building multiple versions of the same dependency.
[ ] Store all Rust object files in MAKEOBJDIRPREFIX, instead of target/
[ ] Invoke `cargo` via `make` during buildworld
[ ] Invoke `cargo` when running `make` in a subdirectory, to build just that subdirectory's contents.
[ ] Rust should link to libs (and build with headers) in the build tree, not in the installed system
[ ] Use Cargo's -Zbuild-dir feature, when that stabilizes, instead of CARGO_TARGET_DIR
[ ] Rename the vendor tree to vendor/rust, to allow for the possibility of components written in other languages.
[ ] Make should control the version of Rust used, rather than relying on PATH.
