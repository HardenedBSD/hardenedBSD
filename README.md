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

<<<<<<< HEAD
*
=======
* Comment out the vendor-related lines in .cargo/config.toml
* Run `mv vendor vendor.bak`
* Run `cargo update -p <crate name>`
* Run `cargo vendor-filterer`
* Test your changes
* Run `rm -r vendor.bak`
* Commit everything
>>>>>>> asomers/rust-in-base-demo

Adding a new Rust crate
-----------------------

Status
======
<<<<<<< HEAD
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
=======
- [x] Add at least one Rust executable
- [x] Add at least one Rust library
- [ ] Add at least one Rust dynamic library
- [ ] Add a crate that builds multiple binaries
- [x] Vendor all Rust dependencies
- [x] Add a new program, wholly written in Rust
- [ ] Add a program that uses a private interface in base.
- [x] Rewrite an existing program in Rust, with enhanced features
- [x] Tweak each crate's dependencies, so as to prevent building multiple versions of the same dependency.
- [x] Store all Rust object files in MAKEOBJDIRPREFIX, instead of target/
- [x] Invoke `cargo` via `make` during buildworld
- [x] Invoke `cargo` when running `make` in a subdirectory, to build just that subdirectory's contents.
- [ ] Rust should link to libs (and build with headers) in the build tree, not in the installed system
- [ ] Use Cargo's -Zbuild-dir feature, when that stabilizes, instead of CARGO_TARGET_DIR
- [x] Rename the vendor tree to vendor/rust, to allow for the possibility of components written in other languages.
- [ ] Make should control the version of Rust used, rather than relying on PATH.
- [ ] Install a Rust crate's tests, then execute them with Kyua.

Problems
========

* Limited concurrency.  `make` currently invokes `cargo` once for each
  subdirectory.  Cargo will do each of those builds in parallel.  But, there
  are chokepoints, like linking.  So the actual concurrency won't be as good as
  if it invoked `cargo` once.
>>>>>>> asomers/rust-in-base-demo
