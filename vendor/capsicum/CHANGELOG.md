# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.4.2] - 2024-06-04

### Fixed

- Fixed cross-compiling the docs.
  ([#103](https://github.com/dlrobertson/capsicum-rs/pull/103))

## [0.4.1] - 2024-06-04

### Fixed

- Fixed the build with Rust 1.77.0, by working around Rust bug 13807
  ([#101](https://github.com/dlrobertson/capsicum-rs/pull/101))

## [0.4.0] - 2024-06-04

### Added

- Added `Right::LinkatSource`.
  ([#86](https://github.com/dlrobertson/capsicum-rs/pull/86))

- Added `Right::RenameatTarget`.
  ([#85](https://github.com/dlrobertson/capsicum-rs/pull/85))

- Implemented `Send` and `Sync` for `CapChannel`.
  ([#66](https://github.com/dlrobertson/capsicum-rs/pull/66))

- `util::Directory` now implements `AsFd`.
  ([#98](https://github.com/dlrobertson/capsicum-rs/pull/98))

### Changed

- The `Casper::service_open` function (usually called via the `service!` and
  `service_open!` macros) now require a mutable `&mut Casper` argument.  So
  does `Casper::try_clone`.  This isn't technically a bug "fix" because in the
  previous release it was impossible to trigger the bug.
  ([#82](https://github.com/dlrobertson/capsicum-rs/pull/82))

- Renamed `Right::Linkat` to `Right::LinkatTarget`.
  ([#86](https://github.com/dlrobertson/capsicum-rs/pull/86))

- Renamed `Right::Renameat` to `Right::RenameatSource`.
  ([#85](https://github.com/dlrobertson/capsicum-rs/pull/85))

- The `IoctlsBuilder`, `FcntlsBuilder`, and `RightsBuilder` structs have been
  heavily changed:
  * `FcntlsBuilder` and `RightsBuilder` are deprecated.  You should now use
    `FcntlRights` and `FileRights` directly.
  * Unlike the builder structs' old `new` methods, `FcntlRights`'s and
    `FileRights`'s new methods take no arguments.  The values formerly supplied
    as arguments to `new` must now be provided to the `allow` methods.
  * `FcntlRights` and `FileRights` are now `Copy` and `Clone`.
  * `IoctlsBuilder` is now `Clone`.
  * `IoctlsBuilder`'s methods now pass by move.
  * `IoctlsBuilder::raw` and `IoctlRights::new` methods are deprecated.
  * `IoctlsBuilder`'s `add` and `remove` methods have been renamed to
    `allow`/`deny`, respectively.  Similarly named methods are added to
    `FileRights` and `FcntlRights`.  `FileRights`'s `set`/`clear` methods are
    similarly deprecated.
  ([#71](https://github.com/dlrobertson/capsicum-rs/pull/71))
  ([#88](https://github.com/dlrobertson/capsicum-rs/pull/88))

- `Rights` are now `Clone`, `Copy`, and `Eq`.
  ([#80](https://github.com/dlrobertson/capsicum-rs/pull/80))

- `CapRights::limit`, `FcntlRights::from_file`, `IoctlRights::from_file`, and
  `FileRights::from_file` now take `AsFd` arguments instead of `AsRawFd`.
  ([#98](https://github.com/dlrobertson/capsicum-rs/pull/98))

### Fixed

- Fixed a crash that could happen within the C library, triggered by combining
  certain `Rights` values.
  ([#80](https://github.com/dlrobertson/capsicum-rs/pull/80))

### Removed

- `RightsBuilder::raw` is removed.
  ([#80](https://github.com/dlrobertson/capsicum-rs/pull/80))

- `FileRights::is_valid` is deprecated, because it is no longer useful with
  the new argument-less `FileRights::new`.
  ([#81](https://github.com/dlrobertson/capsicum-rs/pull/81))

- `util::Directory` is deprecated.  Use the `cap-std` crate instead.
  ([#74](https://github.com/dlrobertson/capsicum-rs/pull/74))

## [0.3.0] - 2023-09-21

### Changed

- The `capsicum::casper::Service` trait's `SERVICE_NAME` field must now be
  defined as a `&'static CStr`.  The [cstr](https://crates.io/crates/cstr)
  crate can help.
  ([#49](https://github.com/dlrobertson/capsicum-rs/pull/49))

- `capsicum::get_mode` now returns a `bool`.
  ([#51](https://github.com/dlrobertson/capsicum-rs/pull/51))

### Fixed

- Fixed cross-building the documentation.
  ([#42](https://github.com/dlrobertson/capsicum-rs/pull/42))
