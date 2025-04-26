# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased] - ReleaseDate

### Added

- Setting the `NO_COLOR` environment variable will now suppress all color in
  the output.
  ([#51](https://github.com/asomers/fsx-rs/pull/51))

### Changed

- The MSRV is now 1.77.0.
  ([#52](https://github.com/asomers/fsx-rs/pull/52))

### Fixed

- `fspacectl` operations now highlight a monitor range (supplied with `-m`)
  correctly.
  ([#47](https://github.com/asomers/fsx-rs/pull/47))

## [0.2.0] - 2023-12-29

### Added

- `fsync` and `fdatasync` operations
  ([#24](https://github.com/asomers/fsx-rs/pull/24))

- `posix_fallocate`
  ([#26](https://github.com/asomers/fsx-rs/pull/26))

- Hole punching via `fspacectl` on FreeBSD or `FALLOC_FL_PUNCH_HOLE` on Linux.
  ([#28](https://github.com/asomers/fsx-rs/pull/28))

- `sendfile`
  ([#29](https://github.com/asomers/fsx-rs/pull/29))

- `posix_fadvise`
  ([#31](https://github.com/asomers/fsx-rs/pull/31))

- `copy_file_range`
  ([#43](https://github.com/asomers/fsx-rs/pull/43))

### Changed

- The CLI has been completely changed by the addition of a config file.  Now,
  most settings are specified in the config file.  Also:

  * close/open and invalidate are specified like other operations, not as
    modifiers that happen after an operation.

  * Seed-for-seed backwards compatibility is broken.  So you can't run fsx-rs
    and expect the exact same sequence of operations as would've been produced
    by legacy fsx.

  * Operations are now selected with variable weights instead of equal
    probabilities.

  * It is no longer possible to specify separate alignment requirements for
    read, write, and truncate.  Now the same alignment requirement applies to
    all.

  ([#23](https://github.com/asomers/fsx-rs/pull/23))

- Better usability when operating on block devices
  ([#35](https://github.com/asomers/fsx-rs/pull/35))

- Log verbosity is now controlled by the `-v` and `-q` flags instead of the
  `RUST_LOG` environment variable.
  ([#44](https://github.com/asomers/fsx-rs/pull/44))

- The MSRV is now 1.70.0

## [0.1.1] - 2023-01-22
### Fixed

- Fixed crash when using `-B` on a file of 0 bytes.
  ([#21](https://github.com/asomers/fsx-rs/pull/21))

- Fixed crashes when using `-B` on files larger than 256 kB.
  ([#17](https://github.com/asomers/fsx-rs/pull/17))

- Fixed a `TryFromIntError` crash when using `-i` with high probabilities.
  ([#14](https://github.com/asomers/fsx-rs/pull/14))
