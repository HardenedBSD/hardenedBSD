# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [0.3.0] - 2024-04-17

### Added

- Added a `busy_time` method to each `Statistics` object.  Added
  `total_duration` and `total_duration_{read,write,free,other}` methods too.
  (#[38](https://github.com/asomers/gstat-rs/pull/38))

## [0.2.4] - 2024-02-05

### Changed

- Update `bindgen` to reduce duplicate dependencies in gstat-rs.
  (#[25](https://github.com/asomers/gstat-rs/pull/25))

## [0.2.3] - 2023-09-22

### Fixed

- Fix the build with Rust 1.72.0+
  (#[21](https://github.com/asomers/gstat-rs/pull/21))

## [ 0.2.2 ] - 2023-05-29

### Fixed

- Update `bindgen` to remove build dependency on the `atty` crate.
  (#[19](https://github.com/asomers/gstat-rs/pull/19))

## [ 0.2.1 ] - 2022-10-05

### Fixed

- Update `bindgen` to remove build dependency on the `ansi_term` crate.
  (#[15](https://github.com/asomers/gstat-rs/pull/15))

## [ 0.2.0 ] - 2021-07-30

### Fixed

- Fix `Gident::{name, rank}` methods.  Previously they would return
  uninitialized data when called on GEOM consumers.  Now they will correctly
  check for the fields validity.  This changes the signature of the
  `Gident::name` method.
  (#[7](https://github.com/asomers/gstat-rs/pull/7))
