# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [Unreleased] - ReleaseDate

### Fixed

- Better error messages
  (#[41](https://github.com/asomers/gstat-rs/pull/41))

## [0.1.6] - 2024-02-05

### Fixed

- Better color contrast, especially on OSX Terminal
  (#[32](https://github.com/asomers/gstat-rs/pull/32))

- Correctly reset terminal settings when quitting the application.
  (#[30](https://github.com/asomers/gstat-rs/pull/30))

## [0.1.5] - 2023-12-19

### Fixed

- Fixed the display of provider names longer than 10 characters, a regression
  since 0.1.3.
  (#[25](https://github.com/asomers/gstat-rs/pull/25))

## [0.1.4] - 2023-09-22

### Fixed

- Remove dependency on the unmaintained tui crate.
  ([RUSTSEC-2023-0049](https://rustsec.org/advisories/RUSTSEC-2023-0049))
  (#[23](https://github.com/asomers/gstat-rs/pull/23))

- Fix the build with Rust 1.72.0+
  (#[21](https://github.com/asomers/gstat-rs/pull/21))

## [ 0.1.3 ] - 2023-05-29

### Fixed

- Update `clap` to remove build dependency on the `atty` crate.
  (#[19](https://github.com/asomers/gstat-rs/pull/19))

- Fixed truncation of the rightmost columns, especially when the filter
  specification excludes all disks.
  (#[20](https://github.com/asomers/gstat-rs/pull/20))

## [ 0.1.2 ] - 2021-07-30

### Fixed

- Don't panic when pressing the arrow keys on a screwed-up terminal.
  ([4218445](https://github.com/asomers/gstat-rs/commit/4218445d63cc864d315bbd5ece15a75457213822))

- When deleting a column with Del, persist that change to the config file.
  ([f406beb](https://github.com/asomers/gstat-rs/commit/f406beb5c8ad6160ded471e2658af22aedb5552d))

- Only use side-by-side mode if it can be done without truncating names.
  (#[8](https://github.com/asomers/gstat-rs/pull/8))

- Don't crash at startup if the config file is corrupt, if `--reset-config` is
  used.
  (#[6](https://github.com/asomers/gstat-rs/pull/6))

- Don't display GEOM consumers.  By mistake, gstat sometimes displayed GEOM
  consumers.  Their names were blank.
  (#[7](https://github.com/asomers/gstat-rs/pull/7))

- Removed the useless `columns` option from the help menu.
  (#[5](https://github.com/asomers/gstat-rs/pull/5))

## [ 0.1.1 ] - 2021-07-16

### Fixed

- Always have a column selected in the column selector
- Fix crashes with up and down arrows for empty tables
- Fix crashes with really small terminals
- When using up and down, pass through deselected before wrapping around
- Accept the 'q' key to quit directly from the column selector menu.
- Don't use the alternate screen.
- Fixed display initial stats at startup.
