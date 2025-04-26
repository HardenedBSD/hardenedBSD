# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - ReleaseDate

### Fixed

- Correctly reset terminal settings when quitting the application.
  (#[38](https://github.com/asomers/gstat-rs/pull/38))

## [0.2.3] - 2023-12-18

### Fixed

- Removed dependency on unmaintained tui crate.
  ([RUSTSEC-2023-0049](https://rustsec.org/advisories/RUSTSEC-2023-0049))
  Removed dependency on atty crate, fixing an unaligned read bug.
  ([RUSTSEC-2021-0145](https://rustsec.org/advisories/RUSTSEC-2021-0145))
  (#[31](https://github.com/asomers/ztop/pull/31))

## [0.2.2] - 2023-03-27

### Added

- Added ZoL support.
  (#[26](https://github.com/asomers/ztop/pull/26))

## [0.2.1] - 2022-09-27

### Fixed

- Fixed annoying warnings on FreeBSD 14.0-CURRENT.
  (#[23](https://github.com/asomers/ztop/pull/23))

## [0.2.0] - 2022-03-15

### Fixed

- Fix sorting on the "kB/s r" and "kB/s w" columns with the -s option
  (#[18](https://github.com/asomers/ztop/pull/18))

- Don't crash if two different pools have objsets of the same ID that list
  adjacently in the sysctl tree.
  (#[15](https://github.com/asomers/ztop/pull/15))

## [0.1.1] - 2021-08-13

### Fixed

- Don't crash on FreeBSD 12.2
  (#[5](https://github.com/asomers/ztop/pull/5))

- Don't crash if no datasets are present
  (#[6](https://github.com/asomers/ztop/pull/6))
