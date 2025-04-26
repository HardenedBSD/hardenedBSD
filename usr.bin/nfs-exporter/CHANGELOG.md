# Change Log

All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/).

## [0.4.4] - 2024-05-22

### Fixed

- Fixed the build with the latest nightly compiler.
  (#[35](https://github.com/Axcient/freebsd-nfs-exporter/pull/35))

## [0.4.3] - 2023-09-21

### Fixed

- Fixed a minor security advisory on the const-cstr crate.
  ([RUSTSEC-2023-0020](https://rustsec.org/advisories/RUSTSEC-2023-0020))
  (#[29](https://github.com/Axcient/freebsd-nfs-exporter/pull/29))

- Fixed a minor security advisory on the atty crate.
  ([RUSTSEC-2021-0145](https://rustsec.org/advisories/RUSTSEC-2021-0145))
  (#[28](https://github.com/Axcient/freebsd-nfs-exporter/pull/28))

- Fixed the build with Rust nightly after 2023-06-28
  (#[26](https://github.com/Axcient/freebsd-nfs-exporter/pull/26))

## [0.4.2] - 2023-03-09

### Fixed

- Fixed the build on aarch64 and arm.
  (#[24](https://github.com/Axcient/freebsd-nfs-exporter/pull/24))

## [0.4.1] - 2023-02-21

### Fixed

- Correctly start Casper from a single-threaded context.
  (#[22](https://github.com/Axcient/freebsd-nfs-exporter/pull/22))

## [0.4.0] - 2023-02-17

### Added

- The nfs-exporter now runs in Capsicum mode for enhanced security.
  (#[20](https://github.com/Axcient/freebsd-nfs-exporter/pull/20))

## [0.3.2] - 2022-12-08

### Fixed

- Fixed a crash if any counter exceeded `i64::MAX_VALUE`.
  (#[17](https://github.com/Axcient/freebsd-nfs-exporter/pull/17))

## [0.3.1] - 2021-08-17
### Fixed

- Fixed the `nfs_nfsd_total_bytes` and `nfs_nfsd_total_duration` gauges on
  FreeBSD 13.0.
  (#[5](https://github.com/Axcient/freebsd-nfs-exporter/pull/5))
- Fixed parsing IPv6 addresses on the command line.
  (#[6](https://github.com/Axcient/freebsd-nfs-exporter/pull/6))
- Fixed several security vulnerabilities in dependencies: RUSTSEC-2021-0079,
  RUSTSEC-2021-0078, RUSTSEC-2021-0020, RUSTSEC-2021-0003.
  (#[7](https://github.com/Axcient/freebsd-nfs-exporter/pull/7))
