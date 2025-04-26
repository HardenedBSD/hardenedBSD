# 0.1.6 (2024-07-01)

- Add support for AIX operating system to `legacy` client.
- Fix `legacy` client to better use dying pooled connections.

# 0.1.5 (2024-05-28)

- Add `server::graceful::GracefulShutdown` helper to coordinate over many connections.
- Add `server::conn::auto::Connection::into_owned()` to unlink lifetime from `Builder`.
- Allow `service` module to be available with only `service` feature enabled.

# 0.1.4 (2024-05-24)

- Add `initial_max_send_streams()` to `legacy` client builder
- Add `max_pending_accept_reset_streams()` to `legacy` client builder
- Add `max_headers(usize)` to `auto` server builder
- Add `http1_onl()` and `http2_only()` to `auto` server builder
- Add connection capturing API to `legacy` client
- Add `impl Connection for TokioIo`
- Fix graceful shutdown hanging on reading the HTTP version

# 0.1.3 (2024-01-31)

### Added

- Add `Error::is_connect()` which returns true if error came from client `Connect`.
- Add timer support to `legacy` pool.
- Add support to enable http1/http2 parts of `auto::Builder` individually.

### Fixed

- Fix `auto` connection so it can handle requests shorter than the h2 preface.
- Fix `legacy::Client` to no longer error when keep-alive is diabled.

# 0.1.2 (2023-12-20)

### Added

- Add `graceful_shutdown()` method to `auto` connections.
- Add `rt::TokioTimer` type that implements `hyper::rt::Timer`.
- Add `service::TowerToHyperService` adapter, allowing using `tower::Service`s as a `hyper::service::Service`.
- Implement `Clone` for `auto::Builder`.
- Exports `legacy::{Builder, ResponseFuture}`.

### Fixed

- Enable HTTP/1 upgrades on the `legacy::Client`.
- Prevent divide by zero if DNS returns 0 addresses.

# 0.1.1 (2023-11-17)

### Added

- Make `server-auto` enable the `server` feature.

### Fixed

- Reduce `Send` bounds requirements for `auto` connections.
- Docs: enable all features when generating.

# 0.1.0 (2023-11-16)

Initial release.
