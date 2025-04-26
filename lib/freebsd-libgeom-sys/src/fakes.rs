//! Fake definitions good enough to cross-build freebsd-libgeom's docs
//!
//! docs.rs does all of its builds on Linux, so the usual build script fails.
//! As a workaround, we skip the usual build script when doing cross-builds, and
//! define these stubs instead.
pub struct devstat();
pub struct gident();
pub struct gmesh();
#[allow(dead_code)]
#[derive(Copy, Clone)]
pub struct timespec(i32);
