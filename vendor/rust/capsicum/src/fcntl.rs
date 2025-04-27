// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    io,
    os::{fd::AsFd, unix::io::AsRawFd},
};

use crate::common::CapRights;

// TODO: use values from libc
/// Fcntl commands that may be limited on file descriptors.
///
/// Note that [`fcntl(2)`](https://www.freebsd.org/cgi/man.cgi?query=fcntl)
/// supports additional commands not listed here.  Those commands are always
/// available and cannot be limited.
#[repr(u32)]
#[derive(Debug)]
pub enum Fcntl {
    /// Get descriptor status flags.
    GetFL = libc::CAP_FCNTL_GETFL,
    /// Set descriptor status flags.
    SetFL = libc::CAP_FCNTL_SETFL,
    /// Get the process ID or process group currently receiving SIGIO and SIGURG
    /// signals.
    GetOwn = libc::CAP_FCNTL_GETOWN,
    /// Set the process or process group to receive SIGIO and SIGURG signal.
    SetOwn = libc::CAP_FCNTL_SETOWN,
}

/// Used to construct a new set of allowed fcntl commands.
///
/// # Example
/// ```
/// # use capsicum::{Fcntl, FcntlsBuilder};
/// let rights = FcntlsBuilder::new(Fcntl::GetFL)
///     .add(Fcntl::SetFL)
///     .finalize();
/// ```
#[derive(Debug, Default)]
#[deprecated(since = "0.4.0", note = "Use FcntlRights directly")]
pub struct FcntlsBuilder(u32);

#[allow(deprecated)]
impl FcntlsBuilder {
    #[allow(missing_docs)]
    pub fn new(right: Fcntl) -> FcntlsBuilder {
        FcntlsBuilder(right as u32)
    }

    #[allow(missing_docs)]
    pub fn add(&mut self, right: Fcntl) -> &mut FcntlsBuilder {
        self.0 |= right as u32;
        self
    }

    /// Finish this Builder and turn it into an `FcntlRights` object.
    pub fn finalize(&self) -> FcntlRights {
        FcntlRights(self.0)
    }

    #[allow(missing_docs)]
    #[deprecated(
        since = "0.4.0",
        note = "If you still need this method, please file an issue at https://github.com/dlrobertson/capsicum-rs/issues"
    )]
    pub fn raw(&self) -> u32 {
        self.0
    }

    #[allow(missing_docs)]
    pub fn remove(&mut self, right: Fcntl) -> &mut FcntlsBuilder {
        self.0 &= !(right as u32);
        self
    }
}

/// Used to limit which
/// [`fcntl(2)`](https://www.freebsd.org/cgi/man.cgi?query=fcntl) commands can be
/// used on a file in capability mode.
///
/// # See Also
/// [`cap_fcntls_limit(2)`](https://www.freebsd.org/cgi/man.cgi?query=cap_fcntls_limit)
///
/// # Example
/// ```
/// # use std::os::unix::io::AsRawFd;
/// # use capsicum::{CapRights, FcntlRights, Fcntl};
/// # use tempfile::tempfile;
/// use nix::errno::Errno;
/// use nix::fcntl::{FcntlArg, OFlag, fcntl};
/// let file = tempfile().unwrap();
/// FcntlRights::new()
///     .allow(Fcntl::GetFL)
///     .limit(&file)
///     .unwrap();
///
/// capsicum::enter().unwrap();
///
/// fcntl(file.as_raw_fd(), FcntlArg::F_GETFL).unwrap();
///
/// let r = fcntl(file.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_CLOEXEC));
/// assert_eq!(r, Err(Errno::ENOTCAPABLE));
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FcntlRights(u32);

impl FcntlRights {
    /// Initialize a new `FcntlsRights` which will deny all rights.
    pub fn new() -> FcntlRights {
        FcntlRights::default()
    }

    /// Allow an additional fcntl
    ///
    /// # Examples
    /// ```
    /// # use capsicum::{Fcntl, FcntlRights};
    ///
    /// let mut rights = FcntlRights::new();
    /// rights.allow(Fcntl::GetFL);
    /// ```
    pub fn allow(&mut self, right: Fcntl) -> &mut Self {
        self.0 |= right as u32;
        self
    }

    /// Remove an allowed fcntl from the list.
    ///
    /// # Example
    /// ```
    /// # use capsicum::{Fcntl, FcntlRights};
    /// let mut common = FcntlRights::new();
    /// common.allow(Fcntl::GetFL);
    /// common.allow(Fcntl::SetFL);
    /// let mut restricted = common.clone();
    /// restricted.deny(Fcntl::SetFL);
    /// ```
    pub fn deny(&mut self, right: Fcntl) -> &mut Self {
        self.0 &= !(right as u32);
        self
    }

    /// Retrieve the list of fcntl rights currently allowed for the given file.
    /// # Example
    /// ```
    /// # use capsicum::{CapRights, Fcntl, FcntlRights};
    /// # use tempfile::tempfile;
    /// use nix::errno::Errno;
    /// use nix::fcntl::{FcntlArg, OFlag, fcntl};
    /// let file = tempfile().unwrap();
    /// let mut rights = FcntlRights::new();
    /// rights.allow(Fcntl::GetFL);
    ///
    /// rights.limit(&file).unwrap();
    /// let rights2 = FcntlRights::from_file(&file).unwrap();
    /// assert_eq!(rights, rights2);
    /// ```
    ///
    /// # See Also
    /// [`cap_fcntls_get(2)`](https://www.freebsd.org/cgi/man.cgi?query=cap_fcntls_get)
    pub fn from_file<F: AsFd>(f: &F) -> io::Result<FcntlRights> {
        unsafe {
            let mut empty_fcntls = 0;
            let fd = f.as_fd().as_raw_fd();
            let res = libc::cap_fcntls_get(fd, &mut empty_fcntls as *mut u32);
            if res < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(FcntlRights(empty_fcntls))
            }
        }
    }
}

impl CapRights for FcntlRights {
    fn limit<F: AsFd>(&self, fd: &F) -> io::Result<()> {
        unsafe {
            if libc::cap_fcntls_limit(fd.as_fd().as_raw_fd(), self.0) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}
