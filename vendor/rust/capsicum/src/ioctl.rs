// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

use std::{
    io,
    os::{fd::AsFd, unix::io::AsRawFd},
};

use libc::u_long;

use crate::common::CapRights;

const CAP_IOCTLS_ALL: isize = isize::MAX;

/// Used to construct a new set of allowed ioctl commands.
///
/// # Example
/// Using ioctl command codes from libc:
/// ```
/// # use capsicum::IoctlsBuilder;
/// let rights = IoctlsBuilder::new()
///     .allow(libc::TIOCGETD)
///     .finalize();
/// ```
/// Declaring ioctl command codes with Nix, for ioctls not present in libc:
/// ```
/// use std::mem;
/// #[macro_use(request_code_read)]
/// extern crate nix;
/// # use capsicum::IoctlsBuilder;
/// const TIOCGETD: libc::u_long = request_code_read!(b't', 26, mem::size_of::<libc::c_int>());
///
/// fn main() {
///     let rights = IoctlsBuilder::new()
///         .allow(TIOCGETD)
///         .finalize();
/// }
#[derive(Clone, Debug, Default)]
pub struct IoctlsBuilder(Vec<u_long>);

impl IoctlsBuilder {
    /// Create a new `IoctlsBuilder` with an initially empty list of allowed ioctls.
    pub fn new() -> IoctlsBuilder {
        IoctlsBuilder::default()
    }

    #[allow(missing_docs)]
    #[allow(clippy::should_implement_trait)]
    #[deprecated(since = "0.4.0", note = "use IoctlsBuilder::allow instead")]
    pub fn add(self, right: u_long) -> Self {
        self.allow(right)
    }

    /// Allow an additional ioctl
    ///
    /// # Examples
    /// ```
    /// # use capsicum::IoctlsBuilder;
    ///
    /// let mut builder = IoctlsBuilder::new();
    /// builder.allow(libc::TIOCGETD);
    /// ```
    pub fn allow(mut self, right: u_long) -> Self {
        self.0.push(right);
        self
    }

    #[allow(missing_docs)]
    #[deprecated(
        since = "0.4.0",
        note = "If you still need this method, please file an issue at https://github.com/dlrobertson/capsicum-rs/issues"
    )]
    pub fn raw(&self) -> Vec<u_long> {
        self.0.clone()
    }

    #[allow(missing_docs)]
    #[deprecated(since = "0.4.0", note = "use IoctlsBuilder::allow instead")]
    pub fn remove(self, right: u_long) -> Self {
        self.deny(right)
    }

    /// Remove an allowed ioctl from the builder's list.
    ///
    /// # Example
    /// ```
    /// # use capsicum::IoctlsBuilder;
    /// let common_builder = IoctlsBuilder::new();
    /// let common_builder = common_builder.allow(libc::TIOCGETD);
    /// let common_builder = common_builder.allow(libc::TIOCSETD);
    /// let restricted_builder = common_builder.clone();
    /// let restricted_builder = restricted_builder.deny(libc::TIOCSETD);
    /// ```
    pub fn deny(mut self, right: u_long) -> Self {
        self.0.retain(|&item| item != right);
        self
    }

    /// Finish this `IoctlsBuilder` into an [`IoctlRights`] object.
    pub fn finalize(self) -> IoctlRights {
        IoctlRights::Limited(self.0)
    }
}

/// Used to reduce (but never expand) the ioctl commands that may be used on a
/// file descriptor.
///
/// # See Also
/// [`ioctl(2)`](https://www.freebsd.org/cgi/man.cgi?query=ioctl)
/// [`cap_ioctls_limit(2)`](https://www.freebsd.org/cgi/man.cgi?query=cap_ioctls_limit)
///
/// # Example
/// ```
/// # use std::os::unix::io::AsRawFd;
/// # use capsicum::{CapRights, IoctlsBuilder};
/// # use tempfile::tempfile;
/// use std::mem;
/// use libc::{c_int, u_long};
/// use nix::{ioctl_read, request_code_read};
/// use nix::errno::Errno;
/// use nix::sys::socket::{AddressFamily, SockType, SockFlag, socketpair};
///
/// const FIONREAD: u_long = request_code_read!(b'f', 127, mem::size_of::<libc::c_int>());
/// ioctl_read!(fionread, b'f', 127, libc::c_int);
/// ioctl_read!(fionwrite, b'f', 119, libc::c_int);
///
/// let (fd1, fd2) = socketpair(
///     AddressFamily::Unix,
///     SockType::Stream,
///     None,
///     SockFlag::empty()
/// ).unwrap();
/// let mut builder = IoctlsBuilder::new();
/// let rights = builder.allow(FIONREAD)
///     .finalize();
///
/// rights.limit(&fd1).unwrap();
///
/// capsicum::enter().unwrap();
///
/// let mut n: c_int = 0;
/// unsafe{ fionread(fd1.as_raw_fd(), &mut n as *mut c_int) }.unwrap();
///
/// let e = unsafe{ fionwrite(fd1.as_raw_fd(), &mut n as *mut c_int) };
/// assert_eq!(e, Err(Errno::ENOTCAPABLE));
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum IoctlRights {
    /// All ioctl commands will be allowed.
    #[default]
    Unlimited,
    /// Only the included ioctl commands will be allowed.
    Limited(Vec<u_long>),
}

impl IoctlRights {
    #[allow(missing_docs)]
    #[deprecated(since = "0.4.0", note = "use IoctlsBuilder insted")]
    pub fn new(rights: Vec<u_long>) -> IoctlRights {
        IoctlRights::Limited(rights)
    }

    /// Retrieve the list of currently allowed ioctl commands from a file.
    ///
    /// # Returns
    ///
    /// - `Ok(IoctlRights::Unlimited)`:      All ioctl commands are allowed
    /// - `Ok(IoctlRights::Limited([]))`:    No ioctl commands are allowed
    /// - `Ok(IoctlRights::Limited([...]))`: Only these ioctl commands are allowed.
    /// - `Err(_)`:           Retrieving the list failed.
    pub fn from_file<F: AsFd>(f: &F, len: usize) -> io::Result<IoctlRights> {
        let mut cmds = Vec::with_capacity(len);
        let fd = f.as_fd().as_raw_fd();
        unsafe {
            let res = libc::cap_ioctls_get(fd, cmds.as_mut_ptr(), len);
            if res == CAP_IOCTLS_ALL {
                Ok(IoctlRights::Unlimited)
            } else if let Ok(rlen) = usize::try_from(res) {
                if rlen > len {
                    panic!("cap_ioctls_get overflowed our buffer")
                } else {
                    cmds.set_len(rlen);
                    Ok(IoctlRights::Limited(cmds))
                }
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }
}

impl CapRights for IoctlRights {
    fn limit<F: AsFd>(&self, f: &F) -> io::Result<()> {
        if let IoctlRights::Limited(v) = self {
            let len = v.len();
            let fd = f.as_fd().as_raw_fd();
            unsafe {
                if libc::cap_ioctls_limit(fd, v.as_ptr(), len) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }
}
