// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#![allow(unused)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]

use std::{
    io,
    mem,
    ops::BitAnd,
    os::{
        fd::AsFd,
        raw::c_char,
        unix::io::{AsRawFd, RawFd},
    },
};

use libc::cap_rights_t;

use crate::common::CapRights;

/// Capsicum capability rights for file descriptors.
///
/// See [`rights(4)`](https://www.freebsd.org/cgi/man.cgi?query=rights) for details.
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(missing_docs)] // Individual bits are documented via the external link.
pub enum Right {
    Null = 0,
    Read = libc::CAP_READ,
    Write = libc::CAP_WRITE,
    SeekTell = libc::CAP_SEEK_TELL,
    Seek = libc::CAP_SEEK,
    Pread = libc::CAP_PREAD,
    Pwrite = libc::CAP_PWRITE,
    Mmap = libc::CAP_MMAP,
    MmapR = libc::CAP_MMAP_R,
    MmapW = libc::CAP_MMAP_W,
    MmapX = libc::CAP_MMAP_X,
    MmapRW = libc::CAP_MMAP_RW,
    MmapRX = libc::CAP_MMAP_RX,
    MmapWX = libc::CAP_MMAP_WX,
    MmapRWX = libc::CAP_MMAP_RWX,
    Create = libc::CAP_CREATE,
    Fexecve = libc::CAP_FEXECVE,
    Fsync = libc::CAP_FSYNC,
    Ftruncate = libc::CAP_FTRUNCATE,
    Lookup = libc::CAP_LOOKUP,
    Fchdir = libc::CAP_FCHDIR,
    Fchflags = libc::CAP_FCHFLAGS,
    Chflagsat = libc::CAP_CHFLAGSAT,
    Fchmod = libc::CAP_FCHMOD,
    Fchmodat = libc::CAP_FCHMODAT,
    Fchown = libc::CAP_FCHOWN,
    Fchownat = libc::CAP_FCHOWNAT,
    Fcntl = libc::CAP_FCNTL,
    Flock = libc::CAP_FLOCK,
    Fpathconf = libc::CAP_FPATHCONF,
    Fsck = libc::CAP_FSCK,
    Fstat = libc::CAP_FSTAT,
    Fstatat = libc::CAP_FSTATAT,
    Fstatfs = libc::CAP_FSTATFS,
    Futimes = libc::CAP_FUTIMES,
    Futimesat = libc::CAP_FUTIMESAT,
    LinkatTarget = libc::CAP_LINKAT_TARGET,
    Mkdirat = libc::CAP_MKDIRAT,
    Mkfifoat = libc::CAP_MKFIFOAT,
    Mknodat = libc::CAP_MKNODAT,
    RenameatSource = libc::CAP_RENAMEAT_SOURCE,
    RenameatTarget = libc::CAP_RENAMEAT_TARGET,
    Symlinkat = libc::CAP_SYMLINKAT,
    Unlinkat = libc::CAP_UNLINKAT,
    Accept = libc::CAP_ACCEPT,
    Bind = libc::CAP_BIND,
    Connect = libc::CAP_CONNECT,
    Getpeername = libc::CAP_GETPEERNAME,
    Getsockname = libc::CAP_GETSOCKNAME,
    Getsockopt = libc::CAP_GETSOCKOPT,
    Listen = libc::CAP_LISTEN,
    Peeloff = libc::CAP_PEELOFF,
    Setsockopt = libc::CAP_SETSOCKOPT,
    Shutdown = libc::CAP_SHUTDOWN,
    Bindat = libc::CAP_BINDAT,
    Connectat = libc::CAP_CONNECTAT,
    LinkatSource = libc::CAP_LINKAT_SOURCE,
    SockClient = libc::CAP_SOCK_CLIENT,
    SockServer = libc::CAP_SOCK_SERVER,
    #[deprecated(since = "0.4.4", note = "May change in later OS versions")]
    #[allow(deprecated)]
    All0 = libc::CAP_ALL0,
    #[deprecated(since = "0.4.4", note = "May disappear in later OS versions")]
    #[allow(deprecated)]
    Unused044 = libc::CAP_UNUSED0_44,
    #[deprecated(since = "0.4.4", note = "May disappear in later OS versions")]
    #[allow(deprecated)]
    Unused057 = libc::CAP_UNUSED0_57,
    MacGet = libc::CAP_MAC_GET,
    MacSet = libc::CAP_MAC_SET,
    SemGetvalue = libc::CAP_SEM_GETVALUE,
    SemPost = libc::CAP_SEM_POST,
    SemWait = libc::CAP_SEM_WAIT,
    Event = libc::CAP_EVENT,
    KqueueEvent = libc::CAP_KQUEUE_EVENT,
    Ioctl = libc::CAP_IOCTL,
    Ttyhook = libc::CAP_TTYHOOK,
    Pdgetpid = libc::CAP_PDGETPID,
    Pdwait = libc::CAP_PDWAIT,
    Pdkill = libc::CAP_PDKILL,
    ExtattrDelete = libc::CAP_EXTATTR_DELETE,
    ExtattrGet = libc::CAP_EXTATTR_GET,
    ExtattrList = libc::CAP_EXTATTR_LIST,
    ExtattrSet = libc::CAP_EXTATTR_SET,
    AclCheck = libc::CAP_ACL_CHECK,
    AclDelete = libc::CAP_ACL_DELETE,
    AclGet = libc::CAP_ACL_GET,
    AclSet = libc::CAP_ACL_SET,
    KqueueChange = libc::CAP_KQUEUE_CHANGE,
    Kqueue = libc::CAP_KQUEUE,
    #[deprecated(since = "0.4.4", note = "May change in later OS versions")]
    #[allow(deprecated)]
    All1 = libc::CAP_ALL1,
    #[deprecated(since = "0.4.4", note = "May disappear in later OS versions")]
    #[allow(deprecated)]
    Unused122 = libc::CAP_UNUSED1_22,
    #[deprecated(since = "0.4.4", note = "May disappear in later OS versions")]
    #[allow(deprecated)]
    Unused157 = libc::CAP_UNUSED1_57,
}

impl Right {
    #[allow(non_upper_case_globals)]
    #[allow(missing_docs)]
    #[deprecated(since = "0.4.3", note = "Use Right::Chflagsat instead")]
    pub const Fchflagsat: Right = Right::Chflagsat;
    #[allow(non_upper_case_globals)]
    #[allow(missing_docs)]
    #[deprecated(since = "0.4.0", note = "Use Right::LinkatTarget instead")]
    pub const Linkat: Right = Right::LinkatTarget;
    #[allow(non_upper_case_globals)]
    #[allow(missing_docs)]
    #[deprecated(since = "0.4.3", note = "Use Right::Mknodat instead")]
    pub const Mknotat: Right = Right::Mknodat;
    #[allow(non_upper_case_globals)]
    #[allow(missing_docs)]
    #[deprecated(since = "0.4.0", note = "Use Right::RenameatSource instead")]
    pub const Renameat: Right = Right::RenameatSource;
}

/// Used to construct a new set of allowed file rights.
///
/// # Example
/// ```
/// # use capsicum::{Right, RightsBuilder};
/// let rights = RightsBuilder::new()
///     .allow(Right::Read)
///     .allow(Right::Fexecve)
///     .finalize();
/// ```
#[derive(Debug)]
#[deprecated(since = "0.4.0", note = "Use FcntlRights directly")]
pub struct RightsBuilder(cap_rights_t);

#[allow(deprecated)]
impl RightsBuilder {
    /// Initialize a new `RightsBuilder` which will deny all rights.
    pub fn new() -> RightsBuilder {
        // cap_rights_init is documented as infalliable.
        let inner_rights = unsafe {
            let mut inner_rights = mem::zeroed();
            libc::__cap_rights_init(
                libc::CAP_RIGHTS_VERSION,
                &mut inner_rights as *mut cap_rights_t,
                0u64,
            );
            inner_rights
        };
        let builder = RightsBuilder(inner_rights);
        debug_assert!(builder.is_valid());
        builder
    }

    #[allow(missing_docs)]
    #[deprecated(since = "0.4.0", note = "use RightsBuilder::allow instead")]
    pub fn add(&mut self, right: Right) -> &mut RightsBuilder {
        self.allow(right)
    }

    /// Add a new `Right` to the list of allowed rights.
    pub fn allow(&mut self, right: Right) -> &mut RightsBuilder {
        let result = unsafe { libc::__cap_rights_set(self.as_mut_ptr(), right as u64, 0u64) };
        debug_assert!(!result.is_null()); // documented as infalliable
        self
    }

    fn as_mut_ptr(&mut self) -> *mut cap_rights_t {
        &mut self.0 as *mut cap_rights_t
    }

    /// Finish this Builder into a `FileRights` object.
    pub fn finalize(&self) -> FileRights {
        FileRights(self.0)
    }

    fn is_valid(&self) -> bool {
        unsafe { libc::cap_rights_is_valid(&self.0) }
    }

    #[allow(missing_docs)]
    #[deprecated(since = "0.4.0", note = "use RightsBuilder::deny instead")]
    pub fn remove(&mut self, right: Right) -> &mut RightsBuilder {
        self.deny(right)
    }

    /// Remove another `Right` from the list of allowed rights.
    pub fn deny(&mut self, right: Right) -> &mut RightsBuilder {
        let result = unsafe { libc::__cap_rights_clear(self.as_mut_ptr(), right as u64, 0u64) };
        debug_assert!(!result.is_null()); // documented as infalliable
        self
    }
}

#[allow(deprecated)]
impl Default for RightsBuilder {
    fn default() -> Self {
        RightsBuilder::new()
    }
}

/// Used to reduce (but never expand) the capabilities on a file descriptor.
///
/// # See Also
///
/// [`cap_rights_limit(2)`](https://www.freebsd.org/cgi/man.cgi?query=cap_rights_limit).
///
/// # Example
/// ```
/// # use std::io::{self, Read, Write};
/// # use capsicum::{CapRights, FileRights, Right};
/// # use tempfile::tempfile;
/// let mut file = tempfile().unwrap();
/// FileRights::new()
///     .allow(Right::Read)
///     .limit(&file).unwrap();
///
/// capsicum::enter().unwrap();
///
/// let mut buf = vec![0u8; 80];
/// file.read(&mut buf[..]).unwrap();
///
/// let e = file.write(&buf[..]).unwrap_err();
/// assert_eq!(e.raw_os_error(), Some(libc::ENOTCAPABLE));
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileRights(cap_rights_t);

impl FileRights {
    /// Initialize a new `FileRights` which will deny all rights.
    pub fn new() -> Self {
        // cap_rights_init is documented as infalliable.
        let inner_rights = unsafe {
            let mut inner_rights = mem::zeroed();
            libc::__cap_rights_init(
                libc::CAP_RIGHTS_VERSION,
                &mut inner_rights as *mut cap_rights_t,
                0u64,
            );
            inner_rights
        };
        let rights = Self(inner_rights);
        debug_assert!(rights.is_valid_priv());
        rights
    }

    fn as_mut_ptr(&mut self) -> *mut cap_rights_t {
        &mut self.0 as *mut cap_rights_t
    }

    /// Retrieve the list of rights currently allowed for the given file.
    /// # Example
    /// ```
    /// # use capsicum::{CapRights, FileRights, Right};
    /// # use tempfile::tempfile;
    /// let file = tempfile().unwrap();
    /// let mut rights = FileRights::new();
    /// rights.allow(Right::Read);
    ///
    /// rights.limit(&file).unwrap();
    /// let rights2 = FileRights::from_file(&file).unwrap();
    /// assert_eq!(rights, rights2);
    /// ```
    ///
    /// # See Also
    /// [`cap_rights_get(3)`](https://www.freebsd.org/cgi/man.cgi?query=cap_rights_get)
    pub fn from_file<F: AsFd>(f: &F) -> io::Result<FileRights> {
        let fd = f.as_fd().as_raw_fd();
        let inner_rights = unsafe {
            let mut inner_rights = unsafe { mem::zeroed() };
            let res = libc::__cap_rights_get(
                libc::CAP_RIGHTS_VERSION,
                fd,
                &mut inner_rights as *mut cap_rights_t,
            );
            if res < 0 {
                return Err(io::Error::last_os_error());
            }
            inner_rights
        };
        let rights = FileRights(inner_rights);
        assert!(rights.is_valid_priv());
        Ok(rights)
    }

    /// Add a new `Right` to the list of allowed rights.
    pub fn allow(&mut self, right: Right) -> &mut Self {
        let result = unsafe { libc::__cap_rights_set(self.as_mut_ptr(), right as u64, 0u64) };
        debug_assert!(!result.is_null()); // documented as infalliable
        self
    }

    /// Checks if `self` contains all of the rights present in `other`.
    ///
    /// # Example
    /// ```
    /// # use capsicum::{CapRights, FileRights, Right};
    /// let mut rights1 = FileRights::new();
    /// rights1.allow(Right::Read);
    /// rights1.allow(Right::Write);
    /// let mut rights2 = FileRights::new();
    /// rights2.allow(Right::Write);
    /// assert!(rights1.contains(&rights2));
    ///
    /// let mut rights3 = FileRights::new();
    /// rights3.allow(Right::Read);
    /// rights3.allow(Right::Seek);
    /// assert!(!rights1.contains(&rights3));
    /// ```
    pub fn contains(&self, other: &FileRights) -> bool {
        unsafe { libc::cap_rights_contains(&self.0, &other.0) }
    }

    /// Is the given [`Right`] set here?
    ///
    /// # Example
    /// ```
    /// # use capsicum::{Right, FileRights};
    ///
    /// let mut rights = FileRights::new();
    /// rights.allow(Right::Read);
    /// assert!(rights.is_set(Right::Read));
    /// assert!(!rights.is_set(Right::Write));
    /// ```
    pub fn is_set(&self, right: Right) -> bool {
        unsafe { libc::__cap_rights_is_set(&self.0 as *const cap_rights_t, right as u64, 0u64) }
    }

    #[deprecated(since = "0.4.0", note = "Unnecessary unless you use FileRights::new")]
    #[allow(missing_docs)]
    pub fn is_valid(&self) -> bool {
        self.is_valid_priv()
    }

    fn is_valid_priv(&self) -> bool {
        unsafe { libc::cap_rights_is_valid(&self.0) }
    }

    /// Add all rights present in `other` to this structure.
    pub fn merge(&mut self, other: &FileRights) -> io::Result<()> {
        unsafe {
            let result = libc::cap_rights_merge(self.as_mut_ptr(), &other.0);
            if result.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    /// Remove any rights present in `other` from this structure, if they are set.
    pub fn remove(&mut self, other: &FileRights) -> io::Result<()> {
        unsafe {
            let result = libc::cap_rights_remove(self.as_mut_ptr(), &other.0);
            if result.is_null() {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    #[allow(missing_docs)]
    #[deprecated(since = "0.4.0", note = "use FileRights::allow instead")]
    pub fn set(&mut self, raw_rights: Right) -> io::Result<()> {
        self.allow(raw_rights);
        Ok(())
    }

    #[allow(missing_docs)]
    #[deprecated(since = "0.4.0", note = "use FileRights::deny instead")]
    pub fn clear(&mut self, raw_rights: Right) -> io::Result<()> {
        self.deny(raw_rights);
        Ok(())
    }

    /// Remove an allowed `Right` from the list.
    pub fn deny(&mut self, right: Right) -> &mut Self {
        let result = unsafe { libc::__cap_rights_clear(self.as_mut_ptr(), right as u64, 0u64) };
        debug_assert!(!result.is_null()); // documented as infalliable
        self
    }
}

impl Default for FileRights {
    fn default() -> Self {
        Self::new()
    }
}

impl CapRights for FileRights {
    fn limit<F: AsFd>(&self, f: &F) -> io::Result<()> {
        let fd = f.as_fd().as_raw_fd();
        unsafe {
            let res = libc::cap_rights_limit(fd, &self.0 as *const cap_rights_t);
            if res < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}
