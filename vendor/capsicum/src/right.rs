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

pub const RIGHTS_VERSION: i32 = 0;

macro_rules! cap_right {
    ($idx:expr, $bit:expr) => {
        ((1u64 << (57 + ($idx))) | ($bit))
    };
}

macro_rules! right_or {
    ($($right:expr),*) => {
        $($right as u64)|*
    }
}

/// Capsicum capability rights for file descriptors.
///
/// See [`rights(4)`](https://www.freebsd.org/cgi/man.cgi?query=rights) for details.
#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(missing_docs)] // Individual bits are documented via the external link.
pub enum Right {
    Null = 0,
    Read = cap_right!(0, 0x1u64),
    Write = cap_right!(0, 0x2u64),
    SeekTell = cap_right!(0, 0x4u64),
    Seek = right_or!(Right::SeekTell, 0x8u64),
    Pread = right_or!(Right::Seek, Right::Read),
    Pwrite = right_or!(Right::Seek, Right::Write),
    Mmap = cap_right!(0, 0x10u64),
    MmapR = right_or!(Right::Mmap, Right::Seek, Right::Read),
    MmapW = right_or!(Right::Mmap, Right::Seek, Right::Write),
    MmapX = right_or!(Right::Mmap, Right::Seek, 0x20u64),
    MmapRW = right_or!(Right::MmapR, Right::MmapW),
    MmapRX = right_or!(Right::MmapR, Right::MmapX),
    MmapWX = right_or!(Right::MmapW, Right::MmapX),
    MmapRWX = right_or!(Right::MmapR, Right::MmapW, Right::MmapX),
    Create = cap_right!(0, 0x40u64),
    Fexecve = cap_right!(0, 0x80u64),
    Fsync = cap_right!(0, 0x100u64),
    Ftruncate = cap_right!(0, 0x200u64),
    Lookup = cap_right!(0, 0x400u64),
    Fchdir = cap_right!(0, 0x800u64),
    Fchflags = cap_right!(0, 0x1000u64),
    Fchflagsat = right_or!(Right::Fchflags, Right::Lookup),
    Fchmod = cap_right!(0, 0x2000u64),
    Fchmodat = right_or!(Right::Fchmod, Right::Lookup),
    Fchown = cap_right!(0, 0x4000u64),
    Fchownat = right_or!(Right::Fchown, Right::Lookup),
    Fcntl = cap_right!(0, 0x8000u64),
    Flock = cap_right!(0, 0x10000u64),
    Fpathconf = cap_right!(0, 0x20000u64),
    Fsck = cap_right!(0, 0x40000u64),
    Fstat = cap_right!(0, 0x80000u64),
    Fstatat = right_or!(Right::Fstat, Right::Lookup),
    Fstatfs = cap_right!(0, 0x100000u64),
    Futimes = cap_right!(0, 0x200000u64),
    Futimesat = right_or!(Right::Futimes, Right::Lookup),
    LinkatTarget = right_or!(Right::Lookup, 0x400000u64),
    Mkdirat = right_or!(Right::Lookup, 0x800000u64),
    Mkfifoat = right_or!(Right::Lookup, 0x1000000u64),
    Mknotat = right_or!(Right::Lookup, 0x2000000u64),
    RenameatSource = right_or!(Right::Lookup, 0x4000000u64),
    RenameatTarget = right_or!(Right::Lookup, 0x0000040000000000u64),
    Symlinkat = right_or!(Right::Lookup, 0x8000000u64),
    Unlinkat = right_or!(Right::Lookup, 0x10000000u64),
    Accept = cap_right!(0, 0x20000000u64),
    Bind = cap_right!(0, 0x40000000u64),
    Connect = cap_right!(0, 0x80000000u64),
    Getpeername = cap_right!(0, 0x100000000u64),
    Getsockname = cap_right!(0, 0x200000000u64),
    Getsockopt = cap_right!(0, 0x400000000u64),
    Listen = cap_right!(0, 0x800000000u64),
    Peeloff = cap_right!(0, 0x1000000000u64),
    Setsockopt = cap_right!(0, 0x2000000000u64),
    Shutdown = cap_right!(0, 0x4000000000u64),
    Bindat = right_or!(Right::Lookup, 0x8000000000u64),
    Connectat = right_or!(Right::Lookup, 0x10000000000u64),
    LinkatSource = right_or!(Right::Lookup, 0x0000020000000000u64),
    SockClient = right_or!(
        Right::Connect,
        Right::Getpeername,
        Right::Getsockname,
        Right::Getsockopt,
        Right::Peeloff,
        Right::Read,
        Right::Write,
        Right::Setsockopt,
        Right::Shutdown
    ),
    SockServer = right_or!(
        Right::Accept,
        Right::Bind,
        Right::Getpeername,
        Right::Getsockname,
        Right::Getsockopt,
        Right::Listen,
        Right::Peeloff,
        Right::Read,
        Right::Write,
        Right::Setsockopt,
        Right::Shutdown
    ),
    All0 = cap_right!(0, 0x7FFFFFFFFFu64),
    Unused044 = cap_right!(0, 0x0000080000000000u64),
    Unused057 = cap_right!(0, 0x0100000000000000u64),
    MacGet = cap_right!(1, 0x1u64),
    MacSet = cap_right!(1, 0x2u64),
    SemGetvalue = cap_right!(1, 0x4u64),
    SemPost = cap_right!(1, 0x8u64),
    SemWait = cap_right!(1, 0x10u64),
    Event = cap_right!(1, 0x20u64),
    KqueueEvent = cap_right!(1, 0x40u64),
    Ioctl = cap_right!(1, 0x80u64),
    Ttyhook = cap_right!(1, 0x100u64),
    Pdgetpid = cap_right!(1, 0x200u64),
    Pdwait = cap_right!(1, 0x400u64),
    Pdkill = cap_right!(1, 0x800),
    ExtattrDelete = cap_right!(1, 0x1000u64),
    ExtattrGet = cap_right!(1, 0x2000u64),
    ExtattrList = cap_right!(1, 0x4000u64),
    ExtattrSet = cap_right!(1, 0x8000u64),
    AclCheck = cap_right!(1, 0x10000u64),
    AclDelete = cap_right!(1, 0x20000u64),
    AclGet = cap_right!(1, 0x40000u64),
    AclSet = cap_right!(1, 0x80000u64),
    KqueueChange = cap_right!(1, 0x100000u64),
    Kqueue = right_or!(Right::KqueueEvent, Right::KqueueChange),
    All1 = cap_right!(1, 0x1FFFFFu64),
    Unused122 = cap_right!(1, 0x200000u64),
    Unused157 = cap_right!(1, 0x100000000000000u64),
}

impl Right {
    #[allow(non_upper_case_globals)]
    #[allow(missing_docs)]
    #[deprecated(since = "0.4.0", note = "Use Right::LinkatTarget instead")]
    pub const Linkat: Right = Right::LinkatTarget;
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
            libc::__cap_rights_init(RIGHTS_VERSION, &mut inner_rights as *mut cap_rights_t, 0u64);
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
            libc::__cap_rights_init(RIGHTS_VERSION, &mut inner_rights as *mut cap_rights_t, 0u64);
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
            let res =
                libc::__cap_rights_get(RIGHTS_VERSION, fd, &mut inner_rights as *mut cap_rights_t);
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

#[test]
fn test_macros() {
    assert_eq!(cap_right!(0, 1), 144115188075855873u64);
    assert_eq!(right_or!(Right::Read, Right::Write), 144115188075855875u64);
}
