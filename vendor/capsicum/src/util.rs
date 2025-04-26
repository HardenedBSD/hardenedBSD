// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
#![allow(deprecated)] // this whole file is deprecated.

use std::{
    ffi::CString,
    fs::File,
    io::{self, ErrorKind},
    os::{
        fd::{AsFd, BorrowedFd},
        unix::{
            ffi::OsStrExt,
            io::{AsRawFd, FromRawFd, RawFd},
        },
    },
    path::Path,
};

use libc::{c_int, c_uint, mode_t, openat};

/// Directory with a set of capabilities.
///
/// A `Directory` is the entry point for file system operations in capability
/// mode.  Typically, you will open a `Directory`, then enter capability mode,
/// and then open other files relative to the `Directory`.
///
/// # Examples
///
/// ```
/// use capsicum::{self, CapRights, Right, FileRights};
/// use capsicum::util::Directory;
///
/// // Open the directory
/// let dir = Directory::new("./src").unwrap();
///
/// // Limit the capabilities of the open directory
/// FileRights::new()
///     .allow(Right::Read)
///     .allow(Right::Lookup)
///     .limit(&dir).unwrap();
///
/// // Enter the sandbox
/// capsicum::enter().unwrap();
///
/// // Since we have "Lookup" capabilities we can open a file
/// // within the ./src directory
/// let fd = dir.open_file("lib.rs", 0, None).unwrap();
/// ```
#[deprecated(since = "0.4.0", note = "Use cap_std::fs::Dir instead")]
pub struct Directory {
    file: File,
}

impl Directory {
    /// Attempt to open a `Directory` from a standard `Path`.  Will fail in
    /// capability mode.
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Directory> {
        let file = File::open(path.as_ref())?;
        Ok(Directory { file })
    }

    /// Open a regular file relative to an already-opened `Directory`.  This is
    /// the normal way to open files in capability mode.
    pub fn open_file<P: AsRef<Path> + ?Sized>(
        &self,
        path: &P,
        flags: c_int,
        mode: Option<mode_t>,
    ) -> io::Result<File> {
        let p = CString::new(path.as_ref().as_os_str().as_bytes())
            .or(Err(io::Error::new(ErrorKind::Other, "not a valid C path")))?;
        unsafe {
            let fd = match mode {
                Some(mode) => openat(self.file.as_raw_fd(), p.as_ptr(), flags, mode as c_uint),
                None => openat(self.file.as_raw_fd(), p.as_ptr(), 0),
            };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(File::from_raw_fd(fd))
            }
        }
    }
}

impl FromRawFd for Directory {
    unsafe fn from_raw_fd(fd: RawFd) -> Directory {
        Directory {
            file: File::from_raw_fd(fd),
        }
    }
}

impl AsFd for Directory {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl AsRawFd for Directory {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}
