#![warn(missing_docs)]
//! Rust bindings to FreeBSD's
//! [md(4)](https://man.freebsd.org/cgi/man.cgi?query=md) driver.
//!
//! `md` devices are memory disks, that can be backed by RAM, swap, or a file.  They can be useful
//! for temporary storage, and they're very useful for working with disk images as files.  This
//! crate provides bindings to `md` that are equivalent to what the
//! [mdconfig(8)](https://man.freebsd.org/cgi/man.cgi?query=mdconfig) utility provides, but
//! Rustier.
//!
//! The main entry point is the [`Builder`] struct.  Use it to construct an [`Md`] device which
//! will automatically destroy itself when dropped.
use std::{
    ffi::OsStr,
    fs,
    io,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
    ptr,
};

use nix::ioctl_readwrite;

cfg_if::cfg_if! {
    if #[cfg(target_pointer_width = "64")] {
        mod ffi64;
        use ffi64 as ffi;
    } else if #[cfg(target_pointer_width = "32")] {
        mod ffi32;
        use ffi32 as ffi;
    }
}

// Nix's ioctl macros create `pub` functions.  Put them into a module to hide them from the public.
mod ioctl {
    use super::*;

    ioctl_readwrite!(mdiocattach, 'm', 0, ffi::md_ioctl);
    ioctl_readwrite!(mdiocdetach, 'm', 1, ffi::md_ioctl);
    ioctl_readwrite!(mdiocresize, 'm', 4, ffi::md_ioctl);
}

macro_rules! set_bool {
    ( $field:expr, $val:expr, $bit:expr) => {
        if $val {
            $field |= $bit;
        } else {
            $field &= !$bit;
        }
    };
}

/// Used to construct a new [`Md`] device.
///
/// Some constructors have required arguments.  Other options can be provided with builder methods.
///
/// # Example
/// ```no_run
/// let md: mdconfig::Md = mdconfig::Builder::swap(1 << 20)
///     .label("Foo")
///     .reserve(true)
///     .create()
///     .unwrap();
/// ```
#[derive(Debug)]
pub struct Builder {
    filename: Option<PathBuf>,
    label:    Option<Vec<u8>>,
    mdio:     ffi::md_ioctl,
}

impl Builder {
    fn new() -> Self {
        let mdio = ffi::md_ioctl {
            md_version:    ffi::MDIOVERSION,
            md_unit:       0,
            md_type:       0,
            md_file:       ptr::null_mut(),
            md_mediasize:  0,
            md_sectorsize: 0,
            md_options:    ffi::MD_AUTOUNIT | ffi::MD_COMPRESS,
            md_base:       0,
            md_fwheads:    0,
            md_fwsectors:  0,
            md_label:      ptr::null_mut(),
            md_pad:        [0; ffi::MDNPAD as usize],
        };
        Builder {
            mdio,
            filename: None,
            label: None,
        }
    }

    /// Construct a new [`Md`] device backed by memory.
    ///
    /// The size of the device, in bytes, is required.
    ///
    /// # Example
    /// ```no_run
    /// let md = mdconfig::Builder::malloc(1 << 20)
    ///     .create()
    ///     .unwrap();
    /// ```
    pub fn malloc(size: u64) -> Self {
        let mut builder = Self::new();
        builder.mdio.md_type = ffi::md_types_MD_MALLOC;
        builder.mdio.md_mediasize = size as i64;
        builder
    }

    /// Construct a new bitsink [`Md`] device.
    ///
    /// No actual memory is consumed.  Writes are discarded and reads return zeros.
    ///
    /// # Example
    /// ```no_run
    /// let md = mdconfig::Builder::null(1 << 20)
    ///     .create()
    ///     .unwrap();
    /// ```
    pub fn null(size: u64) -> Self {
        let mut builder = Self::new();
        builder.mdio.md_type = ffi::md_types_MD_NULL;
        builder.mdio.md_mediasize = size as i64;
        builder
    }

    /// Construct a new [`Md`] device backed by a file.
    ///
    /// The provided path name will be used as the backing store for the device.  By default, the
    /// `Md` device's size will be the size of the file, though that can be overridden by the
    /// [`Builder::size`] method.
    ///
    /// # Example
    /// ```no_run
    /// # use std::path::Path;
    /// let md = mdconfig::Builder::vnode(Path::new("/tmp/vfat.img"))
    ///     .create()
    ///     .unwrap();
    /// ```
    pub fn vnode(path: &Path) -> Self {
        let mut builder = Self::new();
        builder.mdio.md_type = ffi::md_types_MD_VNODE;
        builder.mdio.md_options |= ffi::MD_CLUSTER;
        builder.filename = Some(path.to_owned());
        builder
    }

    /// Construct a new [`Md`] device backed by swap.
    ///
    /// The size of the device, in bytes, is required.  Unlike [`Builder::malloc`], these devices
    /// may be pushed out to swap when there is memory pressure.
    ///
    /// # Example
    /// ```no_run
    /// let md = mdconfig::Builder::swap(1 << 20)
    ///     .create()
    ///     .unwrap();
    /// ```
    pub fn swap(size: u64) -> Self {
        let mut builder = Self::new();
        builder.mdio.md_type = ffi::md_types_MD_SWAP;
        builder.mdio.md_mediasize = size as i64;
        builder.mdio.md_options |= ffi::MD_CLUSTER;
        builder
    }

    /// For vnode backed devices, avoid `IO_SYNC` for increased performance but at the risk of
    /// deadlocking the entire kernel.
    #[doc(alias = "async")]
    pub fn async_(mut self, async_: bool) -> Self {
        set_bool!(self.mdio.md_options, async_, ffi::MD_ASYNC);
        self
    }

    /// For vnode backed devices: enable/disable caching of data in system caches.
    ///
    /// The default is to not cache, because the backing file will usually reside on a file system
    /// that it itself cached.
    pub fn cache(mut self, cache: bool) -> Self {
        set_bool!(self.mdio.md_options, cache, ffi::MD_CACHE);
        self
    }

    /// Enable/disable compression features to reduce memory usage.
    pub fn compress(mut self, compress: bool) -> Self {
        set_bool!(self.mdio.md_options, compress, ffi::MD_COMPRESS);
        self
    }

    /// Construct a specific synthetic geometry, for malloc and vnode backed devices.
    ///
    /// This is useful for constructing bootable images for later download to other devices.
    pub fn heads_per_cylinder(mut self, heads: i32) -> Self {
        self.mdio.md_fwheads = heads;
        self
    }

    /// Associate an arbitrary string with the new memory disk.
    ///
    /// The label will be reported by `mdconfig -lv`.
    pub fn label(mut self, label: &str) -> Self {
        let mut clabel = Vec::with_capacity(libc::PATH_MAX as usize);
        clabel.extend_from_slice(OsStr::new(label).as_bytes());
        clabel.resize(libc::PATH_MAX as usize, 0);
        self.label = Some(clabel);
        self
    }

    /// For vnode backed devices: fail a `BIO_DELETE` request if the underlying file system does
    /// not support hole-punching.
    ///
    /// If `mustdealloc` is not specified and the underlying file system does not support hole
    /// punching, then `BIO_DELETE` requests will be handled by zero-filling.
    // Supported on FreeBSD 14+
    pub fn mustdealloc(mut self, mustdealloc: bool) -> Self {
        set_bool!(self.mdio.md_options, mustdealloc, ffi::MD_MUSTDEALLOC);
        self
    }

    /// Allocate and reserve all needed storage from the start, rather than as needed.
    pub fn reserve(mut self, reserve: bool) -> Self {
        set_bool!(self.mdio.md_options, reserve, ffi::MD_RESERVE);
        self
    }

    /// Enable readonly mode.
    pub fn readonly(mut self, readonly: bool) -> Self {
        set_bool!(self.mdio.md_options, readonly, ffi::MD_READONLY);
        self
    }

    /// Construct a specific synthetic geometry, for malloc and vnode backed devices.
    ///
    /// This is useful for constructing bootable images for later download to other devices.
    pub fn sectors_per_track(mut self, sectors: i32) -> Self {
        self.mdio.md_fwsectors = sectors;
        self
    }

    /// Sectorsize to use for the memory disk, in bytes.
    pub fn sectorsize(mut self, sectorsize: u32) -> Self {
        self.mdio.md_sectorsize = sectorsize;
        self
    }

    /// Set the size of the created device.
    ///
    /// This can be used to override the automatically detected size for a vnode-backed Md.
    pub fn size(mut self, size: libc::off_t) -> Self {
        self.mdio.md_mediasize = size;
        self
    }

    /// Request a specific unit number for the new device.
    ///
    /// The default is to automatically assign a unit number.
    pub fn unit(mut self, unit: u32) -> Self {
        self.mdio.md_unit = unit;
        self.mdio.md_options &= !ffi::MD_AUTOUNIT;
        self
    }

    /// For vnode backed devices: enable/disable requesting verification of the file used for
    /// backing store.
    pub fn verify(mut self, verify: bool) -> Self {
        set_bool!(self.mdio.md_options, verify, ffi::MD_VERIFY);
        self
    }

    /// Finalize the Builder into an [`Md`] device.
    pub fn create(mut self) -> io::Result<Md> {
        let devmd = fs::File::open("/dev/mdctl")?;
        let mut _storage = None;
        if let Some(filename) = self.filename {
            let md = fs::metadata(&filename)?;
            if self.mdio.md_mediasize == 0 {
                self.mdio.md_mediasize = md.size() as libc::off_t;
            }
            let mut v = Vec::with_capacity(libc::PATH_MAX as usize);
            v.extend_from_slice(OsStr::new(&filename).as_bytes());
            v.resize(libc::PATH_MAX as usize, 0);
            self.mdio.md_file = v.as_mut_ptr() as *mut libc::c_char;
            _storage = Some(v);
        }
        if let Some(label) = self.label.as_mut() {
            self.mdio.md_label = label.as_mut_ptr() as *mut libc::c_char;
        }
        unsafe { ioctl::mdiocattach(devmd.as_raw_fd(), &mut self.mdio)? };
        let name = format!("md{}", self.mdio.md_unit);
        let path = Path::new("/dev").join(&name);
        Ok(Md {
            name,
            path,
            unit: self.mdio.md_unit,
        })
    }
}

/// Represents a device like `/dev/md0`, and automatically destroys it on Drop.
///
/// Note that this represents the device itself, not an open device.  To open it, first create it
/// and then open it like any other file.
///
/// During Drop, the device will be forcefully detached, regardless of whether any other process is
/// using it.  To conditionally detach the device only if it is idle, use [`try_destroy`].
///
/// # Example
/// ```no_run
/// let md = mdconfig::Builder::null(1 << 20).create().unwrap();
/// let f = std::fs::File::open(md.path()).unwrap();
/// ```
#[derive(Debug)]
pub struct Md {
    name: String,
    /// Path to the md device.  e.g. /dev/md0
    path: PathBuf,
    /// Unit number
    unit: u32,
}

impl Md {
    fn detach(&mut self, force: bool) -> io::Result<()> {
        let md_options = if force { ffi::MD_FORCE } else { 0 };
        let mut mdio = ffi::md_ioctl {
            md_version: ffi::MDIOVERSION,
            md_unit: self.unit,
            md_type: 0,
            md_file: ptr::null_mut(),
            md_mediasize: 0,
            md_sectorsize: 0,
            md_options,
            md_base: 0,
            md_fwheads: 0,
            md_fwsectors: 0,
            md_label: ptr::null_mut(),
            md_pad: [0; ffi::MDNPAD as usize],
        };
        let mddev = fs::File::open("/dev/mdctl")?;
        unsafe { ioctl::mdiocdetach(mddev.as_raw_fd(), &mut mdio) }?;
        Ok(())
    }

    /// Report the name to the device, like "md0".
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Report the path to the device, like "/dev/md0".
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Change the device's size in bytes.
    ///
    /// If the new size is less than the old size, the `force` option must be used, and data may be
    /// discarded.
    pub fn resize(&self, newsize: libc::off_t, force: bool) -> io::Result<()> {
        let mut mdio = ffi::md_ioctl {
            md_version:    ffi::MDIOVERSION,
            md_unit:       self.unit,
            md_type:       0,
            md_file:       ptr::null_mut(),
            md_mediasize:  newsize,
            md_sectorsize: 0,
            md_options:    0,
            md_base:       0,
            md_fwheads:    0,
            md_fwsectors:  0,
            md_label:      ptr::null_mut(),
            md_pad:        [0; ffi::MDNPAD as usize],
        };
        if force {
            mdio.md_options |= ffi::MD_FORCE;
        }
        let devmd = fs::File::open("/dev/mdctl")?;
        unsafe {
            ioctl::mdiocresize(devmd.as_raw_fd(), &mut mdio)?;
        }
        Ok(())
    }

    /// Attempt to destroy the underlying device within the operating system.
    ///
    /// If unsuccessful, the device will not be changed.  If successful, the actual device will be
    /// deallocated.  A common reason for failure is `EBUSY`, which indicates that some other
    /// process has the device open.
    pub fn try_destroy(mut self) -> std::result::Result<(), (Self, io::Error)> {
        match self.detach(false) {
            Ok(()) => {
                std::mem::forget(self);
                Ok(())
            }
            Err(e) => Err((self, e)),
        }
    }

    /// Report the device's unit number. e.g. the "0" in "md0".
    ///
    /// # Example
    /// ```no_run
    /// let md = mdconfig::Builder::null(1 << 20)
    ///     .unit(666)
    ///     .create()
    ///     .unwrap();
    /// assert_eq!(md.unit(), 666)
    /// ```
    pub fn unit(&self) -> u32 {
        self.unit
    }
}

impl Drop for Md {
    fn drop(&mut self) {
        let r = self.detach(true);
        if !std::thread::panicking() {
            r.expect("Error during MDIOCDETACH during drop");
        }
    }
}
