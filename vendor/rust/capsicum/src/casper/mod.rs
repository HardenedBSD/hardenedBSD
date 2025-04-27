#![warn(missing_docs)]
//! Rust bindings to FreeBSD's libcasper
//!
//! Capsicum is a security feature that restricts processes from accessing all global namespaces.
//! But some common tasks can't be done without global namespaces.  For them, there is libcasper.
//! The Casper service is a separate process forked before the main one enters capability mode.  It
//! connects to the main process via a socket, servicing requests for things that can't be done in
//! capability mode.  Because each Casper process strictly validates each request, the potential
//! harm from a compromised main process is limited, just as with Capsicum.
//!
//! The base libcasper provides no services of its own.  In Rust, the starting point to use Casper
//! is [`service!`] (to create a custom service in Rust), or [`service_connection!`] (to connect to
//! an existing service).
//!
//! # See Also
//! * [libcasper(3)](https://www.freebsd.org/cgi/man.cgi?query=libcasper)
use std::{ffi::CStr, io, ptr};

// Reexport these symbols, consumer crates don't need to directly depend on the
// libnv and libnv-sys crates.
pub use libnv::{
    libnv::{NvFlag, NvList},
    NvError,
};

/// Low-level stuff that we must reexport because it gets used in the macros.
#[doc(hidden)]
pub mod sys {
    pub use casper_sys::{cap_limit_get, cap_limit_set, cap_xfer_nvlist, service_register};
    pub use ctor::ctor;
    pub use libnv_sys::nvlist_t;
}

/// ORable flags for use with [`service!`].
///
/// See `libcasper(3)` for details.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct ServiceRegisterFlags(u64);
impl ServiceRegisterFlags {
    /// The casper service has access to all of the descriptors, besides the
    /// stdio descriptors, from the process it was spawned from.
    pub const FD: ServiceRegisterFlags = ServiceRegisterFlags(casper_sys::CASPER_SERVICE_FD);
    /// No flags.
    pub const NONE: ServiceRegisterFlags = ServiceRegisterFlags(0);
    /// The whole casper communication is using an nvlist(9) with the
    /// `NV_FLAG_NO_UNIQUE` flag.
    pub const NO_UNIQ_LIMITS: ServiceRegisterFlags =
        ServiceRegisterFlags(casper_sys::CASPER_SERVICE_NO_UNIQ_LIMITS);
    /// The casper service has access to the stdio descriptors from the process
    /// it was spawned from.
    pub const STDIO: ServiceRegisterFlags = ServiceRegisterFlags(casper_sys::CASPER_SERVICE_STDIO);
}

impl From<ServiceRegisterFlags> for u64 {
    fn from(f: ServiceRegisterFlags) -> Self {
        f.0
    }
}

/// A channel to communicate with Casper or Casper services
// Must not be Clone or Copy!  The inner pointer is an opaque structure created
// by cap_init, and must be freed with cap_close.
#[derive(Debug)]
#[doc(hidden)]
pub struct CapChannel(ptr::NonNull<casper_sys::cap_channel_t>);

impl CapChannel {
    pub fn as_mut_ptr(&mut self) -> *mut casper_sys::cap_channel_t {
        self.0.as_ptr()
    }

    pub fn as_ptr(&self) -> *const casper_sys::cap_channel_t {
        self.0.as_ptr() as *const _
    }

    fn from_raw_ptr(chan: *mut casper_sys::cap_channel_t) -> Option<Self> {
        ptr::NonNull::new(chan).map(Self)
    }
}

impl Drop for CapChannel {
    fn drop(&mut self) {
        // always safe
        unsafe { casper_sys::cap_close(self.0.as_ptr()) }
    }
}

// CapChannel can be Send and Sync because its contained pointer has unique
// ownership, and it is not Copy or Clone.
unsafe impl Send for CapChannel {}
unsafe impl Sync for CapChannel {}

/// A channel to communicate with the Casper process
#[derive(Debug)]
pub struct Casper(CapChannel);

impl Casper {
    /// Initialize the Casper services.
    ///
    /// # Safety
    ///
    /// The program must be single-threaded at the time of this call.  It's fine
    /// to start additional threads later, however.
    // cap_init internally forks, so it should only be used by single-threaded
    // programs.
    // See https://github.com/rust-lang/rust/issues/39575 for an explanation of
    // why this is considered `unsafe`.
    pub unsafe fn new() -> io::Result<Self> {
        let chan = unsafe { casper_sys::cap_init() };
        CapChannel::from_raw_ptr(chan)
            .map(Casper)
            .ok_or(io::Error::last_os_error())
    }

    /// Open a connection to the named Casper service.  Should not be used
    /// directly except by [`service_connection!`].
    // Needs &mut self because cap_service_open is reentrant but not
    // thread-safe.
    #[doc(hidden)]
    pub fn service_open(&mut self, name: &CStr) -> io::Result<CapChannel> {
        let chan = unsafe { casper_sys::cap_service_open(self.0.as_ptr(), name.as_ptr()) };
        CapChannel::from_raw_ptr(chan).ok_or(io::Error::last_os_error())
    }

    /// Clone the handle to the Casper process.
    // Needs &mut self because cap_clone is reentrant but not
    // thread-safe.
    pub fn try_clone(&mut self) -> io::Result<Self> {
        // Safe as long as self.0 is a valid channel, which we ensure
        let chan2 = unsafe { casper_sys::cap_clone(self.0.as_ptr()) };
        CapChannel::from_raw_ptr(chan2)
            .map(Casper)
            .ok_or(io::Error::last_os_error())
    }
}

mod macros {
    /// Declare a connection to an existing Casper service.
    ///
    /// Note that separate invocations of this macro must be made from separate
    /// modules.
    ///
    /// The generated struct will have two methods defined:
    /// * `limit_get` - Retrieve existing limits as an `NvList`.  If no limits
    ///                 have yet been set, the nvlist will be empty.
    /// * `limit_set` - Set new limits, as an `NvList`.  The nvlist's contents
    ///                 are entirely service-defined.  It should not be possible
    ///                 to set limits less restrictive than those already in
    ///                 place.
    ///
    /// # Arguments
    /// * `vis` - Visibility of the generated structure.
    /// * `astruct` - The name of the struct that accesses the service.
    /// * `cname` - The name that the service registers with Casper.  Must be a
    ///            `&'static CStr`.
    /// * `meth` - The name of the accessor that will be added to `Casper`.
    ///
    /// # Examples
    /// ```
    /// use capsicum::casper;
    ///
    /// casper::service_connection!(
    ///     pub CapGroupAgent,
    ///     c"system.grp",
    ///     group
    /// );
    /// ```
    #[macro_export]
    macro_rules! service_connection {
        (
            $(#[$attr:meta])*
            $vis:vis $astruct:ident, $cname:expr, $meth:ident
        ) => {
            $(#[$attr])*
            $vis struct $astruct($crate::casper::CapChannel);
            impl $astruct {
                /// Retrieve the service's existing limits
                fn limit_get(&mut self) -> ::std::io::Result<$crate::casper::NvList> {
                    let mut nvlp: *mut $crate::casper::sys::nvlist_t = ::std::ptr::null_mut();

                    let r = unsafe {
                        $crate::casper::sys::cap_limit_get(self.0.as_ptr(), &mut nvlp as *mut *mut $crate::casper::sys::nvlist_t)
                    };
                    if r < 0 {
                        return Err(::std::io::Error::last_os_error());
                    }
                    if nvlp.is_null() {
                        Ok($crate::casper::NvList::new($crate::casper::NvFlag::None).unwrap())
                    } else {
                        // Safe because cap_limit_get returns ownership, and we
                        // did a null-check.
                        unsafe{ Ok($crate::casper::NvList::from_ptr(nvlp)) }
                    }
                }
                /// Further restrict the service's capabilities.
                ///
                /// The contents of the nvlist is service-defined.
                fn limit_set(&mut self, limits: $crate::casper::NvList) -> ::std::io::Result<()> {
                    let raw_nvl : *mut $crate::casper::sys::nvlist_t = limits.into();
                    let r = unsafe {
                        $crate::casper::sys::cap_limit_set(self.0.as_ptr(), raw_nvl)
                    };
                    if r < 0 {
                        Err(::std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                }

                /// Transfer a command to the service and await a response.
                fn xfer_nvlist(&mut self, invl: $crate::casper::NvList) -> ::std::io::Result<$crate::casper::NvList> {
                    let r = unsafe {
                        $crate::casper::sys::cap_xfer_nvlist(self.0.as_ptr(), invl.into())
                    };
                    if r.is_null() {
                        Err(::std::io::Error::last_os_error())
                    } else {
                        // Safe because libcasper guarantees its validity, and
                        // we never access it directly after this.
                        let nvl = unsafe{ $crate::casper::NvList::from_ptr(r) };
                        let key = ::std::ffi::CStr::from_bytes_until_nul(b"error\0").unwrap();
                        match nvl.get_number(key) {
                            Ok(Some(0)) => Ok(nvl),
                            Ok(Some(e)) => Err(::std::io::Error::from_raw_os_error(e as i32)),
                            Ok(None) => panic!("zygote did not return error code"),
                            Err($crate::casper::NvError::NativeError(e)) => Err(::std::io::Error::from_raw_os_error(e)),
                            Err($crate::casper::NvError::Io(e)) => Err(e),
                            _ => unimplemented!()
                        }
                    }
                }
            }

            /// Extension trait for [`::capsicum::casper::Casper`] that spawns this service.
            $vis trait CasperExt {
                /// Spawn the
                #[doc = stringify!($meth)]
                /// service.
                fn $meth(&mut self) -> ::std::io::Result<$astruct>;
            }
            impl CasperExt for ::capsicum::casper::Casper {
                fn $meth(&mut self) -> ::std::io::Result<$astruct> {
                    self.service_open($cname)
                        .map($astruct)
                }
            }
        }
    }
    /// Declare a Casper service.
    ///
    /// Note that separate invocations of this macro must be made from separate
    /// modules.
    ///
    /// # Arguments
    /// * `vis` - Visibility of the generated structures.
    /// * `sstruct` - The name of the struct that provides the service.  Must
    ///               implement [`Service`](super::Service).
    /// * `astruct` - The name of the struct that accesses the service.  This
    ///               macro will create the struct.
    /// * `meth` - The name of the accessor that will be added to `Casper`.
    /// * `flags`   - Optional service flags of type
    ///    [`ServiceRegisterFlags`](super::ServiceRegisterFlags).
    ///
    /// # Examples
    /// ```
    /// # use std::{ffi::CStr, io};
    /// # use libnv::libnv::NvList;
    /// use capsicum::casper;
    ///
    /// struct CapUid {}
    /// impl casper::Service for CapUid {
    /// # const SERVICE_NAME: &'static CStr = c"getuid";
    /// # fn cmd(_: &str, _: Option<&NvList>, _: Option<&mut NvList>, _: &mut NvList) -> io::Result<()> {
    /// # unimplemented!()
    /// # }
    /// # fn limit(_: Option<&NvList>, _: Option<&NvList>) -> io::Result<()> {
    /// # unimplemented!()
    /// # }
    ///     // ...
    /// }
    ///
    /// casper::service!(CapUid, CapUidAgent, uid, casper::ServiceRegisterFlags::NONE);
    /// ```
    /// For a complete working example, see `examples/getuid.rs` in the source.
    #[macro_export]
    macro_rules! service {
        (
            $(#[$attr:meta])*
            $vis:vis $sstruct:ident, $astruct:ident, $meth:ident, $flags:expr
        ) => {
            $crate::casper::service_connection!{
                $(#[$attr])*
                $vis $astruct,
                <$sstruct as $crate::casper::Service>::SERVICE_NAME, $meth
            }

            #[$crate::casper::sys::ctor]
            unsafe fn casper_service_init() {
                use $crate::casper::Service;
                $crate::casper::sys::service_register(
                    $sstruct::SERVICE_NAME.as_ptr(),
                    Some($sstruct::c_limit),
                    Some($sstruct::c_cmd),
                    $flags.into()
                );
            }
        }
    }
    pub use service;
    pub use service_connection;
}

pub use macros::{service, service_connection};

/// A Casper Service
///
/// Casper services run in a separate process, connecting to the main process
/// via sockets.  Unlike the main process, the Casper service doesn't run in
/// capability mode, so it can access global namespaces.  Implement this trait
/// to create a custom Casper service.
pub trait Service {
    /// A string that uniquely identifies the service.  Must not start with
    /// "system.".
    const SERVICE_NAME: &'static CStr;

    /// The service will receive this callback for any request from the main
    /// process.  It should mutate `nvout` to communicate with the parent
    /// process.
    fn cmd(
        cmd: &str,
        limits: Option<&NvList>,
        nvin: Option<&mut NvList>,
        nvout: &mut NvList,
    ) -> io::Result<()>;

    /// The service will receive this callback if the main process wishes to
    /// further restrict its privileges.  The content of the limit fields is
    /// fully defined by the service.
    fn limit(_oldlimits: Option<&NvList>, _newlimits: Option<&NvList>) -> io::Result<()> {
        unimplemented!()
    }

    #[doc(hidden)]
    unsafe extern "C" fn c_cmd(
        cmd: *const ::std::os::raw::c_char,
        limits: *const sys::nvlist_t,
        nvlin: *mut sys::nvlist_t,
        nvlout: *mut sys::nvlist_t,
    ) -> i32 {
        let cmd = unsafe { CStr::from_ptr(cmd).to_string_lossy() };
        let limits = if limits.is_null() {
            None
        } else {
            // from_ptr is Safe because we performed a null check, and we pass
            // it back to C later.
            // const cast is safe because we never modify the returned NvList
            unsafe { Some(NvList::from_ptr(limits as *mut sys::nvlist_t)) }
        };
        let mut nvlin = unsafe { NvList::from_ptr(nvlin) };
        let mut nvlout = unsafe { NvList::from_ptr(nvlout) };
        let r = match Self::cmd(&cmd, limits.as_ref(), Some(&mut nvlin), &mut nvlout) {
            Ok(()) => 0,
            Err(e) => e.raw_os_error().unwrap(),
        };
        let _: *mut sys::nvlist_t = nvlin.into();
        let _: *mut sys::nvlist_t = nvlout.into();
        let _ = limits.map(<*mut sys::nvlist_t>::from);
        r
    }

    #[doc(hidden)]
    extern "C" fn c_limit(oldlimits: *const sys::nvlist_t, newlimits: *const sys::nvlist_t) -> i32 {
        let oldlimits = if oldlimits.is_null() {
            None
        } else {
            // from_ptr is Safe because we performed a null check, and we pass
            // it back to C later.
            // const cast is safe because we never modify the returned NvList,
            // and we only give an immutable reference to the Rust callback.
            unsafe { Some(NvList::from_ptr(oldlimits as *mut sys::nvlist_t)) }
        };
        let newlimits = if newlimits.is_null() {
            None
        } else {
            // from_ptr is Safe because we performed a null check, and we pass
            // it back to C later.
            // const cast is safe because we never modify the returned NvList,
            // and we only give an immutable reference to the Rust callback.
            unsafe { Some(NvList::from_ptr(newlimits as *mut sys::nvlist_t)) }
        };
        let r = match Self::limit(oldlimits.as_ref(), newlimits.as_ref()) {
            Ok(()) => 0,
            Err(e) => e.raw_os_error().unwrap(),
        };
        let _ = oldlimits.map(<*mut sys::nvlist_t>::from);
        let _ = newlimits.map(<*mut sys::nvlist_t>::from);
        r
    }
}
