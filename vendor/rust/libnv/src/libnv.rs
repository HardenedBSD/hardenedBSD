//! FreeBSD implementation of Name/value pairs library.

//! All insert operation clone values using `dup(2)` system call. So you
//! don't have to worry about the lifetime of the value. Unless you leak NvList
//! yourself using `unsafe`
//! you don't have to worry about anything. Once list goes out of scope it will
//! call to C library
//! to free all resources associated with it. `nvlist_take_*` and
//! `nvlist_move_*` operations are
//! not supported for this very reason.
//!
//! It's missing a few features:
//!
//! - Sending to socket
//! - Receiving from socket
//! - Insert/Remove file descriptors
//! - Insert/Remove binary
//! - Take operations
//! - Iterator interface
use libc::ENOMEM;

// Importing all because it's cold, I dont want to turn on heater and it's hard
// to type.
use libnv_sys::*;
use std::{
    convert::{From, Into},
    ffi::CStr,
    os::raw::{c_char, c_void},
    os::unix::io::AsRawFd,
    slice,
};
use IntoCStr;

use crate::{NvError, NvResult};

/// Enumeration of available data types that the API supports.
pub enum NvType {
    /// Empty type
    None = 0,
    /// There is no associated data with the name
    Null = 1,
    /// The value is a `bool` value
    Bool = 2,
    /// The value is a `u64` value
    Number = 3,
    /// The value is a C string
    String = 4,
    /// The value is another `nvlist`
    NvList = 5,
    /// The value is a file descriptor
    Descriptor = 6,
    /// The value is a binary buffer
    Binary = 7,
    /// The value is an array of `bool` values
    BoolArray = 8,
    /// The value is an array of `u64` values
    NumberArray = 9,
    /// The value is an array of C strings
    StringArray = 10,
    /// The value is an array of other `nvlist`'s
    NvListArray = 11,
    /// The value is an array of file descriptors
    DescriptorArray = 12,
}

/// Options available for creation of an `nvlist`
#[repr(i32)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum NvFlag {
    /// No user specified options.
    None = 0,
    /// Perform case-insensitive lookups of provided names.
    IgnoreCase = 1,
    /// Names in the nvlist do not have to be unique.
    NoUnique = 2,
    /// Allow duplicate case-insensitive keys.
    Both = 3,
}

impl From<i32> for NvFlag {
    /// This should be TryFrom. This function WILL panic if you pass incorrect
    /// value to it. This should be impossible.
    fn from(source: i32) -> Self {
        match source {
            0 => NvFlag::None,
            1 => NvFlag::IgnoreCase,
            2 => NvFlag::NoUnique,
            3 => NvFlag::Both,
            _ => panic!("Incorrect value passed to NvFlag"),
        }
    }
}

macro_rules! impl_list_op {
    ($type_:ty, $method:ident, false) => {
        impl NvTypeOp for $type_ {
            /// Add a `$type_` value to the `NvList`
            fn add_to_list<'a, N: IntoCStr<'a>>(&self, list: &mut NvList, name: N) -> NvResult<()> {
                return list.$method(name, *self);
            }
        }
    };
    ($type_:ty, $method:ident, true) => {
        impl NvTypeOp for $type_ {
            /// Add a `$type_` value to the `NvList`
            fn add_to_list<'a, N: IntoCStr<'a>>(&self, list: &mut NvList, name: N) -> NvResult<()> {
                return list.$method(name, &*self);
            }
        }
    };
}

/// This allows usage of insert method with basic types. Implement this for your
/// own types if you don't want to convert to primitive types every time.
pub trait NvTypeOp {
    /// Add self to given list.
    fn add_to_list<'a, N: IntoCStr<'a>>(&self, list: &mut NvList, name: N) -> NvResult<()>;
}

impl_list_op! {bool, insert_bool, false}
impl_list_op! {[bool], insert_bools, true}
impl_list_op! {u8, insert_number, false}
impl_list_op! {u16, insert_number, false}
impl_list_op! {u32, insert_number, false}
impl_list_op! {u64, insert_number, false}
impl_list_op! {[u64], insert_numbers, true}
impl_list_op! {str, insert_string, true}
impl_list_op! {NvList, insert_nvlist, true}

/// If `Some` insert content to the list. If `None` insert null.
impl<T> NvTypeOp for Option<T>
where
    T: NvTypeOp,
{
    fn add_to_list<'a, N: IntoCStr<'a>>(&self, list: &mut NvList, name: N) -> NvResult<()> {
        match self {
            Some(ref val) => val.add_to_list(list, name),
            None => list.insert_null(name),
        }
    }
}

/// A list of name/value pairs.
#[derive(Debug)]
pub struct NvList {
    ptr: *mut nvlist_t,
}

#[doc(hidden)]
/// Return new list with no flags.
impl Default for NvList {
    fn default() -> NvList {
        NvList::new(NvFlag::None).expect("Failed to create new list")
    }
}
impl NvList {
    /// Make a copy of a pointer. Danger zone.
    pub fn as_ptr(&self) -> *mut nvlist_t {
        self.ptr
    }

    fn check_if_error(&self) -> NvResult<()> {
        match self.error() {
            errno if errno == 0 => Ok(()),
            errno => Err(NvError::NativeError(errno)),
        }
    }

    /// Create a new name/value pair list (`nvlist`). Call this can only fail
    /// when system is out of memory.
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// let nvlist = NvList::new(NvFlag::None).unwrap();
    /// ```
    pub fn new(flags: NvFlag) -> NvResult<NvList> {
        let raw_list = unsafe { nvlist_create(flags as i32) };
        if raw_list.is_null() {
            Err(NvError::NativeError(ENOMEM))
        } else {
            Ok(NvList { ptr: raw_list })
        }
    }

    /// Take ownership of a raw NvList from C.
    ///
    /// # Safety
    ///
    /// This provided pointer must be valid, and after this function returns
    /// nothing else may access the raw pointer except through the returned
    /// object.
    // Note: this cannot be `impl From<*mut nvlist_t> for Self` because that
    // trait is only for safe conversions.
    pub unsafe fn from_ptr(ptr: *mut nvlist_t) -> Self {
        Self { ptr }
    }

    /// Determines if the `nvlist` is empty.
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    /// let nvlist = NvList::new(NvFlag::IgnoreCase).unwrap();
    /// assert!(nvlist.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        unsafe { nvlist_empty(self.ptr) }
    }

    /// The flags the `nvlist` was created with.
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    /// let nvlist = NvList::new(NvFlag::NoUnique).unwrap();
    ///
    /// assert_eq!(nvlist.flags(), NvFlag::NoUnique);
    /// ```
    pub fn flags(&self) -> NvFlag {
        NvFlag::from(unsafe { nvlist_flags(self.ptr) })
    }

    /// Gets error value that the list may have accumulated.
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    /// let list = NvList::new(NvFlag::NoUnique).unwrap();
    ///
    /// assert_eq!(0, list.error());
    /// ```
    pub fn error(&self) -> i32 {
        unsafe { nvlist_error(self.ptr) }
    }

    /// Sets the `NvList` to be in an error state.
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// let mut list = NvList::new(NvFlag::Both).unwrap();
    ///
    /// // EINVAL
    /// list.set_error(0x16).unwrap();
    ///
    /// assert_eq!(0x16, list.error());
    /// ```
    pub fn set_error(&mut self, error: i32) -> NvResult<()> {
        if self.error() != 0 {
            Err(NvError::AlreadySet)
        } else {
            unsafe { nvlist_set_error(self.ptr, error) }
            Ok(())
        }
    }

    /// Sugared way to add a single value to the NvList.
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag, NvTypeOp};
    ///
    /// let mut list = NvList::default();
    ///
    /// let the_answer: u32 = 1776;
    /// let not_the_answer: Option<u64> = None;
    ///
    /// list.insert("Important year", the_answer);
    /// list.insert("not important year", not_the_answer);
    /// let copy = list.clone();
    /// list.insert("foo", copy);
    ///
    /// assert_eq!(list.get_number("Important year").unwrap().unwrap(), 1776);
    /// ```
    pub fn insert<'a, N: IntoCStr<'a>, T: NvTypeOp>(&mut self, name: N, value: T) -> NvResult<()> {
        value.add_to_list(self, name)
    }

    /// Add a null value to the `NvList`.
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag, NvTypeOp};
    /// let mut list = NvList::new(NvFlag::Both).unwrap();
    /// list.insert_null("Hello, World!");
    /// ```
    pub fn insert_null<'a, N: IntoCStr<'a>>(&mut self, name: N) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        unsafe {
            nvlist_add_null(self.ptr, c_name.as_ptr());
        }
        self.check_if_error()
    }

    /// Add a number to the `NvList`. Number will be converted into u64.
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// let mut list = NvList::new(NvFlag::Both).unwrap();
    ///
    /// list.insert_number("Important year", 1776u64);
    /// ```
    pub fn insert_number<'a, N: IntoCStr<'a>, I: Into<u64>>(
        &mut self,
        name: N,
        value: I,
    ) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        unsafe {
            nvlist_add_number(self.ptr, c_name.as_ptr(), value.into());
        }
        self.check_if_error()
    }

    /// Add a `bool` to the list.
    pub fn insert_bool<'a, N: IntoCStr<'a>>(&mut self, name: N, value: bool) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        unsafe {
            nvlist_add_bool(self.ptr, c_name.as_ptr(), value);
        }
        self.check_if_error()
    }

    /// Add string to the list.
    pub fn insert_string<'a, 'b, N: IntoCStr<'a>, V: IntoCStr<'b>>(
        &mut self,
        name: N,
        value: V,
    ) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        let c_value = value.into_c_str()?;
        unsafe {
            nvlist_add_string(self.ptr, c_name.as_ptr(), c_value.as_ptr());
        }
        self.check_if_error()
    }

    /// Add `NvList` to the list.
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// let mut list = NvList::default();
    ///
    /// let other_list = NvList::default();
    ///
    /// list.insert_nvlist("other list", &other_list).unwrap();
    /// ```
    pub fn insert_nvlist<'a, N: IntoCStr<'a>>(&mut self, name: N, value: &NvList) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        if !value.as_ptr().is_null() {
            unsafe {
                nvlist_add_nvlist(self.ptr, c_name.as_ptr(), value.as_ptr());
            }
        }
        self.check_if_error()
    }

    /// Add binary data to the list.
    #[deprecated(since = "0.4.0", note = "use insert_binary instead")]
    pub unsafe fn add_binary<'a, N: IntoCStr<'a>>(
        &mut self,
        name: N,
        value: *const i8,
        size: usize,
    ) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        nvlist_add_binary(self.ptr, c_name.as_ptr(), value as *const c_void, size);
        self.check_if_error()
    }

    /// Add a byte array to the list.
    pub fn insert_binary<'a, N: IntoCStr<'a>>(&mut self, name: N, value: &[u8]) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        unsafe {
            nvlist_add_binary(
                self.ptr,
                c_name.as_ptr(),
                value.as_ptr() as *const c_void,
                value.len(),
            );
        }
        self.check_if_error()
    }

    /// Add an array of `bool` values.
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// let mut list = NvList::new(NvFlag::Both).unwrap();
    ///
    /// let slice = [true, false, true, false];
    ///
    /// list.insert_bools("Important year", &slice);
    /// ```
    pub fn insert_bools<'a, N: IntoCStr<'a>>(&mut self, name: N, value: &[bool]) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        unsafe {
            nvlist_add_bool_array(self.ptr, c_name.as_ptr(), value.as_ptr(), value.len());
        }
        self.check_if_error()
    }

    /// Add an array if `u64`. TODO: Make it work with any number...
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// let mut list = NvList::new(NvFlag::None).unwrap();
    ///
    /// let slice = [1776, 2017];
    ///
    /// list.insert_numbers("Important year", &slice);
    /// ```
    pub fn insert_numbers<'a, N: IntoCStr<'a>>(&mut self, name: N, value: &[u64]) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        unsafe {
            nvlist_add_number_array(self.ptr, c_name.as_ptr(), value.as_ptr(), value.len());
        }
        self.check_if_error()
    }

    /// Add an array of strings
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// let mut list = NvList::new(NvFlag::None).unwrap();
    ///
    /// let orig = ["Hello", "World!"];
    ///
    /// list.insert_strings("key", orig).unwrap();
    ///
    /// let vec = list.get_strings("key").unwrap().unwrap();
    ///
    /// assert_eq!(*vec, ["Hello", "World!"]);
    /// ```
    pub fn insert_strings<'a, 'b, N: IntoCStr<'a>, V: IntoCStr<'b>, I: IntoIterator<Item=V>>(&mut self, name: N, value: I) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        let strings= value.into_iter()
            .map(IntoCStr::into_c_str)
            .collect::<NvResult<Vec<_>>>()?;
        unsafe {
            let pointers: Vec<*const c_char> = strings.iter().map(|e| e.as_ptr()).collect();

            nvlist_add_string_array(
                self.ptr,
                c_name.as_ptr(),
                pointers.as_slice().as_ptr(),
                strings.len(),
            );
        }
        self.check_if_error()
    }

    /// Add an array of `NvList`s
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// let mut list = NvList::new(NvFlag::Both).unwrap();
    ///
    /// let slice = [NvList::new(NvFlag::Both).unwrap(),
    /// NvList::new(NvFlag::Both).unwrap(),
    ///              NvList::new(NvFlag::None).unwrap()];
    ///
    /// list.insert_nvlists("nvlists", &slice);
    ///
    /// let mut nvlists = list.get_nvlists("nvlists").unwrap().unwrap();
    ///
    /// assert_eq!(NvFlag::None, nvlists.pop().unwrap().flags());
    /// ```
    pub fn insert_nvlists<'a, N: IntoCStr<'a>>(
        &mut self,
        name: N,
        value: &[NvList],
    ) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        let vec = value.to_vec();
        unsafe {
            let lists: Vec<*const nvlist_t> =
                vec.iter().map(|item| item.as_ptr() as *const nvlist_t).collect();
            nvlist_add_nvlist_array(
                self.ptr,
                c_name.as_ptr(),
                lists.as_slice().as_ptr(),
                lists.len(),
            );
        }
        self.check_if_error()
    }

    /// Returns `true` if a name/value pair exists in the `NvList` and `false`
    /// otherwise.
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// let mut list = NvList::new(NvFlag::Both).unwrap();
    ///
    /// let result = list.insert_number("Important year", 1776u64);
    /// assert!(result.is_ok());
    ///
    /// assert!(list.contains_key("Important year").unwrap());
    /// ```
    pub fn contains_key<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<bool> {
        let c_name = name.into_c_str()?;
        unsafe { Ok(nvlist_exists(self.ptr, c_name.as_ptr())) }
    }

    /// Returns `true` if a name/value pair of the specified type exists and
    /// `false` otherwise.
    /// ```
    /// use libnv::libnv::{NvList, NvFlag, NvType};
    ///
    /// let mut list = NvList::new(NvFlag::Both).unwrap();
    ///
    /// let result = list.insert_number("Important year", 1776u64);
    /// assert!(result.is_ok());
    ///
    /// assert!(!list.contains_key_with_type("Important year", NvType::Bool).unwrap());
    /// ```
    pub fn contains_key_with_type<'a, N: IntoCStr<'a>>(
        &self,
        name: N,
        ty: NvType,
    ) -> NvResult<bool> {
        let c_name = name.into_c_str()?;
        unsafe { Ok(nvlist_exists_type(self.ptr, c_name.as_ptr(), ty as i32)) }
    }

    /// Get the first matching byte slice value for the given name
    ///
    /// ```
    /// use libnv::libnv::NvList;
    ///
    /// let x = [1, 2, 3, 4];
    /// let mut list = NvList::default();
    /// list.insert_binary("x", &x).unwrap();
    ///
    /// let v = list.get_binary("x").unwrap().unwrap();
    /// assert_eq!(&x, v);
    /// ```
    pub fn get_binary<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<Option<&[u8]>> {
        let c_name = name.into_c_str()?;
        unsafe {
            let mut size: usize = 0;
            let ret = nvlist_get_binary(self.ptr, c_name.as_ptr(), &mut size as *mut usize);
            if ret.is_null() {
                Ok(None)
            } else {
                Ok(Some(slice::from_raw_parts(ret as *const u8, size)))
            }
        }
    }

    /// Get the first matching `bool` value paired with
    /// the given name.
    ///
    /// ```
    /// use libnv::libnv::NvList;
    ///
    /// let mut list = NvList::default();
    ///
    /// list.insert_bool("Did history start on 1776?", true).unwrap();
    ///
    /// assert!(list.get_bool("Did history start on 1776?").unwrap().unwrap(),
    /// true);
    /// ```
    pub fn get_bool<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<Option<bool>> {
        let c_name = name.into_c_str()?;
        unsafe {
            if nvlist_exists_bool(self.ptr, c_name.as_ptr()) {
                Ok(Some(nvlist_get_bool(self.ptr, c_name.as_ptr())))
            } else {
                Ok(None)
            }
        }
    }

    /// Get the first matching `u64` value paired with
    /// the given name.
    pub fn get_number<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<Option<u64>> {
        let c_name = name.into_c_str()?;
        unsafe {
            if nvlist_exists_number(self.ptr, c_name.as_ptr()) {
                Ok(Some(nvlist_get_number(self.ptr, c_name.as_ptr())))
            } else {
                Ok(None)
            }
        }
    }

    /// Get the first matching `u64` value paired with
    /// the given name
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// // Note: we're allowing duplicate values per name
    /// let mut list = NvList::default();
    ///
    /// list.insert_string("Hello", "World!").unwrap();
    ///
    /// assert_eq!(list.get_string("Hello").unwrap().unwrap(), "World!");
    /// ```
    pub fn get_string<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<Option<String>> {
        let c_name = name.into_c_str()?;
        unsafe {
            if nvlist_exists_string(self.ptr, c_name.as_ptr()) {
                let ret = nvlist_get_string(self.ptr, c_name.as_ptr());
                if ret.is_null() {
                    Ok(None)
                } else {
                    Ok(Some(CStr::from_ptr(ret).to_string_lossy().into_owned()))
                }
            } else {
                Ok(None)
            }
        }
    }

    /// Get the first matching `NvList` value paired with
    /// the given name and clone it
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// let mut list = NvList::new(NvFlag::Both).unwrap();
    ///
    /// list.insert_bool("other list", true).unwrap();
    ///
    /// let mut other_list = NvList::new(NvFlag::None).unwrap();
    /// other_list.insert_number("Important year", 42u32).unwrap();
    ///
    /// list.insert_nvlist("other list", &other_list).unwrap();
    ///
    /// // Since we use `get_nvlist` we will get the
    /// // NvList not the boolean value
    /// let other_nvlist = list.get_nvlist("other list").unwrap().unwrap();
    ///
    /// assert_eq!(other_nvlist.get_number("Important year").unwrap().unwrap(),
    /// 42);
    /// ```
    pub fn get_nvlist<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<Option<NvList>> {
        let c_name = name.into_c_str()?;
        unsafe {
            if nvlist_exists_nvlist(self.ptr, c_name.as_ptr()) {
                let res = nvlist_get_nvlist(self.ptr, c_name.as_ptr());
                Ok(Some(NvList { ptr: nvlist_clone(res) }))
            } else {
                Ok(None)
            }
        }
    }

    /// Get a `&[bool]` from the `NvList`
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// // Note: we're allowing duplicate values per name
    /// let mut list = NvList::new(NvFlag::None).unwrap();
    ///
    /// list.insert_bools("true/false", &[true, false, true]).unwrap();
    ///
    /// assert_eq!(list.get_bools("true/false").unwrap().unwrap(), &[true,
    /// false, true]);
    /// ```
    pub fn get_bools<'a, 'b, N: IntoCStr<'b>>(&'a self, name: N) -> NvResult<Option<&'a [bool]>> {
        let c_name = name.into_c_str()?;
        unsafe {
            if nvlist_exists_bool_array(self.ptr, c_name.as_ptr()) {
                let mut len: usize = 0;
                let arr = nvlist_get_bool_array(self.ptr, c_name.as_ptr(), &mut len as *mut usize);
                Ok(Some(slice::from_raw_parts(arr as *const bool, len)))
            } else {
                Ok(None)
            }
        }
    }

    /// Get a `&[u64]` slice from the `NvList`
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// // Note: we're allowing duplicate values per name
    /// let mut list = NvList::default();
    ///
    /// list.insert_numbers("The Year", &[1, 7, 7, 6]).unwrap();
    ///
    /// assert_eq!(list.get_numbers("The Year").unwrap().unwrap(), &[1, 7, 7,
    /// 6]);
    /// ```
    pub fn get_numbers<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<Option<&[u64]>> {
        let c_name = name.into_c_str()?;
        unsafe {
            if nvlist_exists_number_array(self.ptr, c_name.as_ptr()) {
                let mut len: usize = 0;
                let arr =
                    nvlist_get_number_array(self.ptr, c_name.as_ptr(), &mut len as *mut usize);
                Ok(Some(slice::from_raw_parts(arr as *const u64, len)))
            } else {
                Ok(None)
            }
        }
    }

    /// Get a `Vec<String>` of the first string slice added to the `NvList`
    /// for the given name
    pub fn get_strings<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<Option<Vec<String>>> {
        let c_name = name.into_c_str()?;
        unsafe {
            if nvlist_exists_string_array(self.ptr, c_name.as_ptr()) {
                let mut len: usize = 0;
                let arr =
                    nvlist_get_string_array(self.ptr, c_name.as_ptr(), &mut len as *mut usize);
                let slice = slice::from_raw_parts(arr as *const *const c_char, len);
                let strings = slice
                    .iter()
                    .copied()
                    .map(|ptr| String::from(CStr::from_ptr(ptr).to_string_lossy()))
                    .collect();
                Ok(Some(strings))
            } else {
                Ok(None)
            }
        }
    }

    /// Get an array of `NvList`.
    ///
    /// ```
    /// use libnv::libnv::{NvList, NvFlag};
    ///
    /// let mut list = NvList::new(NvFlag::None).unwrap();
    ///
    /// list.insert_nvlists("lists", &[NvList::default(),
    ///                                       NvList::default()]).unwrap();
    ///
    /// let vec = list.get_nvlists("lists").unwrap().unwrap();
    ///
    /// assert_eq!(vec.len(), 2);
    /// assert_eq!(vec[0].flags(), NvFlag::None);
    /// ```
    pub fn get_nvlists<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<Option<Vec<NvList>>> {
        let c_name = name.into_c_str()?;
        unsafe {
            if nvlist_exists_nvlist_array(self.ptr, c_name.as_ptr()) {
                let mut len: usize = 0;
                let arr =
                    nvlist_get_nvlist_array(self.ptr, c_name.as_ptr(), &mut len as *mut usize);
                let slice = slice::from_raw_parts(arr as *const *const nvlist_t, len);
                Ok(Some(slice.iter().map(|item| NvList { ptr: nvlist_clone(*item) }).collect()))
            } else {
                Ok(None)
            }
        }
    }

    /// Write `NvList` to a file descriptor.
    ///
    /// ```
    /// use std::fs::File;
    /// use libnv::libnv::NvList;
    ///
    /// let mut list = NvList::default();
    ///
    /// list.insert_number("Important year", 1776u64);
    ///
    /// list.dump(File::create("/tmp/libnv_nv.dump").unwrap());
    /// ```
    pub fn dump<T: AsRawFd>(&self, out: T) -> NvResult<()> {
        unsafe { nvlist_dump(self.ptr, out.as_raw_fd()) }
        self.check_if_error()
    }

    /// The size of the current list
    pub fn len(&self) -> usize {
        unsafe { nvlist_size(self.ptr) }
    }

    /// Removes a key from the `NvList`.
    pub fn remove<'a, N: IntoCStr<'a>>(&mut self, name: N) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        unsafe {
            nvlist_free(self.ptr, c_name.as_ptr());
        }
        self.check_if_error()
    }

    /// Remove the element of the given name and type
    /// from the `NvList`
    pub fn remove_with_type<'a, N: IntoCStr<'a>>(&mut self, name: N, ty: NvType) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        unsafe {
            nvlist_free_type(self.ptr, c_name.as_ptr(), ty as i32);
        }
        self.check_if_error()
    }
}

impl Clone for NvList {
    /// Clone list using libnv method. This will perform deep copy.
    fn clone(&self) -> NvList {
        NvList { ptr: unsafe { nvlist_clone(self.ptr) } }
    }
}

impl Drop for NvList {
    /// Using libnv method.
    fn drop(&mut self) {
        unsafe {
            nvlist_destroy(self.ptr);
        }
    }
}

impl From<NvList> for *mut nvlist_t {
    /// Consume the wrapper and return a raw pointer to the inner structure.
    /// Useful for FFI functions that expect to take ownership of the nvlist.
    fn from(outer: NvList) -> *mut nvlist_t {
        let r = outer.ptr;
        std::mem::forget(outer);
        r
    }
}
