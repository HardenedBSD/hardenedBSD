//! Solaris implementation of Name/Value pairs library.

use {nvpair_sys as sys, IntoCStr};

use crate::{NvError, NvResult};
use std::os::unix::io::AsRawFd;
use std::{
    collections::HashMap,
    convert::TryInto,
    ffi::{CStr, CString},
    fmt::Formatter,
    mem::MaybeUninit,
    ptr::null_mut,
};

extern "C" {
    pub fn nvlist_print_json(fp: *mut libc::FILE, nvl: *const sys::nvlist_t) -> i32;
}
/// This allows usage of insert method with basic types. Implement this for your
/// own types if you don't want to convert to primitive types every time.
pub trait NvTypeOp {
    /// Add self to given list.
    fn add_to_list<'a, N: IntoCStr<'a>>(&self, list: &mut NvList, name: N) -> NvResult<()>;
}

#[repr(i32)]
#[derive(Copy, Clone, Debug)]
pub enum NvEncoding {
    /// A basic copy on insert operation.
    Native = 0,
    /// [XDR](https://tools.ietf.org/html/rfc4506) copy suitable for sending to remote host.
    Xdr = 1,
}
/// Options available for creation of an `nvlist`
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum NvFlag {
    /// No flags. Allows duplicate names of any type, but renders `get_` methods useless.
    None = 0b000,
    /// An existing pair of the same type will be removed prior inserting.
    UniqueName = 0b001,
    /// An existing pair of any type will be removed prior inserting.
    UniqueNameType = 0b010,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Value {
    Unknown,
    Bool(bool),
    Int8(i8),
    Uint8(u8),
    Int16(i16),
    Uint16(u16),
    Int32(i32),
    Uint32(u32),
    Int64(i64),
    Uint64(u64),
    String(String),
}

impl Value {
    pub fn as_bool(&self) -> NvResult<bool> {
        if let Value::Bool(val) = self {
            Ok(val.clone())
        } else {
            Err(NvError::OperationNotSupported)
        }
    }

    pub fn as_i8(&self) -> NvResult<i8> {
        if let Value::Int8(val) = self {
            Ok(val.clone())
        } else {
            Err(NvError::OperationNotSupported)
        }
    }

    pub fn as_u8(&self) -> NvResult<u8> {
        if let Value::Uint8(val) = self {
            Ok(val.clone())
        } else {
            Err(NvError::OperationNotSupported)
        }
    }
}

impl From<i8> for Value {
    fn from(src: i8) -> Self {
        Value::Int8(src)
    }
}
impl From<u8> for Value {
    fn from(src: u8) -> Self {
        Value::Uint8(src)
    }
}
impl From<i16> for Value {
    fn from(src: i16) -> Self {
        Value::Int16(src)
    }
}
impl From<u16> for Value {
    fn from(src: u16) -> Self {
        Value::Uint16(src)
    }
}
impl From<i32> for Value {
    fn from(src: i32) -> Self {
        Value::Int32(src)
    }
}
impl From<u32> for Value {
    fn from(src: u32) -> Self {
        Value::Uint32(src)
    }
}
impl From<i64> for Value {
    fn from(src: i64) -> Self {
        Value::Int64(src)
    }
}
impl From<u64> for Value {
    fn from(src: u64) -> Self {
        Value::Uint64(src)
    }
}
impl From<String> for Value {
    fn from(src: String) -> Self {
        Value::String(src)
    }
}
impl From<&str> for Value {
    fn from(src: &str) -> Self {
        Value::String(src.into())
    }
}
pub struct NvList {
    ptr: *mut sys::nvlist_t,
}

impl Drop for NvList {
    fn drop(&mut self) {
        unsafe { sys::nvlist_free(self.ptr) }
    }
}

/// Return new list with no flags.
impl Default for NvList {
    fn default() -> NvList {
        NvList::new(NvFlag::UniqueNameType).expect("Failed to create new list")
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

macro_rules! nvpair_type_array_method {
    ($type_:ty, $rmethod_insert:ident, $smethod_insert:ident, $rmethod_get:ident, $smethod_get:ident) => {
        /// Add `&[$type_]` value to the list.
        pub fn $rmethod_insert<'a, N: IntoCStr<'a>>(
            &mut self,
            name: N,
            value: &mut [$type_],
        ) -> NvResult<()> {
            let c_name = name.into_c_str()?;
            let errno = unsafe {
                sys::$smethod_insert(
                    self.ptr,
                    c_name.as_ptr(),
                    value.as_mut_ptr(),
                    value.len() as u32,
                )
            };
            if errno != 0 {
                Err(NvError::from_errno(errno))
            } else {
                Ok(())
            }
        }

        /// Get a `$type_` value by given name from the list.
        pub fn $rmethod_get<'a, 'b, N: IntoCStr<'b>>(&'a self, name: N) -> NvResult<&'a [$type_]> {
            let c_name = name.into_c_str()?;
            let mut ptr = null_mut();
            let mut len = 0;
            let errno = unsafe { sys::$smethod_get(self.ptr, c_name.as_ptr(), &mut ptr, &mut len) };
            if errno != 0 {
                Err(NvError::from_errno(errno))
            } else {
                let ret = unsafe { std::slice::from_raw_parts(&mut *ptr, len.try_into().unwrap()) };
                Ok(ret)
            }
        }
    };
}
macro_rules! nvpair_type_method {
    ($type_:ty, $rmethod_insert:ident, $smethod_insert:ident, $rmethod_get:ident, $smethod_get:ident) => {
        /// Add `$type_` value to the list.
        pub fn $rmethod_insert<'a, N: IntoCStr<'a>>(
            &mut self,
            name: N,
            value: $type_,
        ) -> NvResult<()> {
            let c_name = name.into_c_str()?;
            let errno = unsafe { sys::$smethod_insert(self.ptr, c_name.as_ptr(), value) };
            if errno != 0 {
                Err(NvError::from_errno(errno))
            } else {
                Ok(())
            }
        }

        /// Get a `$type_` value by given name from the list.
        pub fn $rmethod_get<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<$type_> {
            let c_name = name.into_c_str()?;
            let mut ptr = MaybeUninit::<$type_>::uninit();
            let errno = unsafe { sys::$smethod_get(self.ptr, c_name.as_ptr(), ptr.as_mut_ptr()) };
            if errno != 0 {
                Err(NvError::from_errno(errno))
            } else {
                let ret = unsafe { ptr.assume_init() };
                Ok(ret)
            }
        }
    };
}

impl NvList {
    nvpair_type_method!(i8, insert_i8, nvlist_add_int8, get_i8, nvlist_lookup_int8);

    nvpair_type_method!(u8, insert_u8, nvlist_add_uint8, get_u8, nvlist_lookup_uint8);

    nvpair_type_method!(i16, insert_i16, nvlist_add_int16, get_i16, nvlist_lookup_int16);

    nvpair_type_method!(u16, insert_u16, nvlist_add_uint16, get_u16, nvlist_lookup_uint16);

    nvpair_type_method!(i32, insert_i32, nvlist_add_int32, get_i32, nvlist_lookup_int32);

    nvpair_type_method!(u32, insert_u32, nvlist_add_uint32, get_u32, nvlist_lookup_uint32);

    nvpair_type_method!(i64, insert_i64, nvlist_add_int64, get_i64, nvlist_lookup_int64);

    nvpair_type_method!(u64, insert_u64, nvlist_add_uint64, get_u64, nvlist_lookup_uint64);

    nvpair_type_array_method!(
        i8,
        insert_i8_array,
        nvlist_add_int8_array,
        get_i8_array,
        nvlist_lookup_int8_array
    );

    nvpair_type_array_method!(
        u8,
        insert_u8_array,
        nvlist_add_uint8_array,
        get_u8_array,
        nvlist_lookup_uint8_array
    );

    nvpair_type_array_method!(
        i16,
        insert_i16_array,
        nvlist_add_int16_array,
        get_i16_array,
        nvlist_lookup_int16_array
    );

    nvpair_type_array_method!(
        u16,
        insert_u16_array,
        nvlist_add_uint16_array,
        get_u16_array,
        nvlist_lookup_uint16_array
    );

    nvpair_type_array_method!(
        i32,
        insert_i32_array,
        nvlist_add_int32_array,
        get_i32_array,
        nvlist_lookup_int32_array
    );

    nvpair_type_array_method!(
        u32,
        insert_u32_array,
        nvlist_add_uint32_array,
        get_u32_array,
        nvlist_lookup_uint32_array
    );

    nvpair_type_array_method!(
        i64,
        insert_i64_array,
        nvlist_add_int64_array,
        get_i64_array,
        nvlist_lookup_int64_array
    );

    nvpair_type_array_method!(
        u64,
        insert_u64_array,
        nvlist_add_uint64_array,
        get_u64_array,
        nvlist_lookup_uint64_array
    );

    /// Make a copy of a pointer. Danger zone.
    pub fn as_ptr(&self) -> *mut sys::nvlist_t {
        self.ptr
    }

    pub fn new(flags: NvFlag) -> NvResult<Self> {
        let mut raw_list = null_mut();
        let errno = unsafe { sys::nvlist_alloc(&mut raw_list, flags as u32, 0) };
        if errno != 0 {
            Err(NvError::from_errno(errno))
        } else {
            Ok(NvList { ptr: raw_list })
        }
    }

    pub unsafe fn from_ptr(ptr: *mut sys::nvlist_t) -> Self {
        Self { ptr }
    }

    pub fn iter(&self) -> impl Iterator<Item = NvPairRef> + '_ {
        NvListIter { list: self, position: null_mut() }
    }

    pub fn into_hashmap(self) -> HashMap<String, Value> {
        let mut ret = HashMap::new();
        for pair in self.iter() {
            let key = pair.key().to_string_lossy().to_string();
            ret.insert(key, pair.value());
        }
        ret
    }

    pub fn is_empty(&self) -> bool {
        let ret = unsafe { sys::nvlist_empty(self.as_ptr()) };
        ret != sys::boolean_t::B_FALSE
    }

    pub fn exists<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<bool> {
        let c_name = name.into_c_str()?;
        let ret = unsafe { sys::nvlist_exists(self.as_ptr(), c_name.as_ptr()) };
        Ok(ret != sys::boolean_t::B_FALSE)
    }

    pub fn insert<'a, N: IntoCStr<'a>, T: NvTypeOp>(&mut self, name: N, value: T) -> NvResult<()> {
        value.add_to_list(self, name)
    }

    /// Add a `bool` to the list.
    pub fn insert_boolean_value<'a, N: IntoCStr<'a>>(
        &mut self,
        name: N,
        value: bool,
    ) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        let v = {
            if value {
                sys::boolean_t::B_TRUE
            } else {
                sys::boolean_t::B_FALSE
            }
        };
        let errno = unsafe { sys::nvlist_add_boolean_value(self.ptr, c_name.as_ptr(), v) };
        if errno != 0 {
            Err(NvError::from_errno(errno))
        } else {
            Ok(())
        }
    }

    /// Add a `bool` to the list.
    pub fn insert_boolean<'a, N: IntoCStr<'a>>(&mut self, name: N) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        let errno = unsafe { sys::nvlist_add_boolean(self.ptr, c_name.as_ptr()) };
        if errno != 0 {
            Err(NvError::from_errno(errno))
        } else {
            Ok(())
        }
    }

    /// Get a `bool` from the list.
    pub fn get_boolean_value<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<bool> {
        let c_name = name.into_c_str()?;
        let mut ptr = MaybeUninit::<sys::boolean_t::Type>::uninit();

        let errno = unsafe {
            sys::nvlist_lookup_boolean_value(self.ptr, c_name.as_ptr(), ptr.as_mut_ptr())
        };
        if errno != 0 {
            Err(NvError::from_errno(errno))
        } else {
            let ret = unsafe { ptr.assume_init() };
            Ok(ret != sys::boolean_t::B_FALSE)
        }
    }

    /// Get a `bool` from the list.
    pub fn get_boolean<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<bool> {
        let c_name = name.into_c_str()?;

        let errno = unsafe { sys::nvlist_lookup_boolean(self.ptr, c_name.as_ptr()) };
        if errno != 0 {
            Err(NvError::from_errno(errno))
        } else {
            Ok(true)
        }
    }

    /// Add a `&str` to the list.
    pub fn insert_string<'a, 'b, N: IntoCStr<'a>, V: IntoCStr<'b>>(
        &mut self,
        name: N,
        value: V,
    ) -> NvResult<()> {
        let c_name = name.into_c_str()?;
        let c_value = value.into_c_str()?;
        let errno = unsafe { sys::nvlist_add_string(self.ptr, c_name.as_ptr(), c_value.as_ptr()) };
        if errno != 0 {
            Err(NvError::from_errno(errno))
        } else {
            Ok(())
        }
    }

    pub fn get_cstr<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<&CStr> {
        let c_name = name.into_c_str()?;
        let mut ptr = null_mut();
        let errno = unsafe { sys::nvlist_lookup_string(self.ptr, c_name.as_ptr(), &mut ptr) };
        if errno != 0 {
            Err(NvError::from_errno(errno))
        } else {
            let ret = unsafe { CStr::from_ptr(&*ptr) };
            Ok(ret)
        }
    }

    /// Get a `String` from the list.
    pub fn get_string<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<String> {
        self.get_str(name).map(str::to_owned)
    }

    /// Get a `String` from the list.
    pub fn get_str<'a, N: IntoCStr<'a>>(&self, name: N) -> NvResult<&str> {
        self.get_cstr(name).and_then(|v| v.to_str().map_err(NvError::from))
    }

    /// Turn NvPair into json representation. This method uses libnvpair to do so.
    pub fn save_as_json<F: AsRawFd>(&self, output: F) -> NvResult<()> {
        let mode = CString::new("w").unwrap();
        let file = unsafe { libc::fdopen(output.as_raw_fd(), mode.as_ptr()) };
        let errno = unsafe { nvlist_print_json(file, self.ptr) };
        if errno != 0 {
            Err(NvError::from_errno(errno))
        } else {
            unsafe {
                libc::fflush(file);
            }
            Ok(())
        }
    }
}

impl_list_op! {bool, insert_boolean_value, false}
impl_list_op! {i8, insert_i8, false}
impl_list_op! {u8, insert_u8, false}
impl_list_op! {i16, insert_i16, false}
impl_list_op! {u16, insert_u16, false}
impl_list_op! {i32, insert_i32, false}
impl_list_op! {u32, insert_u32, false}
impl_list_op! {i64, insert_i64, false}
impl_list_op! {u64, insert_u64, false}
impl_list_op! {&str, insert_string, false}

impl std::fmt::Debug for NvList {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(
                self.iter()
                    .map(|ref pair| (pair.key().to_string_lossy().to_string(), pair.value())),
            )
            .finish()
    }
}

pub struct NvPairRef {
    ptr: *mut sys::nvpair_t,
}

impl NvPairRef {
    pub fn as_ptr(&self) -> *mut sys::nvpair_t {
        self.ptr
    }

    pub unsafe fn from_ptr(ptr: *mut sys::nvpair_t) -> Self {
        Self { ptr }
    }

    pub fn key(&self) -> &CStr {
        unsafe { CStr::from_ptr(sys::nvpair_name(self.as_ptr())) }
    }

    pub fn value(&self) -> Value {
        let data_type = unsafe { sys::nvpair_type(self.as_ptr()) };
        match data_type {
            sys::data_type_t::DATA_TYPE_BOOLEAN => Value::Bool(true),
            sys::data_type_t::DATA_TYPE_BOOLEAN_VALUE => {
                let v = unsafe {
                    let mut ptr = MaybeUninit::<sys::boolean_t::Type>::uninit();
                    sys::nvpair_value_boolean_value(self.as_ptr(), ptr.as_mut_ptr());
                    ptr.assume_init() == sys::boolean_t::B_TRUE
                };
                Value::Bool(v)
            },
            sys::data_type_t::DATA_TYPE_INT8 => {
                let v = unsafe {
                    let mut ptr = MaybeUninit::<i8>::uninit();
                    sys::nvpair_value_int8(self.as_ptr(), ptr.as_mut_ptr());
                    ptr.assume_init()
                };
                Value::Int8(v)
            },
            sys::data_type_t::DATA_TYPE_UINT8 => {
                let v = unsafe {
                    let mut ptr = MaybeUninit::<u8>::uninit();
                    sys::nvpair_value_uint8(self.as_ptr(), ptr.as_mut_ptr());
                    ptr.assume_init()
                };
                Value::Uint8(v)
            },
            sys::data_type_t::DATA_TYPE_INT16 => {
                let v = unsafe {
                    let mut ptr = MaybeUninit::<i16>::uninit();
                    sys::nvpair_value_int16(self.as_ptr(), ptr.as_mut_ptr());
                    ptr.assume_init()
                };
                Value::Int16(v)
            },
            sys::data_type_t::DATA_TYPE_UINT16 => {
                let v = unsafe {
                    let mut ptr = MaybeUninit::<u16>::uninit();
                    sys::nvpair_value_uint16(self.as_ptr(), ptr.as_mut_ptr());
                    ptr.assume_init()
                };
                Value::Uint16(v)
            },
            sys::data_type_t::DATA_TYPE_INT32 => {
                let v = unsafe {
                    let mut ptr = MaybeUninit::<i32>::uninit();
                    sys::nvpair_value_int32(self.as_ptr(), ptr.as_mut_ptr());
                    ptr.assume_init()
                };
                Value::Int32(v)
            },
            sys::data_type_t::DATA_TYPE_UINT32 => {
                let v = unsafe {
                    let mut ptr = MaybeUninit::<u32>::uninit();
                    sys::nvpair_value_uint32(self.as_ptr(), ptr.as_mut_ptr());
                    ptr.assume_init()
                };
                Value::Uint32(v)
            },
            sys::data_type_t::DATA_TYPE_INT64 => {
                let v = unsafe {
                    let mut ptr = MaybeUninit::<i64>::uninit();
                    sys::nvpair_value_int64(self.as_ptr(), ptr.as_mut_ptr());
                    ptr.assume_init()
                };
                Value::Int64(v)
            },
            sys::data_type_t::DATA_TYPE_UINT64 => {
                let v = unsafe {
                    let mut ptr = MaybeUninit::<u64>::uninit();
                    sys::nvpair_value_uint64(self.as_ptr(), ptr.as_mut_ptr());
                    ptr.assume_init()
                };
                Value::Uint64(v)
            },
            sys::data_type_t::DATA_TYPE_STRING => {
                let v = unsafe {
                    let mut ptr = null_mut();
                    sys::nvpair_value_string(self.as_ptr(), &mut ptr);
                    CStr::from_ptr(&*ptr)
                };

                Value::String(v.to_string_lossy().to_string())
            },
            _ => Value::Unknown,
        }
    }
}
impl std::fmt::Debug for NvPairRef {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_tuple("NvPair").field(&self.key()).field(&self.value()).finish()
    }
}

pub struct NvListIter<'a> {
    list: &'a NvList,
    position: *mut sys::nvpair_t,
}

impl<'a> Iterator for NvListIter<'a> {
    type Item = NvPairRef;

    fn next(&mut self) -> Option<Self::Item> {
        let next = unsafe { sys::nvlist_next_nvpair(self.list.as_ptr(), self.position) };
        self.position = next;
        if next.is_null() {
            None
        } else {
            Some(unsafe { NvPairRef::from_ptr(next) })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_works() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        assert!(list.is_empty());
        assert!(!list.exists("does_it_work").unwrap());
        list.insert_boolean_value("does_it_work", true).unwrap();
        assert!(!list.is_empty());
        assert!(list.get_boolean_value("does_it_work").unwrap());
        assert!(list.exists("does_it_work").unwrap());
    }
    #[test]
    fn nvop_boolean_value() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert("works", true).unwrap();
        assert!(list.exists("works").unwrap());
    }
    #[test]
    fn nvop_string() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert("works", "yay").unwrap();
        assert!(list.exists("works").unwrap());
    }

    #[test]
    fn nvop_i8() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert("works", 5 as i8).unwrap();
        assert!(list.exists("works").unwrap());
    }

    #[test]
    fn nvop_u8() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert("works", 5 as u8).unwrap();
        assert!(list.exists("works").unwrap());
    }

    #[test]
    fn nvop_i16() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert("works", 5 as i16).unwrap();
        assert!(list.exists("works").unwrap());
    }

    #[test]
    fn nvop_u16() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert("works", 5 as u16).unwrap();
        assert!(list.exists("works").unwrap());
    }

    #[test]
    fn nvop_i32() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert("works", 5 as i32).unwrap();
        assert!(list.exists("works").unwrap());
    }

    #[test]
    fn nvop_u32() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert("works", 5 as u32).unwrap();
        assert!(list.exists("works").unwrap());
    }

    #[test]
    fn nvop_i64() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert("works", 5 as i64).unwrap();
        assert!(list.exists("works").unwrap());
    }

    #[test]
    fn nvop_u64() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert("works", 5 as u64).unwrap();
        assert!(list.exists("works").unwrap());
    }

    #[test]
    fn cr_boolean() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_boolean("random").expect("Failed to insert boolean");
        let ret = list.get_boolean("random").unwrap();
        assert_eq!(true, ret);
    }

    #[test]
    fn cr_i8() {
        let val = 4;
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_i8("random", val).expect("Failed to insert int8");
        let ret = list.get_i8("random").unwrap();
        assert_eq!(val, ret);
    }

    #[test]
    fn cr_u8() {
        let val = 4;
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_u8("random", val).expect("Failed to insert uint8");
        let ret = list.get_u8("random").unwrap();
        assert_eq!(val, ret);
    }
    #[test]
    fn cr_i16() {
        let val = 4;
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_i16("random", val).expect("Failed to insert int16");
        let ret = list.get_i16("random").unwrap();
        assert_eq!(val, ret);
    }
    #[test]
    fn cr_u16() {
        let val = 4;
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_u16("random", val).expect("Failed to insert uint16");
        let ret = list.get_u16("random").unwrap();
        assert_eq!(val, ret);
    }
    #[test]
    fn cr_i32() {
        let val = 4;
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_i32("random", val).expect("Failed to insert int32");
        let ret = list.get_i32("random").unwrap();
        assert_eq!(val, ret);
    }
    #[test]
    fn cr_u32() {
        let val = 4;
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_u32("random", val).expect("Failed to insert uint32");
        let ret = list.get_u32("random").unwrap();
        assert_eq!(val, ret);
    }
    #[test]
    fn cr_i64() {
        let val = 4;
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_i64("random", val).expect("Failed to insert int64");
        let ret = list.get_i64("random").unwrap();
        assert_eq!(val, ret);
    }
    #[test]
    fn cr_u64() {
        let val = 4;
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_u64("random", val).expect("Failed to insert uint64");
        let ret = list.get_u64("random").unwrap();
        assert_eq!(val, ret);
    }

    #[test]
    fn cr_string() {
        let val = "yes";
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_string("is_it_ready?", val).unwrap();
        let ret = list.get_string("is_it_ready?").unwrap();
        assert_eq!(val, &ret);

        let ret = list.get_str("is_it_ready?").unwrap();
        assert_eq!(val, ret);
    }

    #[test]
    fn cr_i8_array() {
        let mut val = [1, 2, 3, 4 as i8];
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_i8_array("works", &mut val as &mut [i8]).unwrap();
        assert!(list.exists("works").unwrap());
        let ret = list.get_i8_array("works").unwrap();
        assert_eq!(4, ret.len());
        assert_eq!(&val, &ret);
    }
    #[test]
    fn cr_u8_array() {
        let mut val = [1, 2, 3, 4 as u8];
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_u8_array("works", &mut val as &mut [u8]).unwrap();
        assert!(list.exists("works").unwrap());
        let ret = list.get_u8_array("works").unwrap();
        assert_eq!(4, ret.len());
        assert_eq!(&val, &ret);
    }

    #[test]
    fn cr_i16_array() {
        let mut val = [1, 2, 3, 4 as i16];
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_i16_array("works", &mut val as &mut [i16]).unwrap();
        assert!(list.exists("works").unwrap());
        let ret = list.get_i16_array("works").unwrap();
        assert_eq!(4, ret.len());
        assert_eq!(&val, &ret);
    }
    #[test]
    fn cr_u16_array() {
        let mut val = [1, 2, 3, 4 as u16];
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_u16_array("works", &mut val as &mut [u16]).unwrap();
        assert!(list.exists("works").unwrap());
        let ret = list.get_u16_array("works").unwrap();
        assert_eq!(4, ret.len());
        assert_eq!(&val, &ret);
    }
    #[test]
    fn cr_i32_array() {
        let mut val = [1, 2, 3, 4 as i32];
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_i32_array("works", &mut val as &mut [i32]).unwrap();
        assert!(list.exists("works").unwrap());
        let ret = list.get_i32_array("works").unwrap();
        assert_eq!(4, ret.len());
        assert_eq!(&val, &ret);
    }
    #[test]
    fn cr_u32_array() {
        let mut val = [1, 2, 3, 4 as u32];
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_u32_array("works", &mut val as &mut [u32]).unwrap();
        assert!(list.exists("works").unwrap());
        let ret = list.get_u32_array("works").unwrap();
        assert_eq!(4, ret.len());
        assert_eq!(&val, &ret);
    }

    #[test]
    fn cr_i64_array() {
        let mut val = [1, 2, 3, 4 as i64];
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_i64_array("works", &mut val as &mut [i64]).unwrap();
        assert!(list.exists("works").unwrap());
        let ret = list.get_i64_array("works").unwrap();
        assert_eq!(4, ret.len());
        assert_eq!(&val, &ret);
    }
    #[test]
    fn cr_u64_array() {
        let mut val = [1, 2, 3, 4 as u64];
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert_u64_array("works", &mut val as &mut [u64]).unwrap();
        assert!(list.exists("works").unwrap());
        let ret = list.get_u64_array("works").unwrap();
        assert_eq!(4, ret.len());
        assert_eq!(&val, &ret);
    }

    #[test]
    fn debug_list() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert("u32", 1u32).unwrap();
        list.insert("i8", 1i8).unwrap();
        list.insert("string", "oh yeah").unwrap();
        dbg!(&list); // make sure Debug is implemented

        let mut iter = list.iter();

        {
            let el = iter.next().unwrap();
            dbg!(&el);
            let pair = (el.key().to_string_lossy().to_string(), el.value());
            let expected_pair = (String::from("u32"), Value::from(1u32));
            assert_eq!(expected_pair, pair);
        }
        {
            let el = iter.next().unwrap();
            dbg!(&el);
            let pair = (el.key().to_string_lossy().to_string(), el.value());
            let expected_pair = (String::from("i8"), Value::from(1i8));
            assert_eq!(expected_pair, pair);
        }
        {
            let el = iter.next().unwrap();
            dbg!(&el);
            let pair = (el.key().to_string_lossy().to_string(), el.value());
            let expected_pair = (String::from("string"), Value::from("oh yeah"));
            assert_eq!(expected_pair, pair);
        }
    }

    #[test]
    fn into_hash_map() {
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert("u32", 1u32).unwrap();
        list.insert("i8", 1i8).unwrap();
        list.insert("string", "oh yeah").unwrap();

        let mut expected_map = HashMap::with_capacity(3);
        expected_map.insert(String::from("u32"), Value::from(1u32));
        expected_map.insert(String::from("i8"), Value::from(1i8));
        expected_map.insert(String::from("string"), Value::from("oh yeah"));

        assert_eq!(expected_map, list.into_hashmap());
    }

    #[test]
    fn into_c_str() {
        let owned = CString::new("owned").unwrap();
        let mut list = NvList::new(NvFlag::UniqueNameType).unwrap();
        list.insert(owned, 1u32).unwrap();

        let borrowed_name = CString::new("borrowed").unwrap();
        let borrowed: &CStr = borrowed_name.as_c_str();
        list.insert(borrowed, 2u32).unwrap();

        let mut expected_map = HashMap::with_capacity(3);
        expected_map.insert(String::from("owned"), Value::from(1u32));
        expected_map.insert(String::from("borrowed"), Value::from(2u32));

        assert_eq!(expected_map, list.into_hashmap());
    }
}
