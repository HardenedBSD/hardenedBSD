//! Module for inspection and manipulation of jail parameters
use crate::sys::JailFlags;
use crate::JailError;
use byteorder::{ByteOrder, LittleEndian, NetworkEndian, WriteBytesExt};
use log::trace;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::iter::FromIterator;
use std::mem;
use std::net;
use std::slice;
use strum_macros::EnumDiscriminants;
use sysctl::{Ctl, CtlFlags, CtlType, CtlValue, Sysctl};

#[cfg(feature = "serialize")]
use serde::Serialize;

#[cfg(target_os = "freebsd")]
impl Type {
    /// Get a parameter type from the name
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::param::Type;
    /// assert_eq!(Type::of_param("osreldate").unwrap(), Type::Int);
    /// assert_eq!(Type::of_param("osrelease").unwrap(), Type::String);
    /// assert_eq!(Type::of_param("ip4.addr").unwrap(), Type::Ipv4Addrs);
    /// assert_eq!(Type::of_param("ip6.addr").unwrap(), Type::Ipv6Addrs);
    /// ```
    pub fn of_param(name: &str) -> Result<Type, JailError> {
        trace!("Type::of_param(name={:?})", name);
        let (ctl_type, _, _) = info(name)?;

        ctltype_to_type(name, ctl_type)
    }

    /// Check if this type is a string.
    ///
    /// # Example
    ///
    /// ```
    /// use jail::param::Type;
    /// assert_eq!(Type::String.is_string(), true);
    /// assert_eq!(Type::Int.is_string(), false);
    /// ```
    pub fn is_string(&self) -> bool {
        trace!("Type::is_string({:?})", self);
        matches!(self, Type::String)
    }

    /// Check if this type is numeric
    ///
    /// # Example
    /// ```
    /// use jail::param::Type;
    /// assert_eq!(Type::Int.is_numeric(), true);
    /// assert_eq!(Type::String.is_numeric(), false);
    /// ```
    pub fn is_numeric(&self) -> bool {
        trace!("Type::is_numeric({:?})", self);
        matches!(
            self,
            Type::S8
                | Type::S16
                | Type::S32
                | Type::S64
                | Type::U8
                | Type::U16
                | Type::U32
                | Type::U64
                | Type::Int
                | Type::Long
                | Type::Uint
                | Type::Ulong
        )
    }

    /// Check if this type is signed
    ///
    /// # Example
    /// ```
    /// use jail::param::Type;
    /// assert_eq!(Type::Int.is_signed(), true);
    /// assert_eq!(Type::Uint.is_signed(), false);
    ///
    /// // Non-numeric types return false
    /// assert_eq!(Type::String.is_signed(), false);
    /// ```
    pub fn is_signed(&self) -> bool {
        trace!("Type::is_signed({:?})", self);
        matches!(
            self,
            Type::S8 | Type::S16 | Type::S32 | Type::S64 | Type::Int | Type::Long
        )
    }

    /// Check if this type is an IP address list
    ///
    /// # Example
    ///
    /// ```
    /// use jail::param::Type;
    /// assert_eq!(Type::Ipv4Addrs.is_ip(), true);
    /// assert_eq!(Type::Ipv6Addrs.is_ip(), true);
    /// assert_eq!(Type::String.is_ip(), false);
    /// ```
    pub fn is_ip(&self) -> bool {
        trace!("Type::is_ip({:?})", self);
        matches!(self, Type::Ipv4Addrs | Type::Ipv6Addrs)
    }

    /// Check if this type is an IPv4 address list
    ///
    /// # Example
    ///
    /// ```
    /// use jail::param::Type;
    /// assert_eq!(Type::Ipv4Addrs.is_ipv4(), true);
    /// assert_eq!(Type::Ipv6Addrs.is_ipv4(), false);
    /// ```
    pub fn is_ipv4(&self) -> bool {
        trace!("Type::is_ipv4({:?})", self);
        matches!(self, Type::Ipv4Addrs)
    }

    /// Check if this type is an IPv4 address list
    ///
    /// # Example
    ///
    /// ```
    /// use jail::param::Type;
    /// assert_eq!(Type::Ipv6Addrs.is_ipv6(), true);
    /// assert_eq!(Type::Ipv4Addrs.is_ipv6(), false);
    /// ```
    pub fn is_ipv6(&self) -> bool {
        trace!("Type::is_ipv6({:?})", self);
        matches!(self, Type::Ipv6Addrs)
    }
}

// impl convert::From<Value> for Type {
//     fn from(t: Value) -> Type {
//         match t {
//             Value::Int(_) => Type::Int,
//             Value::String(_) => Type::String,
//             Value::S64(_) => Type::S64,
//             Value::Uint(_) => Type::Uint,
//             Value::Long(_) => Type::Long,
//             Value::Ulong(_) => Type::Ulong,
//             Value::U64(_) => Type::U64,
//             Value::U8(_) => Type::U8,
//             Value::U16(_) => Type::U16,
//             Value::S8(_) => Type::S8,
//             Value::S16(_) => Type::S16,
//             Value::S32(_) => Type::S32,
//             Value::U32(_) => Type::U32,
//         }
//     }
// }

impl From<Type> for CtlType {
    fn from(t: Type) -> CtlType {
        trace!("CtlType::from::<Type>({:?})", t);
        match t {
            Type::String => CtlType::String,
            Type::U8 => CtlType::U8,
            Type::U16 => CtlType::U16,
            Type::U32 => CtlType::U32,
            Type::U64 => CtlType::U64,
            Type::S8 => CtlType::S8,
            Type::S16 => CtlType::S16,
            Type::S32 => CtlType::S32,
            Type::S64 => CtlType::S64,
            Type::Int => CtlType::Int,
            Type::Long => CtlType::Long,
            Type::Uint => CtlType::Uint,
            Type::Ulong => CtlType::Ulong,
            Type::Ipv4Addrs => CtlType::Struct,
            Type::Ipv6Addrs => CtlType::Struct,
        }
    }
}

/// An enum representing the value of a parameter.
#[derive(EnumDiscriminants, Clone, PartialEq, Eq, Debug, Hash)]
#[strum_discriminants(name(Type), derive(PartialOrd, Ord, Hash))]
#[cfg_attr(feature = "serialize", derive(Serialize))]
pub enum Value {
    Int(libc::c_int),
    String(String),
    S64(i64),
    Uint(libc::c_uint),
    Long(libc::c_long),
    Ulong(libc::c_ulong),
    U64(u64),
    U8(u8),
    U16(u16),
    S8(i8),
    S16(i16),
    S32(i32),
    U32(u32),

    /// Represent a list of IPv4 addresses.
    ///
    /// # Example
    ///
    /// ```
    /// use jail::param::Value;
    /// let rfc1918 = Value::Ipv4Addrs(vec![
    ///     "10.0.0.0".parse().unwrap(),
    ///     "172.16.0.0".parse().unwrap(),
    ///     "192.168.0.0".parse().unwrap(),
    /// ]);
    /// ```
    Ipv4Addrs(Vec<net::Ipv4Addr>),

    /// Represent a list of IPv6 addresses.
    ///
    /// # Example
    ///
    /// ```
    /// use jail::param::Value;
    /// let all_nodes = Value::Ipv6Addrs(vec![
    ///     "ff01::1".parse().unwrap(),
    ///     "ff02::1".parse().unwrap(),
    /// ]);
    /// ```
    Ipv6Addrs(Vec<net::Ipv6Addr>),
}

impl Value {
    /// Get the type of this value
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::param::{Type, Value};
    /// assert_eq!(Value::Int(42).get_type(), Type::Int);
    /// ```
    ///
    /// Types allow for convenient checks:
    ///
    /// ```
    /// use jail::param::Value;
    /// assert!(Value::Int(42).get_type().is_signed());
    /// ```
    pub fn get_type(&self) -> Type {
        trace!("Value::get_type({:?})", self);
        self.into()
    }

    /// Format the value into a vector of bytes as expected by the jail
    /// parameter API.
    pub fn as_bytes(&self) -> Result<Vec<u8>, JailError> {
        trace!("Value::as_bytes({:?})", self);
        let mut bytes: Vec<u8> = vec![];

        // Some conversions are identity on 64 bit, but not on 32 bit and vice versa
        #[cfg_attr(feature = "cargo-clippy", allow(clippy::useless_conversion))]
        match self {
            Value::String(s) => {
                bytes = CString::new(s.as_str())
                    .expect("Could not create CString from value")
                    .to_bytes_with_nul()
                    .to_vec();
                Ok(())
            }
            Value::U8(v) => bytes.write_u8(*v),
            Value::S8(v) => bytes.write_i8(*v),
            Value::U16(v) => bytes.write_u16::<LittleEndian>(*v),
            Value::U32(v) => bytes.write_u32::<LittleEndian>(*v),
            Value::U64(v) => bytes.write_u64::<LittleEndian>(*v),
            Value::S16(v) => bytes.write_i16::<LittleEndian>(*v),
            Value::S32(v) => bytes.write_i32::<LittleEndian>(*v),
            Value::S64(v) => bytes.write_i64::<LittleEndian>(*v),
            Value::Int(v) => {
                bytes.write_int::<LittleEndian>((*v).into(), mem::size_of::<libc::c_int>())
            }
            Value::Long(v) => {
                bytes.write_int::<LittleEndian>((*v).into(), mem::size_of::<libc::c_long>())
            }
            Value::Uint(v) => {
                bytes.write_uint::<LittleEndian>((*v).into(), mem::size_of::<libc::c_uint>())
            }
            Value::Ulong(v) => {
                bytes.write_uint::<LittleEndian>((*v).into(), mem::size_of::<libc::c_ulong>())
            }
            Value::Ipv4Addrs(addrs) => {
                for addr in addrs {
                    let s_addr = nix::sys::socket::Ipv4Addr::from_std(&addr).0.s_addr;
                    let host_u32 = u32::from_be(s_addr);
                    bytes
                        .write_u32::<NetworkEndian>(host_u32)
                        .map_err(|_| JailError::SerializeFailed)?;
                }
                Ok(())
            }
            Value::Ipv6Addrs(addrs) => {
                for addr in addrs {
                    bytes.extend_from_slice(&addr.octets());
                }
                Ok(())
            }
        }
        .map_err(|_| JailError::SerializeFailed)?;

        Ok(bytes)
    }

    /// Attempt to unpack the Vector of IPv4 addresses contained in this value
    ///
    /// # Example
    ///
    /// ```
    /// use jail::param::Value;
    /// use std::net;
    /// # let rfc1918 = Value::Ipv4Addrs(vec![
    /// #     "10.0.0.0".parse().unwrap(),
    /// #     "172.16.0.0".parse().unwrap(),
    /// #     "192.168.0.0".parse().unwrap(),
    /// # ]);
    /// let ips = rfc1918
    ///     .unpack_ipv4()
    ///     .expect("could not unwrap RFC1918 IP Addresses");
    /// assert_eq!(ips[0], net::Ipv4Addr::new(10,0,0,0));
    /// ```
    ///
    /// Attempting to unwrap a different value will fail:
    /// ```should_panic
    /// use jail::param::Value;
    /// let not_ipv4_addrs = Value::U8(42);
    /// not_ipv4_addrs.unpack_ipv4().unwrap();
    /// ```
    pub fn unpack_ipv4(self) -> Result<Vec<net::Ipv4Addr>, JailError> {
        trace!("Value::unpack_ipv4({:?})", self);
        match self {
            Value::Ipv4Addrs(v) => Ok(v),
            _ => Err(JailError::ParameterUnpackError),
        }
    }

    /// Attempt to unpack the Vector of IPv4 addresses contained in this value
    ///
    /// # Example
    ///
    /// ```
    /// use jail::param::Value;
    /// use std::net;
    /// # let all_nodes = Value::Ipv6Addrs(vec![
    /// #     "ff01::1".parse().unwrap(),
    /// #     "ff02::1".parse().unwrap(),
    /// # ]);
    /// let ips = all_nodes
    ///     .unpack_ipv6()
    ///     .expect("could not unwrap 'All Nodes' IPv6 Addresses");
    /// assert_eq!(ips[0], net::Ipv6Addr::new(0xff01, 0, 0, 0, 0, 0, 0, 1))
    /// ```
    ///
    /// Attempting to unwrap a different value will fail:
    /// ```should_panic
    /// use jail::param::Value;
    /// # let rfc1918 = Value::Ipv4Addrs(vec![
    /// #     "10.0.0.0".parse().unwrap(),
    /// #     "172.16.0.0".parse().unwrap(),
    /// #     "192.168.0.0".parse().unwrap(),
    /// # ]);
    /// rfc1918.unpack_ipv6().unwrap();
    /// ```
    pub fn unpack_ipv6(self) -> Result<Vec<net::Ipv6Addr>, JailError> {
        trace!("Value::unpack_ipv6({:?})", self);
        match self {
            Value::Ipv6Addrs(v) => Ok(v),
            _ => Err(JailError::ParameterUnpackError),
        }
    }

    /// Attempt to unpack a String value contained in this parameter Value.
    ///
    /// ```
    /// use jail::param::Value;
    /// let value = Value::String("foobar".into());
    /// assert_eq!(
    ///     value.unpack_string().unwrap(),
    ///     "foobar".to_string()
    /// );
    /// ```
    ///
    /// Attempting to unwrap a different value will fail:
    /// ```should_panic
    /// use jail::param::Value;
    /// let not_a_string = Value::U8(42);
    /// not_a_string.unpack_string().unwrap();
    /// ```
    pub fn unpack_string(self) -> Result<String, JailError> {
        trace!("Value::unpack_string({:?})", self);
        match self {
            Value::String(v) => Ok(v),
            _ => Err(JailError::ParameterUnpackError),
        }
    }

    /// Attempt to unpack any unsigned integer Value into a 64 bit unsigned
    /// integer.
    ///
    /// Shorter values will be zero-extended as appropriate.
    ///
    /// # Example
    /// ```
    /// use jail::param::Value;
    /// assert_eq!(Value::U64(64u64).unpack_u64().unwrap(), 64u64);
    /// assert_eq!(Value::U32(32u32).unpack_u64().unwrap(), 32u64);
    /// assert_eq!(Value::U16(16u16).unpack_u64().unwrap(), 16u64);
    /// assert_eq!(Value::U8(8u8).unpack_u64().unwrap(), 8u64);
    /// assert_eq!(Value::Uint(1234).unpack_u64().unwrap(), 1234u64);
    /// assert_eq!(Value::Ulong(42).unpack_u64().unwrap(), 42u64);
    ///
    /// // Everything else should fail.
    /// assert!(Value::String("1234".into()).unpack_u64().is_err());
    /// assert!(Value::S64(64i64).unpack_u64().is_err());
    /// ```
    pub fn unpack_u64(self) -> Result<u64, JailError> {
        trace!("Value::unpack_u64({:?})", self);
        // Some conversions are identity on 64 bit, but not on 32 bit and vice versa
        #[cfg_attr(feature = "cargo-clippy", allow(clippy::useless_conversion))]
        match self {
            Value::U64(v) => Ok(v),
            Value::U32(v) => Ok(v.into()),
            Value::U16(v) => Ok(v.into()),
            Value::U8(v) => Ok(v.into()),
            Value::Uint(v) => Ok(v.into()),
            Value::Ulong(v) => Ok(v.into()),
            _ => Err(JailError::ParameterUnpackError),
        }
    }

    /// Attempt to unpack any Value containing a signed integer or unsigned
    /// integer shorter than 64 bits into a 64 bit unsigned integer.
    ///
    /// Shorter values will be zero-extended as appropriate.
    ///
    /// # Example
    /// ```
    /// use jail::param::Value;
    /// assert_eq!(Value::S64(-64i64).unpack_i64().unwrap(), -64i64);
    /// assert_eq!(Value::S32(-32i32).unpack_i64().unwrap(), -32i64);
    /// assert_eq!(Value::S16(-16i16).unpack_i64().unwrap(), -16i64);
    /// assert_eq!(Value::S8(-8i8).unpack_i64().unwrap(), -8i64);
    /// assert_eq!(Value::U32(32u32).unpack_i64().unwrap(), 32i64);
    /// assert_eq!(Value::U16(16u16).unpack_i64().unwrap(), 16i64);
    /// assert_eq!(Value::U8(8u8).unpack_i64().unwrap(), 8i64);
    /// assert_eq!(Value::Uint(1234).unpack_i64().unwrap(), 1234i64);
    /// assert_eq!(Value::Int(-1234).unpack_i64().unwrap(), -1234i64);
    /// assert_eq!(Value::Long(-42).unpack_i64().unwrap(), -42i64);
    ///
    /// // Everything else should fail.
    /// assert!(Value::String("1234".into()).unpack_i64().is_err());
    /// assert!(Value::U64(64u64).unpack_i64().is_err());
    /// ```
    pub fn unpack_i64(self) -> Result<i64, JailError> {
        trace!("Value::unpack_i64({:?})", self);
        // Some conversions are identity on 64 bit, but not on 32 bit and vice versa
        #[cfg_attr(feature = "cargo-clippy", allow(clippy::useless_conversion))]
        match self {
            Value::S64(v) => Ok(v),
            Value::S32(v) => Ok(v.into()),
            Value::S16(v) => Ok(v.into()),
            Value::S8(v) => Ok(v.into()),
            Value::U32(v) => Ok(v.into()),
            Value::U16(v) => Ok(v.into()),
            Value::U8(v) => Ok(v.into()),
            Value::Uint(v) => Ok(v.into()),
            Value::Int(v) => Ok(v.into()),
            Value::Long(v) => Ok(v.into()),
            _ => Err(JailError::ParameterUnpackError),
        }
    }
}

#[cfg(target_os = "freebsd")]
fn info(name: &str) -> Result<(CtlType, CtlFlags, usize), JailError> {
    trace!("info({:?})", name);
    // Get parameter type
    let ctlname = format!("security.jail.param.{}", name);

    let ctl = Ctl::new(&ctlname).map_err(|_| JailError::NoSuchParameter(name.to_string()))?;

    let flags = ctl.flags().map_err(JailError::SysctlError)?;
    let paramtype = ctl.value_type().map_err(JailError::ParameterTypeError)?;

    let typesize = match paramtype {
        CtlType::Int => mem::size_of::<libc::c_int>(),
        CtlType::String => {
            let length = match ctl.value().map_err(JailError::ParameterStringLengthError)? {
                CtlValue::String(l) => l,
                _ => panic!("param sysctl reported to be string, but isn't"),
            };

            length
                .parse::<usize>()
                .map_err(|_| JailError::ParameterLengthNaN(length.to_string()))?
        }

        CtlType::S64 => mem::size_of::<i64>(),
        CtlType::Uint => mem::size_of::<libc::c_uint>(),
        CtlType::Long => mem::size_of::<libc::c_long>(),
        CtlType::Ulong => mem::size_of::<libc::c_ulong>(),
        CtlType::U64 => mem::size_of::<u64>(),
        CtlType::U8 => mem::size_of::<u8>(),
        CtlType::U16 => mem::size_of::<u16>(),
        CtlType::S8 => mem::size_of::<i8>(),
        CtlType::S16 => mem::size_of::<i16>(),
        CtlType::S32 => mem::size_of::<i32>(),
        CtlType::U32 => mem::size_of::<u32>(),
        CtlType::Struct => match ctl.value().map_err(JailError::ParameterStructLengthError)? {
            CtlValue::Struct(data) => {
                assert!(
                    data.len() >= mem::size_of::<usize>(),
                    "Error: struct sysctl returned too few bytes."
                );
                LittleEndian::read_uint(&data, mem::size_of::<usize>()) as usize
            }
            _ => panic!("param sysctl reported to be struct, but isn't"),
        },
        _ => return Err(JailError::ParameterTypeUnsupported(paramtype)),
    };

    Ok((paramtype, flags, typesize))
}

#[cfg(target_os = "freebsd")]
fn ctltype_to_type(name: &str, ctl_type: CtlType) -> Result<Type, JailError> {
    trace!("ctltype_to_type({:?}, ctl_type={:?})", name, ctl_type);
    let param_type = match ctl_type {
        CtlType::Int => Type::Int,
        CtlType::S64 => Type::S64,
        CtlType::Uint => Type::Uint,
        CtlType::Long => Type::Long,
        CtlType::Ulong => Type::Ulong,
        CtlType::U64 => Type::U64,
        CtlType::U8 => Type::U8,
        CtlType::U16 => Type::U16,
        CtlType::S8 => Type::S8,
        CtlType::S16 => Type::S16,
        CtlType::S32 => Type::S32,
        CtlType::U32 => Type::U32,
        CtlType::String => Type::String,
        CtlType::Struct => match name {
            "ip4.addr" => Type::Ipv4Addrs,
            "ip6.addr" => Type::Ipv6Addrs,
            _ => return Err(JailError::ParameterTypeUnsupported(ctl_type)),
        },
        _ => return Err(JailError::ParameterTypeUnsupported(ctl_type)),
    };

    Ok(param_type)
}

/// Get a jail parameter given the jid and the parameter name.
///
/// # Examples
/// ```
/// use jail::param;
/// # use jail::StoppedJail;
/// # let jail = StoppedJail::new("/rescue")
/// #     .name("testjail_getparam")
/// #     .start()
/// #     .expect("could not start jail");
/// # let jid = jail.jid;
///
/// let hostuuid = param::get(jid, "host.hostuuid")
///     .expect("could not get parameter");
///
/// println!("{:?}", hostuuid);
/// #
/// # jail.kill().expect("could not stop jail");
/// ```
#[cfg(target_os = "freebsd")]
pub fn get(jid: i32, name: &str) -> Result<Value, JailError> {
    trace!("get(jid={}, name={:?})", jid, name);
    let (paramtype, _, typesize) = info(name)?;

    // ip4.addr and ip6.addr are arrays, which can be up to
    // security.jail.jail_max_af_ips long:
    let jail_max_af_ips = match Ctl::new("security.jail.jail_max_af_ips")
        .map_err(JailError::JailMaxAfIpsFailed)?
        .value()
        .map_err(JailError::JailMaxAfIpsFailed)?
    {
        CtlValue::Uint(u) => u as usize,
        _ => panic!("security.jail.jail_max_af_ips has the wrong type."),
    };

    let valuesize = match name {
        "ip4.addr" => typesize * jail_max_af_ips,
        "ip6.addr" => typesize * jail_max_af_ips,
        _ => typesize,
    };

    let paramname = CString::new(name).expect("Could not convert parameter name to CString");

    let mut value: Vec<u8> = vec![0; valuesize];
    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };

    let mut jiov: Vec<libc::iovec> = vec![
        iovec!(b"jid\0"),
        iovec!(&jid as *const _, mem::size_of::<i32>()),
        iovec!(paramname.as_ptr(), paramname.as_bytes().len() + 1),
        iovec!(value.as_mut_ptr(), valuesize),
        iovec!(b"errmsg\0"),
        iovec!(errmsg.as_mut_ptr(), errmsg.len()),
    ];

    let jid = unsafe {
        libc::jail_get(
            jiov[..].as_mut_ptr() as *mut libc::iovec,
            jiov.len() as u32,
            JailFlags::empty().bits(),
        )
    };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut libc::c_char) }
        .to_string_lossy()
        .to_string();

    let value = match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(JailError::from_errno()),
            _ => Err(JailError::JailGetError(err)),
        },
        _ => Ok(value),
    }?;

    // Wrap in Enum and return
    match ctltype_to_type(name, paramtype)? {
        Type::Int => Ok(Value::Int(
            LittleEndian::read_int(&value, mem::size_of::<libc::c_int>()) as libc::c_int,
        )),
        Type::S64 => Ok(Value::S64(LittleEndian::read_i64(&value))),
        Type::Uint => Ok(Value::Uint(
            LittleEndian::read_uint(&value, mem::size_of::<libc::c_uint>()) as libc::c_uint,
        )),
        Type::Long => Ok(Value::Long(
            LittleEndian::read_int(&value, mem::size_of::<libc::c_long>()) as libc::c_long,
        )),
        Type::Ulong => Ok(Value::Ulong(LittleEndian::read_uint(
            &value,
            mem::size_of::<libc::c_ulong>(),
        ) as libc::c_ulong)),
        Type::U64 => Ok(Value::U64(LittleEndian::read_u64(&value))),
        Type::U8 => Ok(Value::U8(value[0])),
        Type::U16 => Ok(Value::U16(LittleEndian::read_u16(&value))),
        Type::S8 => Ok(Value::S8(value[0] as i8)),
        Type::S16 => Ok(Value::S16(LittleEndian::read_i16(&value))),
        Type::S32 => Ok(Value::S32(LittleEndian::read_i32(&value))),
        Type::U32 => Ok(Value::U32(LittleEndian::read_u32(&value))),
        Type::String => Ok(Value::String({
            unsafe { CStr::from_ptr(value.as_ptr() as *mut libc::c_char) }
                .to_string_lossy()
                .into_owned()
        })),
        Type::Ipv4Addrs => {
            // Make sure we got the right data size
            let addrsize = mem::size_of::<libc::in_addr>();
            let count = valuesize / addrsize;

            assert_eq!(
                0,
                typesize % addrsize,
                "Error: memory size mismatch. Length of data \
                 retrieved is not a multiple of the size of in_addr."
            );

            #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
            let ips: Vec<net::Ipv4Addr> =
                unsafe { slice::from_raw_parts(value.as_ptr() as *const libc::in_addr, count) }
                    .iter()
                    .map(|in_addr| u32::from_be(in_addr.s_addr))
                    .map(net::Ipv4Addr::from)
                    .filter(|ip| !ip.is_unspecified())
                    .collect();

            Ok(Value::Ipv4Addrs(ips))
        }
        Type::Ipv6Addrs => {
            // Make sure we got the right data size
            let addrsize = mem::size_of::<libc::in6_addr>();
            let count = valuesize / addrsize;

            assert_eq!(
                0,
                typesize % addrsize,
                "Error: memory size mismatch. Length of data \
                 retrieved is not a multiple of the size of in_addr."
            );

            #[cfg_attr(feature = "cargo-clippy", allow(clippy::cast_ptr_alignment))]
            let ips: Vec<net::Ipv6Addr> =
                unsafe { slice::from_raw_parts(value.as_ptr() as *const libc::in6_addr, count) }
                    .iter()
                    .map(|in6_addr| net::Ipv6Addr::from(in6_addr.s6_addr))
                    .filter(|ip| !ip.is_unspecified())
                    .collect();

            Ok(Value::Ipv6Addrs(ips))
        }
    }
}

/// Set a jail parameter given the jid, the parameter name and the value.
///
/// # Examples
/// ```
/// use jail::param;
/// # use jail::StoppedJail;
/// # let jail = StoppedJail::new("/rescue")
/// #     .name("testjail_setparam")
/// #     .start()
/// #     .expect("could not start jail");
/// # let jid = jail.jid;
///
/// param::set(jid, "allow.raw_sockets", param::Value::Int(1))
///     .expect("could not set parameter");
/// #
/// # let readback = param::get(jid, "allow.raw_sockets")
/// #     .expect("could not read back value");
/// # assert_eq!(readback, param::Value::Int(1));
/// # jail.kill().expect("could not stop jail");
/// ```
///
/// Tunable parameters cannot be set:
/// ```
/// use jail::{param, JailError};
/// # use jail::StoppedJail;
/// # let jail = StoppedJail::new("/rescue")
/// #     .name("testjail_setparam_tunable")
/// #     .start()
/// #     .expect("could not start jail");
/// # let jid = jail.jid;
/// # let res =
/// param::set( jid, "osrelease", param::Value::String("CantTouchThis".into()))
///     .expect_err("Setting a tunable parameter on a running jail succeeded");
/// # match res {
/// #     JailError::ParameterTunableError(tun) => {
/// #         assert_eq!(tun, "osrelease")
/// #     },
/// #     e => {
/// #         jail.kill().expect("could not stop jail");
/// #         panic!("Wrong error returned");
/// #     },
/// # }
/// # jail.kill().expect("could not stop jail");
/// ```
pub fn set(jid: i32, name: &str, value: Value) -> Result<(), JailError> {
    trace!("set(jid={}, name={:?}, value={:?})", jid, name, value);
    let (ctltype, ctl_flags, _) = info(name)?;

    // Check if this is a tunable.
    if ctl_flags.contains(CtlFlags::TUN) {
        return Err(JailError::ParameterTunableError(name.into()));
    }

    let paramname = CString::new(name).expect("Could not convert parameter name to CString");

    let mut errmsg: [u8; 256] = unsafe { mem::zeroed() };

    let paramtype: Type = (&value).into();
    assert_eq!(ctltype, paramtype.into());

    let mut bytes = value.as_bytes()?;

    let mut jiov: Vec<libc::iovec> = vec![
        iovec!(b"jid\0"),
        iovec!(&jid as *const _, mem::size_of::<i32>()),
        iovec!(paramname.as_ptr(), paramname.as_bytes().len() + 1),
        iovec!(bytes.as_mut_ptr(), bytes.len()),
        iovec!(b"errmsg\0"),
        iovec!(errmsg.as_mut_ptr(), errmsg.len()),
    ];

    let jid = unsafe {
        libc::jail_set(
            jiov[..].as_mut_ptr() as *mut libc::iovec,
            jiov.len() as u32,
            JailFlags::UPDATE.bits(),
        )
    };

    let err = unsafe { CStr::from_ptr(errmsg.as_ptr() as *mut libc::c_char) }
        .to_string_lossy()
        .to_string();

    match jid {
        e if e < 0 => match errmsg[0] {
            0 => Err(JailError::from_errno()),
            _ => Err(JailError::JailSetError(err)),
        },
        _ => Ok(()),
    }
}

/// Set a jail parameter given the jid, the parameter name and the value.
///
/// # Examples
/// ```
/// use jail::param;
/// # use jail::StoppedJail;
/// # let jail = StoppedJail::new("/rescue")
/// #     .name("testjail_get_all_params")
/// #     .param("allow.raw_sockets", param::Value::Int(1))
/// #     .start()
/// #     .expect("could not start jail");
/// # let jid = jail.jid;
///
/// let params = param::get_all(jid)
///     .expect("could not get all parameters");
///
/// assert_eq!(params.get("allow.raw_sockets"), Some(&param::Value::Int(1)));
/// # jail.kill().expect("could not stop jail");
/// ```
pub fn get_all(jid: i32) -> Result<HashMap<String, Value>, JailError> {
    trace!("get_all(jid={})", jid);

    // If we have individual filters on each of these, we'll end up with a
    // very large type_length_limit. We can quickly check names against a vec
    // to avoid that.
    let filtered_names = vec![
        // The following parameters are dynamic
        "jid",
        "dying",
        "parent",
        "children.cur",
        "cpuset.id",
        // The following parameters are handled separately
        "name",
        "hostname",
        "path",
        "ip4.addr",
        "ip6.addr",
    ];

    let params: Result<Vec<(String, Value)>, JailError> = Ctl::new("security.jail.param")
        .map_err(JailError::SysctlError)?
        .into_iter()
        .filter_map(Result::ok)
        // Get name
        .map(|ctl| ctl.name())
        .filter_map(Result::ok)
        // Remove leading "security.jail.param"
        .filter(|name| name.starts_with("security.jail.param"))
        .map(|string| string["security.jail.param.".len()..].to_string())
        .filter(|name| {
            // Remove elements with a trailing dot (nodes)
            !name.ends_with('.')
            // Filter out any names in the filtered_names vec.
            && !filtered_names.contains(&name.as_str())
        })
        // get parameters
        .map(|name| get(jid, &name).map(|v| (name, v)))
        .collect();

    Ok(HashMap::from_iter(params?))
}
