//! This module is used to parse a string to byte size,
//! supports units of 2^10 like "KiB", "MiB",
//! or units of 1000 like "KB", "MB"
//!
//! # Example
//!
//! ```
//! use humanize_rs::bytes::{Bytes, Unit};
//!
//! let gigabytes1 = Bytes::new(1, Unit::GiByte);
//! let gigabytes2 = "1 GiB".parse::<Bytes>();
//! assert_eq!(gigabytes1, gigabytes2);
//! assert_eq!(gigabytes2.unwrap().size(), 1 << 30);
//! ```

use super::num::Int;
use std::fmt;
use std::str::FromStr;
use ParseError;

const IBYTES: [u64; 7] = [1, 1 << 10, 1 << 20, 1 << 30, 1 << 40, 1 << 50, 1 << 60];
const BYTES: [u64; 7] = [
    1,
    1_000,
    1_000_000,
    1_000_000_000,
    1_000_000_000_000,
    1_000_000_000_000_000,
    1_000_000_000_000_000_000,
];

/// Bytes units, like "KB", "KiB"
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Unit {
    /// 1 Byte
    Byte,

    /// 1 << 10 Byte
    KiByte,

    /// 1 << 20 Byte
    MiByte,

    /// 1 << 30 Byte
    GiByte,

    /// 1 << 40 Byte
    TiByte,

    /// 1 << 50 Byte
    PiByte,

    /// 1 << 60 Byte
    EiByte,

    /// 1000 Byte
    KByte,

    /// 1000 KByte
    MByte,

    /// 1000 MByte
    GByte,

    /// 1000 GByte
    TByte,

    /// 1000 TByte
    PByte,

    /// 1000 PByte
    EByte,
}

impl Unit {
    fn size<T: Int>(&self) -> Result<T, ParseError> {
        let v = match self {
            Unit::Byte => <T>::from_u64(1),
            Unit::KiByte => <T>::from_u64(IBYTES[1]),
            Unit::MiByte => <T>::from_u64(IBYTES[2]),
            Unit::GiByte => <T>::from_u64(IBYTES[3]),
            Unit::TiByte => <T>::from_u64(IBYTES[4]),
            Unit::PiByte => <T>::from_u64(IBYTES[5]),
            Unit::EiByte => <T>::from_u64(IBYTES[6]),
            Unit::KByte => <T>::from_u64(BYTES[1]),
            Unit::MByte => <T>::from_u64(BYTES[2]),
            Unit::GByte => <T>::from_u64(BYTES[3]),
            Unit::TByte => <T>::from_u64(BYTES[4]),
            Unit::PByte => <T>::from_u64(BYTES[5]),
            Unit::EByte => <T>::from_u64(BYTES[6]),
        }.ok_or(ParseError::Overflow)?;

        Ok(v)
    }
}

impl fmt::Display for Unit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let unit = match self {
            Unit::Byte => "B",
            Unit::KiByte => "KiB",
            Unit::MiByte => "MiB",
            Unit::GiByte => "GiB",
            Unit::TiByte => "TiB",
            Unit::PiByte => "PiB",
            Unit::EiByte => "EiB",
            Unit::KByte => "KB",
            Unit::MByte => "MB",
            Unit::GByte => "GB",
            Unit::TByte => "TB",
            Unit::PByte => "PB",
            Unit::EByte => "EB",
        };

        f.pad(unit)
    }
}

impl FromStr for Unit {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" | "b" => Ok(Unit::Byte),
            "ki" | "kib" => Ok(Unit::KiByte),
            "mi" | "mib" => Ok(Unit::MiByte),
            "gi" | "gib" => Ok(Unit::GiByte),
            "ti" | "tib" => Ok(Unit::TiByte),
            "pi" | "pib" => Ok(Unit::PiByte),
            "ei" | "eib" => Ok(Unit::EiByte),
            "k" | "kb" => Ok(Unit::KByte),
            "m" | "mb" => Ok(Unit::MByte),
            "g" | "gb" => Ok(Unit::GByte),
            "t" | "tb" => Ok(Unit::TByte),
            "p" | "pb" => Ok(Unit::PByte),
            "e" | "eb" => Ok(Unit::EByte),
            _ => Err(ParseError::InvalidUnit),
        }
    }
}

/// Size calculated in [`Unit::Byte`]
///
/// [`Unit::Byte`]: ./enum.Unit.html#variant.Byte
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Bytes<T: Int = usize>(T);

impl Bytes {
    /// Returns a `Bytes` with a numeric value and a specific unit, or a `ParseError` if exists,
    /// only [`ParseError::Overflow`] here.
    ///
    /// # Example
    ///
    /// ```
    /// use humanize_rs::bytes::{Bytes, Unit};
    ///
    /// let megabytes = Bytes::new(1, Unit::MByte).unwrap();
    /// ```
    ///
    /// [`ParseError::Overflow`]: ../enum.ParseError.html#variant.Overflow
    pub fn new<T: Int>(value: T, unit: Unit) -> Result<Bytes<T>, ParseError> {
        let unit_size = unit.size::<T>()?;
        let size = value.checked_mul(unit_size).ok_or(ParseError::Overflow)?;

        Ok(Bytes(size))
    }
}

impl<T: Int> Bytes<T> {
    /// return inner value of Bytes
    pub fn size(&self) -> T {
        return self.0;
    }
}

impl<T: Int> FromStr for Bytes<T> {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let input = s.trim();
        if input.is_empty() {
            return Err(ParseError::EmptyInput);
        }

        let unit_index = input
            .chars()
            .position(|c| c.is_alphabetic() || c.is_whitespace())
            .unwrap_or(input.len());

        if unit_index == 0 {
            return Err(ParseError::MissingValue);
        }

        let (vstr, ustr) = input.split_at(unit_index);
        let unit = ustr.trim().to_lowercase().parse()?;
        let value = vstr.parse::<T>().or(Err(ParseError::InvalidValue))?;

        Bytes::new(value, unit)
    }
}

#[cfg(test)]
mod tests;
