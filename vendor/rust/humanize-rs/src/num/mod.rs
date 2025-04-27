//! This module provides some numeric traits used in parsing.
//!
//!

use std::mem::size_of;
#[cfg(has_i128)]
use std::{i128, u128};
use std::{i16, i32, i64, i8, isize, u16, u32, u64, u8, usize};

mod checked;
pub use self::checked::*;

use std::str::FromStr;

/// Represents the integer trait
pub trait Int: Sized + Copy + FromStr + CheckedMul {
    /// Returns a value from given u64 num
    fn from_u64(n: u64) -> Option<Self>;
}

macro_rules! impl_int {
    ($dst:ident) => {
        impl Int for $dst {
            fn from_u64(n: u64) -> Option<$dst> {
                let max = $dst::MAX as u64;
                if size_of::<u64>() < size_of::<$dst>() || n <= max {
                    Some(n as $dst)
                } else {
                    None
                }
            }
        }
    };
}

impl_int!(i8);
impl_int!(u8);

impl_int!(i16);
impl_int!(u16);

impl_int!(i32);
impl_int!(u32);

impl_int!(i64);
impl_int!(u64);

impl_int!(isize);
impl_int!(usize);

#[cfg(has_i128)]
impl_int!(i128);
#[cfg(has_i128)]
impl_int!(u128);

#[cfg(test)]
mod tests;
