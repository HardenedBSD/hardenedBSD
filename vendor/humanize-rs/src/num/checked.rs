use std::ops::Mul;

// Performs multiplication that returns `None` instead of wrapping around on underflow or
/// overflow.
pub trait CheckedMul: Copy + Sized + Mul<Self, Output = Self> {
    /// Multiplies two numbers, checking for underflow or overflow. If underflow
    /// or overflow happens, `None` is returned.
    fn checked_mul(self, rhs: Self) -> Option<Self>;
}

macro_rules! impl_checked_mul {
    ($T:ty) => {
        impl CheckedMul for $T {
            fn checked_mul(self, rhs: $T) -> Option<$T> {
                <$T>::checked_mul(self, rhs)
            }
        }
    };
}

impl_checked_mul!(i8);
impl_checked_mul!(u8);
impl_checked_mul!(i16);
impl_checked_mul!(u16);
impl_checked_mul!(i32);
impl_checked_mul!(u32);
impl_checked_mul!(i64);
impl_checked_mul!(u64);
impl_checked_mul!(isize);
impl_checked_mul!(usize);

#[cfg(has_i128)]
impl_checked_mul!(i128);
#[cfg(has_i128)]
impl_checked_mul!(u128);
