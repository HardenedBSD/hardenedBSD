//! Handling non-zero literal values.

use super::NonZeroAble;

/// A representation of a non-zero literal. Used by the [`nonzero!`] macro.
///
/// This struct has no use outside of this macro (even though it can be constructed by anyone).
/// It needs to exist to support the use of the [`nonzero!`] macro in const expressions.
pub struct NonZeroLiteral<T: NonZeroAble>(pub T);
