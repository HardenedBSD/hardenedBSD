use crate::{
    const_marker::Bool,
    TypeCmp,
    TypeEq,
    TypeWitnessTypeArg, MakeTypeWitness,
};



/// Type Witness that [`Bool<B>`](Bool) is either `Bool<true>` or `Bool<false>`.
/// 
/// # Example
/// 
/// Making a function that takes a generic `Foo<B>` and calls methods on 
/// `Foo<false>` or `Foo<true>` depending on the value of the `const B: bool` parameter.
/// 
/// ```rust
/// use typewit::{const_marker::{Bool, BoolWit}, MakeTypeWitness};
/// 
/// 
/// assert_eq!(call_next(Incrementor::<GO_UP>(4)), Incrementor(5));
/// assert_eq!(call_next(Incrementor::<GO_UP>(5)), Incrementor(6));
/// 
/// assert_eq!(call_next(Incrementor::<GO_DOWN>(4)), Incrementor(3));
/// assert_eq!(call_next(Incrementor::<GO_DOWN>(3)), Incrementor(2));
/// 
/// 
/// const fn call_next<const B: bool>(incrementor: Incrementor<B>) -> Incrementor<B> {
///     typewit::type_fn! {
///         // type-level function from `Bool<B>` to `Incrementor<B>`
///         struct IncrementorFn;
///         impl<const B: bool> Bool<B> => Incrementor<B>
///     }
/// 
///     // The example below this one shows how to write this match more concisely
///     match BoolWit::MAKE {
///         // `bw: TypeEq<Bool<B>, Bool<true>>`
///         BoolWit::True(bw) => {
///             // `te: TypeEq<Incrementor<B>, Incrementor<true>>`
///             let te = bw.project::<IncrementorFn>();
/// 
///             // `te.to_right` casts `Incrementor<B>` to `Incrementor<true>`,
///             // (this allows calling the inherent method).
///             // 
///             // `te.to_left` casts `Incrementor<true>` to `Incrementor<B>`
///             te.to_left(te.to_right(incrementor).next())
///         }
///         // `bw: TypeEq<Bool<B>, Bool<false>>`
///         BoolWit::False(bw) => {
///             // `te: TypeEq<Incrementor<B>, Incrementor<false>>`
///             let te = bw.project::<IncrementorFn>();
/// 
///             // like the other branch, but with `Incrementor<false>`
///             te.to_left(te.to_right(incrementor).next())
///         }
///     }
/// }
/// 
/// 
/// #[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// struct Incrementor<const GO_UP: bool>(usize);
/// 
/// const GO_UP: bool = true;
/// const GO_DOWN: bool = false;
/// 
/// impl Incrementor<GO_DOWN> {
///     #[track_caller]
///     pub const fn next(self) -> Self {
///         Self(self.0 - 1)
///     }
/// }
/// 
/// impl Incrementor<GO_UP> {
///     pub const fn next(self) -> Self {
///         Self(self.0 + 1)
///     }
/// }
/// 
/// ```
/// 
/// ### Using `polymatch` for conciseness
/// 
/// The [`polymatch`](crate::polymatch) macro can be used to 
/// more concisely implement the `call_next` function.
/// 
/// ```
/// # use typewit::{const_marker::{Bool, BoolWit}, MakeTypeWitness};
/// # 
/// const fn call_next<const B: bool>(incrementor: Incrementor<B>) -> Incrementor<B> {
///     typewit::type_fn! {
///         struct IncrementorFn;
///         impl<const B: bool> Bool<B> => Incrementor<B>
///     }
/// 
///     // expands to a match with two arms, 
///     // one for `BoolWit::True` and one for `BoolWit::False`,
///     // copying the expression to the right of the `=>` to both arms.
///     typewit::polymatch! {BoolWit::MAKE;
///         BoolWit::True(bw) | BoolWit::False(bw) => {
///             let te = bw.project::<IncrementorFn>();
///             te.to_left(te.to_right(incrementor).next())
///         }
///     }
/// }
/// # 
/// # #[derive(Debug, Copy, Clone, PartialEq, Eq)]
/// # struct Incrementor<const GO_UP: bool>(usize);
/// # 
/// # const GO_UP: bool = true;
/// # const GO_DOWN: bool = false;
/// # 
/// # impl Incrementor<GO_DOWN> {
/// #     #[track_caller]
/// #     pub const fn next(self) -> Self { unimplemented!() }
/// # }
/// # 
/// # impl Incrementor<GO_UP> {
/// #     pub const fn next(self) -> Self { unimplemented!() }
/// # }
/// ```
/// 
/// ### What happens without `BoolWit`
/// 
/// If the `call_next` function was defined like this:
/// ```rust,compile_fail
/// # use typewit::{const_marker::{Bool, BoolWit}, MakeTypeWitness};
/// # 
/// const fn call_next<const B: bool>(incrementor: Incrementor<B>) -> Incrementor<B> {
///     incrementor.next()
/// }
/// # #[derive(Copy, Clone)]
/// # struct Incrementor<const WRAPPING: bool>(usize);
/// # 
/// # impl Incrementor<false> {
/// #     pub const fn next(self) -> Self {
/// #         unimplemented!()
/// #     }
/// # }
/// # 
/// # impl Incrementor<true> {
/// #     pub const fn next(self) -> Self {
/// #         unimplemented!()
/// #     }
/// # }
/// ```
/// it would produce this error
/// ```text
/// error[E0599]: no method named `next` found for struct `Incrementor<B>` in the current scope
///   --> src/const_marker/const_witnesses.rs:20:17
///    |
/// 7  |     incrementor.next()
///    |                 ^^^^ method not found in `Incrementor<B>`
/// ...
/// 38 | struct Incrementor<const WRAPPING: bool>(usize);
///    | ---------------------------------------- method `next` not found for this struct
///    |
///    = note: the method was found for
///            - `Incrementor<false>`
///            - `Incrementor<true>`
/// ```
/// 
/// 
pub enum BoolWit<const B: bool> {
    /// Witnesses that `B == true`
    True(TypeEq<Bool<B>, Bool<true>>),
    /// Witnesses that `B == false`
    False(TypeEq<Bool<B>, Bool<false>>),
}

impl<const B: bool> TypeWitnessTypeArg for BoolWit<B> {
    type Arg = Bool<B>;
}

impl<const B: bool> MakeTypeWitness for BoolWit<B> {
    const MAKE: Self = {
        if let TypeCmp::Eq(te) = Bool.equals(Bool) {
            BoolWit::True(te)
        } else if let TypeCmp::Eq(te) = Bool.equals(Bool) {
            BoolWit::False(te)
        } else {
            panic!("unreachable: `B` is either `true` or `false`")
        }
    };
}

