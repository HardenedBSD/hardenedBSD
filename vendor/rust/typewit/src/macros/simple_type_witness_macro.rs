/// Declares a [type witness](crate#what-are-type-witnesses) enum.
/// 
#[doc = explain_type_witness!()]
/// 
/// [**examples below**](#examples)
/// 
/// # Generated items
/// 
/// This macro always generates:
/// 
/// - An enum with tuple variants, each of which has a single [`TypeEq`] field.
/// 
/// - Impls of [`Copy`] and [`Clone`] for the enum.
/// 
/// - An impl of [`TypeWitnessTypeArg`] for the enum.
/// 
/// - An impl of [`MakeTypeWitness`] for each variant of the enum.
/// 
/// Additional trait impls are generated when the [`derive(...)`](#derive) syntax is used.
/// 
/// ### Derivation
/// 
/// These impls are generated if you opt into them with the [`derive(...)`](#derive) syntax:
/// 
/// - `Debug`
/// - `PartialEq`
/// - `Eq`
/// - `PartialOrd`
/// - `Ord`
/// - `Hash`
/// 
/// As opposed to `#[derive(...))]`-generated implementations,
/// these impls don't require type parameters to implement the derived trait.
/// 
/// This macro always implements `Copy` and `Clone` for the declared type witness,
/// `derive(Copy, Clone)` does nothing.
/// 
/// # Syntax
/// 
/// This macro takes an enum-like syntax:
/// ```text
///     $(#[$enum_meta:meta])*
///     $(derive($($derive:ident),* $(,)?)))?
///     $vis:vis enum $enum:ident $(<$($generics:generics_param),* $(,)?>)? 
///     $(where $($where:where_predicate),* $(,)? )?
///     {
///         $(
///             $(#[$variant_meta:meta])*
///             $variant:ident $(<$($var_gen_args:generic_arg)*>)?
///             // additional bounds for the MakeTypeWitness impl that constructs this variant.
///             $(where $($vari_where:where_predicate)*)?
///             // the type that this variant requires the 
///             // implicit `__Wit` type parameter to be.
///             = $witnessed_ty:ty
///         ),*
///         $(,)?
///     }
/// ```
/// 
/// <span id = "var_gen_args-param"></span> `<$($var_gen_args:generic_arg)*>`
/// (optional parameter)[(example usage)](#var_gen_args-example): 
/// this parameter overrides the generic arguments of the enum in its 
/// [`MakeTypeWitness`] implementation.
/// 
/// <span id = "derive"></span>
/// `derive($($derive:ident),* $(,)?)`(optional parameter)[(example)](#derive-example):
/// supports deriving the traits listed in the [derivation](#derivation) section
/// 
/// `#[cfg(...)]` attributes on variants are copied to their respective 
/// [`MakeTypeWitness`] impls.
/// 
/// Generic parameters support the `#[cfg(...)]` attribute, 
/// no other attribute is supported.
/// 
/// Defaults for generic parameters are only used 
/// as the default value of [`$var_gen_args`](#var_gen_args-param)
/// [(example usage)](#var_gen_args-example) .
/// 
/// <details>
/// <summary>
/// <b>Soft-deprecated older syntax</b>
/// </summary>
/// 
/// This macro originally required the following syntax,
/// which is soft-deprecated, and will be supported for the rest of `"1.*"` versions.
/// 
/// ```text
///     $(#[$enum_meta:meta])*
///     // Allows deriving some traits without the bounds that 
///     // standard derives add to type parameters.
///     $(derive($($derive:ident),* $(,)?)))?
///     $vis:vis enum $enum:ident $([$($generics:tt)*])? 
///     // The where clause of the enum
///     $(where[$($where:tt)*])?
///     {
///         $(
///             $(#[$variant_meta:meta])*
///             $variant:ident $([$($var_gen_args:tt)*])?
///             // additional bounds for the MakeTypeWitness impl that constructs this variant.
///             $(where[$($vari_where:tt)*])?
///             // the type this variant requires the implicit `__Wit` type parameter to be.
///             = $witnessed_ty:ty
///         ),*
///         $(,)?
///     }
/// ```
/// 
/// </details>
/// 
/// ### Limitations
/// 
/// <span id = "const-parameter-limitation"></span>
/// When used in Rust versions prior to 1.59.0,
/// type witnesses declared with this macro cannot have const parameters,
/// because this macro always adds a `__Wit` type parameter after all generic parameters,
/// and those old versions don't allow type parameters after const parameters.
/// 
/// # Examples
/// 
/// ### Basic
/// 
/// This example demonstrates a basic usage of this macro
/// 
/// ```rust
/// use typewit::MakeTypeWitness;
/// 
/// assert_eq!(do_it(1), 1);
/// assert_eq!(do_it(2), 4);
/// assert_eq!(do_it(3), 9);
/// assert_eq!(do_it("foo"), 3);
/// assert_eq!(do_it("hello"), 5);
/// 
/// const fn do_it<'a, T>(arg: T) -> usize 
/// where
///     Witness<'a, T>: MakeTypeWitness,
/// {
///     match MakeTypeWitness::MAKE {
///         // `te` is a `TypeEq<T, u8>`, `te.to_right(arg)` goes from `T` to `u8.`
///         Witness::U8(te) => (te.to_right(arg) as usize).pow(2),
///
///         // `te` is a `TypeEq<T, &'a str>`, `te.to_right(arg)` goes from `T` to `&'a str.`
///         Witness::Str(te) => te.to_right(arg).len(),
///     }
/// }
/// 
/// typewit::simple_type_witness! {
///     // Declares an `enum Witness<'a, __Wit>`,
///     // the `__Wit` type parameter is added after all generics.
///     enum Witness<'a> {
///         // This variant requires `__Wit == u8`
///         U8 = u8,
///         // This variant requires `__Wit == &'a str`
///         Str = &'a str,
///     }
/// }
/// ```
/// the above invocation of `simple_type_witness` effectively generates this code:
/// ```rust
/// enum Witness<'a, __Wit> {
///     U8(typewit::TypeEq<__Wit, u8>),
///     Str(typewit::TypeEq<__Wit, &'a str>),
/// }
/// impl<'a, __Wit> typewit::TypeWitnessTypeArg for Witness<'a, __Wit> {
///     type Arg = __Wit;
/// }
/// impl<'a> typewit::MakeTypeWitness for Witness<'a, u8> {
///     const MAKE: Self = Self::U8(typewit::TypeEq::NEW);
/// }
/// impl<'a> typewit::MakeTypeWitness for Witness<'a, &'a str> {
///     const MAKE: Self = Self::Str(typewit::TypeEq::NEW);
/// }
/// ```
/// (consult the [generated items] section for all the generated impls)
/// 
/// ### where clauses 
/// 
/// This example demonstrates a variant with a where clause.
/// ```rust
/// # use std::fmt::Debug;
/// typewit::simple_type_witness! {
///     // Declares an `enum Witness<'a, T, __Wit>`,
///     // the `__Wit` type parameter is added after all generics.
///     #[non_exhaustive]
///     enum Witness<'a, T: 'a>
///     where 
///         T: 'a + Debug
///     {
///         // This variant requires `__Wit == T`.
///         // The `MakeTypeWitness` impl for this variant also requires `T: Copy`.
///         #[cfg(feature = "foo")]
///         Value where T: Copy = T,
///
///         // This variant requires `__Wit == &'a T`
///         Ref = &'a T,
///     }
/// }
/// ```
/// the above invocation of `simple_type_witness` effectively generates this code:
/// ```rust
/// # use core::fmt::Debug;
/// # 
/// #[non_exhaustive]
/// enum Witness<'a, T: 'a, __Wit: ?Sized>
/// where
///     T: 'a + Debug,
/// {
///     #[cfg(feature = "foo")]
///     Value(typewit::TypeEq<__Wit, T>),
/// 
///     Ref(typewit::TypeEq<__Wit, &'a T>),
/// }
/// 
/// impl<'a, T: 'a, __Wit: ?Sized> typewit::TypeWitnessTypeArg for Witness<'a, T, __Wit>
/// where
///     T: 'a + Debug,
/// {
///     type Arg = __Wit;
/// }
/// 
/// #[cfg(feature = "foo")]
/// impl<'a, T: 'a> typewit::MakeTypeWitness for Witness<'a, T, T>
/// where
///     T: 'a + Debug + Copy,
/// {
///     const MAKE: Self = Self::Value(typewit::TypeEq::NEW);
/// }
/// 
/// impl<'a, T: 'a> typewit::MakeTypeWitness for Witness<'a, T, &'a T>
/// where
///     T: 'a + Debug,
/// {
///     const MAKE: Self = Self::Ref(typewit::TypeEq::NEW);
/// }
/// ```
/// (consult the [generated items] section for all the generated impls)
/// 
/// <span id = "var_gen_args-example"></span>
/// ### `$var_gen_args` parameter
/// 
/// This example shows what the `$var_gen_args` parameter does,
/// as well as how generic parameter defaults relate to it.
/// 
/// ([this example requires Rust 1.59.0](#const-parameter-limitation))
/// 
#[cfg_attr(not(feature = "rust_1_61"), doc = "```ignore")]
#[cfg_attr(feature = "rust_1_61", doc = "```rust")]
/// typewit::simple_type_witness! {
///     // Declares an `enum Foo<T, const N: usize, __Wit>`,
///     // the `__Wit` type parameter is added after all generics.
///     //
///     // The defaults for generic parameters are only used 
///     // as the default value of the generic arguments of variants.
///     enum Foo<T = i8, const N: usize = 1234> {
///         // This variant requires `__Wit == u64`.
///         // 
///         // The `<(), 3>` here
///         // replaces `impl<T, const N: usize> MakeTypeWitness for Foo<T, N, u64>`
///         // with     `impl                    MakeTypeWitness for Foo<(), 3, u64>`.
///         // Using `<(), 3>` allows the  `T` and `N` type parameters to be inferred
///         // when the `MakeTypeWitness` impl for `Foo<_, _, u64>` is used.
///         U64<(), 3> = u64,
///         // This variant requires `__Wit == bool`.
///         // 
///         // The `<>` here uses the defaults for the generic arguments to 
///         // replace `impl<T, const N: usize> MakeTypeWitness for Foo<T, N, bool>`
///         // with    `impl                    MakeTypeWitness for Foo<i8, 1234, bool>`.
///         Bool<> = bool,
///         // This variant requires `__Wit == [T; N]`.
///         Array = [T; N],
///     }
/// }
/// ```
/// the above effectively expands to this:
#[cfg_attr(not(feature = "rust_1_61"), doc = "```ignore")]
#[cfg_attr(feature = "rust_1_61", doc = "```rust")]
/// enum Foo<T, const N: usize, __Wit: ?Sized> {
///     U64(typewit::TypeEq<__Wit, u64>),
///     Bool(typewit::TypeEq<__Wit, bool>),
///     Array(typewit::TypeEq<__Wit, [T; N]>),
/// }
/// impl<T, const N: usize, __Wit: ?Sized> typewit::TypeWitnessTypeArg for Foo<T, N, __Wit> {
///     type Arg = __Wit;
/// }
/// impl typewit::MakeTypeWitness for Foo<(), 3, u64> {
///     const MAKE: Self = Self::U64(typewit::TypeEq::NEW);
/// }
/// impl typewit::MakeTypeWitness for Foo<i8, 1234, bool> {
///     const MAKE: Self = Self::Bool(typewit::TypeEq::NEW);
/// }
/// impl<T, const N: usize> typewit::MakeTypeWitness for Foo<T, N, [T; N]> {
///     const MAKE: Self = Self::Array(typewit::TypeEq::NEW);
/// }
/// ```
/// (consult the [generated items] section for all the generated impls)
/// 
/// <span id = "derive-example"></span>
/// ### Derives
/// 
/// This example demonstrates derivation of all the supported traits 
/// using the `derive(...)` syntax (as opposed to the `#[derive(...)]` attribute).
/// 
/// ```rust
/// use typewit::{MakeTypeWitness, TypeEq};
/// 
/// struct NoImpls;
///
/// assert_eq!(Witness::<u8>::MAKE, Witness::<u8>::MAKE);
/// 
/// // Witness doesn't require its type parameters to impl any traits in its derives.
/// // The standard derives require that type parameters impl the derived trait,
/// // so this comparison wouldn't work (because `NoImpls` doesn't impl `PartialEq`).
/// assert_eq!(Witness::<NoImpls>::MAKE, Witness::NoImp(TypeEq::NEW));
/// 
/// typewit::simple_type_witness! {
///     // Declares an `enum Witness<__Wit>`,
///     // the `__Wit` type parameter is added after all generics.
///     derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)
///     enum Witness {
///         U8 = u8,
///         NoImp = NoImpls,
///     }
/// }
/// ```
/// 
/// 
/// [`TypeEq`]: crate::TypeEq
/// [`TypeWitnessTypeArg`]: crate::TypeWitnessTypeArg
/// [`MakeTypeWitness`]: crate::MakeTypeWitness
/// [generated items]: #generated-items
#[macro_export]
macro_rules! simple_type_witness {
    (
        $(#[$enum_meta:meta])*
        $(derive($($derive:ident),* $(,)?))?
        $(pub $(($($pub:tt)*))?)? 
        enum $enum:ident $($rem:tt)*
    ) => {
        $crate::__parse_generics!{
            ($crate::__stw_with_parsed_generics!(
                (
                    $(#[$enum_meta])*
                    derive($($($derive)*)?)
                    $(pub $(($($pub)*))? )? 
                    enum $enum
                )
                $enum
            ))
            [$($rem)*]
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __stw_with_parsed_generics {
    (
        ($($prev_args:tt)*)
        $enum:ident

        [$(($gen_arg:tt ($($gen_phantom:tt)*) $( = $($gen_def:tt)* )? ))*]
        [$(($($generics:tt)*))*]
        $deleted_markers:tt

        $($rem:tt)*
    ) => {
        $crate::__parse_where_clause_for_item! {
            ($crate::__stw_with_parsed_where ! (
                (
                    $($prev_args)*
                    [$($($generics)*,)*]
                    [ $($gen_arg,)* ]
                )
                [
                    $enum
                    [
                        $((
                            ( $(($($gen_def)*))? ($gen_arg) )
                            ( $(($($gen_def)*))? [$gen_arg] )
                        ))*
                    ]
                ]
            ))
            $($rem)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __stw_with_parsed_where {
    (
        ($($prev_args:tt)*)
        $vari_vars:tt

        $where_clause:tt

        {$($variants:tt)*}
    ) => {
        $crate::__::__stw_parse_variants!{
            ($($prev_args)* where $where_clause)
            $vari_vars
            []
            [$($variants)*]
        }
    }
}


macro_rules! declare__stw_parse_variants {
    ($_:tt ($($vari_params:tt)*) ($($vari_output:tt)*) $variant_:ident) => {
        #[doc(hidden)]
        #[macro_export]
        macro_rules! __stw_parse_variants_ {
            (
                ($_($fixed:tt)*) 
                $vari_vars:tt 
                // fast path for enums with no attributes on variants other than docs
                [$_(($variant:ident ($_(#[doc $_($docs:tt)*])*) $_($rem_vari:tt)*))*] 
                [$_(,)*]
            )=>{
                $crate::__stw_with_parsed_args! {
                    $_($fixed)*
                    { $_(($variant ($_(#[doc $_($docs)*])*) $_($rem_vari)*))* }
                }
            };
            (
                $fixed:tt
                $vari_vars:tt
                [
                    ($pvariant:ident ($_($pattrs:tt)*) $_($prem:tt)*)
                    $_($variants:tt)*
                ]
                [$_(,)*]
            )=>{
                $crate::__stw_parse_variants_attrs!{
                    $fixed
                    [/*prev variants*/] [ ($pvariant ($_($pattrs)*) $_($prem)*) $_($variants)*]
                    [/*prev attrs of variant*/] [/*prev cfgs of variant*/] [$_($pattrs)*]
                }
            };
            (
                $fixed:tt
                $vari_vars:tt
                [$_($prev:tt)*]
                [$($vari_params)* = $var_type:ty $_(, $_($rem:tt)*)?]
            )=>{
                $crate::__::__stw_parse_variants!{
                    $fixed
                    $vari_vars
                    // The four token trees in the parentheses here are:
                    // (
                    //      variant_name 
                    //      ($($attributes:tt)*)
                    //      (replacement_for_Self)
                    //      [where_clause_for_variant]
                    //      withnessed_type
                    // )
                    [$_($prev)* ($($vari_output)* () [] $var_type)]
                    [$_($_($rem)*)?]
                }
            };
            (
                $fixed:tt 
                [$enum:ident $gen_with_defs:tt]
                $prev:tt
                [$($vari_params)* < $_($rem:tt)*]
            )=>{
                $crate::__::__parse_generic_args_with_defaults! {
                    (
                        (
                            ($crate::__stw_parse_variant_Self_ty!(
                                $fixed
                                [$enum $gen_with_defs]
                                $prev
                                ($($vari_output)*)
                            ))

                            $crate::__::concat!(
                                "`",
                                $crate::__::stringify!($_ $variant_), 
                                "` variant",
                            )
                        )
                        []
                        $gen_with_defs
                    )
                    []
                    []
                    [$_($rem)*]
                }
            };
            (
                $fixed:tt
                [$enum:ident $gen_with_defs:tt]
                $prev:tt
                [$($vari_params)* [$_($SelfArgs:tt)*] $_($rem:tt)*]
            )=>{
                $crate::__::__parse_generic_args_with_defaults! {
                    (
                        (
                            ($crate::__stw_parse_variant_Self_ty!(
                                $fixed
                                [$enum $gen_with_defs]
                                $prev
                                ($($vari_output)*)
                            ))

                            $crate::__::concat!(
                                "`",
                                $crate::__::stringify!($_ $variant_), 
                                "` variant",
                            )
                        )
                        []
                        $gen_with_defs
                    )
                    []
                    []
                    [$_($SelfArgs)* > $_($rem)*]
                }
            };
            ($fixed:tt $vari_vars:tt $prev:tt [$($vari_params)* where $_($rem:tt)*])=>{
                $crate::__parse_where_clause_for_item!{
                    ($crate::__stw_parsed_variant_with_where_clause!(
                        $fixed $vari_vars $prev [$($vari_output)* ()]
                    ))
                    where $_($rem)*
                }
            };
        }
    };
}

declare__stw_parse_variants!{
    $
    ($(#[$($vari_attr:tt)*])* $variant:ident)
    ($variant ($(#[$($vari_attr)*])*))
    variant
}

pub use __stw_parse_variants_ as __stw_parse_variants;


#[doc(hidden)]
#[macro_export]
macro_rules! __stw_parse_variants_attrs {
    (
        ($($fixed:tt)*) 
        [$($variants:tt)*] []
        [] [] []
    )=>{
        $crate::__stw_with_parsed_args! {
            $($fixed)*
            { $($variants)* }
        }
    };
    (
        $fixed:tt
        $prev_vari:tt $next_vari:tt
        $prev_attrs:tt [$($prev_cfgs:tt)*] [#[cfg($($cfg:tt)*)] $($rest_attrs:tt)*]
    ) => {
        $crate::__stw_parse_variants_attrs! {
            $fixed
            $prev_vari $next_vari
            $prev_attrs [$($prev_cfgs)* ($($cfg)*)] [$($rest_attrs)*]
        }
    };
    (
        $fixed:tt
        $prev_vari:tt $next_vari:tt
        [$($prev_attrs:tt)*] $prev_cfgs:tt [#[$($attr:tt)*] $($rest_attrs:tt)*]
    ) => {
        $crate::__stw_parse_variants_attrs! {
            $fixed
            $prev_vari $next_vari
            [$($prev_attrs)* #[$($attr)*]] $prev_cfgs [$($rest_attrs)*]
        }
    };
    // none of the attributes of the variant were cfg
    (
        $fixed:tt
        [$($prev_vari:tt)*] 
        [   
            $curr_vari:tt 
            $(
                ($nvariant:ident ($($nattrs:tt)*) $($nrem:tt)*) 
                $($rem_vari:tt)*
            )?
        ]
        $prev_attrs:tt [] []
    ) => {
        $crate::__stw_parse_variants_attrs! {
            $fixed
            [$($prev_vari)* $curr_vari] [
                $(($nvariant ($($nattrs)*) $($nrem)*)  $($rem_vari)*)?
            ]
            [] [] [$($($nattrs)*)?]
        }
    };
    // some of the attributes of the variant were cfg
    (
        $fixed:tt
        [$($prev_vari:tt)*] 
        [   
            ($cvariant:ident $__cattrs:tt $($crem:tt)*) 
            $(
                ($nvariant:ident ($($nattrs:tt)*) $($nrem:tt)*) 
                $($rem_vari:tt)*
            )?
        ]
        [$($prev_attrs:tt)*] [$(($($cfg:tt)*))+] []
    ) => {
        #[cfg(all($($($cfg)*)+))]
        $crate::__stw_parse_variants_attrs! {
            $fixed
            [$($prev_vari)* ($cvariant ($($prev_attrs)*) $($crem)*) ] [
                $(($nvariant ($($nattrs)*) $($nrem)*)  $($rem_vari)*)?
            ]
            [] [] [$($($nattrs)*)?]
        }

        #[cfg(not(all($($($cfg)*)+)))]
        $crate::__stw_parse_variants_attrs! {
            $fixed
            [$($prev_vari)*] [
                $(($nvariant ($($nattrs)*) $($nrem)*)  $($rem_vari)*)?
            ]
            [] [] [$($($nattrs)*)?]
        }
    };
} 


#[doc(hidden)]
#[macro_export]
macro_rules! __stw_parse_variant_Self_ty {
    (
        $fixed:tt
        [$enum:ident $($rem_vars:tt)*]
        $prev:tt 
        ($($vari_prev:tt)*) 
        [$($SelfTy:tt)*] 
        where $($rem:tt)*
    )=>{
        $crate::__parse_where_clause_for_item!{
            ($crate::__stw_parsed_variant_with_where_clause!(
                $fixed 
                [$enum $($rem_vars)*]
                $prev 
                [$($vari_prev)* ($enum < $($SelfTy)*)]
            ))
            where $($rem)*
        }
    };
    (
        $fixed:tt
        [$enum:ident $($rem_vars:tt)*]
        [$($prev:tt)*] 
        ($($vari_prev:tt)*)
        [$($SelfTy:tt)*] 
        = $var_type:ty 
        $(, $($rem:tt)*)?
    )=>{
        $crate::__::__stw_parse_variants!{
            $fixed
            [$enum $($rem_vars)*]
            [$($prev)* ($($vari_prev)* ($enum < $($SelfTy)*) [] $var_type)]
            [$($($rem)*)?]
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __stw_parsed_variant_with_where_clause {
    (
        $fixed:tt
        $vari_vars:tt
        [$($prev:tt)*] 
        [$($vari_prev:tt)*]
        $where_clause:tt
        = $var_type:ty $(, $($rem:tt)*)?
    ) => {
        $crate::__::__stw_parse_variants!{
            $fixed
            $vari_vars
            [$($prev)* ($($vari_prev)* $where_clause $var_type)]
            [$($($rem)*)?]
        }
    }
}


#[doc(hidden)]
#[macro_export]
macro_rules! __stw_with_parsed_args {
    (
        $(# $enum_meta:tt)*
        derive $derive:tt
        $vis:vis enum $enum:ident $generics:tt $gen_args:tt
        where $where:tt
        { $($variant_args:tt)* }
    ) => {
        $crate::__stw_top_items!{
            $(# $enum_meta)*
            $vis enum $enum $generics $gen_args
            where $where

            { $($variant_args)* }
        }

        $crate::__stw_derive_dispatcher!{
            derive $derive
            enum $enum $generics $gen_args
            where $where
            { $($variant_args)* }
        }

        $(
            $crate::__stw_make_type_witness_impl!{
                $enum $generics $gen_args
                where $where
                $variant_args
            }
        )*
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __stw_top_items {
    (
        $(# $enum_meta:tt)*
        $vis:vis enum $enum:ident[$($generics:tt)*] [$($gen_args:tt)*]
        where [$($where:tt)*]

        {
            $((
                $variant:ident
                ($(#[$variant_meta:meta])*)
                ($($SelfTy:tt)*)
                $vari_where:tt
                $witnessed_ty:ty
            ))*
        }
    ) => {
        $(#$enum_meta)*
        $vis enum $enum <$($generics)* __Wit: ?Sized> 
        where $($where)*
        {
            $(
                $(#[$variant_meta])*
                $variant($crate::TypeEq<__Wit, $witnessed_ty>),
            )*
        }

        impl<$($generics)* __Wit: ?Sized> $crate::__::Copy for $enum<$($gen_args)* __Wit> 
        where $($where)*
        {}

        impl<$($generics)* __Wit: ?Sized> $crate::__::Clone for $enum<$($gen_args)* __Wit> 
        where $($where)*
        {
            fn clone(&self) -> Self {
                *self
            }
        }

        impl<$($generics)* __Wit: ?Sized> 
            $crate::TypeWitnessTypeArg 
        for $enum<$($gen_args)* __Wit> 
        where $($where)*
        {
            type Arg = __Wit;
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __stw_derive_dispatcher {
    (
        derive($($trait:ident)*)
        enum $enum:ident $generics:tt $gen_args:tt
        where $where:tt
        $variant_args:tt
    ) => {
        $(
            $crate::__stw_derive_dispatcher_inner!{
                $trait
                $enum $generics $gen_args
                where $where
                $variant_args
            }
        )*
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __stw_derive_dispatcher_inner {
    (
        $trait:ident $enum:ident[$($generics:tt)*] [$($gen_args:tt)*]
        where [$($where:tt)*]
        {$(($variant:ident $($rem:tt)*))*}
    ) => {
        $crate::__stw_single_derive!{
            (
                impl<$($generics)* __Wit: ?Sized> $enum<$($gen_args)* __Wit> 
                where
                    $($where)*
            )
            (
                impl<$($generics)* __Wit: ?Sized> 
                    $crate::__::$trait 
                for $enum<$($gen_args)* __Wit> 
                where
                    $($where)*
            )
            $trait
            [$($variant)*]
        }
    }
}

#[doc(hidden)]
#[macro_export]
macro_rules! __stw_single_derive {
    ($inh_header:tt ($($impl_header:tt)*) Debug [$($variant:ident)*]) => {
        $($impl_header)*
        {
            fn fmt(&self, f: &mut $crate::__::Formatter<'_>) -> $crate::__::FmtResult {
                f.write_str(match self {
                    $(Self::$variant{..} => stringify!($variant),)*
                })
            }
        }
    };
    ($inh_header:tt ($($impl_header:tt)*) PartialEq [$($variant:ident)*]) => {
        $($impl_header)*
        {
            fn eq(&self, other: &Self) -> $crate::__::bool {
                $crate::__::discriminant(self) == $crate::__::discriminant(other)
            }
        }
    };
    (($($inh_header:tt)*) ($($impl_header:tt)*) PartialOrd [$($variant:ident)*]) => {
        $($inh_header)* {
            const fn __variant_number(&self) -> usize {
                mod number {
                    enum __Number__ {
                        $($variant,)*
                    }
                    $( pub const $variant: $crate::__::usize = __Number__::$variant as _; )*
                }

                match self {
                    $(Self::$variant{..} => number::$variant,)*
                }
            }
        }

        $($impl_header)* {
            fn partial_cmp(&self, other: &Self) -> $crate::__::Option<$crate::__::Ordering> {
                $crate::__::PartialOrd::partial_cmp(
                    &self.__variant_number(),
                    &other.__variant_number(),
                )
            }
        }
    };
    ($inh_header:tt ($($impl_header:tt)*) Ord [$($variant:ident)*]) => {
        $($impl_header)* {
            fn cmp(&self, other: &Self) -> $crate::__::Ordering {
                $crate::__::Ord::cmp(
                    &self.__variant_number(),
                    &other.__variant_number(),
                )
            }
        }
    };
    ($inh_header:tt ($($impl_header:tt)*) Eq [$($variant:ident)*]) => {
        $($impl_header)* { }
    };
    ($inh_header:tt ($($impl_header:tt)*) Hash [$($variant:ident)*]) => {
        $($impl_header)* {
            fn hash<H: $crate::__::Hasher>(&self, state: &mut H) {
                $crate::__::Hash::hash(&$crate::__::discriminant(self), state)
            }
        }
    };
    // this is always implemented
    ($inh_header:tt $impl_header:tt Copy $variants:tt) => {};
    // this is always implemented
    ($inh_header:tt $impl_header:tt Clone $variants:tt) => {};
    ($inh_header:tt $impl_header:tt $derive:ident $variants:tt) => {
        $crate::__::compile_error!{$crate::__::concat!{
            "The `simple_type_witness` macro does not support deriving `",
            $crate::__::stringify!($derive),
            "`.\n",
            "help: You could try using `#[derive(", 
            $crate::__::stringify!($derive),
            ")]`.",
        }}
    };
}


#[doc(hidden)]
#[macro_export]
macro_rules! __stw_make_type_witness_impl {
    (
        $enum:ident[$($generics:tt)*] [$($gen_args:tt)*]
        where [$($where:tt)*]

        (
            $variant:ident
            $attrs:tt
            ($( $($SelfTy:tt)+ )?)
            [$($vari_where:tt)*]
            $witnessed_ty:ty
        )
    ) => {
        $crate::__impl_with_span! {
            $variant // span
            () // attributes on impl block
            ( <$($generics)* __Wit: ?Sized> $crate::MakeTypeWitness )
            // for
            (
                $crate::__first_ty!(
                    $($($SelfTy)+ $witnessed_ty>,)? 
                    $enum<$($gen_args)* $witnessed_ty>,
                ) 
            )
            (
                where
                    Self: $crate::__::Identity<Type = $enum<$($gen_args)* __Wit>>,
                    $($where)*
                    $($vari_where)*
            )
            (
                const MAKE: Self = Self::$variant($crate::TypeEq::NEW);
            )
        }
    }
}


#[doc(hidden)]
#[macro_export]
macro_rules! __first_ty {
    ($first:ty, $($rem:tt)*) => {
        $first
    }
}
