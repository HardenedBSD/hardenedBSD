macro_rules! style_builder_for {
    ($T:ty, |$s:ident| $props:expr, $($name:ident: $property:ident),*) => ($(
        #[doc = concat!(
            "Enables the _", stringify!($name), "_ style on `self`.\n",
            "```rust\n",
            "use yansi::Paint;\n",
            "\n",
            "println!(\"Using ", stringify!($name), ": {}\", ",
                "Paint::new(\"hi\").", stringify!($name), "());\n",
            "```\n"
        )]
        #[inline]
        pub fn $name(self) -> $T {
            let mut $s = self;
            $props.set(Property::$property);
            $s
        }
    )*)
}
