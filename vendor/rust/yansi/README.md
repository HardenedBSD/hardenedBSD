# yansi

[![Build Status](https://travis-ci.org/SergioBenitez/yansi.svg?branch=master)](https://travis-ci.org/SergioBenitez/yansi)
[![Current Crates.io Version](https://img.shields.io/crates/v/yansi.svg)](https://crates.io/crates/yansi)
[![Documentation](https://docs.rs/yansi/badge.svg)](https://docs.rs/yansi)

A dead simple ANSI terminal color painting library for Rust.

```rust
use yansi::Paint;

print!("{} light, {} light!", Paint::green("Green"), Paint::red("red").underline());
```

See the [documentation](https://docs.rs/yansi/) for more.

# Why?

Several terminal coloring libraries exist ([`ansi_term`], [`colored`],
[`term_painter`], to name a few), begging the question: why yet another? Here
are a few reasons:

  * This library is _much_ simpler: there are three types!
  * Unlike [`ansi_term`] or [`colored`], _any_ type implementing `Display`
    or `Debug` can be stylized, not only strings.
  * Styling can be enabled and disabled globally, on the fly.
  * Arbitrary items can be [_masked_] for selective disabling.
  * Styling can [_wrap_] any arbitrarily styled item.
  * Typically only one type needs to be imported: `Paint`.
  * Zero dependencies. It really is simple.
  * The name `yansi` is pretty short.

All that being said, this library borrows API ideas from the three libraries as
well as implementation details from [`ansi_term`].

[`ansi_term`]: https://crates.io/crates/ansi_term
[`colored`]: https://crates.io/crates/colored
[`term_painter`]: https://crates.io/crates/term-painter
[_masked_]: https://docs.rs/yansi/#masking
[_wrap_]: https://docs.rs/yansi/#wrapping

## License

`yansi` is licensed under either of the following, at your option:

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT License ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
