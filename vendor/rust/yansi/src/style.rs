use std::hash::{Hash, Hasher};
use std::fmt::{self, Display};
use std::ops::BitOr;

use {Paint, Color};

#[derive(Default, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Copy, Clone)]
pub struct Property(u8);

impl Property {
    pub const BOLD: Self = Property(1 << 0);
    pub const DIMMED: Self = Property(1 << 1);
    pub const ITALIC: Self = Property(1 << 2);
    pub const UNDERLINE: Self = Property(1 << 3);
    pub const BLINK: Self = Property(1 << 4);
    pub const INVERT: Self = Property(1 << 5);
    pub const HIDDEN: Self = Property(1 << 6);
    pub const STRIKETHROUGH: Self = Property(1 << 7);

    #[inline(always)]
    pub fn contains(self, other: Property) -> bool {
        (other.0 & self.0) == other.0
    }

    #[inline(always)]
    pub fn set(&mut self, other: Property) {
        self.0 |= other.0;
    }

    #[inline(always)]
    pub fn iter(self) -> Iter {
        Iter { index: 0, properties: self }
    }
}

impl BitOr for Property {
    type Output = Self;

    #[inline(always)]
    fn bitor(self, rhs: Self) -> Self {
        Property(self.0 | rhs.0)
    }
}

pub struct Iter {
    index: u8,
    properties: Property,
}

impl Iterator for Iter {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < 8 {
            let index = self.index;
            self.index += 1;

            if self.properties.contains(Property(1 << index)) {
                return Some(index as usize);
            }
        }

        None
    }
}

/// Represents a set of styling options.
///
/// See the [crate level documentation](./) for usage information.
///
/// # Method Glossary
///
/// The `Style` structure exposes many methods for convenience. The majority of
/// these methods are shared with [`Paint`](Paint).
///
/// ### Foreground Color Constructors
///
/// Return a new `Style` structure with a foreground `color` applied.
///
///   * [`Style::new(color: Color)`](Style::new())
///
/// ### Setters
///
/// Set a style property on a given `Style` structure.
///
///   * [`style.fg(color: Color)`](Style::fg())
///   * [`style.bg(color: Color)`](Style::bg())
///   * [`style.mask()`](Style::mask())
///   * [`style.wrap()`](Style::wrap())
///   * [`style.bold()`](Style::bold())
///   * [`style.dimmed()`](Style::dimmed())
///   * [`style.italic()`](Style::italic())
///   * [`style.underline()`](Style::underline())
///   * [`style.blink()`](Style::blink())
///   * [`style.invert()`](Style::invert())
///   * [`style.hidden()`](Style::hidden())
///   * [`style.strikethrough()`](Style::strikethrough())
///
/// These methods can be chained:
///
/// ```rust
/// use yansi::{Style, Color::{Red, Magenta}};
///
/// Style::new(Red).bg(Magenta).underline().invert().italic().dimmed().bold();
/// ```
///
/// ### Converters
///
/// Convert a `Style` into another structure.
///
///   * [`style.paint<T>(item: T) -> Paint<T>`](Style::paint())
///
/// ### Getters
///
/// Return information about a `Style` structure.
///
///   * [`style.fg_color()`](Style::fg_color())
///   * [`style.bg_color()`](Style::bg_color())
///   * [`style.is_masked()`](Style::is_masked())
///   * [`style.is_wrapping()`](Style::is_wrapping())
///   * [`style.is_bold()`](Style::is_bold())
///   * [`style.is_dimmed()`](Style::is_dimmed())
///   * [`style.is_italic()`](Style::is_italic())
///   * [`style.is_underline()`](Style::is_underline())
///   * [`style.is_blink()`](Style::is_blink())
///   * [`style.is_invert()`](Style::is_invert())
///   * [`style.is_hidden()`](Style::is_hidden())
///   * [`style.is_strikethrough()`](Style::is_strikethrough())
///
/// ### Raw Formatters
///
/// Write the raw ANSI codes for a given `Style` to any `fmt::Write`.
///
///   * [`style.fmt_prefix(f: &mut fmt::Write)`](Style::fmt_prefix())
///   * [`style.fmt_suffix(f: &mut fmt::Write)`](Style::fmt_suffix())
#[repr(packed)]
#[derive(Default, Debug, Eq, Ord, PartialOrd, Copy, Clone)]
pub struct Style {
    pub(crate) foreground: Color,
    pub(crate) background: Color,
    pub(crate) properties: Property,
    pub(crate) masked: bool,
    pub(crate) wrap: bool,
}

impl PartialEq for Style {
    fn eq(&self, other: &Style) -> bool {
        self.foreground == other.foreground
            && self.background == other.background
            && self.properties == other.properties
    }
}

impl Hash for Style {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.foreground.hash(state);
        self.background.hash(state);
        self.properties.hash(state);
    }
}

macro_rules! checker_for {
    ($($name:ident ($fn_name:ident): $property:ident),*) => ($(
        #[doc = concat!(
            "Returns `true` if the _", stringify!($name), "_ property is set on `self`.\n",
            "```rust\n",
            "use yansi::Style;\n",
            "\n",
            "let plain = Style::default();\n",
            "assert!(!plain.", stringify!($fn_name), "());\n",
            "\n",
            "let styled = plain.", stringify!($name), "();\n",
            "assert!(styled.", stringify!($fn_name), "());\n",
            "```\n"
        )]
        #[inline]
        pub fn $fn_name(&self) -> bool {
            self.properties.contains(Property::$property)
        }
    )*)
}

#[inline]
fn write_spliced<T: Display>(c: &mut bool, f: &mut fmt::Write, t: T) -> fmt::Result {
    if *c {
        write!(f, ";{}", t)
    } else {
        *c = true;
        write!(f, "{}", t)
    }
}

impl Style {
    /// Default style with the foreground set to `color` and no other set
    /// properties.
    ///
    /// ```rust
    /// use yansi::Style;
    ///
    /// let plain = Style::default();
    /// assert_eq!(plain, Style::default());
    /// ```
    #[inline]
    pub fn new(color: Color) -> Style {
        Self::default().fg(color)
    }

    /// Sets the foreground to `color`.
    ///
    /// ```rust
    /// use yansi::{Color, Style};
    ///
    /// let red_fg = Style::default().fg(Color::Red);
    /// ```
    #[inline]
    pub fn fg(mut self, color: Color) -> Style {
        self.foreground = color;
        self
    }

    /// Sets the background to `color`.
    ///
    /// ```rust
    /// use yansi::{Color, Style};
    ///
    /// let red_bg = Style::default().bg(Color::Red);
    /// ```
    #[inline]
    pub fn bg(mut self, color: Color) -> Style {
        self.background = color;
        self
    }

    /// Sets `self` to be masked.
    ///
    /// An item with _masked_ styling is not written out when painting is
    /// disabled during `Display` or `Debug` invocations. When painting is
    /// enabled, masking has no effect.
    ///
    /// ```rust
    /// use yansi::Style;
    ///
    /// let masked = Style::default().mask();
    ///
    /// // "Whoops! " will only print when coloring is enabled.
    /// println!("{}Something happened.", masked.paint("Whoops! "));
    /// ```
    #[inline]
    pub fn mask(mut self) -> Style {
        self.masked = true;
        self
    }

    /// Sets `self` to be wrapping.
    ///
    /// A wrapping `Style` converts all color resets written out by the internal
    /// value to the styling of itself. This allows for seamless color wrapping
    /// of other colored text.
    ///
    /// # Performance
    ///
    /// In order to wrap an internal value, the internal value must first be
    /// written out to a local buffer and examined. As a result, displaying a
    /// wrapped value is likely to result in a heap allocation and copy.
    ///
    /// ```rust
    /// use yansi::{Paint, Style, Color};
    ///
    /// let inner = format!("{} and {}", Paint::red("Stop"), Paint::green("Go"));
    /// let wrapping = Style::new(Color::Blue).wrap();
    ///
    /// // 'Hey!' will be unstyled, "Stop" will be red, "and" will be blue, and
    /// // "Go" will be green. Without a wrapping `Paint`, "and" would be
    /// // unstyled.
    /// println!("Hey! {}", wrapping.paint(inner));
    /// ```
    #[inline]
    pub fn wrap(mut self) -> Style {
        self.wrap = true;
        self
    }

    style_builder_for!(Style, |style| style.properties,
                       bold: BOLD, dimmed: DIMMED, italic: ITALIC,
                       underline: UNDERLINE, blink: BLINK, invert: INVERT,
                       hidden: HIDDEN, strikethrough: STRIKETHROUGH);

    /// Constructs a new `Paint` structure that encapsulates `item` with the
    /// style set to `self`.
    ///
    /// ```rust
    /// use yansi::{Style, Color};
    ///
    /// let alert = Style::new(Color::Red).bold().underline();
    /// println!("Alert: {}", alert.paint("This thing happened!"));
    /// ```
    #[inline]
    pub fn paint<T>(self, item: T) -> Paint<T> {
        Paint::new(item).with_style(self)
    }

    /// Returns the foreground color of `self`.
    ///
    /// ```rust
    /// use yansi::{Style, Color};
    ///
    /// let plain = Style::default();
    /// assert_eq!(plain.fg_color(), Color::Unset);
    ///
    /// let red = plain.fg(Color::Red);
    /// assert_eq!(red.fg_color(), Color::Red);
    /// ```
    #[inline]
    pub fn fg_color(&self) -> Color {
        self.foreground
    }

    /// Returns the foreground color of `self`.
    ///
    /// ```rust
    /// use yansi::{Style, Color};
    ///
    /// let plain = Style::default();
    /// assert_eq!(plain.bg_color(), Color::Unset);
    ///
    /// let white = plain.bg(Color::White);
    /// assert_eq!(white.bg_color(), Color::White);
    /// ```
    #[inline]
    pub fn bg_color(&self) -> Color {
        self.background
    }

    /// Returns `true` if `self` is masked.
    ///
    /// ```rust
    /// use yansi::Style;
    ///
    /// let plain = Style::default();
    /// assert!(!plain.is_masked());
    ///
    /// let masked = plain.mask();
    /// assert!(masked.is_masked());
    /// ```
    #[inline]
    pub fn is_masked(&self) -> bool {
        self.masked
    }

    /// Returns `true` if `self` is wrapping.
    ///
    /// ```rust
    /// use yansi::Style;
    ///
    /// let plain = Style::default();
    /// assert!(!plain.is_wrapping());
    ///
    /// let wrapping = plain.wrap();
    /// assert!(wrapping.is_wrapping());
    /// ```
    #[inline]
    pub fn is_wrapping(&self) -> bool {
        self.wrap
    }

    checker_for!(bold (is_bold): BOLD, dimmed (is_dimmed): DIMMED,
        italic (is_italic): ITALIC, underline (is_underline): UNDERLINE,
        blink (is_blink): BLINK, invert (is_invert): INVERT,
        hidden (is_hidden): HIDDEN,
        strikethrough (is_strikethrough): STRIKETHROUGH);

    #[inline(always)]
    fn is_plain(&self) -> bool {
        self == &Style::default()
    }

    /// Writes the ANSI code prefix for the currently set styles.
    ///
    /// This method is intended to be used inside of [`fmt::Display`] and
    /// [`fmt::Debug`] implementations for custom or specialized use-cases. Most
    /// users should use [`Paint`] for all painting needs.
    ///
    /// This method writes the ANSI code prefix irrespective of whether painting
    /// is currently enabled or disabled. To write the prefix only if painting
    /// is enabled, condition a call to this method on [`Paint::is_enabled()`].
    ///
    /// [`fmt::Display`]: fmt::Display
    /// [`fmt::Debug`]: fmt::Debug
    /// [`Paint`]: Paint
    /// [`Paint::is_enabled()`]: Paint::is_enabled()
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fmt;
    /// use yansi::Style;
    ///
    /// struct CustomItem {
    ///     item: u32,
    ///     style: Style
    /// }
    ///
    /// impl fmt::Display for CustomItem {
    ///     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    ///         self.style.fmt_prefix(f)?;
    ///         write!(f, "number: {}", self.item)?;
    ///         self.style.fmt_suffix(f)
    ///     }
    /// }
    /// ```
    pub fn fmt_prefix(&self, f: &mut fmt::Write) -> fmt::Result {
        // A user may just want a code-free string when no styles are applied.
        if self.is_plain() {
            return Ok(());
        }

        let mut splice = false;
        write!(f, "\x1B[")?;

        for i in self.properties.iter() {
            let k = if i >= 5 { i + 2 } else { i + 1 };
            write_spliced(&mut splice, f, k)?;
        }

        if self.background != Color::Unset {
            write_spliced(&mut splice, f, "4")?;
            self.background.ascii_fmt(f)?;
        }

        if self.foreground != Color::Unset {
            write_spliced(&mut splice, f, "3")?;
            self.foreground.ascii_fmt(f)?;
        }

        // All the codes end with an `m`.
        write!(f, "m")
    }

    /// Writes the ANSI code suffix for the currently set styles.
    ///
    /// This method is intended to be used inside of [`fmt::Display`] and
    /// [`fmt::Debug`] implementations for custom or specialized use-cases. Most
    /// users should use [`Paint`] for all painting needs.
    ///
    /// This method writes the ANSI code suffix irrespective of whether painting
    /// is currently enabled or disabled. To write the suffix only if painting
    /// is enabled, condition a call to this method on [`Paint::is_enabled()`].
    ///
    /// [`fmt::Display`]: fmt::Display
    /// [`fmt::Debug`]: fmt::Debug
    /// [`Paint`]: Paint
    /// [`Paint::is_enabled()`]: Paint::is_enabled()
    ///
    /// # Example
    ///
    /// ```rust
    /// use std::fmt;
    /// use yansi::Style;
    ///
    /// struct CustomItem {
    ///     item: u32,
    ///     style: Style
    /// }
    ///
    /// impl fmt::Display for CustomItem {
    ///     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    ///         self.style.fmt_prefix(f)?;
    ///         write!(f, "number: {}", self.item)?;
    ///         self.style.fmt_suffix(f)
    ///     }
    /// }
    /// ```
    pub fn fmt_suffix(&self, f: &mut fmt::Write) -> fmt::Result {
        if self.is_plain() {
            return Ok(());
        }

        write!(f, "\x1B[0m")
    }
}
