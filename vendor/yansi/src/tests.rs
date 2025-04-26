extern crate serial_test;

use self::serial_test::serial;

use super::Color::*;
use super::{Paint, Style};

macro_rules! assert_renders {
    ($($input:expr => $expected:expr,)*) => {
        $(
            let (input, expected) = ($input.to_string(), $expected.to_string());
            if input != expected {
                panic!("expected {:?}, got {:?} from {:?} ({:?})",
                       expected, input, $input.inner(), $input.style())
            }
        )*
    };
}

macro_rules! assert_disabled_renders {
    ($($input:expr => $expected:expr,)*) => {
        $(
            Paint::disable();
            let (actual, expected) = ($input.to_string(), $expected.to_string());
            Paint::enable();
            assert_eq!(actual, expected);
        )*
    };
}

#[test]
#[serial]
fn colors_enabled() {
    assert_renders! {
        Paint::new("text/plain") => "text/plain",
        Paint::red("hi") => "\x1B[31mhi\x1B[0m",
        Paint::black("hi") => "\x1B[30mhi\x1B[0m",
        Paint::yellow("hi").bold() => "\x1B[1;33mhi\x1B[0m",
        Paint::new("hi").fg(Yellow).bold() => "\x1B[1;33mhi\x1B[0m",
        Paint::blue("hi").underline() => "\x1B[4;34mhi\x1B[0m",
        Paint::green("hi").bold().underline() => "\x1B[1;4;32mhi\x1B[0m",
        Paint::green("hi").underline().bold() => "\x1B[1;4;32mhi\x1B[0m",
        Paint::magenta("hi").bg(White) => "\x1B[47;35mhi\x1B[0m",
        Paint::red("hi").bg(Blue).fg(Yellow) => "\x1B[44;33mhi\x1B[0m",
        Paint::cyan("hi").bg(Blue).fg(Yellow) => "\x1B[44;33mhi\x1B[0m",
        Paint::cyan("hi").bold().bg(White) => "\x1B[1;47;36mhi\x1B[0m",
        Paint::cyan("hi").underline().bg(White) => "\x1B[4;47;36mhi\x1B[0m",
        Paint::cyan("hi").bold().underline().bg(White) => "\x1B[1;4;47;36mhi\x1B[0m",
        Paint::cyan("hi").underline().bold().bg(White) => "\x1B[1;4;47;36mhi\x1B[0m",
        Paint::fixed(100, "hi") => "\x1B[38;5;100mhi\x1B[0m",
        Paint::fixed(100, "hi").bg(Magenta) => "\x1B[45;38;5;100mhi\x1B[0m",
        Paint::fixed(100, "hi").bg(Fixed(200)) => "\x1B[48;5;200;38;5;100mhi\x1B[0m",
        Paint::rgb(70, 130, 180, "hi") => "\x1B[38;2;70;130;180mhi\x1B[0m",
        Paint::rgb(70, 130, 180, "hi").bg(Blue) => "\x1B[44;38;2;70;130;180mhi\x1B[0m",
        Paint::blue("hi").bg(RGB(70, 130, 180)) => "\x1B[48;2;70;130;180;34mhi\x1B[0m",
        Paint::rgb(70, 130, 180, "hi").bg(RGB(5,10,15)) => "\x1B[48;2;5;10;15;38;2;70;130;180mhi\x1B[0m",
        Paint::new("hi").bold() => "\x1B[1mhi\x1B[0m",
        Paint::new("hi").underline() => "\x1B[4mhi\x1B[0m",
        Paint::new("hi").bold().underline() => "\x1B[1;4mhi\x1B[0m",
        Paint::new("hi").dimmed() => "\x1B[2mhi\x1B[0m",
        Paint::new("hi").italic() => "\x1B[3mhi\x1B[0m",
        Paint::new("hi").blink() => "\x1B[5mhi\x1B[0m",
        Paint::new("hi").invert() => "\x1B[7mhi\x1B[0m",
        Paint::new("hi").hidden() => "\x1B[8mhi\x1B[0m",
        Paint::new("hi").strikethrough() => "\x1B[9mhi\x1B[0m",
    }
}

#[test]
#[serial]
fn colors_disabled() {
    assert_disabled_renders! {
        Paint::new("text/plain") => "text/plain",
        Paint::red("hi") => "hi",
        Paint::black("hi") => "hi",
        Paint::yellow("hi").bold() => "hi",
        Paint::new("hi").fg(Yellow).bold() => "hi",
        Paint::blue("hi").underline() => "hi",
        Paint::green("hi").bold().underline() => "hi",
        Paint::green("hi").underline().bold() => "hi",
        Paint::magenta("hi").bg(White) => "hi",
        Paint::red("hi").bg(Blue).fg(Yellow) => "hi",
        Paint::cyan("hi").bg(Blue).fg(Yellow) => "hi",
        Paint::cyan("hi").bold().bg(White) => "hi",
        Paint::cyan("hi").underline().bg(White) => "hi",
        Paint::cyan("hi").bold().underline().bg(White) => "hi",
        Paint::cyan("hi").underline().bold().bg(White) => "hi",
        Paint::fixed(100, "hi") => "hi",
        Paint::fixed(100, "hi").bg(Magenta) => "hi",
        Paint::fixed(100, "hi").bg(Fixed(200)) => "hi",
        Paint::rgb(70, 130, 180, "hi") => "hi",
        Paint::rgb(70, 130, 180, "hi").bg(Blue) => "hi",
        Paint::blue("hi").bg(RGB(70, 130, 180)) => "hi",
        Paint::blue("hi").bg(RGB(70, 130, 180)).wrap() => "hi",
        Paint::rgb(70, 130, 180, "hi").bg(RGB(5,10,15)) => "hi",
        Paint::new("hi").bold() => "hi",
        Paint::new("hi").underline() => "hi",
        Paint::new("hi").bold().underline() => "hi",
        Paint::new("hi").dimmed() => "hi",
        Paint::new("hi").italic() => "hi",
        Paint::new("hi").blink() => "hi",
        Paint::new("hi").invert() => "hi",
        Paint::new("hi").hidden() => "hi",
        Paint::new("hi").strikethrough() => "hi",
        Paint::new("hi").strikethrough().wrap() => "hi",
    }
}

#[test]
#[serial]
fn masked_when_disabled() {
    assert_disabled_renders! {
        Paint::masked("text/plain") => "",
        Paint::masked("text/plain").mask() => "",
        Paint::new("text/plain").mask() => "",
        Paint::new("text/plain").mask() => "",
        Paint::red("hi").mask() => "",
        Paint::black("hi").mask() => "",
        Paint::yellow("hi").bold().mask() => "",
        Paint::cyan("hi").bg(Blue).fg(Yellow).mask() => "",
        Paint::cyan("hi").underline().bold().bg(White).mask() => "",
    }
}

#[test]
#[serial]
fn masked_when_enabled() {
    assert_renders! {
        Paint::masked("text/plain") => "text/plain",
        Paint::masked("text/plain").mask() => "text/plain",
        Paint::black("hi").mask() => "\x1B[30mhi\x1B[0m",
        Paint::yellow("hi").bold().mask() => "\x1B[1;33mhi\x1B[0m",
        Paint::new("hi").fg(Yellow).bold().mask() => "\x1B[1;33mhi\x1B[0m",
        Paint::cyan("hi").underline().bg(White).mask() => "\x1B[4;47;36mhi\x1B[0m",
        Paint::cyan("hi").bold().underline().bg(White).mask() => "\x1B[1;4;47;36mhi\x1B[0m",
        Paint::rgb(70, 130, 180, "hi").mask() => "\x1B[38;2;70;130;180mhi\x1B[0m",
        Paint::new("hi").underline().mask() => "\x1B[4mhi\x1B[0m",
        Paint::new("hi").bold().underline().mask() => "\x1B[1;4mhi\x1B[0m",
        Paint::new("hi").hidden().mask() => "\x1B[8mhi\x1B[0m",
    }
}

#[test]
#[serial]
fn wrapping() {
    let inner = || format!("{} b {}", Paint::red("a"), Paint::green("c"));
    let inner2 = || format!("0 {} 1", Paint::magenta(&inner()).wrap());
    assert_renders! {
        Paint::new("text/plain").wrap() => "text/plain",
        Paint::new(&inner()).wrap() => &inner(),
        Paint::new(&inner()).wrap() =>
            "\u{1b}[31ma\u{1b}[0m b \u{1b}[32mc\u{1b}[0m",
        Paint::new(&inner()).fg(Blue).wrap() =>
            "\u{1b}[34m\u{1b}[31ma\u{1b}[0m\u{1b}[34m b \
            \u{1b}[32mc\u{1b}[0m\u{1b}[34m\u{1b}[0m",
        Paint::new(&inner2()).wrap() => &inner2(),
        Paint::new(&inner2()).wrap() =>
            "0 \u{1b}[35m\u{1b}[31ma\u{1b}[0m\u{1b}[35m b \
            \u{1b}[32mc\u{1b}[0m\u{1b}[35m\u{1b}[0m 1",
        Paint::new(&inner2()).fg(Blue).wrap() =>
            "\u{1b}[34m0 \u{1b}[35m\u{1b}[31ma\u{1b}[0m\u{1b}[34m\u{1b}[35m b \
            \u{1b}[32mc\u{1b}[0m\u{1b}[34m\u{1b}[35m\u{1b}[0m\u{1b}[34m 1\u{1b}[0m",
    }
}

#[test]
fn hash_eq() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    let a = Style::default();
    let b = Style::default().mask();

    assert_eq!(a, b);
    assert_eq!(hash(&a), hash(&b));
}
