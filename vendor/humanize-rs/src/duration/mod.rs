//! This module is used to parse strings to duration.
//!
//! # Example
//! ```
//! use humanize_rs::duration::parse;
//! use std::time::Duration;
//!
//! assert_eq!(parse("1h 30m 71s"), Ok(Duration::from_secs(60 * 90 + 71)));
//! ```

use std::str::from_utf8;
use std::time::Duration;
use ParseError;

const DIGIT_MIN: u8 = b'0';
const DIGIT_MAX: u8 = b'9';

const NANOS: [u64; 7] = [
    1,                         // ns
    1_000,                     // us
    1_000_000,                 // ms
    1_000_000_000,             // s
    60 * 1_000_000_000,        // min
    3600 * 1_000_000_000,      // h
    24 * 3600 * 1_000_000_000, // d
];

/// parse a duration-type string, (e.g. "1h", "1h 30m")
///
/// # Example
/// ```
/// use humanize_rs::duration::parse;
///
///
/// let d = parse("1h 30m").unwrap();
/// println!("{:?}", d);
/// ```
pub fn parse(s: &str) -> Result<Duration, ParseError> {
    let input = s.trim();
    if input.is_empty() {
        return Err(ParseError::EmptyInput);
    }

    if input == "0" {
        return Ok(Duration::new(0, 0));
    }

    let mut value: u64 = 0;

    let bs = input.as_bytes();
    let mut read: usize = 0;

    while read < bs.len() {
        let (v, consumed) = read_int(&bs[read..])?;
        read += consumed;

        let (unit, consumed) = read_unit(&bs[read..])?;
        read += consumed;

        let nanos = unit_to_nanos(unit)?;

        value = v
            .checked_mul(nanos)
            .and_then(|res| value.checked_add(res))
            .ok_or(ParseError::Overflow)?;
    }

    Ok(Duration::from_nanos(value))
}

fn read_int(bs: &[u8]) -> Result<(u64, usize), ParseError> {
    let mut v: u64 = 0;
    let mut read: usize = 0;
    while read < bs.len() {
        let c = bs[read];
        if c < DIGIT_MIN || c > DIGIT_MAX {
            break;
        }

        v = v
            .checked_mul(10)
            .and_then(|res| res.checked_add((c - DIGIT_MIN) as u64))
            .ok_or(ParseError::Overflow)?;

        read += 1;
    }

    if read == 0 {
        return Err(ParseError::MissingValue);
    }

    Ok((v, read))
}

fn read_unit(bs: &[u8]) -> Result<(&str, usize), ParseError> {
    let mut read: usize = 0;
    while read < bs.len() {
        let c = bs[read];
        if DIGIT_MIN <= c && c <= DIGIT_MAX {
            break;
        }

        read += 1;
    }

    if read == 0 {
        return Err(ParseError::MissingUnit);
    }

    let unit = from_utf8(&bs[..read]).or(Err(ParseError::InvalidUnit))?;

    Ok((unit.trim(), read))
}

fn unit_to_nanos(unit: &str) -> Result<u64, ParseError> {
    match unit {
        "ns" => Ok(NANOS[0]),
        "us" => Ok(NANOS[1]),
        "ms" => Ok(NANOS[2]),
        "s" => Ok(NANOS[3]),
        "m" => Ok(NANOS[4]),
        "h" => Ok(NANOS[5]),
        "d" => Ok(NANOS[6]),
        _ => Err(ParseError::InvalidUnit),
    }
}

#[cfg(test)]
mod tests;
