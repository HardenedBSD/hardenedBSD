#![warn(missing_docs)]

//! This lib is used to parse formatted strings to different types

use std::error::Error;
use std::fmt;

pub mod bytes;
pub mod duration;
pub mod num;
pub mod time;

/// Error parsing formatted strings
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ParseError {
    /// Parsing an empty string
    EmptyInput,

    /// The numeric value is missing
    MissingValue,

    /// Malformed numeric value
    InvalidValue,

    /// The unit is missing
    MissingUnit,

    /// Unknown unit
    InvalidUnit,

    /// The unit shows multiple times in the string
    DuplicateUnit,

    /// The numeric value is too large
    Overflow,

    /// Too short for some pattern
    TooShort,

    /// Too long for some pattern
    TooLong,

    /// Malformed string
    Malformed,

    /// Invalid timezone
    InvalidTimezone,
}

impl ParseError {
    fn description(&self) -> &str {
        match self {
            ParseError::EmptyInput => "empty input",
            ParseError::MissingValue => "missing value",
            ParseError::InvalidValue => "invalid value",
            ParseError::MissingUnit => "missing unit",
            ParseError::InvalidUnit => "invalid unit",
            ParseError::DuplicateUnit => "duplicate unit",
            ParseError::Overflow => "value overflow",
            ParseError::TooShort => "too short",
            ParseError::TooLong => "too long",
            ParseError::Malformed => "malformed",
            ParseError::InvalidTimezone => "invalid timezone",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.pad(self.description())
    }
}

impl Error for ParseError {}
