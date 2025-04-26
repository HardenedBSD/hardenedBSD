use std::str::FromStr;
use ParseError;

const OFFSETS: [i32; 25] = [
    3600 * -12,
    3600 * -11,
    3600 * -10,
    3600 * -9,
    3600 * -8,
    3600 * -7,
    3600 * -6,
    3600 * -5,
    3600 * -4,
    3600 * -3,
    3600 * -2,
    3600 * -1,
    0,
    3600,
    3600 * 2,
    3600 * 3,
    3600 * 4,
    3600 * 5,
    3600 * 6,
    3600 * 7,
    3600 * 8,
    3600 * 9,
    3600 * 10,
    3600 * 11,
    3600 * 12,
];

/// Represents timezone in datetime string
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TimeZone(i32);

impl TimeZone {
    /// Returns timezone UTC
    pub fn utc() -> TimeZone {
        TimeZone(0)
    }

    /// Returns a timezone with the given hour offset
    pub fn new(hoffset: i32) -> Option<TimeZone> {
        if hoffset < -12 || hoffset > 12 {
            return None;
        }

        Some(TimeZone(OFFSETS[(hoffset + 12) as usize]))
    }

    /// Returns the actual offset in seconds
    pub fn offset(&self) -> i32 {
        return self.0;
    }
}

impl FromStr for TimeZone {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" | "Z" | "+00:00" | "-00:00" => Ok(TimeZone(0)),
            "-12:00" => Ok(TimeZone(OFFSETS[0])),
            "-11:00" => Ok(TimeZone(OFFSETS[1])),
            "-10:00" => Ok(TimeZone(OFFSETS[2])),
            "-09:00" => Ok(TimeZone(OFFSETS[3])),
            "-08:00" => Ok(TimeZone(OFFSETS[4])),
            "-07:00" => Ok(TimeZone(OFFSETS[5])),
            "-06:00" => Ok(TimeZone(OFFSETS[6])),
            "-05:00" => Ok(TimeZone(OFFSETS[7])),
            "-04:00" => Ok(TimeZone(OFFSETS[8])),
            "-03:00" => Ok(TimeZone(OFFSETS[9])),
            "-02:00" => Ok(TimeZone(OFFSETS[10])),
            "-01:00" => Ok(TimeZone(OFFSETS[11])),

            "+01:00" => Ok(TimeZone(OFFSETS[13])),
            "+02:00" => Ok(TimeZone(OFFSETS[14])),
            "+03:00" => Ok(TimeZone(OFFSETS[15])),
            "+04:00" => Ok(TimeZone(OFFSETS[16])),
            "+05:00" => Ok(TimeZone(OFFSETS[17])),
            "+06:00" => Ok(TimeZone(OFFSETS[18])),
            "+07:00" => Ok(TimeZone(OFFSETS[19])),
            "+08:00" => Ok(TimeZone(OFFSETS[20])),
            "+09:00" => Ok(TimeZone(OFFSETS[21])),
            "+10:00" => Ok(TimeZone(OFFSETS[22])),
            "+11:00" => Ok(TimeZone(OFFSETS[23])),
            "+12:00" => Ok(TimeZone(OFFSETS[24])),
            _ => Err(ParseError::InvalidTimezone),
        }
    }
}
