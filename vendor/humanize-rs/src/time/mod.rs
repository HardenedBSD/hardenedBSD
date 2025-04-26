//! This module is used to parse [`RFC3339`] datetime string
//!
//! # Example
//! ```
//! use humanize_rs::time::{Time, TimeZone};
//!
//! assert_eq!(
//!     "2018-09-21T16:56:44.234867232+08:00".parse::<Time>(),
//!     Ok(Time::from_timetuple(
//!         2018,
//!         9,
//!         21,
//!         16,
//!         56,
//!         44,
//!         234867232,
//!         TimeZone::new(8).unwrap(),
//!     ).unwrap())
//! );
//! ```
//!
//! [`RFC3339`]: https://tools.ietf.org/html/rfc3339

mod timezone;

pub use self::timezone::*;

use std::cmp::Ordering;
use std::str::{from_utf8, FromStr};
use std::time::{Duration, SystemTime};
use ParseError;

const MAX_SECONDS: u64 = 315569433600;
const UNIX_EPOCH: Time = Time {
    sec: 62167132800,
    nano: 0,
};

const SECS_PER_MINUTE: u64 = 60;
const SECS_PER_HOUR: u64 = 60 * SECS_PER_MINUTE;
const SECS_PER_DAY: u64 = 24 * SECS_PER_HOUR;
const DAYS_PER_400_YEARS: u32 = 365 * 400 + 97;
const DAYS_PER_100_YEARS: u32 = 365 * 100 + 24;
const DAYS_PER_4_YEARS: u32 = 365 * 4 + 1;
const DAYS_BEFORE: [u32; 13] = [
    0,
    31,
    31 + 28,
    31 + 28 + 31,
    31 + 28 + 31 + 30,
    31 + 28 + 31 + 30 + 31,
    31 + 28 + 31 + 30 + 31 + 30,
    31 + 28 + 31 + 30 + 31 + 30 + 31,
    31 + 28 + 31 + 30 + 31 + 30 + 31 + 31,
    31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30,
    31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31,
    31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30,
    31 + 28 + 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31,
];

const DATE_TIME_FORMAT_MIN_LENGTH: usize = 10; // "2006-01-02"
const DATE_TIME_FORMAT_WITH_TIME: usize = 19; // "2006-01-02T15:04:05"
const DATE_TIME_FORMAT_MAX_LENGTH: usize = 35; // "2006-01-02T15:04:05.999999999Z07:00"

/// Represents a time in range [0000-01-01T00:00:00Z, 10000-01-01T00:00:00Z)
#[derive(Debug, Eq, PartialEq)]
pub struct Time {
    sec: u64,
    nano: u32,
}

impl Time {
    /// Represents `1970-01-01 00:00:00Z`
    pub const UNIX_EPOCH: Time = UNIX_EPOCH;

    /// Returns a Time with the given time tuple
    pub fn from_timetuple(
        year: u32,
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
        nano: u32,
        timezone: TimeZone,
    ) -> Option<Time> {
        if !in_range(year, 0, 10000)
            || !in_range(month, 1, 12)
            || !in_range(day, 1, 31)
            || !in_range(hour, 0, 23)
            || !in_range(minute, 0, 59)
            || !in_range(second, 0, 59)
            || !in_range(nano, 0, 1_000_000_000 - 1)
        {
            return None;
        }

        let is_leap = is_leap_year(year);

        if !is_day_validate(is_leap, month, day) {
            return None;
        }

        let mut d: u32 = 0;

        let mut y = year;

        let mut n: u32 = y / 400;
        y -= 400 * n;
        d += DAYS_PER_400_YEARS * n;

        n = y / 100;
        y -= n * 100;
        d += DAYS_PER_100_YEARS * n;

        n = y / 4;
        y -= n * 4;
        d += DAYS_PER_4_YEARS * n;

        n = y;
        d += 365 * n;

        d += DAYS_BEFORE[(month - 1) as usize];
        // already calculated in DAYS_PER_XX_YEARS
        if year > 0 && is_leap && month <= 2 {
            d -= 1;
        }

        d += day - 1;

        let mut sec: u64 = d as u64 * SECS_PER_DAY
            + hour as u64 * SECS_PER_HOUR
            + minute as u64 * SECS_PER_MINUTE
            + second as u64;

        let offset = timezone.offset();
        if offset >= 0 {
            let minus = offset as u64;
            if minus > sec {
                return None;
            }

            sec -= minus;
        } else {
            sec += (-offset) as u64;
        }

        if sec >= MAX_SECONDS {
            return None;
        }

        Some(Time {
            sec: sec,
            nano: nano,
        })
    }

    /// Convert the time to SystemTime, returns None if the time is before unix epoch
    pub fn to_system_time(&self) -> Option<SystemTime> {
        if let Some(d) = self.since(&UNIX_EPOCH) {
            return Some(SystemTime::UNIX_EPOCH + d);
        }

        None
    }

    /// Returns the duration since an earlier time, and None if earlier is not before self.
    pub fn since(&self, earlier: &Time) -> Option<Duration> {
        if self < earlier {
            return None;
        }

        let mut sec = self.sec - earlier.sec;
        let mut nano = self.nano;
        if nano < earlier.nano {
            sec -= 1;
            nano += 1_000_000_000;
        }
        nano -= earlier.nano;

        Some(Duration::new(sec, nano))
    }
}

fn is_leap_year(y: u32) -> bool {
    return y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
}

fn in_range(n: u32, min: u32, max: u32) -> bool {
    return min <= n && n <= max;
}

fn is_day_validate(is_leap: bool, m: u32, d: u32) -> bool {
    match m {
        2 if is_leap => d <= 29,
        2 => d <= 28,
        4 | 6 | 9 | 11 => d <= 30,
        _ => d <= 31,
    }
}

impl FromStr for Time {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_rfc3339(s)
    }
}

impl PartialOrd for Time {
    fn partial_cmp(&self, other: &Time) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Time {
    fn cmp(&self, other: &Time) -> Ordering {
        let ord = self.sec.cmp(&other.sec);
        match ord {
            Ordering::Equal => self.nano.cmp(&other.nano),
            _ => ord,
        }
    }
}

/// Parses a [`RFC3339`] datetime string
///
/// [`RFC3339`]: https://tools.ietf.org/html/rfc3339
pub fn parse_rfc3339(s: &str) -> Result<Time, ParseError> {
    let bs = s.trim().as_bytes();
    let size = bs.len();
    if size == 0 {
        return Err(ParseError::EmptyInput);
    }

    if size < DATE_TIME_FORMAT_MIN_LENGTH
        || (size > DATE_TIME_FORMAT_MIN_LENGTH && size < DATE_TIME_FORMAT_WITH_TIME)
    {
        return Err(ParseError::TooShort);
    }

    if size > DATE_TIME_FORMAT_MAX_LENGTH {
        return Err(ParseError::TooLong);
    }

    if !check_pattern(bs) {
        return Err(ParseError::Malformed);
    }

    let year = read_u32(&bs[0..4])?;
    let month = read_u32(&bs[5..7])?;
    let day = read_u32(&bs[8..10])?;

    let hour: u32;
    let minute: u32;
    let second: u32;
    if size > DATE_TIME_FORMAT_MIN_LENGTH {
        hour = read_u32(&bs[DATE_TIME_FORMAT_MIN_LENGTH + 1..DATE_TIME_FORMAT_MIN_LENGTH + 3])?;
        minute = read_u32(&bs[DATE_TIME_FORMAT_MIN_LENGTH + 4..DATE_TIME_FORMAT_MIN_LENGTH + 6])?;
        second = read_u32(&bs[DATE_TIME_FORMAT_MIN_LENGTH + 7..DATE_TIME_FORMAT_MIN_LENGTH + 9])?;
    } else {
        hour = 0;
        minute = 0;
        second = 0;
    }

    let nano: u32;
    let tzstr: &str;
    if size > DATE_TIME_FORMAT_WITH_TIME {
        let tz_start: usize;
        if bs[DATE_TIME_FORMAT_WITH_TIME] == b'.' {
            let (v, read) = read_nano(&bs[DATE_TIME_FORMAT_WITH_TIME + 1..]);
            if read == 0 {
                return Err(ParseError::MissingValue);
            }
            nano = v;
            tz_start = DATE_TIME_FORMAT_WITH_TIME + 1 + read;
        } else {
            nano = 0;
            tz_start = DATE_TIME_FORMAT_WITH_TIME;
        }

        tzstr = from_utf8(&bs[tz_start..]).or(Err(ParseError::InvalidTimezone))?;
    } else {
        nano = 0;
        tzstr = "";
    }

    let tz = tzstr.parse::<TimeZone>()?;

    Time::from_timetuple(year, month, day, hour, minute, second, nano, tz)
        .ok_or(ParseError::Overflow)
}

fn check_pattern(bs: &[u8]) -> bool {
    if bs[4] != b'-' || bs[7] != b'-' {
        return false;
    }

    if bs.len() > DATE_TIME_FORMAT_MIN_LENGTH {
        if (bs[DATE_TIME_FORMAT_MIN_LENGTH] != b'T' && bs[DATE_TIME_FORMAT_MIN_LENGTH] != b' ')
            || bs[DATE_TIME_FORMAT_MIN_LENGTH + 3] != b':'
            || bs[DATE_TIME_FORMAT_MIN_LENGTH + 6] != b':'
        {
            return false;
        }
    }

    if bs.len() > DATE_TIME_FORMAT_WITH_TIME {
        if bs[DATE_TIME_FORMAT_WITH_TIME] != b'.'
            && bs[DATE_TIME_FORMAT_WITH_TIME] != b'Z'
            && bs[DATE_TIME_FORMAT_WITH_TIME] != b'+'
            && bs[DATE_TIME_FORMAT_WITH_TIME] != b'-'
        {
            return false;
        }
    }

    true
}

fn read_u32(bs: &[u8]) -> Result<u32, ParseError> {
    let mut read: usize = 0;
    let mut n: u32 = 0;

    while read < bs.len() {
        let c = bs[read];
        if c < b'0' || c > b'9' {
            return Err(ParseError::InvalidValue);
        }

        n = n * 10;
        n += (c - b'0') as u32;

        read += 1;
    }

    Ok(n)
}

fn read_nano(bs: &[u8]) -> (u32, usize) {
    let mut read: usize = 0;
    let mut n: u32 = 0;

    while read < bs.len() && read <= 9 {
        let c = bs[read];
        if c < b'0' || c > b'9' {
            break;
        }

        n = n * 10;
        n += (c - b'0') as u32;

        read += 1;
    }

    if read < 9 {
        n = n * 10_u32.pow((9 - read) as u32);
    }

    (n, read)
}

#[cfg(test)]
mod tests;
