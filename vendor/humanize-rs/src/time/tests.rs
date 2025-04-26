use super::TimeZone;
use super::{is_leap_year, parse_rfc3339, Time, UNIX_EPOCH};
use std::time::{Duration, SystemTime};
use ParseError;

#[test]
fn test_timetuple() {
    struct Case {
        tuple: (u32, u32, u32, u32, u32, u32, u32, TimeZone),
        expect: Option<Duration>,
    }

    let cases = vec![
        Case {
            tuple: (2018, 1, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(1514736000, 0)),
        },
        Case {
            tuple: (2018, 2, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(1517414400, 0)),
        },
        Case {
            tuple: (2018, 3, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(1519833600, 0)),
        },
        Case {
            tuple: (2018, 4, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(1522512000, 0)),
        },
        Case {
            tuple: (2018, 5, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(1525104000, 0)),
        },
        Case {
            tuple: (2018, 6, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(1527782400, 0)),
        },
        Case {
            tuple: (2018, 7, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(1530374400, 0)),
        },
        Case {
            tuple: (2018, 8, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(1533052800, 0)),
        },
        Case {
            tuple: (2018, 9, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(1535731200, 0)),
        },
        Case {
            tuple: (2018, 10, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(1538323200, 0)),
        },
        Case {
            tuple: (2018, 11, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(1541001600, 0)),
        },
        Case {
            tuple: (2018, 12, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(1543593600, 0)),
        },
        Case {
            tuple: (
                2018,
                9,
                21,
                16,
                56,
                44,
                234867232,
                TimeZone::new(8).unwrap(),
            ),
            expect: Some(Duration::new(1537520204, 234867232)),
        },
        Case {
            tuple: (2000, 2, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(949334400, 0)),
        },
        Case {
            tuple: (2000, 3, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(951840000, 0)),
        },
        Case {
            tuple: (2100, 2, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(4105094400, 0)),
        },
        Case {
            tuple: (2100, 3, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(4107513600, 0)),
        },
        Case {
            tuple: (2104, 2, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(4231238400, 0)),
        },
        Case {
            tuple: (2104, 3, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(4233744000, 0)),
        },
        Case {
            tuple: (2105, 2, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(4262860800, 0)),
        },
        Case {
            tuple: (2105, 3, 1, 0, 0, 0, 0, TimeZone::new(8).unwrap()),
            expect: Some(Duration::new(4265280000, 0)),
        },
    ];

    for c in cases {
        let d = Time::from_timetuple(
            c.tuple.0, c.tuple.1, c.tuple.2, c.tuple.3, c.tuple.4, c.tuple.5, c.tuple.6, c.tuple.7,
        ).unwrap();

        assert_eq!(d.since(&UNIX_EPOCH), c.expect);
    }
}

#[test]
fn test_1970_to_9999() {
    let mut sec: u64 = 0; // +08:00

    for y in 1970..10000 {
        let year = y as u32;
        if year > 1970 {
            sec += 3600 * 24 * 365;
            if is_leap_year(year - 1) {
                sec += 3600 * 24;
            }
        }

        assert!(
            Time::from_timetuple(year, 1, 1, 0, 0, 0, 0, TimeZone::utc())
                .unwrap()
                .to_system_time()
                == Some(SystemTime::UNIX_EPOCH + Duration::new(sec.clone(), 0)),
            "{}-01-01",
            year,
        );

        let feb_1st_sec = sec + 3600 * 24 * 31;
        assert!(
            Time::from_timetuple(year, 2, 1, 0, 0, 0, 0, TimeZone::new(0).unwrap())
                .unwrap()
                .to_system_time()
                == Some(SystemTime::UNIX_EPOCH + Duration::new(feb_1st_sec, 0)),
            "{}-02-01",
            year,
        );

        let mut march_1st_sec = sec + 3600 * 24 * (31 + 28);
        if is_leap_year(year) {
            march_1st_sec += 3600 * 24;
        }

        assert!(
            Time::from_timetuple(year, 3, 1, 0, 0, 0, 0, TimeZone::new(0).unwrap())
                .unwrap()
                .to_system_time()
                == Some(SystemTime::UNIX_EPOCH + Duration::new(march_1st_sec, 0)),
            "{}-03-01",
            year,
        );
    }
}

#[test]
fn test_invalid_timetuple() {
    let tuples: Vec<(u32, u32, u32, u32, u32, u32, u32, TimeZone)> = vec![
        (10000, 1, 1, 0, 0, 0, 0, TimeZone::utc()),
        (0, 1, 1, 0, 0, 0, 0, TimeZone::new(1).unwrap()),
        (9999, 12, 31, 23, 0, 0, 0, TimeZone::new(-1).unwrap()),
        (1988, 0, 1, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 13, 1, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 1, 0, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 1, 32, 0, 0, 0, 0, TimeZone::utc()),
        (1987, 2, 29, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 2, 30, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 3, 32, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 4, 31, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 5, 32, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 6, 31, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 7, 32, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 8, 32, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 9, 31, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 10, 32, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 11, 31, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 12, 32, 0, 0, 0, 0, TimeZone::utc()),
        (1988, 1, 1, 24, 0, 0, 0, TimeZone::utc()),
        (1988, 1, 1, 23, 60, 0, 0, TimeZone::utc()),
        (1988, 1, 1, 23, 59, 60, 0, TimeZone::utc()),
        (1988, 1, 1, 23, 59, 59, 1_000_000_000, TimeZone::utc()),
    ];

    for t in tuples {
        assert_eq!(
            Time::from_timetuple(t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7),
            None,
            "{:?}",
            t,
        );
    }
}

#[test]
fn test_parse_rfc3339() {
    struct Case<'a> {
        s: &'a str,
        expect: Result<Time, ParseError>,
    }

    let cases: Vec<Case> = vec![
        Case {
            s: "2006-01-02",
            expect: Ok(Time::from_timetuple(2006, 1, 2, 0, 0, 0, 0, TimeZone::utc()).unwrap()),
        },
        Case {
            s: "2006-01-02T15:04:05",
            expect: Ok(Time::from_timetuple(2006, 1, 2, 15, 4, 5, 0, TimeZone::utc()).unwrap()),
        },
        Case {
            s: "2006-01-02 15:04:05",
            expect: Ok(Time::from_timetuple(2006, 1, 2, 15, 4, 5, 0, TimeZone::utc()).unwrap()),
        },
        Case {
            s: "2006-01-02 15:04:05Z",
            expect: Ok(Time::from_timetuple(2006, 1, 2, 15, 4, 5, 0, TimeZone::utc()).unwrap()),
        },
        Case {
            s: "2006-01-02 15:04:05+00:00",
            expect: Ok(Time::from_timetuple(2006, 1, 2, 15, 4, 5, 0, TimeZone::utc()).unwrap()),
        },
        Case {
            s: "2006-01-02 15:04:05-00:00",
            expect: Ok(Time::from_timetuple(2006, 1, 2, 15, 4, 5, 0, TimeZone::utc()).unwrap()),
        },
        Case {
            s: "2006-01-02T15:04:05.999999999Z",
            expect: Ok(
                Time::from_timetuple(2006, 1, 2, 15, 4, 5, 999999999, TimeZone::utc()).unwrap(),
            ),
        },
        Case {
            s: "2006-01-02T15:04:05.123Z",
            expect: Ok(
                Time::from_timetuple(2006, 1, 2, 15, 4, 5, 123000000, TimeZone::utc()).unwrap(),
            ),
        },
        Case {
            s: "2018-09-21T16:56:44.234867232+08:00",
            expect: Ok(Time::from_timetuple(
                2018,
                9,
                21,
                16,
                56,
                44,
                234867232,
                TimeZone::new(8).unwrap(),
            ).unwrap()),
        },
    ];

    for c in cases {
        assert_eq!(parse_rfc3339(c.s), c.expect, "{}", c.s);
    }
}

#[test]
fn test_parse_rfc3339_errors() {
    struct Case<'a> {
        s: &'a str,
        expect: Result<Time, ParseError>,
    }

    let cases: Vec<Case> = vec![
        Case {
            s: "",
            expect: Err(ParseError::EmptyInput),
        },
        Case {
            s: "2006-01-0",
            expect: Err(ParseError::TooShort),
        },
        Case {
            s: "2006-01-02 15:04:5",
            expect: Err(ParseError::TooShort),
        },
        Case {
            s: "2006-01-02T15:04:05.1234567890+08:00",
            expect: Err(ParseError::TooLong),
        },
        Case {
            s: "2006-01/02T15:04:05",
            expect: Err(ParseError::Malformed),
        },
        Case {
            s: "2006-01-02F15:04:05",
            expect: Err(ParseError::Malformed),
        },
        Case {
            s: "2006-01-02 15+04:05",
            expect: Err(ParseError::Malformed),
        },
        Case {
            s: "2006-01-02 15:04:05?",
            expect: Err(ParseError::Malformed),
        },
        Case {
            s: "200A-01-02 15:04:05",
            expect: Err(ParseError::InvalidValue),
        },
        Case {
            s: "2006-A1-02 15:04:05",
            expect: Err(ParseError::InvalidValue),
        },
        Case {
            s: "2006-01-0A 15:04:05",
            expect: Err(ParseError::InvalidValue),
        },
        Case {
            s: "2006-01-02 1A:04:05",
            expect: Err(ParseError::InvalidValue),
        },
        Case {
            s: "2006-01-02 15:0A:05",
            expect: Err(ParseError::InvalidValue),
        },
        Case {
            s: "2006-01-02 15:04:A5",
            expect: Err(ParseError::InvalidValue),
        },
        Case {
            s: "2006-01-02 15:04:05.Z",
            expect: Err(ParseError::MissingValue),
        },
        Case {
            s: "2006-01-02T15:04:05.1235Z08",
            expect: Err(ParseError::InvalidTimezone),
        },
        Case {
            s: "2018-02-29T15:04:05.1235",
            expect: Err(ParseError::Overflow),
        },
    ];

    for c in cases {
        assert_eq!(parse_rfc3339(c.s), c.expect, "{}", c.s);
    }
}

#[test]
fn test_from_str() {
    assert_eq!(
        "2018-09-21T16:56:44.234867232+08:00".parse::<Time>(),
        Ok(Time::from_timetuple(
            2018,
            9,
            21,
            16,
            56,
            44,
            234867232,
            TimeZone::new(8).unwrap(),
        ).unwrap())
    );
}
