use super::parse;
use std::time::Duration;
use ParseError;

#[test]
fn test_parse_duration_units() {
    assert_eq!(parse("1d"), Ok(Duration::from_secs(86400)));
    assert_eq!(parse("1h"), Ok(Duration::from_secs(3600)));
    assert_eq!(parse("1m"), Ok(Duration::from_secs(60)));
    assert_eq!(parse("1s"), Ok(Duration::from_secs(1)));
    assert_eq!(parse("1ms"), Ok(Duration::from_millis(1)));
    assert_eq!(parse("1us"), Ok(Duration::from_micros(1)));
    assert_eq!(parse("1ns"), Ok(Duration::from_nanos(1)));

    assert_eq!(parse("0d"), Ok(Duration::new(0, 0)));
    assert_eq!(parse("0h"), Ok(Duration::new(0, 0)));
    assert_eq!(parse("0m"), Ok(Duration::new(0, 0)));
    assert_eq!(parse("0s"), Ok(Duration::new(0, 0)));
    assert_eq!(parse("0ms"), Ok(Duration::new(0, 0)));
    assert_eq!(parse("0us"), Ok(Duration::new(0, 0)));
    assert_eq!(parse("0ns"), Ok(Duration::new(0, 0)));
    assert_eq!(parse("0"), Ok(Duration::new(0, 0)));
}

#[test]
fn test_parse_duration_multi_parts() {
    assert_eq!(parse("1d12h"), Ok(Duration::from_secs(86400 / 2 * 3)));
    assert_eq!(parse("1h50m"), Ok(Duration::from_secs(60 * 110)));
    assert_eq!(parse("3m20s"), Ok(Duration::from_secs(60 * 3 + 20)));

    assert_eq!(parse("1d 12h"), Ok(Duration::from_secs(86400 / 2 * 3)));
    assert_eq!(parse("1h 50m"), Ok(Duration::from_secs(60 * 110)));
    assert_eq!(parse("3m 20s"), Ok(Duration::from_secs(60 * 3 + 20)));

    assert_eq!(
        parse("1d 12h 120s"),
        Ok(Duration::from_secs(86400 / 2 * 3 + 120))
    );
    assert_eq!(
        parse("1h 50m 35ms"),
        Ok(Duration::new(60 * 110, 35 * 1_000_000))
    );
    assert_eq!(parse("3m 20s 100ns"), Ok(Duration::new(60 * 3 + 20, 100)));
}

#[test]
fn test_parse_errors() {
    assert_eq!(parse(""), Err(ParseError::EmptyInput));
    assert_eq!(parse("1"), Err(ParseError::MissingUnit));
    assert_eq!(parse("s"), Err(ParseError::MissingValue));
    assert_eq!(parse("1ss"), Err(ParseError::InvalidUnit));
    assert_eq!(parse("1 中文"), Err(ParseError::InvalidUnit));

    assert_eq!(parse("100000000000000000000ns"), Err(ParseError::Overflow));
    assert_eq!(parse("100000000000000000us"), Err(ParseError::Overflow));
    assert_eq!(parse("100000000000000ms"), Err(ParseError::Overflow));

    assert_eq!(parse("100000000000000000000s"), Err(ParseError::Overflow));
    assert_eq!(parse("10000000000000000000m"), Err(ParseError::Overflow));
    assert_eq!(parse("1000000000000000000h"), Err(ParseError::Overflow));
    assert_eq!(parse("100000000000000000d"), Err(ParseError::Overflow));
}
