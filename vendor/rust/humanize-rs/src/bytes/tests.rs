use super::{Bytes, Unit};
use ParseError;

#[test]
fn test_parsing_strings() {
    let cases: Vec<(&str, Result<Bytes, ParseError>)> = vec![
        ("0", Ok(Bytes(0))),
        ("1", Ok(Bytes(1))),
        ("1b", Ok(Bytes(1))),
        ("1B", Ok(Bytes(1))),
        ("1 b", Ok(Bytes(1))),
        ("1 B", Ok(Bytes(1))),
        ("1 ki", Ok(Bytes(Unit::KiByte.size::<usize>().unwrap()))),
        ("1 Ki", Ok(Bytes(Unit::KiByte.size::<usize>().unwrap()))),
        ("1 kib", Ok(Bytes(Unit::KiByte.size::<usize>().unwrap()))),
        ("1 KiB", Ok(Bytes(Unit::KiByte.size::<usize>().unwrap()))),
        ("1 mi", Ok(Bytes(Unit::MiByte.size::<usize>().unwrap()))),
        ("1 Mi", Ok(Bytes(Unit::MiByte.size::<usize>().unwrap()))),
        ("1 mib", Ok(Bytes(Unit::MiByte.size::<usize>().unwrap()))),
        ("1 MiB", Ok(Bytes(Unit::MiByte.size::<usize>().unwrap()))),
        ("1 gi", Ok(Bytes(Unit::GiByte.size::<usize>().unwrap()))),
        ("1 Gi", Ok(Bytes(Unit::GiByte.size::<usize>().unwrap()))),
        ("1 gib", Ok(Bytes(Unit::GiByte.size::<usize>().unwrap()))),
        ("1 GiB", Ok(Bytes(Unit::GiByte.size::<usize>().unwrap()))),
        ("1 ti", Ok(Bytes(Unit::TiByte.size::<usize>().unwrap()))),
        ("1 Ti", Ok(Bytes(Unit::TiByte.size::<usize>().unwrap()))),
        ("1 tib", Ok(Bytes(Unit::TiByte.size::<usize>().unwrap()))),
        ("1 TiB", Ok(Bytes(Unit::TiByte.size::<usize>().unwrap()))),
        ("1 pi", Ok(Bytes(Unit::PiByte.size::<usize>().unwrap()))),
        ("1 Pi", Ok(Bytes(Unit::PiByte.size::<usize>().unwrap()))),
        ("1 pib", Ok(Bytes(Unit::PiByte.size::<usize>().unwrap()))),
        ("1 PiB", Ok(Bytes(Unit::PiByte.size::<usize>().unwrap()))),
        ("1 ei", Ok(Bytes(Unit::EiByte.size::<usize>().unwrap()))),
        ("1 Ei", Ok(Bytes(Unit::EiByte.size::<usize>().unwrap()))),
        ("1 eib", Ok(Bytes(Unit::EiByte.size::<usize>().unwrap()))),
        ("1 EiB", Ok(Bytes(Unit::EiByte.size::<usize>().unwrap()))),
        ("1 k", Ok(Bytes(Unit::KByte.size::<usize>().unwrap()))),
        ("1 K", Ok(Bytes(Unit::KByte.size::<usize>().unwrap()))),
        ("1 kb", Ok(Bytes(Unit::KByte.size::<usize>().unwrap()))),
        ("1 KB", Ok(Bytes(Unit::KByte.size::<usize>().unwrap()))),
        ("1 m", Ok(Bytes(Unit::MByte.size::<usize>().unwrap()))),
        ("1 M", Ok(Bytes(Unit::MByte.size::<usize>().unwrap()))),
        ("1 mb", Ok(Bytes(Unit::MByte.size::<usize>().unwrap()))),
        ("1 MB", Ok(Bytes(Unit::MByte.size::<usize>().unwrap()))),
        ("1 g", Ok(Bytes(Unit::GByte.size::<usize>().unwrap()))),
        ("1 G", Ok(Bytes(Unit::GByte.size::<usize>().unwrap()))),
        ("1 gb", Ok(Bytes(Unit::GByte.size::<usize>().unwrap()))),
        ("1 GB", Ok(Bytes(Unit::GByte.size::<usize>().unwrap()))),
        ("1 t", Ok(Bytes(Unit::TByte.size::<usize>().unwrap()))),
        ("1 T", Ok(Bytes(Unit::TByte.size::<usize>().unwrap()))),
        ("1 tb", Ok(Bytes(Unit::TByte.size::<usize>().unwrap()))),
        ("1 TB", Ok(Bytes(Unit::TByte.size::<usize>().unwrap()))),
        ("1 p", Ok(Bytes(Unit::PByte.size::<usize>().unwrap()))),
        ("1 P", Ok(Bytes(Unit::PByte.size::<usize>().unwrap()))),
        ("1 pb", Ok(Bytes(Unit::PByte.size::<usize>().unwrap()))),
        ("1 PB", Ok(Bytes(Unit::PByte.size::<usize>().unwrap()))),
        ("1 e", Ok(Bytes(Unit::EByte.size::<usize>().unwrap()))),
        ("1 E", Ok(Bytes(Unit::EByte.size::<usize>().unwrap()))),
        ("1 eb", Ok(Bytes(Unit::EByte.size::<usize>().unwrap()))),
        ("1 EB", Ok(Bytes(Unit::EByte.size::<usize>().unwrap()))),
        ("", Err(ParseError::EmptyInput)),
        ("EB", Err(ParseError::MissingValue)),
        ("0.5 EB", Err(ParseError::InvalidValue)),
        ("-1 EB", Err(ParseError::InvalidValue)),
        ("1 EEEEB", Err(ParseError::InvalidUnit)),
        ("100 EB", Err(ParseError::Overflow)),
    ];

    for c in cases {
        let b = c.0.parse::<Bytes>();
        assert_eq!(b, c.1);
    }
}

#[test]
fn test_int_types() {
    assert_eq!("1 B".parse::<Bytes<i8>>(), Ok(Bytes::<i8>(1)));
    assert_eq!("1 B".parse::<Bytes<u8>>(), Ok(Bytes::<u8>(1)));
    assert_eq!("1 B".parse::<Bytes<i16>>(), Ok(Bytes::<i16>(1)));
    assert_eq!("1 B".parse::<Bytes<u16>>(), Ok(Bytes::<u16>(1)));
    assert_eq!("1 B".parse::<Bytes<i32>>(), Ok(Bytes::<i32>(1)));
    assert_eq!("1 B".parse::<Bytes<u32>>(), Ok(Bytes::<u32>(1)));
    assert_eq!("1 B".parse::<Bytes<i64>>(), Ok(Bytes::<i64>(1)));
    assert_eq!("1 B".parse::<Bytes<u64>>(), Ok(Bytes::<u64>(1)));
    assert_eq!("1 B".parse::<Bytes<isize>>(), Ok(Bytes::<isize>(1)));
    assert_eq!("1 B".parse::<Bytes<usize>>(), Ok(Bytes::<usize>(1)));

    #[cfg(has_i128)]
    assert_eq!("1 B".parse::<Bytes<i128>>(), Ok(Bytes::<i128>(1)));
    #[cfg(has_i128)]
    assert_eq!("1 B".parse::<Bytes<u128>>(), Ok(Bytes::<u128>(1)));
}

#[test]
fn test_size() {
    assert_eq!("1 B".parse::<Bytes>().unwrap().size(), 1_usize);
    assert_eq!("1 B".parse::<Bytes<i8>>().unwrap().size(), 1_i8);
    assert_eq!("1 B".parse::<Bytes<u8>>().unwrap().size(), 1_u8);
    assert_eq!("1 B".parse::<Bytes<i16>>().unwrap().size(), 1_i16);
    assert_eq!("1 B".parse::<Bytes<u16>>().unwrap().size(), 1_u16);
    assert_eq!("1 B".parse::<Bytes<i32>>().unwrap().size(), 1_i32);
    assert_eq!("1 B".parse::<Bytes<u32>>().unwrap().size(), 1_u32);
    assert_eq!("1 B".parse::<Bytes<i64>>().unwrap().size(), 1_i64);
    assert_eq!("1 B".parse::<Bytes<u64>>().unwrap().size(), 1_u64);
    assert_eq!("1 B".parse::<Bytes<isize>>().unwrap().size(), 1_isize);
    assert_eq!("1 B".parse::<Bytes<usize>>().unwrap().size(), 1_usize);

    #[cfg(has_i128)]
    assert_eq!("1 B".parse::<Bytes<i128>>().unwrap().size(), 1_i128);
    #[cfg(has_i128)]
    assert_eq!("1 B".parse::<Bytes<u128>>().unwrap().size(), 1_u128);
}
