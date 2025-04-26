use super::Int;
use std::i16;

#[test]
fn test_int_from_u64() {
    let num: u64 = i16::MAX as u64;

    let res_i8: Option<i8> = Int::from_u64(num);
    let res_i32: Option<i32> = Int::from_u64(num);

    assert_eq!(res_i8, None);
    assert_eq!(res_i32, Some(i16::MAX as i32));
}
