## humanize-rs
[![Crates.io](https://img.shields.io/crates/v/humanize-rs.svg)](https://crates.io/crates/humanize-rs)
[![Docs](https://docs.rs/humanize-rs/badge.svg)](https://docs.rs/humanize-rs)

This lib aims at converting human-readable strings to specific types.

It's mainly used in parsing config files.

### Usage
1. Add this lib as a dependency
```
[dependencies]
humanize-rs = "0.1"
```

2. Add the crate reference
```
extern crate humanize_rs;
```


### Example


#### Bytes
```
use humanize_rs::bytes::{Bytes, Unit};

let gigabytes1 = Bytes::new(1, Unit::GiByte);
let gigabytes2 = "1 GiB".parse::<Bytes>();
assert_eq!(gigabytes1, gigabytes2);
assert_eq!(gigabytes2.unwrap().size(), 1 << 30);
```

#### Duration
```
use humanize_rs::duration::parse;
use std::time::Duration;

assert_eq!(parse("1h 30m 71s"), Ok(Duration::from_secs(60 * 90 + 71)));
```

#### RFC3339 Datetime
```
use humanize_rs::time::{Time, TimeZone};

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
```


### Contributing

Any PRs or issues are welcomed.
