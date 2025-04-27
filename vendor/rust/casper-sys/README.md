# capsicum

[![Current Version](https://img.shields.io/crates/v/capsicum.svg)](https://crates.io/crates/capsicum)

## Contain the awesome!

Rust bindings for the FreeBSD [capsicum](https://www.freebsd.org/cgi/man.cgi?query=capsicum)
framework for OS capability and sandboxing

## Prerequisites

[Rust](https://www.rust-lang.org/), [Cargo](https://crates.io/), and [FreeBSD](https://www.freebsd.org/).

**Note:** This currently only compiles on FreeBSD

## Getting Started

### Get the code

```
git clone https://github.com/danlrobertson/capsicum-rs
cd capsicum-rs
cargo build
```

### Writing code using `capsicum-rs`

#### Entering capability mode

```rust
    use capsicum::{enter, sandboxed};
    use std::fs::File;
    use std::io::Read;

    let mut ok_file = File::open("/tmp/foo").unwrap();
    let mut s = String::new();

    enter().expect("enter failed!");
    assert!(sandboxed(), "application is not sandboxed!");

    match File::create("/tmp/cant_touch_this") {
        Ok(_) => panic!("application is not properly sandboxed!"),
        Err(e) => println!("properly sandboxed: {:?}", e)
    }

    match ok_file.read_to_string(&mut s) {
        Ok(_) => println!("This is okay since we opened the descriptor before sandboxing"),
        Err(_) => panic!("application is not properly sandboxed!")
    }
```

#### Limit capability rights to files

```rust
    use capsicum::{CapRights, Right, RightsBuilder};
    use std::fs::File;
    use std::io::Read;

    let x = rand::random::<bool>();
    
    let mut ok_file = File::open("/tmp/foo").unwrap();
    let mut s = String::new();
    
    let mut builder = RightsBuilder::new(Right::Seek);
    
    if x {
        builder.add(Right::Read);
    }

    let rights = builder.finalize().unwrap();

    rights.limit(&ok_file).unwrap();
    
    match ok_file.read_to_string(&mut s) {
        Ok(_) if x => println!("Allowed reading: x = {} ", x),
        Err(_) if !x => println!("Did not allow reading: x = {}", x),
        _ => panic!("Not properly sandboxed"),
    }
```
