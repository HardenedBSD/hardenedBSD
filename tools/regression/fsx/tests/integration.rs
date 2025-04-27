// vim: tw=80

use std::{ffi::CString, fs, io::Write, process::Command};

use assert_cmd::{cargo::cargo_bin, prelude::*};
use pretty_assertions::assert_eq;
use rstest::rstest;
use tempfile::{NamedTempFile, TempDir};

/// Test that fsx-rs's testing sequence is stable, and identical to the C-based
/// FSX's as of FreeBSD 14.0.
#[rstest]
// Equivalent to C's fsx -N 10 -S 4 -o 65536 -O.  Includes both MapRead
// and MapWrite.
#[case::sixtyfourk_ops(
    "[opsize]
     min = 65536
     max = 65536",
    "-N10 -S 2",
    "[DEBUG fsx] Using seed 2
[INFO  fsx]  1 mapwrite 0x17dbf .. 0x27dbe (0x10000 bytes)
[INFO  fsx]  2 read     0x216ce .. 0x27dbe ( 0x66f1 bytes)
[INFO  fsx]  3 write    0x2309f .. 0x3309e (0x10000 bytes)
[INFO  fsx]  4 read     0x1ba2b .. 0x2ba2a (0x10000 bytes)
[INFO  fsx]  5 mapread   0xf8f5 .. 0x1f8f4 (0x10000 bytes)
[INFO  fsx]  6 write    0x196ff .. 0x296fe (0x10000 bytes)
[INFO  fsx]  7 mapread  0x32da7 .. 0x3309e (  0x2f8 bytes)
[INFO  fsx]  8 truncate 0x3309f => 0x2eb10
[INFO  fsx]  9 mapwrite 0x3c53a .. 0x3ffff ( 0x3ac6 bytes)
[INFO  fsx] 10 mapwrite 0x119bb .. 0x219ba (0x10000 bytes)
"
)]
// Equivalent to C's fsx -N 10 -S 2 -o 65536 -O -RW.  Disables mmapped read and
// write.
#[case::no_mmap(
    "[opsize]
     min = 65536
     max = 65536
     [weights]
     mapread = 0
     mapwrite = 0
     read = 1
     write = 1
     truncate = 1",
    "-N10 -S 2",
    "[DEBUG fsx] Using seed 2
[INFO  fsx]  1 truncate     0x0 => 0x32aab
[INFO  fsx]  2 truncate 0x32aab =>  0xf651
[INFO  fsx]  3 truncate  0xf651 => 0x19f9c
[INFO  fsx]  4 write    0x2ba51 .. 0x3ba50 (0x10000 bytes)
[INFO  fsx]  5 write    0x2147b .. 0x3147a (0x10000 bytes)
[INFO  fsx]  6 truncate 0x3ba51 =>  0x7315
[INFO  fsx]  7 write    0x14b4f .. 0x24b4e (0x10000 bytes)
[INFO  fsx]  8 read      0xee93 .. 0x1ee92 (0x10000 bytes)
[INFO  fsx]  9 write    0x3f395 .. 0x3ffff (  0xc6b bytes)
[INFO  fsx] 10 write    0x3c53a .. 0x3ffff ( 0x3ac6 bytes)
"
)]
// Equivalent to C's fsx -N 10 -d -S 9 -o 65536 -O.  Includes both truncate
// down and truncate up.
#[case::truncate(
    "[opsize]
     min = 65536
     max = 65536",
    "-N10 -S 9",
    "[DEBUG fsx] Using seed 9
[DEBUG fsx]  1 skipping zero size read
[INFO  fsx]  2 truncate     0x0 => 0x2423e
[INFO  fsx]  3 mapwrite 0x2b9f0 .. 0x3b9ef (0x10000 bytes)
[INFO  fsx]  4 truncate 0x3b9f0 => 0x12104
[INFO  fsx]  5 write    0x3a59d .. 0x3ffff ( 0x5a63 bytes)
[INFO  fsx]  6 mapwrite  0x138b .. 0x1138a (0x10000 bytes)
[INFO  fsx]  7 mapread  0x334c8 .. 0x3ffff ( 0xcb38 bytes)
[INFO  fsx]  8 mapread   0x4d50 .. 0x14d4f (0x10000 bytes)
[INFO  fsx]  9 read     0x3c386 .. 0x3ffff ( 0x3c7a bytes)
[INFO  fsx] 10 mapread  0x3ebc3 .. 0x3ffff ( 0x143d bytes)
"
)]
// Equivalent to C's fsx -b 100 -N 110 -S 4 -o 65536 -O. Uses "-b"
#[case::opnum(
    "[opsize]
     min = 65536
     max = 65536",
    "-N 110 -b 100 -S 4",
    "[DEBUG fsx] Using seed 4
[DEBUG fsx]   1 skipping zero size read
[DEBUG fsx]   2 skipping zero size read
[DEBUG fsx]   3 skipping zero size read
[DEBUG fsx]   4 skipping zero size read
[DEBUG fsx]   5 skipping zero size read
[DEBUG fsx]   6 skipping zero size read
[INFO  fsx] 100 truncate 0x2b4f5 =>  0xb098
[INFO  fsx] 101 read      0xa71b ..  0xb097 (  0x97d bytes)
[INFO  fsx] 102 mapread   0x7b34 ..  0xb097 ( 0x3564 bytes)
[INFO  fsx] 103 mapwrite 0x1dc30 .. 0x2dc2f (0x10000 bytes)
[INFO  fsx] 104 mapread  0x21f8c .. 0x2dc2f ( 0xbca4 bytes)
[INFO  fsx] 105 read     0x23629 .. 0x2dc2f ( 0xa607 bytes)
[INFO  fsx] 106 mapwrite  0x8dd8 .. 0x18dd7 (0x10000 bytes)
[INFO  fsx] 107 mapread   0x8b44 .. 0x18b43 (0x10000 bytes)
[INFO  fsx] 108 mapread   0x9f4b .. 0x19f4a (0x10000 bytes)
[INFO  fsx] 109 mapread  0x27b0b .. 0x2dc2f ( 0x6125 bytes)
[INFO  fsx] 110 truncate 0x2dc30 => 0x35f5f
"
)]
// Equivalent to C's fsx -N 2 -S 13 -o 65536 -O -c 2
// Exercises closeopen
#[case::closeopen(
    "[opsize]
     min = 65536
     max = 65536
     [weights]
     close_open = 100",
    "-N 1 -S 13",
    "[DEBUG fsx] Using seed 13
[INFO  fsx] 1 close/open
"
)]
// Equivalent to C's fsx -N 2 -S 20
// Uses random oplen
#[case::baseline(
    "",
    "-N10 -S 20",
    "[DEBUG fsx] Using seed 20
[DEBUG fsx]  1 skipping zero size read
[DEBUG fsx]  2 skipping zero size read
[INFO  fsx]  3 write    0x202a1 .. 0x20407 (  0x167 bytes)
[INFO  fsx]  4 write     0x6798 ..  0xcb41 ( 0x63aa bytes)
[INFO  fsx]  5 truncate 0x20408 => 0x2442d
[INFO  fsx]  6 write    0x20d0c .. 0x27672 ( 0x6967 bytes)
[INFO  fsx]  7 read      0x2f75 ..  0xfb0b ( 0xcb97 bytes)
[INFO  fsx]  8 mapread  0x24f47 .. 0x27672 ( 0x272c bytes)
[INFO  fsx]  9 write    0x1c0c3 .. 0x2ac4f ( 0xeb8d bytes)
[INFO  fsx] 10 mapwrite  0x6ed1 ..  0xcc12 ( 0x5d42 bytes)
"
)]
// Equivalent to C's fsx -N 10 -S 20 -U
// Exercises -U, though that doesn't change the output
#[case::nomsyncafterwrite(
    "nomsyncafterwrite = true",
    "-N10 -S20",
    "[DEBUG fsx] Using seed 20
[DEBUG fsx]  1 skipping zero size read
[DEBUG fsx]  2 skipping zero size read
[INFO  fsx]  3 write    0x202a1 .. 0x20407 (  0x167 bytes)
[INFO  fsx]  4 write     0x6798 ..  0xcb41 ( 0x63aa bytes)
[INFO  fsx]  5 truncate 0x20408 => 0x2442d
[INFO  fsx]  6 write    0x20d0c .. 0x27672 ( 0x6967 bytes)
[INFO  fsx]  7 read      0x2f75 ..  0xfb0b ( 0xcb97 bytes)
[INFO  fsx]  8 mapread  0x24f47 .. 0x27672 ( 0x272c bytes)
[INFO  fsx]  9 write    0x1c0c3 .. 0x2ac4f ( 0xeb8d bytes)
[INFO  fsx] 10 mapwrite  0x6ed1 ..  0xcc12 ( 0x5d42 bytes)
"
)]
// Equivalent to C's fsx -N 10 -S 30 -o 4096
// Exercises opsize.max
#[case::oplen(
    "[opsize]
     min = 0
     max = 4096",
    "-N 10 -S 30",
    "[DEBUG fsx] Using seed 30
[INFO  fsx]  1 mapwrite 0x21c83 .. 0x2232d ( 0x6ab bytes)
[INFO  fsx]  2 mapread  0x115e9 .. 0x11da7 ( 0x7bf bytes)
[INFO  fsx]  3 truncate 0x2232e => 0x16494
[INFO  fsx]  4 write    0x2568f .. 0x263da ( 0xd4c bytes)
[INFO  fsx]  5 mapread   0xaa7c ..  0xb5fe ( 0xb83 bytes)
[INFO  fsx]  6 write    0x108ee .. 0x10dae ( 0x4c1 bytes)
[INFO  fsx]  7 read      0xf806 ..  0xfd1a ( 0x515 bytes)
[INFO  fsx]  8 truncate 0x263db => 0x1a27d
[INFO  fsx]  9 mapwrite 0x17b4b .. 0x18934 ( 0xdea bytes)
[INFO  fsx] 10 mapread   0x9a99 ..  0xa000 ( 0x568 bytes)
"
)]
// Equivalent to C's fsx -N 10 -S 50 -l 1048576
// Exercises flen
#[case::flen(
    "flen = 1048576",
    "-N 10 -S 56",
    "[DEBUG fsx] Using seed 56
[DEBUG fsx]  1 skipping zero size read
[INFO  fsx]  2 write     0xcfb9a ..  0xdc46b ( 0xc8d2 bytes)
[INFO  fsx]  3 mapwrite  0xff116 ..  0xfffff (  0xeea bytes)
[INFO  fsx]  4 mapread   0x9a519 ..  0xa7667 ( 0xd14f bytes)
[INFO  fsx]  5 write      0xa51a ..   0xf359 ( 0x4e40 bytes)
[INFO  fsx]  6 read      0xcb8e3 ..  0xd5a23 ( 0xa141 bytes)
[INFO  fsx]  7 read      0x24dfa ..  0x2abd5 ( 0x5ddc bytes)
[INFO  fsx]  8 write       0x5fb ..   0x30f9 ( 0x2aff bytes)
[INFO  fsx]  9 truncate 0x100000 =>  0xaf4f4
[INFO  fsx] 10 read      0x609f2 ..  0x65b0c ( 0x511b bytes)
"
)]
// Equivalent to C's fsx -N 10 -S 42 -N 10 -i 2
// Exercises -i
#[case::inval(
    "[weights]
    invalidate = 10",
    "-N 10 -S 42",
    "[DEBUG fsx] Using seed 42
[DEBUG fsx]  1 skipping zero size read
[DEBUG fsx]  2 skipping invalidate of zero-length file
[DEBUG fsx]  3 skipping zero size read
[INFO  fsx]  4 truncate     0x0 => 0x2e4c0
[INFO  fsx]  5 msync(MS_INVALIDATE)
[INFO  fsx]  6 truncate 0x2e4c0 => 0x3cad8
[INFO  fsx]  7 read     0x3416a .. 0x3cad7 ( 0x896e bytes)
[INFO  fsx]  8 mapread  0x16b78 .. 0x18c4b ( 0x20d4 bytes)
[INFO  fsx]  9 mapread  0x2cf1c .. 0x32605 ( 0x56ea bytes)
[INFO  fsx] 10 mapread   0xd0c6 .. 0x12b21 ( 0x5a5c bytes)
"
)]
// Equivalent to C's fsx -N 1 -i 1 -S 10
// https://github.com/asomers/fsx-rs/issues/13
#[case::mmap_underflow(
    "[weights]
    invalidate = 1000",
    "-N 1 -S 10",
    "[DEBUG fsx] Using seed 10
[DEBUG fsx] 1 skipping invalidate of zero-length file
"
)]
// Equivalent to C's fsx -N 10 -S 46 -r 4096
// Exercises -r
#[case::align(
    "[opsize]
    align = 4096",
    "-N 10 -S 46",
    "[DEBUG fsx] Using seed 46
[INFO  fsx]  1 mapwrite 0x2e000 .. 0x31fff ( 0x4000 bytes)
[INFO  fsx]  2 write    0x18000 .. 0x1cfff ( 0x5000 bytes)
[INFO  fsx]  3 read     0x1e000 .. 0x27fff ( 0xa000 bytes)
[INFO  fsx]  4 mapread  0x1f000 .. 0x21fff ( 0x3000 bytes)
[INFO  fsx]  5 truncate 0x32000 => 0x1180e
[INFO  fsx]  6 read      0xd000 .. 0x10fff ( 0x4000 bytes)
[INFO  fsx]  7 mapread   0x1000 ..  0xdfff ( 0xd000 bytes)
[INFO  fsx]  8 mapwrite  0x9000 ..  0xafff ( 0x2000 bytes)
[INFO  fsx]  9 read      0xc000 ..  0xdfff ( 0x2000 bytes)
[INFO  fsx] 10 read     0x10000 .. 0x10fff ( 0x1000 bytes)
"
)]
// Equivalent to C's fsx -N 10 -S 68 -m 32768:65536
// Exercises -m
#[case::monitor(
    "",
    "-N 10 -S 68 -m 32768:65536",
    "[DEBUG fsx] Using seed 68
[DEBUG fsx]  1 skipping zero size read
[DEBUG fsx]  2 skipping zero size read
[DEBUG fsx]  3 skipping zero size read
[DEBUG fsx]  4 skipping zero size read
[INFO  fsx]  5 write    0x127e6 .. 0x1730a ( 0x4b25 bytes)
[INFO  fsx]  6 mapwrite 0x3a97f .. 0x3ffff ( 0x5681 bytes)
[INFO  fsx]  7 truncate 0x40000 => 0x1a45e
[WARN  fsx]  8 mapread   0x40f3 ..  0xe8fb ( 0xa809 bytes)
[INFO  fsx]  9 write    0x1defe .. 0x2100e ( 0x3111 bytes)
[WARN  fsx] 10 mapread   0x159c ..  0xed17 ( 0xd77c bytes)
"
)]
// Equivalent to C's fsx -S 72 -L -N 10
// Exercises -B
#[case::blockmode(
    "blockmode = true
    [weights]
    truncate = 0",
    "-S 72 -N 10 -P /tmp",
    "[DEBUG fsx] Using seed 72
[INFO  fsx]  1 write     0xc0405 ..  0xc2ac7 ( 0x26c3 bytes)
[INFO  fsx]  2 mapwrite  0x77eb8 ..  0x78c78 (  0xdc1 bytes)
[INFO  fsx]  3 read      0x323d0 ..  0x37cd9 ( 0x590a bytes)
[INFO  fsx]  4 read      0xb8dbb ..  0xc2342 ( 0x9588 bytes)
[INFO  fsx]  5 read      0x45efa ..  0x4d083 ( 0x718a bytes)
[INFO  fsx]  6 mapwrite  0x926be ..  0xa06d8 ( 0xe01b bytes)
[INFO  fsx]  7 mapwrite  0x2656c ..  0x35a66 ( 0xf4fb bytes)
[INFO  fsx]  8 mapread   0xb3066 ..  0xb9a9c ( 0x6a37 bytes)
[INFO  fsx]  9 mapread   0x7296b ..  0x7b6f8 ( 0x8d8e bytes)
[INFO  fsx] 10 read      0x58941 ..  0x5b149 ( 0x2809 bytes)
"
)]
fn stability(#[case] conf: &str, #[case] args: &str, #[case] stderr: &str) {
    let mut cf = NamedTempFile::new().unwrap();
    cf.write_all(conf.as_bytes()).unwrap();

    let mut tf = NamedTempFile::new().unwrap();

    if conf.contains("blockmode = true") {
        // When using -B, must manually set file size before starting program
        // Set flen higher than default
        // https://github.com/asomers/fsx-rs/issues/13
        tf.as_file_mut().set_len(1048576).unwrap();
    }

    let cmd = Command::new(cargo_bin!("fsx"))
        .args(args.split_ascii_whitespace())
        .args(["-vv", "-f"])
        .arg(cf.path())
        .arg(tf.path())
        .assert()
        .success();
    let actual_stderr = CString::new(cmd.get_output().stderr.clone())
        .unwrap()
        .into_string()
        .unwrap();
    assert_eq!(stderr, actual_stderr);
}

#[cfg_attr(not(target_os = "freebsd"), allow(unused))]
#[rstest]
fn miscompare() {
    let tf = NamedTempFile::new().unwrap();

    let cmd = Command::new(cargo_bin!("fsx"))
        .args(["-vv", "-N10", "-S10", "--inject", "3"])
        .arg(tf.path())
        .assert()
        .failure();
    #[cfg(target_os = "freebsd")] // Depends on exact PRNG output
    {
        let actual_stderr = CString::new(cmd.get_output().stderr.clone())
            .unwrap()
            .into_string()
            .unwrap();
        assert_eq!(
            "[DEBUG fsx] Using seed 10
[DEBUG fsx]  1 skipping zero size read
[INFO  fsx]  2 truncate     0x0 => 0x19efd
[INFO  fsx]  4 truncate 0x19efd => 0x1cb67
[INFO  fsx]  5 mapread   0xe279 .. 0x10931 ( 0x26b9 bytes)
[ERROR fsx] miscompare: offset= 0xe279, size = 0x26b9
[ERROR fsx] OFFSET  GOOD  BAD  RANGE  
[ERROR fsx]  0xe279 0xd1 0x00  0x26a9
[ERROR fsx] Step# for the bad data is unknown; check HOLE and EXTEND ops
[ERROR fsx] Using seed 10
[ERROR fsx] LOG DUMP
[ERROR fsx]  1 SKIPPED  (read)
[ERROR fsx]  2 TRUNCATE  UP   from     0x0 to 0x19efd
[ERROR fsx]  3 WRITE     0xda28 => 0x14205 ( 0x67dd bytes)
[ERROR fsx]  4 TRUNCATE  UP   from 0x19efd to 0x1cb67
[ERROR fsx]  5 MAPREAD   0xe279 => 0x10932 ( 0x26b9 bytes)
",
            actual_stderr
        );
    }
    // There should be a .fsxgood artifact
    let mut fsxgoodfname = tf.path().to_owned();
    let mut final_component = fsxgoodfname.file_name().unwrap().to_owned();
    final_component.push(".fsxgood");
    fsxgoodfname.set_file_name(final_component);
    assert_eq!(fs::metadata(&fsxgoodfname).unwrap().len(), 262144);

    // finally, clean it up.
    fs::remove_file(&fsxgoodfname).unwrap();
}

#[test]
fn artifacts_dir() {
    let tf = NamedTempFile::new().unwrap();
    let artifacts_dir = TempDir::new().unwrap();

    Command::new(cargo_bin!("fsx"))
        .args(["-vv", "-N2", "-S11", "--inject", "1", "-P"])
        .arg(artifacts_dir.path())
        .arg(tf.path())
        .assert()
        .failure();
    // Don't bother checking stderr; we cover that in the miscompare test.  Here
    // we're just checking the location of the artifacts.

    // Check the location of the .fsxgood artifact
    let mut fsxgoodfname = artifacts_dir.path().to_owned();
    let mut final_component = tf.path().file_name().unwrap().to_owned();
    final_component.push(".fsxgood");
    fsxgoodfname.push(final_component);
    assert_eq!(fs::metadata(&fsxgoodfname).unwrap().len(), 262144);

    // finally, clean it up.
    fs::remove_file(&fsxgoodfname).unwrap();
}

// https://github.com/asomers/fsx-rs/issues/20
#[test]
fn blockmode_zero() {
    let mut cf = NamedTempFile::new().unwrap();
    cf.write_all(
        b"blockmode = true
[weights]
truncate = 0",
    )
    .unwrap();

    let tf = NamedTempFile::new().unwrap();
    let artifacts_dir = TempDir::new().unwrap();

    let cmd = Command::new(cargo_bin!("fsx"))
        .args(["-N2", "-S72", "-P"])
        .arg(artifacts_dir.path())
        .arg(tf.path())
        .arg("-f")
        .arg(cf.path())
        .assert()
        .failure();

    let actual_stderr = CString::new(cmd.get_output().stderr.clone())
        .unwrap()
        .into_string()
        .unwrap();
    assert_eq!(
        actual_stderr,
        "[ERROR fsx] ERROR: file length must be greater than zero
"
    );
}

/// flen is optional with blockmode, but can be used to limit RAM consumption
#[test]
fn blockmode_flen() {
    let mut cf = NamedTempFile::new().unwrap();
    cf.write_all(
        b"blockmode = true
flen = 131072
[weights]
truncate = 0",
    )
    .unwrap();

    let mut tf = NamedTempFile::new().unwrap();
    tf.as_file_mut().set_len(1 << 40).unwrap(); // 1 TiB
    let artifacts_dir = TempDir::new().unwrap();

    Command::new(cargo_bin!("fsx"))
        .args(["-N1", "-S72", "-P"])
        .arg(artifacts_dir.path())
        .arg(tf.path())
        .arg("-f")
        .arg(cf.path())
        .assert()
        .success();
    // Don't bother checking stderr.  If the flen option isn't handled
    // correctly, fsx will either report failure or else consume 1 TiB of RAM.
}

/// Checks that the weights are assigned in the correct order, for operations
/// that must read.
#[rstest]
#[case::read(
    "[weights]\nread = 1000000",
    "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 read        0x0 .. 0x1fff ( 0x2000 bytes)
"
)]
#[case::mapread(
    "[weights]\nmapread = 1000000",
    "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 mapread     0x0 .. 0x1fff ( 0x2000 bytes)
"
)]
#[case::invalidate(
    "[weights]\ninvalidate = 1000000",
    "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 msync(MS_INVALIDATE)
"
)]
#[cfg_attr(
    not(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
    )),
    ignore
)]
#[case::sendfile(
    "[weights]\nsendfile = 1000000",
    "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 sendfile    0x0 .. 0x1fff ( 0x2000 bytes)
"
)]
#[cfg_attr(
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd"
    )),
    ignore
)]
#[case::posix_fadvise(
    "[weights]\nposix_fadvise = 1000000",
    "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 posix_fadvise(WillNeed  )    0x0 .. 0x1fff ( 0x2000 bytes)
"
)]
#[cfg_attr(not(any(target_os = "linux", target_os = "freebsd")), ignore)]
#[case::copy_file_range(
    "[weights]\ncopy_file_range = 1000000",
    "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 copy_file_range [   0x0: 0xfff] => [0x1000:0x1fff] ( 0x1000 \
     bytes)
"
)]
fn read_weights(#[case] wconf: &str, #[case] stderr: &str) {
    let mut cf = NamedTempFile::new().unwrap();
    let conf = format!(
        "blockmode=true\n[opsize]\nalign=4096\nmin=4096\n{wconf}\ntruncate = \
         0.0"
    );
    cf.write_all(conf.as_bytes()).unwrap();

    let mut tf = NamedTempFile::new().unwrap();
    tf.as_file_mut().set_len(8192).unwrap();

    let cmd = Command::new(cargo_bin!("fsx"))
        .args(["-vv", "-S", "200", "-N", "1", "-P", "/tmp"])
        .arg("-f")
        .arg(cf.path())
        .arg(tf.path())
        .assert()
        .success();
    let actual_stderr = CString::new(cmd.get_output().stderr.clone())
        .unwrap()
        .into_string()
        .unwrap();
    assert_eq!(stderr, actual_stderr);
}

/// Checks that the weights are assigned in the correct order
#[rstest]
#[case::close_open(
    "[weights]\nclose_open = 1000000",
    "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 close/open
"
)]
#[case::write(
    "[weights]\nwrite = 1000000",
    "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 write    0x18004 .. 0x1a03a ( 0x2037 bytes)
"
)]
#[case::mapwrite(
    "[weights]\nmapwrite = 1000000",
    "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 mapwrite 0x18004 .. 0x1a03a ( 0x2037 bytes)
"
)]
#[case::truncate(
    "[weights]\ntruncate = 1000000",
    "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 truncate     0x0 => 0x11184
"
)]
#[case::fsync(
    "[weights]\nfsync = 1000000",
    "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 fsync
"
)]
#[case::fdatasync(
    "[weights]\nfdatasync = 1000000",
    "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 fdatasync
"
)]
fn weights(#[case] wconf: &str, #[case] stderr: &str) {
    let mut cf = NamedTempFile::new().unwrap();
    cf.write_all(wconf.as_bytes()).unwrap();

    let tf = NamedTempFile::new().unwrap();

    let cmd = Command::new(cargo_bin!("fsx"))
        .args(["-vv", "-S", "200", "-N", "1"])
        .arg("-f")
        .arg(cf.path())
        .arg(tf.path())
        .assert()
        .success();
    let actual_stderr = CString::new(cmd.get_output().stderr.clone())
        .unwrap()
        .into_string()
        .unwrap();
    assert_eq!(stderr, actual_stderr);
}

#[test]
#[cfg_attr(
    not(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "emscripten",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "linux"
    )),
    ignore
)]
fn posix_fallocate() {
    let mut cf = NamedTempFile::new().unwrap();
    cf.write_all(b"[weights]\nposix_fallocate=1000000").unwrap();

    let tf = NamedTempFile::new().unwrap();

    let mut cmd = Command::new(cargo_bin!("fsx"));
    cmd.args(["-vv", "-S", "200", "-N", "1"])
        .arg("-f")
        .arg(cf.path())
        .arg(tf.path());
    let result = cmd.ok();
    match result {
        Ok(r) => {
            // fsx passed.  Now check its output
            let actual_stderr =
                CString::new(r.stderr).unwrap().into_string().unwrap();
            let expected = "[DEBUG fsx] Using seed 200
[INFO  fsx] 1 posix_fallocate 0x18004 .. 0x1a03a ( 0x2037 bytes)
";
            assert_eq!(expected, actual_stderr);
        }
        Err(e) => {
            let actual_stderr =
                CString::new(e.as_output().unwrap().stderr.clone())
                    .unwrap()
                    .into_string()
                    .unwrap();
            if actual_stderr
                .contains("Test file system does not support posix_fallocate.")
            {
                // XXX It would be nice if we could report a "skipped" status
                eprintln!("Skipped(posix_fallocate unsupported)");
            } else {
                panic!("{e}");
            }
        }
    }
}

/// Exercise all advice types.
#[test]
#[cfg_attr(
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd"
    )),
    ignore
)]
fn posix_fadvise() {
    let mut cf = NamedTempFile::new().unwrap();
    cf.write_all(b"[weights]\nposix_fadvise=1000000").unwrap();

    let tf = NamedTempFile::new().unwrap();

    let mut cmd = Command::new(cargo_bin!("fsx"));
    cmd.args(["-vv", "-N", "6", "-S", "12318153001044186923"])
        .arg("-f")
        .arg(cf.path())
        .arg(tf.path());
    let r = cmd.ok().unwrap();
    let actual_stderr = CString::new(r.stderr).unwrap().into_string().unwrap();
    let expected = "[DEBUG fsx] Using seed 12318153001044186923
[INFO  fsx] 1 posix_fadvise(Sequential)     0x0 ..     0x0 (    0x0 bytes)
[INFO  fsx] 2 posix_fadvise(NoReuse   )     0x0 ..     0x0 (    0x0 bytes)
[INFO  fsx] 3 posix_fadvise(Random    )     0x0 ..     0x0 (    0x0 bytes)
[INFO  fsx] 4 posix_fadvise(WillNeed  )     0x0 ..     0x0 (    0x0 bytes)
[INFO  fsx] 5 posix_fadvise(DontNeed  )     0x0 ..     0x0 (    0x0 bytes)
[INFO  fsx] 6 posix_fadvise(Normal    )     0x0 ..     0x0 (    0x0 bytes)
";
    assert_eq!(expected, actual_stderr);
}

#[cfg_attr(
    not(any(
        have_fspacectl,
        target_os = "android",
        target_os = "emscripten",
        target_os = "fuchsia",
        target_os = "linux"
    )),
    ignore
)]
#[test]
fn punch_hole() {
    let mut cf = NamedTempFile::new().unwrap();
    cf.write_all(
        b"[weights]\npunch_hole=10\nmapread=0\nmapwrite=0\ntruncate=0",
    )
    .unwrap();

    let tf = NamedTempFile::new().unwrap();

    let cmd = Command::new(cargo_bin!("fsx"))
        .args(["-vv", "-S", "301", "-N", "10", "-P", "/tmp", "-f"])
        .arg(cf.path())
        .arg(tf.path())
        .assert()
        .success();
    let actual_stderr = CString::new(cmd.get_output().stderr.clone())
        .unwrap()
        .into_string()
        .unwrap();
    let expected: &str = "[DEBUG fsx] Using seed 301
[INFO  fsx]  1 write    0x31a71 .. 0x32208 (  0x798 bytes)
[INFO  fsx]  2 write    0x1b01b .. 0x2a456 ( 0xf43c bytes)
[INFO  fsx]  3 read     0x2a547 .. 0x32208 ( 0x7cc2 bytes)
[INFO  fsx]  4 punch_hole  0xe1a3 .. 0x1a7bb ( 0xc619 bytes)
[INFO  fsx]  5 read      0x2df9 .. 0x11e7c ( 0xf084 bytes)
[INFO  fsx]  6 punch_hole 0x2794a .. 0x32208 ( 0xa8bf bytes)
[INFO  fsx]  7 write    0x2a1af .. 0x2a72c (  0x57e bytes)
[INFO  fsx]  8 read     0x1eba8 .. 0x21a49 ( 0x2ea2 bytes)
[INFO  fsx]  9 read     0x2298f .. 0x2bf0a ( 0x957c bytes)
[INFO  fsx] 10 punch_hole  0x6e88 ..  0xac44 ( 0x3dbd bytes)
";
    assert_eq!(expected, actual_stderr);
}

/// During punch hole, monitor affected byte ranges
#[cfg_attr(
    not(any(
        have_fspacectl,
        target_os = "android",
        target_os = "emscripten",
        target_os = "fuchsia",
        target_os = "linux"
    )),
    ignore
)]
#[test]
fn punch_hole_monitor() {
    let mut cf = NamedTempFile::new().unwrap();
    cf.write_all(
        b"[weights]\npunch_hole=3\nread=0\nwrite=0\nmapread=0\nmapwrite=0\ntruncate=1",
    )
    .unwrap();

    let tf = NamedTempFile::new().unwrap();

    let cmd = Command::new(cargo_bin!("fsx"))
        .args([
            "-vv",
            "-S",
            "7482128686191834117",
            "-N",
            "4",
            "-m",
            "94428:94429",
            "-P",
            "/tmp",
            "-f",
        ])
        .arg(cf.path())
        .arg(tf.path())
        .assert()
        .success();
    let actual_stderr = CString::new(cmd.get_output().stderr.clone())
        .unwrap()
        .into_string()
        .unwrap();
    let expected: &str = "[DEBUG fsx] Using seed 7482128686191834117
[INFO  fsx] 1 truncate     0x0 => 0x170de
[WARN  fsx] 2 punch_hole 0x13847 .. 0x170dd ( 0x3897 bytes)
[INFO  fsx] 3 punch_hole  0x9876 .. 0x16b4e ( 0xd2d9 bytes)
[INFO  fsx] 4 punch_hole  0x99ea .. 0x15902 ( 0xbf19 bytes)
";
    assert_eq!(expected, actual_stderr);
}

/// Skip zero-length hole punches
#[cfg_attr(
    not(any(
        have_fspacectl,
        target_os = "android",
        target_os = "emscripten",
        target_os = "fuchsia",
        target_os = "linux"
    )),
    ignore
)]
#[test]
fn punch_hole_zero() {
    let mut cf = NamedTempFile::new().unwrap();
    cf.write_all(b"[weights]\npunch_hole=1000").unwrap();

    let tf = NamedTempFile::new().unwrap();

    let cmd = Command::new(cargo_bin!("fsx"))
        .args(["-vv", "-S", "301", "-N", "1", "-f"])
        .arg(cf.path())
        .arg(tf.path())
        .assert()
        .success();
    let actual_stderr = CString::new(cmd.get_output().stderr.clone())
        .unwrap()
        .into_string()
        .unwrap();
    let expected: &str = "[DEBUG fsx] Using seed 301
[DEBUG fsx] 1 skipping zero size hole punch
";
    assert_eq!(expected, actual_stderr);
}

/// Tests that work on real device files
mod blockdev {
    use cfg_if::cfg_if;
    use rstest::fixture;

    use super::*;

    cfg_if! {
        if #[cfg(target_os = "freebsd")] {
            use mdconfig::Md;

            #[fixture]
            fn md() -> Option<Md> {
                mdconfig::Builder::swap(1 << 20).create().ok()
            }
        } else if #[cfg(target_os = "netbsd")] {
            use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::{Path, PathBuf}};

            struct Md(PathBuf);

            impl Md {
                fn path(&self) -> &Path {
                    self.0.as_path()
                }
            }
            impl Drop for Md {
                fn drop(&mut self) {
                    Command::new("mdconfig")
                        .args(["-d", "-u"])
                        .arg(&self.0)
                        .output()
                        .expect("failed to deallocate md(4) device");
                }
            }

            #[fixture]
            fn md() -> Option<Md> {
                let output = Command::new("mdconfig")
                    .args(["-a", "-t", "swap", "-s", "1m"])
                    .output()
                    .expect("failed to allocate md(4) device");
                if output.status.success() {
                    // Strip the trailing "\n"
                    let l = output.stdout.len().saturating_sub(1);
                    let mddev = OsStr::from_bytes(&output.stdout[0..l]);
                    Some(Md(Path::new("/dev").join(mddev)))
                } else {
                    let l = output.stderr.len().saturating_sub(1);
                    eprintln!("Skipping test: {}",
                              OsStr::from_bytes(&output.stderr[0..l])
                              .to_string_lossy());
                    None
                }
            }
        } else if #[cfg(target_os = "linux")] {
            use std::{ffi::OsStr, os::unix::ffi::OsStrExt, path::{Path, PathBuf}};
            struct Md(PathBuf);

            impl Md {
                fn path(&self) -> &Path {
                    self.0.as_path()
                }
            }
            impl Drop for Md {
                fn drop(&mut self) {
                    Command::new("losetup")
                        .args(["-d"])
                        .arg(&self.0)
                        .output()
                        .expect("failed to deallocate loop device");
                }
            }

            #[fixture]
            fn md() -> Option<Md> {
                let tf = NamedTempFile::new().unwrap();
                tf.as_file().set_len(1048576).unwrap();
                let output = Command::new("/sbin/losetup")
                    .args(["-f", "--show"])
                    .arg(tf.path())
                    .output()
                    .expect("failed to allocate loop device");
                if output.status.success() {
                    // Strip the trailing "\n"
                    let l = output.stdout.len() - 1;
                    let mddev = OsStr::from_bytes(&output.stdout[0..l]);
                    Some(Md(mddev.into()))
                } else {
                    let l = output.stderr.len().saturating_sub(1);
                    eprintln!("Skipping test: {}",
                              OsStr::from_bytes(&output.stderr[0..l])
                              .to_string_lossy());
                    None
                }
            }
        } else {
            struct Md(PathBuf);

            #[fixture]
            fn md() -> Option<Md> {
                unimplemented!()
            }
        }
    }

    /// When operating on a block device, fsx will automatically determine the
    /// file size.
    #[rstest]
    fn flen_zero(md: Option<Md>) {
        if md.is_none() {
            return;
        }
        let md = md.unwrap();

        let mut cf = NamedTempFile::new().unwrap();
        cf.write_all(
            b"blockmode = true
[opsize]
align = 4096
[weights]
mapread = 0
mapwrite = 0
truncate = 0",
        )
        .unwrap();

        let artifacts_dir = TempDir::new().unwrap();

        Command::new(cargo_bin!("fsx"))
            .args(["-N10", "-P"])
            .arg(artifacts_dir.path())
            .arg("-f")
            .arg(cf.path())
            .arg(md.path())
            .assert()
            .success();
    }
}
