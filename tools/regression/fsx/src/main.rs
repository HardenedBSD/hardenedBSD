// vim: tw=80
use std::{
    ffi::OsStr,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    mem,
    num::{NonZeroU64, NonZeroUsize},
    os::unix::{
        fs::{FileExt, FileTypeExt},
        io::{AsFd, AsRawFd, IntoRawFd, RawFd},
    },
    path::PathBuf,
    process,
};

use cfg_if::cfg_if;
use clap::{
    builder::TypedValueParser,
    error::ErrorKind,
    Arg,
    Command,
    Error,
    Parser,
};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use libc::c_void;
use log::{debug, error, info, log, warn, Level};
use nix::{
    errno,
    sys::mman::{mmap, msync, munmap, MapFlags, MsFlags, ProtFlags},
    unistd::{sysconf, SysconfVar},
};
use rand::{
    distributions::{Distribution, Standard, WeightedIndex},
    thread_rng,
    Rng,
    RngCore,
    SeedableRng,
};
use rand_xorshift::XorShiftRng;
use ringbuffer::{AllocRingBuffer, RingBuffer, RingBufferExt, RingBufferWrite};
use serde_derive::Deserialize;

cfg_if! {
    if #[cfg(any(
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "netbsd",
            ))] {

        fn mediasize(fd: RawFd) -> io::Result<u64> {

            nix::ioctl_read! {
                /// Get the size of the entire device in bytes.  This should be
                /// a multiple of the sector size.
                diocgmediasize, 'd', 129, nix::libc::off_t
            }

            let mut mediasize = mem::MaybeUninit::<nix::libc::off_t>::uninit();
            // This ioctl is always safe
            unsafe{
                diocgmediasize(fd, mediasize.as_mut_ptr())
                .map(|_| mediasize.assume_init() as u64)
            }
            .map_err(|_| io::Error::from_raw_os_error(errno::Errno::last_raw()))
        }
    } else if #[cfg(any(target_os = "linux"))] {
        fn mediasize(fd: RawFd) -> io::Result<u64> {
            nix::ioctl_read!{blkgetsize64, 0x12, 0x72, u64}

            let mut mediasize = mem::MaybeUninit::<u64>::uninit();
            // This ioctl is always safe
            unsafe{
                blkgetsize64(fd, mediasize.as_mut_ptr())
                .map(|_| mediasize.assume_init())
            }
            .map_err(|_| io::Error::from_raw_os_error(nix::errno::errno()))
        }
    } else {
        fn mediasize(_fd: RawFd) -> io::Result<u64> {
            unimplemented!()
        }
    }
}

cfg_if! {
    if #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd"
        ))] {
        #[derive(Copy, Clone, Debug)]
        struct PosixFadviseAdvice(nix::fcntl::PosixFadviseAdvice);

        impl Distribution<PosixFadviseAdvice> for Standard {
            fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> PosixFadviseAdvice
            {
                use nix::fcntl;

                let inner = match rng.next_u32() % 6 {
                    0u32 => fcntl::PosixFadviseAdvice::POSIX_FADV_NORMAL,
                    1u32 => fcntl::PosixFadviseAdvice::POSIX_FADV_SEQUENTIAL,
                    2u32 => fcntl::PosixFadviseAdvice::POSIX_FADV_RANDOM,
                    3u32 => fcntl::PosixFadviseAdvice::POSIX_FADV_NOREUSE,
                    4u32 => fcntl::PosixFadviseAdvice::POSIX_FADV_WILLNEED,
                    5u32 => fcntl::PosixFadviseAdvice::POSIX_FADV_DONTNEED,
                    _ => unreachable!()
                };
                PosixFadviseAdvice(inner)
            }
        }

        impl fmt::Display for PosixFadviseAdvice {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error>
            {
                use nix::fcntl::PosixFadviseAdvice::*;

                match self.0 {
                    POSIX_FADV_NORMAL => "Normal".fmt(f),
                    POSIX_FADV_SEQUENTIAL => "Sequential".fmt(f),
                    POSIX_FADV_RANDOM => "Random".fmt(f),
                    POSIX_FADV_NOREUSE => "NoReuse".fmt(f),
                    POSIX_FADV_WILLNEED => "WillNeed".fmt(f),
                    POSIX_FADV_DONTNEED => "DontNeed".fmt(f),
                    _ => unimplemented!()
                }
            }
        }
    } else {
        #[derive(Copy, Clone, Debug)]
        struct PosixFadviseAdvice(());
        impl Distribution<PosixFadviseAdvice> for Standard {
            fn sample<R: Rng + ?Sized>(&self, _: &mut R) -> PosixFadviseAdvice
            {
                PosixFadviseAdvice(())
            }
        }

        impl fmt::Display for PosixFadviseAdvice {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
                "".fmt(f)
            }
        }
    }
}

cfg_if! {
    if #[cfg(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "emscripten",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "linux"
    ))] {
        use nix::fcntl::posix_fallocate;
    } else {
        fn posix_fallocate(
            _fd: std::os::unix::io::RawFd,
            _offset: libc::off_t,
            _len: libc::off_t,
        ) -> nix::Result<()> {
                eprintln!("posix_fallocate is not supported on this platform.");
                process::exit(1);
         }
    }
}

/// Calculate the maximum field width needed to print numbers up to this size
fn field_width(max: usize, hex: bool) -> usize {
    if hex {
        2 + (8 * mem::size_of_val(&max) - max.leading_zeros() as usize + 3) / 4
    } else {
        1 + (max as f64).log(10.0) as usize
    }
}

#[derive(Clone)]
struct MonitorParser {}
impl TypedValueParser for MonitorParser {
    type Value = (u64, u64);

    fn parse_ref(
        &self,
        cmd: &Command,
        _arg: Option<&Arg>,
        value: &OsStr,
    ) -> Result<Self::Value, Error> {
        let vs = value.to_str().ok_or_else(|| {
            clap::Error::new(ErrorKind::InvalidUtf8).with_cmd(cmd)
        })?;
        let fields = vs.split(':').collect::<Vec<_>>();
        if fields.len() != 2 {
            let e = clap::Error::raw(
                ErrorKind::InvalidValue,
                "-m argument must contain exactly one ':'",
            )
            .with_cmd(cmd);
            return Err(e);
        }
        let startop = fields[0].parse::<u64>().map_err(|_| {
            clap::Error::raw(
                ErrorKind::InvalidValue,
                "-m arguments must be numeric",
            )
        })?;
        let endop = fields[1].parse::<u64>().map_err(|_| {
            clap::Error::raw(
                ErrorKind::InvalidValue,
                "-m arguments must be numeric",
            )
        })?;
        Ok((startop, endop))
    }
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Beginning operation number
    #[arg(short = 'b', default_value_t = NonZeroU64::new(1u64).unwrap())]
    opnum: NonZeroU64,

    /// Config file path
    #[arg(short = 'f', value_name = "PATH")]
    config: Option<PathBuf>,

    /// Monitor specified byte range
    #[arg(short = 'm', value_name = "FROM:TO", value_parser = MonitorParser{})]
    monitor: Option<(u64, u64)>,

    /// Total number of operations to do [default infinity]
    #[arg(short = 'N')]
    numops: Option<u64>,

    /// Save artifacts to this directory [default ./]
    #[arg(short = 'P', value_name = "DIRPATH")]
    artifacts_dir: Option<PathBuf>,

    /// Seed for RNG
    #[arg(short = 'S')]
    seed: Option<u64>,

    /// File name to operate on
    fname: PathBuf,

    /// Inject an error on step N
    // This option mainly exists just for the sake of the integration tests.
    #[arg(long = "inject", hide = true, value_name = "N")]
    inject: Option<u64>,

    #[command(flatten)]
    verbose: Verbosity<WarnLevel>,
}

const fn default_flen() -> u64 {
    256 * 1024
}

/// Configuration file format, as toml
#[derive(Debug, Default, Deserialize)]
struct Config {
    /// Maximum file size
    // NB: could be u64, but the C-based FSX only works with 32-bit file sizes
    #[serde(default)]
    flen: Option<u32>,

    /// Disable verifications of file size
    #[serde(default)]
    nosizechecks: bool,

    /// Block mode: never change the file's size.
    #[serde(default)]
    blockmode: bool,

    /// Disable msync after mapwrite
    #[serde(default)]
    nomsyncafterwrite: bool,

    /// Specifies size distribution for all operations
    #[serde(default)]
    opsize: Opsize,

    /// Specifies relative statistical weights of all operations
    #[serde(default)]
    weights: Weights,
}

impl Config {
    fn load(path: &PathBuf) -> Self {
        let r = match fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s),
            Err(e) => {
                eprintln!("Error reading config file: {e}");
                process::exit(1);
            }
        };
        match r {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error reading config file: {e}");
                process::exit(1);
            }
        }
    }

    /// Validate compatibility with these CLI arguments
    fn validate(&self, cli: &Cli) {
        if self.flen == Some(0) {
            eprintln!("error: file length must be greater than zero");
            process::exit(2);
        }
        if self.opsize.max == 0 {
            eprintln!(
                "error: Maximum operation size must be greater than zero"
            );
            process::exit(2);
        }
        if self.opsize.min > self.opsize.max {
            eprintln!(
                "error: Minimum operation size must be no greater than maximum"
            );
            process::exit(2);
        }
        let align = self.opsize.align.map(usize::from).unwrap_or(1);
        if align > self.opsize.max {
            eprintln!(
                "error: operation alignment must be no greater than maximum \
                 operation size"
            );
            process::exit(2);
        }
        if self.blockmode && self.weights.close_open > 0.0 {
            eprintln!("error: cannot use close_open with blockmode");
            process::exit(2);
        }
        if self.blockmode && self.weights.truncate > 0.0 {
            eprintln!("error: cannot use truncate with blockmode");
            process::exit(2);
        }
        if self.blockmode && self.weights.posix_fallocate > 0.0 {
            eprintln!("error: cannot use posix_fallocate with blockmode");
            process::exit(2);
        }
        if self.blockmode && cli.artifacts_dir.is_none() {
            eprintln!("error: must specify -P when using blockmode");
            process::exit(2);
        }
    }
}

const fn default_opsize_max() -> usize {
    65536
}

#[derive(Clone, Copy, Debug, Deserialize)]
struct Opsize {
    /// Minium size for operations
    #[serde(default)]
    min:   usize,
    /// Maximum size for operations
    #[serde(default = "default_opsize_max")]
    max:   usize,
    /// Alignment in bytes for all operations
    align: Option<NonZeroUsize>,
}

impl Default for Opsize {
    fn default() -> Self {
        Opsize {
            min:   0,
            max:   65536,
            align: NonZeroUsize::new(1),
        }
    }
}

const fn default_weight() -> f64 {
    10.0
}

#[derive(Debug, Deserialize)]
struct Weights {
    #[serde(default)]
    close_open:      f64,
    #[serde(default)]
    invalidate:      f64,
    #[serde(default = "default_weight")]
    mapread:         f64,
    #[serde(default = "default_weight")]
    mapwrite:        f64,
    #[serde(default = "default_weight")]
    read:            f64,
    #[serde(default = "default_weight")]
    write:           f64,
    #[serde(default = "default_weight")]
    truncate:        f64,
    #[serde(default)]
    fsync:           f64,
    #[serde(default)]
    fdatasync:       f64,
    #[serde(default)]
    posix_fallocate: f64,
    #[serde(default)]
    punch_hole:      f64,
    #[serde(default)]
    sendfile:        f64,
    #[serde(default)]
    posix_fadvise:   f64,
    #[serde(default)]
    copy_file_range: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Weights {
            close_open:      0.0,
            invalidate:      0.0,
            mapread:         1.0,
            mapwrite:        1.0,
            read:            1.0,
            write:           1.0,
            truncate:        1.0,
            fsync:           0.0,
            fdatasync:       0.0,
            posix_fallocate: 0.0,
            punch_hole:      0.0,
            sendfile:        0.0,
            posix_fadvise:   0.0,
            copy_file_range: 0.0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Op {
    CloseOpen,
    Read,
    Write,
    MapRead,
    Truncate,
    Invalidate,
    MapWrite,
    Fsync,
    Fdatasync,
    PosixFallocate,
    PunchHole,
    Sendfile,
    PosixFadvise,
    CopyFileRange,
}

impl Op {
    fn make_weighted_index<I>(weights: I) -> WeightedIndex<f64>
    where
        I: IntoIterator<Item = f64> + ExactSizeIterator,
    {
        assert_eq!(weights.len(), 14);
        WeightedIndex::new(weights).unwrap()
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            Op::CloseOpen => "close/open".fmt(f),
            Op::Read => "read".fmt(f),
            Op::Write => "write".fmt(f),
            Op::MapRead => "mapread".fmt(f),
            Op::Truncate => "truncate".fmt(f),
            Op::Invalidate => "invalidate".fmt(f),
            Op::MapWrite => "mapwrite".fmt(f),
            Op::Fsync => "fsync".fmt(f),
            Op::Fdatasync => "fdatasync".fmt(f),
            Op::PosixFallocate => "posix_fallocate".fmt(f),
            Op::PunchHole => "punch_hole".fmt(f),
            Op::Sendfile => "sendfile".fmt(f),
            Op::PosixFadvise => "posix_fadvise".fmt(f),
            Op::CopyFileRange => "copy_file_range".fmt(f),
        }
    }
}

impl Distribution<Op> for WeightedIndex<f64> {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Op {
        match self.sample(rng) {
            0usize => Op::CloseOpen,
            1 => Op::Read,
            2 => Op::Write,
            3 => Op::MapRead,
            4 => Op::Truncate,
            5 => Op::Invalidate,
            6 => Op::MapWrite,
            7 => Op::Fsync,
            8 => Op::Fdatasync,
            9 => Op::PosixFallocate,
            10 => Op::PunchHole,
            11 => Op::Sendfile,
            12 => Op::PosixFadvise,
            13 => Op::CopyFileRange,
            _ => panic!("WeightedIndex was generated with too many keys"),
        }
    }
}

#[derive(Clone, Copy)]
enum LogEntry {
    Skip(Op),
    CloseOpen,
    // offset, size
    Read(u64, usize),
    // old file len, offset, size
    Write(u64, u64, usize),
    // offset, size
    MapRead(u64, usize),
    // old file len, new file len
    Truncate(u64, u64),
    Invalidate,
    // old file len, offset, size
    MapWrite(u64, u64, usize),
    Fsync,
    Fdatasync,
    // offset, len
    PosixFallocate(u64, u64),
    // offset, len
    PunchHole(u64, u64),
    // offset, len
    Sendfile(u64, usize),
    // advice, offset, len
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "freebsd"
    ))]
    PosixFadvise(PosixFadviseAdvice, u64, u64),
    // old file len, in_offset, out_offset, len
    CopyFileRange(u64, u64, u64, usize),
}

struct Exerciser {
    align:             usize,
    artifacts_dir:     Option<PathBuf>,
    blockmode:         bool,
    /// Current file size
    file_size:         u64,
    flen:              u64,
    fname:             PathBuf,
    /// Width for printing fields containing file offsets
    fwidth:            usize,
    /// Inject an error on this step
    inject:            Option<u64>,
    // What the file ought to contain
    good_buf:          Vec<u8>,
    /// Monitor these byte ranges in extra detail.
    monitor:           Option<(u64, u64)>,
    nomsyncafterwrite: bool,
    nosizechecks:      bool,
    numops:            Option<u64>,
    // Records most recent operations for future dumping
    oplog:             AllocRingBuffer<LogEntry>,
    opsize:            Opsize,
    seed:              u64,
    // 0-indexed operation number to begin real transfers.
    simulatedopcount:  u64,
    /// Width for printing fields containing operation sizes
    swidth:            usize,
    /// Width for printing the step number field
    stepwidth:         usize,
    // File's original data
    original_buf:      Vec<u8>,
    // Use XorShiftRng because it's deterministic and seedable
    rng:               XorShiftRng,
    // Number of steps completed so far
    steps:             u64,
    file:              File,
    wi:                WeightedIndex<f64>,
}

impl Exerciser {
    cfg_if! {
        if #[cfg(any(target_os = "macos", target_os = "dragonfly", target_os = "ios"))] {
            fn dosendfile(&mut self, buf: &mut [u8], offset: u64, size: usize) {
                use std::{io::Read, os::fd::BorrowedFd, os::unix::net::UnixStream, thread};
                use nix::sys::sendfile::sendfile;

                let (mut rd, wr) = UnixStream::pair().unwrap();
                // Safe because we unconditionally join the thread below.
                let (ffd, sfd) = unsafe {(
                    BorrowedFd::borrow_raw(self.file.as_raw_fd()),
                    BorrowedFd::borrow_raw(wr.as_raw_fd()),
                )};

                let jh = thread::spawn(move || {
                    sendfile(
                        ffd,
                        sfd,
                        offset as i64,
                        Some(size as _),
                        None,
                        None,
                    )
                });
                rd.read_exact(buf).unwrap();
                let (res, bytes_written) = jh.join().unwrap();
                if res.is_err() {
                    error!("sendfile returned {:?}", res);
                    self.fail();
                }
                if bytes_written != size as i64 {
                    error!("Short read with sendfile: {:#x} bytes instead of {:#x}",
                           bytes_written, size);
                    self.fail();
                }
            }
        } else if #[cfg(target_os = "freebsd")] {
            fn dosendfile(&mut self, buf: &mut [u8], offset: u64, size: usize) {
                use std::{io::Read, os::fd::BorrowedFd, os::unix::net::UnixStream, thread};
                use nix::sys::sendfile::{sendfile, SfFlags};

                let (mut rd, wr) = UnixStream::pair().unwrap();
                // Safe because we unconditionally join the thread below.
                let (ffd, sfd) = unsafe {(
                    BorrowedFd::borrow_raw(self.file.as_raw_fd()),
                    BorrowedFd::borrow_raw(wr.as_raw_fd()),
                )};

                let jh = thread::spawn(move || {
                    sendfile(
                        ffd,
                        sfd,
                        offset as i64,
                        Some(size),
                        None,
                        None,
                        SfFlags::empty(),
                        0
                    )
                });
                rd.read_exact(buf).unwrap();
                let (res, bytes_written) = jh.join().unwrap();
                if res.is_err() {
                    error!("sendfile returned {:?}", res);
                    self.fail();
                }
                if bytes_written != size as i64 {
                    error!("Short read with sendfile: {:#x} bytes instead of {:#x}",
                           bytes_written, size);
                    self.fail();
                }
            }
        } else if #[cfg(any(target_os = "android", target_os = "linux"))] {
            fn dosendfile(&mut self, buf: &mut [u8], offset: u64, size: usize) {
                use std::{io::Read, os::fd::BorrowedFd, os::unix::net::UnixStream, thread};
                use nix::sys::sendfile::sendfile64;

                let (mut rd, wr) = UnixStream::pair().unwrap();
                let mut ioffs = offset as i64;
                // Safe because we unconditionally join the thread below.
                let (ffd, sfd) = unsafe {(
                    BorrowedFd::borrow_raw(self.file.as_raw_fd()),
                    BorrowedFd::borrow_raw(wr.as_raw_fd()),
                )};

                let jh = thread::spawn(move || {
                    sendfile64(sfd, ffd, Some(&mut ioffs), size)
                });
                rd.read_exact(buf).unwrap();
                let res = jh.join().unwrap();
                let bytes_written = match res {
                    Ok(b) => b,
                    Err(e) => {
                        error!("sendfile returned {:?}", e);
                        self.fail();
                    }
                };
                if bytes_written != size {
                    error!("Short read with sendfile: {:#x} bytes instead of {:#x}",
                           bytes_written, size);
                    self.fail();
                }
            }
        } else {
            fn dosendfile(&mut self, _buf: &mut [u8], _offset: u64, _size: usize) {
                eprintln!("sendfile is not supported on this platform.");
                process::exit(1);
            }
        }
    }

    cfg_if! {
        if #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "freebsd"
        ))] {
            fn posix_fadvise(
                &mut self,
                advice: PosixFadviseAdvice,
                offset: u64,
                size: u64)
            {
                self.oplog.push(LogEntry::PosixFadvise(advice, offset, size));

                if self.skip() {
                    return;
                }
                info!(
                    "{:stepwidth$} posix_fadvise({:10}) {:#fwidth$x} .. \
                    {:#fwidth$x} ({:#swidth$x} bytes)",
                    self.steps,
                    advice,
                    offset,
                    (offset + size).saturating_sub(1),
                    size,
                    stepwidth = self.stepwidth,
                    fwidth = self.fwidth,
                    swidth = self.swidth
                );
                let r = nix::fcntl::posix_fadvise(self.file.as_raw_fd(),
                    offset as i64, size as i64, advice.0);
                if let Err(e) = r {
                    error!("posix_fadvise failed with {e}");
                    self.fail();
                }
            }
        } else {
            fn posix_fadvise(&mut self, _: PosixFadviseAdvice, _: u64, _: u64) {
                eprintln!("posix_fadvise is not supported on this platform.");
                process::exit(1);
            }
        }
    }

    fn check_buffers(&self, buf: &[u8], mut offset: u64) {
        let mut size = buf.len();
        if self.good_buf[offset as usize..offset as usize + size] != buf[..] {
            error!("miscompare: offset= {:#x}, size = {:#x}", offset, size);
            let mut i = 0;
            let mut n = 0;
            let mut good = 0;
            let mut bad = 0;
            let mut badoffset = 0;
            let mut op = 0;
            error!(
                "{:fwidth$} GOOD  BAD  {:swidth$}",
                "OFFSET",
                "RANGE",
                fwidth = self.fwidth,
                swidth = self.swidth
            );
            while size > 0 {
                let c = self.good_buf[offset as usize];
                let t = buf[i];
                if c != t {
                    if n == 0 {
                        good = c;
                        bad = t;
                        badoffset = offset;
                        op = buf[if offset & 1 != 0 { i + 1 } else { i }];
                    }
                    n += 1;
                }
                offset += 1;
                i += 1;
                size -= 1;
            }
            assert!(n > 0);
            // XXX The reported range may be a little too small, because
            // some bytes in the damaged range may coincidentally match.  But
            // this is the way that the C-based FSX reported it.
            error!(
                "{:#fwidth$x} {:#04x} {:#04x} {:#swidth$x}",
                badoffset,
                good,
                bad,
                n,
                fwidth = self.fwidth,
                swidth = self.swidth
            );
            if op > 0 {
                error!("Step# (mod 256) for a misdirected write may be {}", op);
            } else {
                error!(
                    "Step# for the bad data is unknown; check HOLE and EXTEND \
                     ops"
                );
            }
            self.fail();
        }
    }

    fn check_eofpage(&self, offset: u64, p: *const c_void, size: usize) {
        let page_size = Self::getpagesize() as usize;
        let page_mask = page_size as isize - 1;
        if offset + size as u64 <= self.file_size & !(page_mask as u64) {
            return;
        }

        // We landed in the last page of the file.  Test to make sure the VM
        // system provided 0's beyond the true end of the file mapping (as
        // required by mmap def in 1996 posix 1003.1).
        //
        // Safety: mmap always maps to the end of a page, and we drop the slice
        // before munmap().
        let last_page = unsafe {
            let last_page_p = ((p as *mut u8)
                .offset((offset as isize & page_mask) + size as isize)
                as isize
                & !page_mask) as *const u8;
            std::slice::from_raw_parts(last_page_p, page_size)
        };
        for (i, b) in last_page[self.file_size as usize & page_mask as usize..]
            .iter()
            .enumerate()
        {
            if *b != 0 {
                error!(
                    "Mapped non-zero data past EoF ({:#x}) page offset {:#x} \
                     is {:#x}",
                    self.file_size - 1,
                    (self.file_size & page_mask as u64) + i as u64,
                    *b
                );
                self.fail();
            }
        }
    }

    fn check_size(&mut self) {
        if !self.nosizechecks {
            let size = self.file.metadata().unwrap().len();
            let size_by_seek = self.file.seek(SeekFrom::End(0)).unwrap();
            if size != self.file_size || size_by_seek != self.file_size {
                error!(
                    "Size error: expected {:#x} but found {:#x} by stat and \
                     {:#x} by seek",
                    self.file_size, size, size_by_seek
                );
                self.fail();
            }
        }
    }

    /// Close and reopen the file
    fn closeopen(&mut self) {
        self.oplog.push(LogEntry::CloseOpen);

        if self.skip() {
            return;
        }
        info!("{:width$} close/open", self.steps, width = self.stepwidth);

        // We must remove and drop the old File before opening it, and that
        // requires swapping its contents.
        // Safe because we never access the uninitialized File object.
        unsafe {
            let placeholder: File = mem::MaybeUninit::zeroed().assume_init();
            drop(mem::replace(&mut self.file, placeholder));
            let newfile = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.fname)
                .expect("Cannot open file");
            let placeholder = mem::replace(&mut self.file, newfile);
            placeholder.into_raw_fd();
        }
    }

    fn copy_file_range(
        &mut self,
        op: Op,
        mut ioffset: u64,
        mut ooffset: u64,
        mut size: usize,
    ) {
        let cur_file_size = self.file_size;

        ioffset = if self.file_size > 0 {
            ioffset % self.file_size
        } else {
            0
        };
        ioffset -= ioffset % self.align as u64;
        if ioffset + size as u64 > self.file_size {
            size = usize::try_from(self.file_size - ioffset).unwrap();
        }

        ooffset %= self.flen;
        ooffset -= ooffset % self.align as u64;
        if ooffset + size as u64 > self.flen {
            size = usize::try_from(self.flen - ooffset).unwrap();
        }

        size = if ooffset >= ioffset {
            size.min((ooffset - ioffset) as usize)
        } else {
            size.min((ioffset - ooffset) as usize)
        };
        size -= size % self.align;

        if size == 0 {
            self.oplog.push(LogEntry::Skip(op));
            debug!(
                "{:width$} skipping zero size copy_file_range",
                self.steps,
                width = self.stepwidth
            );
        } else {
            if self.file_size < ooffset + size as u64 {
                if self.file_size < ooffset {
                    self.good_buf[self.file_size as usize..ooffset as usize]
                        .fill(0);
                }
                self.file_size = ooffset + size as u64;
            }
            let i = ioffset as usize;
            let j = ooffset as usize;
            self.good_buf[..].copy_within(i..i + size, j);

            self.oplog.push(LogEntry::CopyFileRange(
                cur_file_size,
                ioffset,
                ooffset,
                size,
            ));
            let loglevel = self.loglevel(ioffset, Some(ooffset), size);
            log!(
                loglevel,
                "{:stepwidth$} copy_file_range [{:#fwidth$x}:{:#fwidth$x}] => \
                 [{:#fwidth$x}:{:#fwidth$x}] ({:#swidth$x} bytes)",
                self.steps,
                ioffset,
                ioffset + size as u64 - 1,
                ooffset,
                ooffset + size as u64 - 1,
                size,
                stepwidth = self.stepwidth,
                fwidth = self.fwidth,
                swidth = self.swidth
            );
            self.do_copy_file_range(ioffset, ooffset, size)
        }
    }

    /// Actually perform the copy_file_range, including retrying short writes
    #[cfg(any(target_os = "freebsd", target_os = "linux"))]
    fn do_copy_file_range(&mut self, inoff: u64, outoff: u64, mut len: usize) {
        let mut inoff: i64 = inoff.try_into().unwrap();
        let mut outoff: i64 = outoff.try_into().unwrap();
        while len > 0 {
            let r = nix::fcntl::copy_file_range(
                self.file.as_fd(),
                Some(&mut inoff),
                self.file.as_fd(),
                Some(&mut outoff),
                len,
            )
            .unwrap();
            assert!(r > 0, "0-length copy_file_range");
            len -= r;
        }
    }

    #[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
    fn do_copy_file_range(&mut self, _inoff: u64, _outoff: u64, _len: usize) {
        eprintln!("copy_file_range is not supported on this platform.");
        process::exit(1);
    }

    fn doread(&mut self, buf: &mut [u8], offset: u64, size: usize) {
        let read = self.file.read_at(buf, offset).unwrap();
        if read < size {
            error!("short read: {:#x} bytes instead of {:#x}", read, size);
            self.fail();
        }
    }

    fn domapread(&mut self, buf: &mut [u8], offset: u64, size: usize) {
        let page_mask = Self::getpagesize() as usize - 1;
        let pg_offset = offset as usize & page_mask;
        let map_size = pg_offset + size;
        unsafe {
            let p = mmap(
                None,
                map_size.try_into().unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_FILE | MapFlags::MAP_SHARED,
                self.file.as_fd(),
                offset as i64 - pg_offset as i64,
            )
            .unwrap();
            p.as_ptr()
                .cast::<u8>()
                .add(pg_offset)
                .copy_to(buf.as_mut_ptr(), size);
            self.check_eofpage(offset, p.as_ptr(), size);
        }
    }

    fn domapwrite(&mut self, cur_file_size: u64, size: usize, offset: u64) {
        if self.file_size > cur_file_size {
            self.file.set_len(self.file_size).unwrap();
        }
        let buf = &self.good_buf[offset as usize..offset as usize + size];
        let page_mask = Self::getpagesize() as usize - 1;
        let pg_offset = offset as usize & page_mask;
        let map_size = pg_offset + size;
        // Safety: good luck proving it's safe.
        unsafe {
            let p = mmap(
                None,
                map_size.try_into().unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_FILE | MapFlags::MAP_SHARED,
                self.file.as_fd(),
                offset as i64 - pg_offset as i64,
            )
            .unwrap();
            p.as_ptr()
                .cast::<u8>()
                .add(pg_offset)
                .copy_from(buf.as_ptr(), size);
            if !self.nomsyncafterwrite {
                msync(p, map_size, MsFlags::MS_SYNC).unwrap();
            }
            self.check_eofpage(offset, p.as_ptr(), size);
            munmap(p, map_size).unwrap();
        }
    }

    fn dowrite(&mut self, _cur_file_size: u64, size: usize, offset: u64) {
        let buf = &self.good_buf[offset as usize..offset as usize + size];
        let written = self.file.write_at(buf, offset).unwrap();
        if written != size {
            error!("short write: {:#x} bytes instead of {:#x}", written, size);
            self.fail();
        }
    }

    /// Dump the contents of the oplog
    fn dump_logfile(&self) {
        let mut i = self.steps + 1 - self.oplog.len() as u64;
        error!("Using seed {}", self.seed);
        error!("LOG DUMP");
        for le in self.oplog.iter() {
            match le {
                LogEntry::Skip(op) => error!(
                    "{:stepwidth$} SKIPPED  ({})",
                    i,
                    op,
                    stepwidth = self.stepwidth
                ),
                LogEntry::CloseOpen => error!(
                    "{:stepwidth$} CLOSE/OPEN",
                    i,
                    stepwidth = self.stepwidth
                ),
                LogEntry::Read(offset, size) => error!(
                    "{:stepwidth$} READ     {:#fwidth$x} => {:#fwidth$x} \
                     ({:#swidth$x} bytes)",
                    i,
                    offset,
                    offset + *size as u64,
                    size,
                    stepwidth = self.stepwidth,
                    fwidth = self.fwidth,
                    swidth = self.swidth
                ),
                LogEntry::MapRead(offset, size) => error!(
                    "{:stepwidth$} MAPREAD  {:#fwidth$x} => {:#fwidth$x} \
                     ({:#swidth$x} bytes)",
                    i,
                    offset,
                    offset + *size as u64,
                    size,
                    stepwidth = self.stepwidth,
                    fwidth = self.fwidth,
                    swidth = self.swidth
                ),
                LogEntry::Write(old_len, offset, size) => {
                    let sym = if offset > old_len {
                        " HOLE"
                    } else if offset + *size as u64 > *old_len {
                        " EXTEND"
                    } else {
                        ""
                    };
                    error!(
                        "{:stepwidth$} WRITE    {:#fwidth$x} => {:#fwidth$x} \
                         ({:#swidth$x} bytes){}",
                        i,
                        offset,
                        offset + *size as u64,
                        size,
                        sym,
                        stepwidth = self.stepwidth,
                        fwidth = self.fwidth,
                        swidth = self.swidth
                    )
                }
                LogEntry::MapWrite(old_len, offset, size) => {
                    let sym = if offset > old_len {
                        " HOLE"
                    } else if offset + *size as u64 > *old_len {
                        " EXTEND"
                    } else {
                        ""
                    };
                    error!(
                        "{:stepwidth$} MAPWRITE {:#fwidth$x} => {:#fwidth$x} \
                         ({:#swidth$x} bytes){}",
                        i,
                        offset,
                        offset + *size as u64,
                        size,
                        sym,
                        stepwidth = self.stepwidth,
                        fwidth = self.fwidth,
                        swidth = self.swidth
                    )
                }
                LogEntry::Truncate(old_len, new_len) => {
                    let dir = if new_len > old_len { "UP" } else { "DOWN" };
                    error!(
                        "{:stepwidth$} TRUNCATE  {:4} from {:#fwidth$x} to \
                         {:#fwidth$x}",
                        i,
                        dir,
                        old_len,
                        new_len,
                        stepwidth = self.stepwidth,
                        fwidth = self.fwidth
                    );
                }
                LogEntry::Invalidate => error!(
                    "{:stepwidth$} INVALIDATE",
                    i,
                    stepwidth = self.stepwidth
                ),
                LogEntry::Fsync => {
                    error!("{:stepwidth$} FSYNC", i, stepwidth = self.stepwidth)
                }
                LogEntry::Fdatasync => error!(
                    "{:stepwidth$} FDATASYNC",
                    i,
                    stepwidth = self.stepwidth
                ),
                LogEntry::PosixFallocate(offset, len) => {
                    error!(
                        "{:stepwidth$} POSIX_FALLOCATE {:#fwidth$x} => \
                         {:#fwidth$x} ({:#swidth$x} bytes)",
                        i,
                        offset,
                        offset + len - 1,
                        len,
                        stepwidth = self.stepwidth,
                        swidth = self.swidth,
                        fwidth = self.fwidth
                    );
                }
                LogEntry::PunchHole(offset, len) => {
                    error!(
                        "{:stepwidth$} PUNCH_HOLE {:#fwidth$x} => \
                         {:#fwidth$x} ({:#swidth$x} bytes)",
                        i,
                        offset,
                        offset + len - 1,
                        len,
                        stepwidth = self.stepwidth,
                        swidth = self.swidth,
                        fwidth = self.fwidth
                    );
                }
                LogEntry::Sendfile(offset, size) => error!(
                    "{:stepwidth$} SENDFILE {:#fwidth$x} => {:#fwidth$x} \
                     ({:#swidth$x} bytes)",
                    i,
                    offset,
                    offset + *size as u64,
                    size,
                    stepwidth = self.stepwidth,
                    fwidth = self.fwidth,
                    swidth = self.swidth
                ),
                #[cfg(any(
                    target_os = "linux",
                    target_os = "android",
                    target_os = "freebsd"
                ))]
                LogEntry::PosixFadvise(advice, offset, len) => error!(
                    "{:stepwidth$} POSIX_FADVISE({:10}) {:#fwidth$x} => \
                     {:#fwidth$x} ({:#swidth$x} bytes)",
                    i,
                    advice,
                    offset,
                    offset + len - 1,
                    len,
                    stepwidth = self.stepwidth,
                    swidth = self.swidth,
                    fwidth = self.fwidth
                ),
                LogEntry::CopyFileRange(old_len, ioffset, ooffset, size) => {
                    let sym = if ooffset > old_len {
                        " HOLE"
                    } else if ooffset + *size as u64 > *old_len {
                        " EXTEND"
                    } else {
                        ""
                    };
                    error!(
                        "{:stepwidth$} COPY_FILE_RANGE \
                         [{:#fwidth$x},{:#fwidth$x}] => \
                         [{:#fwidth$x},{:#fwidth$x}] ({:#swidth$x} bytes){}",
                        i,
                        ioffset,
                        ioffset + *size as u64,
                        ooffset,
                        ooffset + *size as u64,
                        size,
                        sym,
                        stepwidth = self.stepwidth,
                        fwidth = self.fwidth,
                        swidth = self.swidth
                    )
                }
            }
            i += 1;
        }
    }

    /// Report a failure and exit.
    fn fail(&self) -> ! {
        self.dump_logfile();
        self.save_goodfile();
        process::exit(1);
    }

    /// Wrapper around read-like operations
    fn read_like<F>(&mut self, op: Op, offset: u64, size: usize, f: F)
    where
        F: Fn(&mut Exerciser, &mut [u8], u64, usize),
    {
        if size == 0 {
            self.oplog.push(LogEntry::Skip(op));
            debug!(
                "{:width$} skipping zero size read",
                self.steps,
                width = self.stepwidth
            );
            return;
        }
        if size as u64 + offset > self.file_size {
            self.oplog.push(LogEntry::Skip(op));
            debug!(
                "{:width$} skipping seek/read past EoF",
                self.steps,
                width = self.stepwidth
            );
            return;
        }
        match op {
            Op::Read => self.oplog.push(LogEntry::Read(offset, size)),
            Op::MapRead => self.oplog.push(LogEntry::MapRead(offset, size)),
            Op::Sendfile => self.oplog.push(LogEntry::Sendfile(offset, size)),
            _ => unimplemented!(),
        }
        if self.skip() {
            return;
        }
        let loglevel = self.loglevel(offset, None, size);
        log!(
            loglevel,
            "{:stepwidth$} {:8} {:#fwidth$x} .. {:#fwidth$x} ({:#swidth$x} \
             bytes)",
            self.steps,
            op,
            offset,
            offset + size as u64 - 1,
            size,
            stepwidth = self.stepwidth,
            fwidth = self.fwidth,
            swidth = self.swidth
        );
        let mut temp_buf = vec![0u8; size];
        f(self, &mut temp_buf[..], offset, size);
        self.check_buffers(&temp_buf, offset)
    }

    fn save_goodfile(&self) {
        let mut final_component =
            self.fname.as_path().file_name().unwrap().to_owned();
        final_component.push(".fsxgood");
        let mut fsxgoodfname = if let Some(d) = &self.artifacts_dir {
            d.clone()
        } else {
            let mut fname = self.fname.clone();
            fname.pop();
            fname
        };
        fsxgoodfname.push(final_component);
        let mut fsxgoodfile = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&fsxgoodfname)
            .expect("Cannot create fsxgood file");
        if let Err(e) = fsxgoodfile.write_all(&self.good_buf) {
            warn!("writing {}: {}", fsxgoodfname.display(), e);
        }
    }

    /// Should this step be skipped as not part of the test plan?
    fn skip(&self) -> bool {
        self.steps <= self.simulatedopcount || Some(self.steps) == self.inject
    }

    /// Wrapper around write-like operations.
    fn write_like<F>(&mut self, op: Op, offset: u64, size: usize, f: F)
    where
        F: Fn(&mut Exerciser, u64, usize, u64),
    {
        if size == 0 {
            self.oplog.push(LogEntry::Skip(op));
            debug!(
                "{:width$} skipping zero size write",
                self.steps,
                width = self.stepwidth
            );
            return;
        }

        self.gendata(offset, size);

        let cur_file_size = self.file_size;
        if self.file_size < offset + size as u64 {
            if self.file_size < offset {
                self.good_buf[self.file_size as usize..offset as usize].fill(0);
            }
            self.file_size = offset + size as u64;
        }
        assert!(!self.blockmode || self.file_size == cur_file_size);

        if op == Op::Write {
            self.oplog
                .push(LogEntry::Write(cur_file_size, offset, size));
        } else {
            self.oplog
                .push(LogEntry::MapWrite(cur_file_size, offset, size));
        }

        if self.skip() {
            return;
        }

        let loglevel = self.loglevel(offset, None, size);
        log!(
            loglevel,
            "{:stepwidth$} {:8} {:#fwidth$x} .. {:#fwidth$x} ({:#swidth$x} \
             bytes)",
            self.steps,
            op,
            offset,
            offset + size as u64 - 1,
            size,
            stepwidth = self.stepwidth,
            fwidth = self.fwidth,
            swidth = self.swidth
        );

        f(self, cur_file_size, size, offset)
    }

    fn exercise(&mut self) {
        loop {
            if let Some(n) = self.numops {
                if n <= self.steps {
                    break;
                }
            }
            self.step();
        }

        println!("All operations completed A-OK!");
    }

    fn fsync(&mut self) {
        self.oplog.push(LogEntry::Fsync);

        if self.skip() {
            return;
        }
        info!("{:width$} fsync", self.steps, width = self.stepwidth);
        self.file.sync_all().unwrap();
    }

    fn fdatasync(&mut self) {
        self.oplog.push(LogEntry::Fdatasync);

        if self.skip() {
            return;
        }
        info!("{:width$} fdatasync", self.steps, width = self.stepwidth);
        self.file.sync_data().unwrap();
    }

    fn gendata(&mut self, offset: u64, mut size: usize) {
        let mut uoff = usize::try_from(offset).unwrap();
        loop {
            size -= 1;
            self.good_buf[uoff] = (self.steps % 256) as u8;
            if uoff % 2 > 0 {
                self.good_buf[uoff] =
                    self.good_buf[uoff].wrapping_add(self.original_buf[uoff]);
            }
            uoff += 1;
            if size == 0 {
                break;
            }
        }
    }

    fn getpagesize() -> i32 {
        // This function is inherently safe
        sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as i32
    }

    fn invalidate(&mut self) {
        self.oplog.push(LogEntry::Invalidate);

        if self.skip() {
            return;
        }
        let len = self.file_size as usize;
        if len == 0 {
            debug!(
                "{:width$} skipping invalidate of zero-length file",
                self.steps,
                width = self.stepwidth
            );
            return;
        }
        info!(
            "{:width$} msync(MS_INVALIDATE)",
            self.steps,
            width = self.stepwidth
        );
        unsafe {
            let p = mmap(
                None,
                len.try_into().unwrap(),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_FILE | MapFlags::MAP_SHARED,
                self.file.as_fd(),
                0,
            )
            .unwrap();
            msync(p, 0, MsFlags::MS_INVALIDATE).unwrap();
            munmap(p, len).unwrap();
        }
    }

    /// Log level to use for I/O operations.
    fn loglevel(
        &self,
        offset: u64,
        offset2: Option<u64>,
        size: usize,
    ) -> Level {
        let mut loglevel = Level::Info;
        if let Some((start, end)) = self.monitor {
            if start < offset + size as u64 && offset <= end {
                loglevel = Level::Warn;
            }
            if let Some(offset2) = offset2 {
                if start < offset2 + size as u64 && offset2 <= end {
                    loglevel = Level::Warn;
                }
            }
        }
        loglevel
    }

    fn mapread(&mut self, offset: u64, size: usize) {
        self.read_like(Op::MapRead, offset, size, Self::domapread)
    }

    fn mapwrite(&mut self, offset: u64, size: usize) {
        self.write_like(Op::MapWrite, offset, size, Self::domapwrite)
    }

    fn read(&mut self, offset: u64, size: usize) {
        self.read_like(Op::Read, offset, size, Self::doread)
    }

    fn sendfile(&mut self, offset: u64, size: usize) {
        self.read_like(Op::Sendfile, offset, size, Self::dosendfile)
    }

    fn step(&mut self) {
        let op: Op = self.wi.sample(&mut self.rng);

        if self.simulatedopcount > 0 && self.steps == self.simulatedopcount {
            self.writefileimage();
        }
        self.steps += 1;

        let mut size = self.rng.gen_range(self.opsize.min..=self.opsize.max);
        let mut offset: u64 = self.rng.gen::<u32>() as u64;

        match op {
            Op::CloseOpen => self.closeopen(),
            Op::Write | Op::MapWrite => {
                offset %= self.flen;
                offset -= offset % self.align as u64;
                if offset + size as u64 > self.flen {
                    size = usize::try_from(self.flen - offset).unwrap();
                }
                size -= size % self.align;
                if op == Op::MapWrite {
                    self.mapwrite(offset, size);
                } else {
                    self.write(offset, size);
                }
            }
            Op::Truncate => {
                let fsize = u64::from(self.rng.gen::<u32>()) % self.flen;
                self.truncate(fsize)
            }
            Op::Invalidate => self.invalidate(),
            Op::Read | Op::MapRead | Op::Sendfile | Op::PosixFadvise => {
                offset = if self.file_size > 0 {
                    offset % self.file_size
                } else {
                    0
                };
                offset -= offset % self.align as u64;
                if offset + size as u64 > self.file_size {
                    size = usize::try_from(self.file_size - offset).unwrap();
                }
                size -= size % self.align;
                match op {
                    Op::MapRead => self.mapread(offset, size),
                    Op::Read => self.read(offset, size),
                    Op::Sendfile => self.sendfile(offset, size),
                    Op::PosixFadvise => {
                        let advice: PosixFadviseAdvice = self.rng.gen();
                        self.posix_fadvise(advice, offset, size as u64)
                    }
                    _ => unreachable!(),
                }
            }
            Op::Fsync => self.fsync(),
            Op::Fdatasync => self.fdatasync(),
            Op::PosixFallocate => {
                offset %= self.flen;
                if offset + size as u64 > self.flen {
                    size = usize::try_from(self.flen - offset).unwrap();
                }
                size -= size % self.align;
                self.posix_fallocate(offset, size as u64)
            }
            Op::PunchHole => {
                offset = if self.file_size > 0 {
                    offset % self.file_size
                } else {
                    0
                };
                offset -= offset % self.align as u64;
                if offset + size as u64 > self.file_size {
                    size = usize::try_from(self.file_size - offset).unwrap();
                }
                size -= size % self.align;
                self.punch_hole(offset, size as u64)
            }
            Op::CopyFileRange => {
                let ooffset: u64 = self.rng.gen::<u32>() as u64;
                self.copy_file_range(op, offset, ooffset, size);
            }
        }
        if self.steps > self.simulatedopcount {
            self.check_size();
        }
    }

    fn posix_fallocate(&mut self, offset: u64, len: u64) {
        let new_size = self.file_size.max(offset + len);
        if new_size > self.file_size {
            self.good_buf[self.file_size as usize..new_size as usize].fill(0);
        }
        self.file_size = new_size;
        self.oplog.push(LogEntry::PosixFallocate(offset, len));

        if self.skip() {
            return;
        }

        // XXX Should not log at WARN if size < self.monitor.0 and
        // self.file_size < self.monitor.0.  But the C-based implementation
        // does.
        let mut loglevel = Level::Info;
        if let Some((_, end)) = self.monitor {
            if len <= end {
                loglevel = Level::Warn;
            }
        }
        log!(
            loglevel,
            "{:stepwidth$} posix_fallocate {:#fwidth$x} .. {:#fwidth$x} \
             ({:#swidth$x} bytes)",
            self.steps,
            offset,
            offset + len - 1,
            len,
            stepwidth = self.stepwidth,
            fwidth = self.fwidth,
            swidth = self.swidth
        );
        let r =
            posix_fallocate(self.file.as_raw_fd(), offset as i64, len as i64);
        match r {
            Ok(()) => (),
            Err(nix::Error::EINVAL) => {
                eprintln!("Test file system does not support posix_fallocate.");
                self.fail();
            }
            Err(e) => {
                eprintln!("posix_fallocate unexpectedly failed with {e}");
                self.fail();
            }
        }
    }

    fn punch_hole(&mut self, offset: u64, len: u64) {
        assert!(offset + len <= self.file_size);

        if len == 0 {
            self.oplog.push(LogEntry::Skip(Op::PunchHole));
            debug!(
                "{:width$} skipping zero size hole punch",
                self.steps,
                width = self.stepwidth
            );
            return;
        }

        self.good_buf[offset as usize..(offset + len) as usize].fill(0);
        self.oplog.push(LogEntry::PunchHole(offset, len));

        if self.skip() {
            return;
        }

        let loglevel = self.loglevel(offset, None, len as usize);
        log!(
            loglevel,
            "{:stepwidth$} punch_hole {:#fwidth$x} .. {:#fwidth$x} \
             ({:#swidth$x} bytes)",
            self.steps,
            offset,
            offset + len - 1,
            len,
            stepwidth = self.stepwidth,
            fwidth = self.fwidth,
            swidth = self.swidth
        );
        cfg_if! {
            if #[cfg(have_fspacectl)] {
                nix::fcntl::fspacectl_all(
                    self.file.as_raw_fd(),
                    offset as i64,
                    len as i64
                ).unwrap();
            } else if #[cfg(any(
                    target_os = "android",
                    target_os = "emscripten",
                    target_os = "fuchsia",
                    target_os = "linux",
                ))] {
                use nix::fcntl::FallocateFlags;

                nix::fcntl::fallocate(
                    self.file.as_raw_fd(),
                    FallocateFlags::FALLOC_FL_PUNCH_HOLE |
                        FallocateFlags::FALLOC_FL_KEEP_SIZE,
                    offset as i64,
                    len as i64
                ).unwrap();
            } else {
                eprintln!("hole punching is not supported on this platform.");
                process::exit(1);
            }
        }
    }

    fn truncate(&mut self, size: u64) {
        if size > self.file_size {
            self.good_buf[self.file_size as usize..size as usize].fill(0);
        }
        let cur_file_size = self.file_size;
        self.file_size = size;

        self.oplog
            .push(LogEntry::Truncate(cur_file_size, self.file_size));

        if self.skip() {
            return;
        }

        // XXX Should not log at WARN if size < self.monitor.0 and
        // self.file_size < self.monitor.0.  But the C-based implementation
        // does.
        let mut loglevel = Level::Info;
        if let Some((_, end)) = self.monitor {
            if size <= end {
                loglevel = Level::Warn;
            }
        }
        log!(
            loglevel,
            "{:stepwidth$} truncate {:#fwidth$x} => {:#fwidth$x}",
            self.steps,
            cur_file_size,
            size,
            stepwidth = self.stepwidth,
            fwidth = self.fwidth
        );
        self.file.set_len(size).unwrap();
    }

    fn write(&mut self, offset: u64, size: usize) {
        self.write_like(Op::Write, offset, size, Self::dowrite)
    }

    fn writefileimage(&mut self) {
        let written = self
            .file
            .write_at(&self.good_buf[..self.file_size as usize], 0)
            .unwrap();
        if written as u64 != self.file_size {
            error!(
                "short write: {:#x} bytes instead of {:#x}",
                written, self.file_size
            );
            self.fail();
        }
        if !self.blockmode {
            self.file.set_len(self.file_size).unwrap();
        }
    }

    // Clippy false positive:
    // https://github.com/rust-lang/rust-clippy/issues/11300
    #[allow(clippy::useless_conversion)]
    fn new(cli: Cli, conf: Config) -> Self {
        let seed = cli.seed.unwrap_or_else(|| {
            let mut seeder = thread_rng();
            seeder.gen::<u64>()
        });
        debug!("Using seed {}", seed);
        let mut oo = OpenOptions::new();
        oo.read(true).write(true);
        if !conf.blockmode {
            oo.create(true).truncate(true);
        }
        let mut file = oo.open(&cli.fname).expect("Cannot create file");
        let flen = conf.flen.map(u64::from).unwrap_or_else(|| {
            if conf.blockmode {
                let md = file.metadata().unwrap();
                let ft = md.file_type();
                if ft.is_file() {
                    md.len()
                } else if ft.is_char_device() || ft.is_block_device() {
                    mediasize(file.as_raw_fd()).unwrap()
                } else {
                    unimplemented!()
                }
            } else {
                default_flen()
            }
        });
        if flen == 0 {
            error!("ERROR: file length must be greater than zero");
            process::exit(2);
        }
        let nosizechecks = if !conf.blockmode {
            conf.nosizechecks
        } else {
            // No point in checking size when using blockmode.  We don't change
            // it any way.
            true
        };
        let file_size = if conf.blockmode { flen } else { 0 };
        let mut original_buf = vec![0u8; flen as usize];
        let good_buf = vec![0u8; flen as usize];
        if conf.blockmode {
            // Zero existing file
            file.write_all(&good_buf).unwrap();
        }
        let mut rng = XorShiftRng::seed_from_u64(seed);
        rng.fill_bytes(&mut original_buf[..]);
        let fwidth = field_width(flen as usize, true);
        let swidth = field_width(conf.opsize.max, true);
        let stepwidth = field_width(
            cli.numops.map(|x| x as usize).unwrap_or(999999),
            false,
        );
        let wi = Op::make_weighted_index(
            [
                conf.weights.close_open,
                conf.weights.read,
                conf.weights.write,
                conf.weights.mapread,
                conf.weights.truncate,
                conf.weights.invalidate,
                conf.weights.mapwrite,
                conf.weights.fsync,
                conf.weights.fdatasync,
                conf.weights.posix_fallocate,
                conf.weights.punch_hole,
                conf.weights.sendfile,
                conf.weights.posix_fadvise,
                conf.weights.copy_file_range,
            ]
            .into_iter(),
        );
        Exerciser {
            align: conf.opsize.align.map(usize::from).unwrap_or(1),
            artifacts_dir: cli.artifacts_dir,
            blockmode: conf.blockmode,
            file,
            file_size,
            flen,
            fwidth,
            fname: cli.fname,
            good_buf,
            inject: cli.inject,
            monitor: cli.monitor,
            nomsyncafterwrite: conf.nomsyncafterwrite,
            nosizechecks,
            numops: cli.numops,
            opsize: conf.opsize,
            oplog: AllocRingBuffer::with_capacity(1024),
            seed,
            simulatedopcount: <NonZeroU64 as Into<u64>>::into(cli.opnum) - 1,
            swidth,
            stepwidth,
            original_buf,
            rng,
            steps: 0,
            wi,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    env_logger::builder()
        .filter_level(cli.verbose.log_level_filter())
        .format_timestamp(None)
        .init();
    let config = cli.config.as_ref().map(Config::load).unwrap_or_default();
    config.validate(&cli);
    let mut exerciser = Exerciser::new(cli, config);
    exerciser.exercise()
}
