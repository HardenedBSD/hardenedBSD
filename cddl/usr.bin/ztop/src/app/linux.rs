// vim: tw=80

#![warn(clippy::all, clippy::pedantic)]

use std::{
    error::Error,
    fs::File,
    io,
    io::BufRead,
    iter::{Flatten, Peekable},
};

use glob::{glob, Paths, Pattern};

use super::Snapshot;

// Similar to sysctl::CtlValue, but only as many types as necessary.
#[derive(Debug)]
enum ObjsetValue {
    String(String),
    U64(u64),
}

fn parse_objset_row(row: &str) -> Option<(String, ObjsetValue)> {
    let mut fields = row.split_ascii_whitespace();

    match (fields.next(), fields.next(), fields.next()) {
        (Some(name), Some(_), Some(value)) => {
            let field_name = (*name).to_string();
            if field_name == "dataset_name" {
                Some((field_name, ObjsetValue::String((*value).to_string())))
            } else {
                match value.parse::<u64>().ok() {
                    Some(n) => Some((field_name, ObjsetValue::U64(n))),
                    None => Some((
                        field_name,
                        ObjsetValue::String((*value).to_string()),
                    )),
                }
            }
        }
        _ => None,
    }
}

fn parse_objset<R: BufRead>(reader: R) -> io::Result<Snapshot> {
    // The first line contains raw numeric data that we don't collect.
    // The second line contains column headers. Both these lines are skipped.
    let lines = reader.lines().skip(2);

    let mut snap = Snapshot::default();

    for line in lines {
        let fields = parse_objset_row(&line?).expect("malformed objset row");
        match fields.1 {
            ObjsetValue::String(name) => snap.name = name,
            ObjsetValue::U64(n) => match fields.0.as_str() {
                "nread" => snap.nread = n,
                "nunlinked" => snap.nunlinked = n,
                "nunlinks" => snap.nunlinks = n,
                "nwritten" => snap.nwritten = n,
                "reads" => snap.reads = n,
                "writes" => snap.writes = n,
                _ => (),
            },
        }
    }
    Ok(snap)
}

/// Convenience implementation for use with glob's `PathBuf`'s
impl TryFrom<File> for Snapshot {
    type Error = io::Error;

    fn try_from(file: File) -> io::Result<Self> {
        parse_objset(io::BufReader::new(file))
    }
}

/// Convenience implementation for simpler testing
#[cfg(test)]
impl TryFrom<&str> for Snapshot {
    type Error = io::Error;

    fn try_from(s: &str) -> io::Result<Self> {
        parse_objset(io::BufReader::new(s.as_bytes()))
    }
}

pub(super) struct SnapshotIter {
    inner: Peekable<Flatten<Paths>>,
}

impl SnapshotIter {
    // Clippy complains about unnecessary wraps, but the type signature is
    // retained to be consistent with FreeBSD implementation.
    #[allow(clippy::unnecessary_wraps, clippy::single_match_else)]
    pub(crate) fn new(pool: Option<&str>) -> Result<Self, Box<dyn Error>> {
        let paths = match pool {
            Some(poolname) => {
                let poolpat = Pattern::escape(poolname);
                let mut paths =
                    glob(&format!("/proc/spl/kstat/zfs/{poolpat}/objset-*"))?
                        .flatten()
                        .peekable();
                if paths.peek().is_none() {
                    eprintln!("Statistics not found for pool {poolname}");
                    std::process::exit(1);
                }
                paths
            }
            None => {
                let mut paths = glob("/proc/spl/kstat/zfs/*/objset-*")?
                    .flatten()
                    .peekable();
                if paths.peek().is_none() {
                    eprintln!("No pools found; ZFS module not loaded?");
                    std::process::exit(1);
                }
                paths
            }
        };

        Ok(SnapshotIter { inner: paths })
    }
}

impl Iterator for SnapshotIter {
    type Item = io::Result<Snapshot>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|glob_result| {
            let file = File::open(glob_result)?;
            Snapshot::try_from(file)
        })
    }
}

#[cfg(test)]
mod t {
    // While I normally agree that wildcard imports are bad, "use super::*" is
    // an exception.
    #[allow(clippy::wildcard_imports)]
    use super::*;

    const SAMPLE_OBJSET: &str = "28 1 0x01 7 2160 5156962179 648086076730177
name                            type data
dataset_name                    7    rpool/ROOT/default
writes                          4    5
nwritten                        4    100
reads                           4    8
nread                           4    160
nunlinks                        4    7
nunlinked                       4    7
";

    #[test]
    fn objset_parsing() {
        let reader = io::BufReader::new(SAMPLE_OBJSET.as_bytes());
        let snap = parse_objset(reader).unwrap();
        assert_eq!("rpool/ROOT/default", snap.name.as_str());
        assert_eq!(8, snap.reads);
        assert_eq!(5, snap.writes);
        assert_eq!(160, snap.nread);
        assert_eq!(7, snap.nunlinks);
        assert_eq!(7, snap.nunlinked);
        assert_eq!(100, snap.nwritten);
    }

    #[test]
    fn objset_try_from() {
        let snap = Snapshot::try_from(SAMPLE_OBJSET).unwrap();
        assert_eq!("rpool/ROOT/default", snap.name.as_str());
        assert_eq!(8, snap.reads);
        assert_eq!(5, snap.writes);
        assert_eq!(160, snap.nread);
        assert_eq!(7, snap.nunlinks);
        assert_eq!(7, snap.nunlinked);
        assert_eq!(100, snap.nwritten);
    }
}
