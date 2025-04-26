// vim: tw=80
use std::{
    collections::{btree_map, BTreeMap},
    error::Error,
    mem,
    num::NonZeroUsize,
    ops::AddAssign,
};

use cfg_if::cfg_if;
use nix::{
    sys::time::TimeSpec,
    time::{clock_gettime, ClockId},
};
use regex::Regex;

cfg_if! {
    if #[cfg(target_os = "freebsd")] {
        mod freebsd;
        use freebsd::SnapshotIter;
        const CLOCK_UPTIME: ClockId = ClockId::CLOCK_UPTIME;
    } else if #[cfg(target_os = "linux")] {
        mod linux;
        use linux::SnapshotIter;
        const CLOCK_UPTIME: ClockId = ClockId::CLOCK_BOOTTIME;
    }
}

/// A snapshot in time of a dataset's statistics.
///
/// The various fields are not saved atomically, but ought to be close.
#[derive(Clone, Debug, Default)]
struct Snapshot {
    name:      String,
    nunlinked: u64,
    nunlinks:  u64,
    nread:     u64,
    reads:     u64,
    nwritten:  u64,
    writes:    u64,
}

impl Snapshot {
    fn compute(&self, prev: Option<&Self>, etime: f64) -> Element {
        if let Some(prev) = prev {
            Element {
                name:  self.name.clone(),
                ops_r: (self.reads - prev.reads) as f64 / etime,
                r_s:   (self.nread - prev.nread) as f64 / etime,
                ops_w: (self.writes - prev.writes) as f64 / etime,
                w_s:   (self.nwritten - prev.nwritten) as f64 / etime,
                ops_d: (self.nunlinks - prev.nunlinks) as f64 / etime,
                d_s:   (self.nunlinked - prev.nunlinked) as f64 / etime,
            }
        } else {
            Element {
                name:  self.name.clone(),
                ops_r: self.reads as f64 / etime,
                r_s:   self.nread as f64 / etime,
                ops_w: self.writes as f64 / etime,
                w_s:   self.nwritten as f64 / etime,
                ops_d: self.nunlinks as f64 / etime,
                d_s:   self.nunlinked as f64 / etime,
            }
        }
    }

    /// Iterate through ZFS datasets, returning stats for each.
    ///
    /// Iterates through every dataset beneath each of the given pools, or
    /// through all datasets if no pool is supplied.
    pub fn iter(pool: Option<&str>) -> Result<SnapshotIter, Box<dyn Error>> {
        SnapshotIter::new(pool)
    }
}

impl AddAssign<&Self> for Snapshot {
    fn add_assign(&mut self, other: &Self) {
        assert!(
            other.name.starts_with(&self.name),
            "Why would you want to combine two unrelated datasets?"
        );
        self.nunlinked += other.nunlinked;
        self.nunlinks += other.nunlinks;
        self.nread += other.nread;
        self.reads += other.reads;
        self.nwritten += other.nwritten;
        self.writes += other.writes;
    }
}

#[derive(Default)]
struct DataSource {
    children: bool,
    prev:     BTreeMap<String, Snapshot>,
    prev_ts:  Option<TimeSpec>,
    cur:      BTreeMap<String, Snapshot>,
    cur_ts:   Option<TimeSpec>,
    pools:    Vec<String>,
}

impl DataSource {
    fn new(children: bool, pools: Vec<String>) -> Self {
        DataSource {
            children,
            pools,
            ..Default::default()
        }
    }

    /// Iterate through all the datasets, returning current stats
    fn iter(&mut self) -> impl Iterator<Item = Element> + '_ {
        let etime = if let Some(prev_ts) = self.prev_ts.as_ref() {
            let delta = *self.cur_ts.as_ref().unwrap() - *prev_ts;
            delta.tv_sec() as f64 + delta.tv_nsec() as f64 * 1e-9
        } else {
            let boottime = clock_gettime(CLOCK_UPTIME).unwrap();
            boottime.tv_sec() as f64 + boottime.tv_nsec() as f64 * 1e-9
        };
        DataSourceIter {
            inner_iter: self.cur.iter(),
            ds: self,
            etime,
        }
    }

    /// Iterate over all of the names of parent datasets of the argument
    fn with_parents(s: &str) -> impl Iterator<Item = &str> {
        s.char_indices().filter_map(move |(idx, c)| {
            if c == '/' {
                Some(s.split_at(idx).0)
            } else if idx == s.len() - 1 {
                Some(s)
            } else {
                None
            }
        })
    }

    fn refresh(&mut self) -> Result<(), Box<dyn Error>> {
        let now = clock_gettime(ClockId::CLOCK_MONOTONIC)?;
        self.prev = mem::take(&mut self.cur);
        self.prev_ts = self.cur_ts.replace(now);
        if self.pools.is_empty() {
            for rss in Snapshot::iter(None).unwrap() {
                let ss = rss?;
                Self::upsert(&mut self.cur, ss, self.children);
            }
        } else {
            for pool in self.pools.iter() {
                for rss in Snapshot::iter(Some(pool)).unwrap() {
                    let ss = rss?;
                    Self::upsert(&mut self.cur, ss, self.children);
                }
            }
        }
        Ok(())
    }

    fn toggle_children(&mut self) -> Result<(), Box<dyn Error>> {
        self.children ^= true;
        // Wipe out previous statistics.  The next refresh will report stats
        // since boot.
        self.refresh()?;
        mem::take(&mut self.prev);
        self.prev_ts = None;
        Ok(())
    }

    /// Insert a snapshot into `cur`, and/or update it and its parents
    fn upsert(
        cur: &mut BTreeMap<String, Snapshot>,
        ss: Snapshot,
        children: bool,
    ) {
        if children {
            for dsname in Self::with_parents(&ss.name) {
                match cur.entry(dsname.to_string()) {
                    btree_map::Entry::Vacant(ve) => {
                        if ss.name == dsname {
                            ve.insert(ss.clone());
                        } else {
                            let mut parent_ss = ss.clone();
                            parent_ss.name = dsname.to_string();
                            ve.insert(parent_ss);
                        }
                    }
                    btree_map::Entry::Occupied(mut oe) => {
                        *oe.get_mut() += &ss;
                    }
                }
            }
        } else {
            match cur.entry(ss.name.clone()) {
                btree_map::Entry::Vacant(ve) => {
                    ve.insert(ss);
                }
                btree_map::Entry::Occupied(mut oe) => {
                    *oe.get_mut() += &ss;
                }
            }
        };
    }
}

struct DataSourceIter<'a> {
    inner_iter: btree_map::Iter<'a, String, Snapshot>,
    ds:         &'a DataSource,
    etime:      f64,
}

impl<'a> Iterator for DataSourceIter<'a> {
    type Item = Element;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_iter
            .next()
            .map(|(_, ss)| ss.compute(self.ds.prev.get(&ss.name), self.etime))
    }
}

/// One thing to display in the table
#[derive(Clone, Debug)]
pub struct Element {
    pub name:  String,
    /// Read IOPs
    pub ops_r: f64,
    /// Read B/s
    pub r_s:   f64,
    /// Delete IOPs
    pub ops_d: f64,
    /// Delete B/s
    pub d_s:   f64,
    /// Write IOPs
    pub ops_w: f64,
    /// Write B/s
    pub w_s:   f64,
}

#[derive(Default)]
pub struct App {
    auto:        bool,
    data:        DataSource,
    depth:       Option<NonZeroUsize>,
    filter:      Option<Regex>,
    reverse:     bool,
    should_quit: bool,
    /// 0-based index of the column to sort by, if any
    sort_idx:    Option<usize>,
}

impl App {
    pub fn new(
        auto: bool,
        children: bool,
        pools: Vec<String>,
        depth: Option<NonZeroUsize>,
        filter: Option<Regex>,
        reverse: bool,
        sort_idx: Option<usize>,
    ) -> Self {
        let mut data = DataSource::new(children, pools);
        data.refresh().unwrap();
        App {
            auto,
            data,
            depth,
            filter,
            reverse,
            sort_idx,
            ..Default::default()
        }
    }

    pub fn clear_filter(&mut self) {
        self.filter = None;
    }

    /// Return the elements that should be displayed, in order
    #[rustfmt::skip]
    pub fn elements(&mut self) -> Vec<Element> {
        let auto = self.auto;
        let depth = self.depth;
        let filter = &self.filter;
        let mut v = self.data.iter()
            .filter(move |elem| {
                if let Some(limit) = depth {
                    let edepth = elem.name.split('/').count();
                    edepth <= limit.get()
                } else {
                    true
                }
            }).filter(|elem|
                 filter.as_ref()
                 .map(|f| f.is_match(&elem.name))
                 .unwrap_or(true)
            ).filter(|elem| !auto || (elem.r_s + elem.w_s + elem.d_s > 1.0))
            .collect::<Vec<_>>();
        match (self.reverse, self.sort_idx) {
            (false, Some(0)) => v.sort_by(|x, y| x.ops_r.total_cmp(&y.ops_r)),
            (true,  Some(0)) => v.sort_by(|x, y| y.ops_r.total_cmp(&x.ops_r)),
            (false, Some(1)) => v.sort_by(|x, y| x.r_s.total_cmp(&y.r_s)),
            (true,  Some(1)) => v.sort_by(|x, y| y.r_s.total_cmp(&x.r_s)),
            (false, Some(2)) => v.sort_by(|x, y| x.ops_w.total_cmp(&y.ops_w)),
            (true,  Some(2)) => v.sort_by(|x, y| y.ops_w.total_cmp(&x.ops_w)),
            (false, Some(3)) => v.sort_by(|x, y| x.w_s.total_cmp(&y.w_s)),
            (true,  Some(3)) => v.sort_by(|x, y| y.w_s.total_cmp(&x.w_s)),
            (false, Some(4)) => v.sort_by(|x, y| x.ops_d.total_cmp(&y.ops_d)),
            (true,  Some(4)) => v.sort_by(|x, y| y.ops_d.total_cmp(&x.ops_d)),
            (false, Some(5)) => v.sort_by(|x, y| x.d_s.total_cmp(&y.d_s)),
            (true,  Some(5)) => v.sort_by(|x, y| y.d_s.total_cmp(&x.d_s)),
            (false, Some(6)) => v.sort_by(|x, y| x.name.cmp(&y.name)),
            (true,  Some(6)) => v.sort_by(|x, y| y.name.cmp(&x.name)),
            _ => ()
        }
        v
    }

    pub fn on_a(&mut self) {
        self.auto ^= true;
    }

    pub fn on_c(&mut self) -> Result<(), Box<dyn Error>> {
        self.data.toggle_children()
    }

    pub fn on_d(&mut self, more_depth: bool) {
        self.depth = if more_depth {
            match self.depth {
                None => NonZeroUsize::new(1),
                Some(x) => NonZeroUsize::new(x.get() + 1),
            }
        } else {
            match self.depth {
                None => None,
                Some(x) => NonZeroUsize::new(x.get() - 1),
            }
        }
    }

    pub fn on_minus(&mut self) {
        self.sort_idx = match self.sort_idx {
            Some(0) => None,
            Some(old) => Some(old - 1),
            None => Some(6),
        }
    }

    pub fn on_plus(&mut self) {
        self.sort_idx = match self.sort_idx {
            Some(old) if old >= 6 => None,
            Some(old) => Some(old + 1),
            None => Some(0),
        }
    }

    pub fn on_q(&mut self) {
        self.should_quit = true;
    }

    pub fn on_r(&mut self) {
        self.reverse ^= true;
    }

    pub fn on_tick(&mut self) {
        self.data.refresh().unwrap();
    }

    pub fn set_filter(&mut self, filter: Regex) {
        self.filter = Some(filter);
    }

    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    pub fn sort_idx(&self) -> Option<usize> {
        self.sort_idx
    }
}

#[cfg(test)]
mod t {
    mod with_parents {
        use super::super::*;

        /// The empty string is not a valid dataset, but make sure nothing bad
        /// happens anyway
        #[test]
        fn empty() {
            let ds = "";
            let mut actual = DataSource::with_parents(ds);
            assert!(actual.next().is_none());
        }

        #[test]
        fn pool() {
            let ds = "zroot";
            let expected = ["zroot"];
            let actual = DataSource::with_parents(ds).collect::<Vec<_>>();
            assert_eq!(&expected[..], &actual[..]);
        }

        #[test]
        fn one_level() {
            let ds = "zroot/ROOT";
            let expected = ["zroot", "zroot/ROOT"];
            let actual = DataSource::with_parents(ds).collect::<Vec<_>>();
            assert_eq!(&expected[..], &actual[..]);
        }

        #[test]
        fn two_levels() {
            let ds = "zroot/ROOT/13.0-RELEASE";
            let expected = ["zroot", "zroot/ROOT", "zroot/ROOT/13.0-RELEASE"];
            let actual = DataSource::with_parents(ds).collect::<Vec<_>>();
            assert_eq!(&expected[..], &actual[..]);
        }
    }
}
