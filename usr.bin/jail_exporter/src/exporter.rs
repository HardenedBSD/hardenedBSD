// exporter: This module handles the gathering and exporting of jail metrics.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use crate::{
    register_counter_with_registry,
    register_gauge_with_registry,
    register_info_with_registry,
};
use crate::errors::ExporterError;
use crate::httpd::{
    Collector,
    HttpdError,
};
use jail::RunningJail;
use parking_lot::Mutex;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::{
    counter::Counter,
    family::Family,
    gauge::Gauge,
};
use prometheus_client::registry::{
    Registry,
    Unit,
};
use rctl::Resource;
use std::collections::{
    HashMap,
    HashSet,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tracing::debug;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct NameLabel {
    // Jail name.
    name: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct VersionLabels {
    // Version of Rust that the exporter was compiled with.
    rustversion: String,

    // Version of the exporter.
    version: String,
}

/// Type alias for our resource usage metrics coming from the rctl library.
type Rusage = HashMap<Resource, usize>;

/// Set of String representing jails that we have seen during the current
/// scrape.
type SeenJails = HashSet<String>;

/// Exporter structure containing the time series that are being tracked.
pub struct Exporter {
    // Exporter Registry
    registry: Registry,

    // Prometheus time series
    // These come from rctl
    coredumpsize:    Family<NameLabel, Gauge>,
    cputime:         Family<NameLabel, Counter>,
    datasize:        Family<NameLabel, Gauge>,
    memorylocked:    Family<NameLabel, Gauge>,
    memoryuse:       Family<NameLabel, Gauge>,
    msgqsize:        Family<NameLabel, Gauge>,
    maxproc:         Family<NameLabel, Gauge>,
    msgqqueued:      Family<NameLabel, Gauge>,
    nmsgq:           Family<NameLabel, Gauge>,
    nsem:            Family<NameLabel, Gauge>,
    nsemop:          Family<NameLabel, Gauge>,
    nshm:            Family<NameLabel, Gauge>,
    nthr:            Family<NameLabel, Gauge>,
    openfiles:       Family<NameLabel, Gauge>,
    pcpu_used:       Family<NameLabel, Gauge>,
    pseudoterminals: Family<NameLabel, Gauge>,
    readbps:         Family<NameLabel, Gauge>,
    readiops:        Family<NameLabel, Gauge>,
    shmsize:         Family<NameLabel, Gauge>,
    stacksize:       Family<NameLabel, Gauge>,
    swapuse:         Family<NameLabel, Gauge>,
    vmemoryuse:      Family<NameLabel, Gauge>,
    wallclock:       Family<NameLabel, Counter>,
    writebps:        Family<NameLabel, Gauge>,
    writeiops:       Family<NameLabel, Gauge>,

    // Metrics this library generates
    jail_id:  Family<NameLabel, Gauge>,
    jail_num: Gauge,

    // This keeps a record of which jails we saw on the last run. We use this
    // to reap old jails (remove their label sets).
    jail_names: Arc<Mutex<HashSet<String>>>,
}

impl Default for Exporter {
    // Descriptions of these metrics are taken from rctl(8) where possible.
    #![allow(clippy::too_many_lines)]
    fn default() -> Self {
        // We want to set this as a field in the returned struct, as well as
        // pass it to the macros.
        let mut registry = Registry::with_prefix("jail");

        let version_labels = VersionLabels {
            rustversion: env!("RUSTC_VERSION").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
         };

        // Static info metric, doesn't need to be in the struct.
        register_info_with_registry!(
            "exporter_build",
            "A metric with constant '1' value labelled by version \
             from which jail_exporter was built",
            version_labels,
            registry,
        );

        Self {
            coredumpsize: register_gauge_with_registry!(
                "coredumpsize",
                "core dump size, in bytes",
                NameLabel,
                Unit::Bytes,
                registry,
            ),

            cputime: register_counter_with_registry!(
                "cputime",
                "CPU time, in seconds",
                NameLabel,
                Unit::Seconds,
                registry,
            ),

            datasize: register_gauge_with_registry!(
                "datasize",
                "data size, in bytes",
                NameLabel,
                Unit::Bytes,
                registry,
            ),

            maxproc: register_gauge_with_registry!(
                "maxproc",
                "number of processes",
                NameLabel,
                registry,
            ),

            memorylocked: register_gauge_with_registry!(
                "memorylocked",
                "locked memory, in bytes",
                NameLabel,
                Unit::Bytes,
                registry,
            ),

            memoryuse: register_gauge_with_registry!(
                "memoryuse",
                "resident set size, in bytes",
                NameLabel,
                Unit::Bytes,
                registry,
            ),

            msgqqueued: register_gauge_with_registry!(
                "msgqqueued",
                "number of queued SysV messages",
                NameLabel,
                registry,
            ),

            msgqsize: register_gauge_with_registry!(
                "msgqsize",
                "SysV message queue size, in bytes",
                NameLabel,
                Unit::Bytes,
                registry,
            ),

            nmsgq: register_gauge_with_registry!(
                "nmsgq",
                "number of SysV message queues",
                NameLabel,
                registry,
            ),

            nsem: register_gauge_with_registry!(
                "nsem",
                "number of SysV semaphores",
                NameLabel,
                registry,
            ),

            nsemop: register_gauge_with_registry!(
                "nsemop",
                "number of SysV semaphores modified in a single semop(2) call",
                NameLabel,
                registry,
            ),

            nshm: register_gauge_with_registry!(
                "nshm",
                "number of SysV shared memory segments",
                NameLabel,
                registry,
            ),

            nthr: register_gauge_with_registry!(
                "nthr",
                "number of threads",
                NameLabel,
                registry,
            ),

            openfiles: register_gauge_with_registry!(
                "openfiles",
                "file descriptor table size",
                NameLabel,
                registry,
            ),

            pcpu_used: register_gauge_with_registry!(
                "pcpu_used",
                "%CPU, in percents of a single CPU core",
                NameLabel,
                registry,
            ),

            pseudoterminals: register_gauge_with_registry!(
                "pseudoterminals",
                "number of PTYs",
                NameLabel,
                registry,
            ),

            readbps: register_gauge_with_registry!(
                "readbps",
                "filesystem reads, in bytes per second",
                NameLabel,
                registry,
            ),

            readiops: register_gauge_with_registry!(
                "readiops",
                "filesystem reads, in operations per second",
                NameLabel,
                registry,
            ),

            shmsize: register_gauge_with_registry!(
                "shmsize",
                "SysV shared memory size, in bytes",
                NameLabel,
                Unit::Bytes,
                registry,
            ),

            stacksize: register_gauge_with_registry!(
                "stacksize",
                "stack size, in bytes",
                NameLabel,
                Unit::Bytes,
                registry,
            ),

            swapuse: register_gauge_with_registry!(
                "swapuse",
                "swap space that may be reserved or used, in bytes",
                NameLabel,
                Unit::Bytes,
                registry,
            ),

            vmemoryuse: register_gauge_with_registry!(
                "vmemoryuse",
                "address space limit, in bytes",
                NameLabel,
                Unit::Bytes,
                registry,
            ),

            wallclock: register_counter_with_registry!(
                "wallclock",
                "wallclock time, in seconds",
                NameLabel,
                Unit::Seconds,
                registry,
            ),

            writebps: register_gauge_with_registry!(
                "writebps",
                "filesystem writes, in bytes per second",
                NameLabel,
                registry,
            ),

            writeiops: register_gauge_with_registry!(
                "writeiops",
                "filesystem writes, in operations per second",
                NameLabel,
                registry,
            ),

            // Metrics created by the exporter
            jail_id: register_gauge_with_registry!(
                "id",
                "ID of the named jail",
                NameLabel,
                registry,
            ),

            jail_num: register_gauge_with_registry!(
                "num",
                "Current number of running jails",
                registry,
            ),

            // Registry must be added after the macros making use of it
            registry: registry,

            // Jail name tracking
            // We keep a set of jails that we saw on the run, so that on the
            // next run, we can tell which jails have disappeared (if any) and
            // delete those metric families.
            jail_names: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

/// Exporter implementation
impl Exporter {
    /// Return a new Exporter instance.
    ///
    /// This will create the initial time series and return a metrics struct.
    ///
    /// # Example
    ///
    /// ```
    /// let exporter = jail_exporter::Exporter::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Collect and export the rctl metrics.
    ///
    /// This will return a `Vec<u8>` representing the Prometheus metrics
    /// text format.
    ///
    /// # Example
    ///
    /// ```
    /// # let exporter = jail_exporter::Exporter::new();
    /// let output = exporter.export();
    /// ```
    pub fn export(&self) -> Result<String, ExporterError> {
        // Collect metrics
        self.get_jail_metrics()?;

        // Collect them in a buffer
        let mut buffer = String::new(); //vec![];
        encode(&mut buffer, &self.registry).expect("encode");

        // Return the exported metrics
        Ok(buffer)
    }

    /// Processes the Rusage setting the appripriate time series.
    fn process_rusage(&self, name: &str, metrics: &Rusage) {
        debug!("process_metrics_hash");

        // Add the jail name to seen jails.
        self.add_seen_jail(name);

        // Convenience variable
        let labels = &NameLabel {
            name: name.to_string(),
        };

        for (key, value) in metrics {
            // The original value comes in as a usize. Convert it to a u64 for
            // our Counter values, and clamp it down to an i64 for our Gauge
            // values.
            let unsigned = *value as u64;

            // Since we come from a usize, we can't get any negative values,
            // so clamping to a 0 min is fine.
            let signed = i64::try_from(unsigned.clamp(0, i64::MAX as u64))
                .expect("i64 from u64");

            match key {
                Resource::CoreDumpSize => {
                    self.coredumpsize.get_or_create(labels).set(signed);
                },
                Resource::CpuTime => {
                    // CPU time should only ever increase. Store the value from
                    // the OS directly.
                    self.cputime
                        .get_or_create(labels)
                        .inner()
                        .store(unsigned, Ordering::Relaxed);
                },
                Resource::DataSize => {
                    self.datasize.get_or_create(labels).set(signed);
                },
                Resource::MaxProcesses => {
                    self.maxproc.get_or_create(labels).set(signed);
                },
                Resource::MemoryLocked => {
                    self.memorylocked.get_or_create(labels).set(signed);
                },
                Resource::MemoryUse => {
                    self.memoryuse.get_or_create(labels).set(signed);
                },
                Resource::MsgqQueued => {
                    self.msgqqueued.get_or_create(labels).set(signed);
                },
                Resource::MsgqSize => {
                    self.msgqsize.get_or_create(labels).set(signed);
                },
                Resource::NMsgq => {
                    self.nmsgq.get_or_create(labels).set(signed);
                },
                Resource::Nsem => {
                    self.nsem.get_or_create(labels).set(signed);
                },
                Resource::NSemop => {
                    self.nsemop.get_or_create(labels).set(signed);
                },
                Resource::NShm => {
                    self.nshm.get_or_create(labels).set(signed);
                },
                Resource::NThreads => {
                    self.nthr.get_or_create(labels).set(signed);
                },
                Resource::OpenFiles => {
                    self.openfiles.get_or_create(labels).set(signed);
                },
                Resource::PercentCpu => {
                    self.pcpu_used.get_or_create(labels).set(signed);
                },
                Resource::PseudoTerminals => {
                    self.pseudoterminals.get_or_create(labels).set(signed);
                },
                Resource::ReadBps => {
                    self.readbps.get_or_create(labels).set(signed);
                },
                Resource::ReadIops => {
                    self.readiops.get_or_create(labels).set(signed);
                },
                Resource::ShmSize => {
                    self.shmsize.get_or_create(labels).set(signed);
                },
                Resource::StackSize => {
                    self.stacksize.get_or_create(labels).set(signed);
                },
                Resource::SwapUse => {
                    self.swapuse.get_or_create(labels).set(signed);
                },
                Resource::VMemoryUse => {
                    self.vmemoryuse.get_or_create(labels).set(signed);
                },
                Resource::Wallclock => {
                    // Wallclock should only ever increase, store the value
                    // from the OS directly.
                    self.wallclock
                        .get_or_create(labels)
                        .inner()
                        .store(unsigned, Ordering::Relaxed);
                },
                Resource::WriteBps => {
                    self.writebps.get_or_create(labels).set(signed);
                },
                Resource::WriteIops => {
                    self.writeiops.get_or_create(labels).set(signed);
                },
            }
        }
    }

    fn get_jail_metrics(&self) -> Result<(), ExporterError> {
        debug!("get_jail_metrics");

        // Set jail_total to zero before gathering.
        self.jail_num.set(0);

        // Get a new vec of seen jails.
        let mut seen = SeenJails::new();

        // Loop over jails.
        for jail in RunningJail::all() {
            let name = jail.name()?;
            let rusage = jail.racct_statistics()?;

            debug!("JID: {}, Name: {:?}", jail.jid, name);

            // Add to our vec of seen jails.
            seen.insert(name.clone());

            // Process rusage for the named jail, setting time series.
            self.process_rusage(&name, &rusage);

            let labels = &NameLabel {
                name: name,
            };

            self.jail_id.get_or_create(labels).set(i64::from(jail.jid));
            self.jail_num.set(self.jail_num.get() + 1);
        }

        // Get a list of dead jails based on what we've seen, and reap them.
        // Performed in two steps due to Mutex locking issues.
        let dead = self.dead_jails(&seen);
        self.reap(dead);

        Ok(())
    }

    fn add_seen_jail(&self, seen: &str) {
        let mut names = self.jail_names.lock();
        names.insert(seen.to_string());
    }

    fn remove_dead_jails(&self, dead: &SeenJails) {
        let mut names = self.jail_names.lock();
        *names = &*names - dead;
    }

    // Loop over jail names from the previous run, as determined by book
    // keeping, and create a vector of jail names that no longer exist.
    fn dead_jails(&self, seen: &SeenJails) -> HashSet<String> {
        let names = self.jail_names.lock();
        &*names - seen
    }

    // Loop over dead jails removing old labels and killing old book keeping.
    fn reap(&self, dead: SeenJails) {
        self.remove_dead_jails(&dead);

        for name in dead {
            self.remove_jail_metrics(&name);
        }
    }

    fn remove_jail_metrics(&self, name: &str) {
        // Convenience variable
        let labels = &NameLabel {
            name: name.to_string(),
        };

        // Remove the jail metrics
        self.coredumpsize.remove(labels);
        self.cputime.remove(labels);
        self.datasize.remove(labels);
        self.maxproc.remove(labels);
        self.memorylocked.remove(labels);
        self.memoryuse.remove(labels);
        self.msgqqueued.remove(labels);
        self.msgqsize.remove(labels);
        self.nmsgq.remove(labels);
        self.nsem.remove(labels);
        self.nsemop.remove(labels);
        self.nshm.remove(labels);
        self.nthr.remove(labels);
        self.openfiles.remove(labels);
        self.pcpu_used.remove(labels);
        self.pseudoterminals.remove(labels);
        self.readbps.remove(labels);
        self.readiops.remove(labels);
        self.shmsize.remove(labels);
        self.stacksize.remove(labels);
        self.swapuse.remove(labels);
        self.vmemoryuse.remove(labels);
        self.wallclock.remove(labels);
        self.writebps.remove(labels);
        self.writeiops.remove(labels);

        //// Reset metrics we generated.
        self.jail_id.remove(labels);
    }
}

/// Implements the Collector trait used by the Httpd component.
impl Collector for Exporter {
    fn collect(&self) -> Result<String, HttpdError> {
        self.export()
            .map_err(|e| HttpdError::CollectorError(e.to_string()))
    }
}

// Tests
#[cfg(test)]
mod tests {
    // We need some of the main functions.
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn cputime_counter_increase() {
        let names = ["test", "test2"];
        let exporter = Exporter::new();

        for name in names.iter() {
            let mut hash = Rusage::new();

            let labels = &NameLabel {
                name: name.to_string(),
            };

            // Initial check, should be zero. We didn't set anything yet.
            assert_eq!(exporter.cputime.get_or_create(labels).get(), 0);

            // First run, adds 1000, total 1000.
            hash.insert(Resource::CpuTime, 1000);
            exporter.process_rusage(&name, &hash);
            assert_eq!(exporter.cputime.get_or_create(labels).get(), 1000);

            // Second, adds 20, total 1020
            hash.insert(Resource::CpuTime, 1020);
            exporter.process_rusage(&name, &hash);
            assert_eq!(exporter.cputime.get_or_create(labels).get(), 1020);

            // Third, counter was reset. Adds 10, total 1030.
            hash.insert(Resource::CpuTime, 10);
            exporter.process_rusage(&name, &hash);
            assert_eq!(exporter.cputime.get_or_create(labels).get(), 10);

            // Fourth, adds 40, total 1070.
            hash.insert(Resource::CpuTime, 50);
            exporter.process_rusage(&name, &hash);
            assert_eq!(exporter.cputime.get_or_create(labels).get(), 50);

            // Fifth, add 0, total 1070
            hash.insert(Resource::CpuTime, 50);
            exporter.process_rusage(&name, &hash);
            assert_eq!(exporter.cputime.get_or_create(labels).get(), 50);
        }
    }

    #[test]
    fn dead_jails_ok() {
        let names = ["test_a", "test_b", "test_c"];
        let exporter = Exporter::new();

        // Create some metrics for test_{a,b,c}.
        for name in names.iter() {
            let mut hash = Rusage::new();
            hash.insert(Resource::CpuTime, 1000);
            exporter.process_rusage(&name, &hash);
        }

        // Now, create a seen array containing only a and c.
        let seen = SeenJails::from([
            "test_a".into(),
            "test_c".into(),
        ]);

        // Workout which jails are dead, it should be b.
        let dead = exporter.dead_jails(&seen);
        let ok = SeenJails::from([
            "test_b".into(),
        ]);

        assert_eq!(ok, dead);
    }

    #[test]
    fn reap_ok() {
        let names = ["test_a", "test_b", "test_c"];
        let exporter = Exporter::new();

        // Create some metrics for test_{a,b,c}.
        for name in names.iter() {
            let mut hash = Rusage::new();
            hash.insert(Resource::CpuTime, 1000);
            exporter.process_rusage(&name, &hash);
        }

        // Now, create a seen array containing only a and c.
        let seen = SeenJails::from([
            "test_a".into(),
            "test_c".into(),
        ]);

        let dead_jail = "test_b";
        let labels = &NameLabel {
            name: dead_jail.to_string(),
        };

        assert_eq!(exporter.cputime.get_or_create(labels).get(), 1000);

        // Workout which jails are dead, it should be b.
        let dead = exporter.dead_jails(&seen);
        exporter.reap(dead);

        assert_eq!(exporter.cputime.get_or_create(labels).get(), 0);
    }

    #[test]
    fn wallclock_counter_increase() {
        let names = ["test", "test2"];
        let exporter = Exporter::new();

        for name in names.iter() {
            let mut hash = Rusage::new();

            let labels = &NameLabel {
                name: name.to_string(),
            };

            // Initial check, should be zero. We didn't set anything yet.
            assert_eq!(exporter.wallclock.get_or_create(labels).get(), 0);

            // First run, adds 1000, total 1000.
            hash.insert(Resource::Wallclock, 1000);
            exporter.process_rusage(&name, &hash);
            assert_eq!(exporter.wallclock.get_or_create(labels).get(), 1000);

            // Second, adds 20, total 1020
            hash.insert(Resource::Wallclock, 1020);
            exporter.process_rusage(&name, &hash);
            assert_eq!(exporter.wallclock.get_or_create(labels).get(), 1020);

            // Third, counter was reset. Adds 10, total 1030.
            hash.insert(Resource::Wallclock, 10);
            exporter.process_rusage(&name, &hash);
            assert_eq!(exporter.wallclock.get_or_create(labels).get(), 10);

            // Fourth, adds 40, total 1070.
            hash.insert(Resource::Wallclock, 50);
            exporter.process_rusage(&name, &hash);
            assert_eq!(exporter.wallclock.get_or_create(labels).get(), 50);

            // Fifth, add 0, total 1070
            hash.insert(Resource::Wallclock, 50);
            exporter.process_rusage(&name, &hash);
            assert_eq!(exporter.wallclock.get_or_create(labels).get(), 50);
        }
    }
}
