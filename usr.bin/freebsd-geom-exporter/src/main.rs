// vim: tw=80
use std::{
    error::Error,
    net::{IpAddr, SocketAddr},
};

use clap::Parser;
use freebsd_libgeom::{Snapshot, Statistics, Tree};
use prometheus_exporter::prometheus::register_gauge_vec;
use regex::Regex;

/// Export GEOM device metrics to Prometheus
#[derive(Debug, Default, clap::Parser)]
struct Cli {
    /// Bind to this local address
    #[clap(short = 'b', default_value = "0.0.0.0")]
    addr:     String,
    /// Only report physical providers (those with rank of 1).
    #[clap(short = 'P', long = "physical")]
    physical: bool,
    /// Only report devices with names matching this regex.
    #[clap(short = 'f', long = "include")]
    include:  Option<String>,
    /// Do not report devices with names matching this regex
    #[clap(short = 'F', long = "exclude")]
    exclude:  Option<String>,
    /// TCP port
    #[clap(short = 'p', default_value = "9248")]
    port:     u16,
}

fn main() -> Result<(), Box<dyn Error>> {
    let cli: Cli = Cli::parse();

    // Parse address used to bind exporter to.
    let ia: IpAddr = cli.addr.parse().unwrap();
    let sa = SocketAddr::new(ia, cli.port);

    let include = cli.include.as_ref().map(|s| Regex::new(s).unwrap());
    let exclude = cli.exclude.as_ref().map(|s| Regex::new(s).unwrap());

    let exporter = prometheus_exporter::start(sa).unwrap();

    let duration = register_gauge_vec!(
        "geom_duration",
        "Total time spent processing commands in seconds",
        &["device", "method"]
    )
    .expect("cannot create gauge");
    let bytes = register_gauge_vec!(
        "geom_bytes",
        "Total bytes processed",
        &["device", "method"]
    )
    .expect("cannot create gauge");
    let ops = register_gauge_vec!(
        "geom_operations",
        "Total operations processed",
        &["device", "method"]
    )
    .expect("cannot create gauge");
    let busy_time = register_gauge_vec!(
        "geom_busy_time",
        "Cumulative time in seconds that the device had at least one \
         outstanding operation",
        &["device"]
    )
    .expect("cannot create gauge");
    let queue_length = register_gauge_vec!(
        "geom_queue_length",
        "Number of incomplete transactions at the sampling instant",
        &["device"]
    )
    .expect("cannot create gauge");

    loop {
        let _guard = exporter.wait_request();
        // Note: it might be more efficient to only call Tree:new if we detect
        // that a device has arrived or departed.  But on a system with hundreds
        // of disks, it only takes 13ms.
        let mut tree = Tree::new()?;
        let mut current = Snapshot::new()?;
        busy_time.reset();
        duration.reset();
        bytes.reset();
        ops.reset();
        queue_length.reset();
        for item in current.iter() {
            if let Some(gident) = tree.lookup(item.id()) {
                if let Some(rank) = gident.rank() {
                    if rank > 1 && cli.physical {
                        continue;
                    }
                    let device = gident.name().unwrap().to_string_lossy();
                    if !include
                        .as_ref()
                        .map(|f| f.is_match(&device))
                        .unwrap_or(true)
                    {
                        continue;
                    }
                    if exclude
                        .as_ref()
                        .map(|f| f.is_match(&device))
                        .unwrap_or(false)
                    {
                        continue;
                    }
                    let stats = Statistics::compute(item, None, 0.0);

                    busy_time
                        .with_label_values(&[&device])
                        .set(stats.busy_time());
                    queue_length
                        .with_label_values(&[&device])
                        .set(stats.queue_length() as f64);
                    bytes
                        .with_label_values(&[&device, "read"])
                        .set(stats.total_bytes_read() as f64);
                    duration
                        .with_label_values(&[&device, "read"])
                        .set(stats.total_duration_read());
                    ops.with_label_values(&[&device, "read"])
                        .set(stats.total_transfers_read() as f64);
                    bytes
                        .with_label_values(&[&device, "write"])
                        .set(stats.total_bytes_write() as f64);
                    duration
                        .with_label_values(&[&device, "write"])
                        .set(stats.total_duration_write());
                    ops.with_label_values(&[&device, "write"])
                        .set(stats.total_transfers_write() as f64);
                    bytes
                        .with_label_values(&[&device, "free"])
                        .set(stats.total_bytes_free() as f64);
                    duration
                        .with_label_values(&[&device, "free"])
                        .set(stats.total_duration_free());
                    ops.with_label_values(&[&device, "free"])
                        .set(stats.total_transfers_free() as f64);
                    duration
                        .with_label_values(&[&device, "other"])
                        .set(stats.total_duration_other());
                    ops.with_label_values(&[&device, "other"])
                        .set(stats.total_transfers_other() as f64);
                }
            }
        }
    }
}
