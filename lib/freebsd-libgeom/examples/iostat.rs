//! Similar to "iostat -x -w 1 -c 2".  See iostat(8).

use std::{error::Error, thread::sleep, time::Duration};

use freebsd_libgeom::*;
use nix::time::{clock_gettime, ClockId};

fn main() -> Result<(), Box<dyn Error>> {
    let mut tree = Tree::new()?;

    let mut previous: Option<Snapshot> = None;
    println!(
        "{:8}{:>8}{:>8}{:>9}{:>9}{:>6}{:>6}{:>6}{:>6}{:>5}{:>4}",
        "device",
        "r/s",
        "w/s",
        "kr/s",
        "kw/s",
        "ms/r",
        "ms/w",
        "ms/o",
        "ms/t",
        "qlen",
        "%b"
    );
    for _ in 0..2 {
        let mut current = Snapshot::new()?;
        let etime = if let Some(prev) = previous.as_mut() {
            f64::from(current.timestamp() - prev.timestamp())
        } else {
            let boottime = clock_gettime(ClockId::CLOCK_UPTIME)?;
            boottime.tv_sec() as f64 + boottime.tv_nsec() as f64 * 1e-9
        };
        for (curstat, prevstat) in current.iter_pair(previous.as_mut()) {
            if let Some(gident) = tree.lookup(curstat.id()) {
                if let Some(1) = gident.rank() {
                    let stats = Statistics::compute(curstat, prevstat, etime);
                    println!(
                        "{:8} {:>7.0} {:>7.0} {:>8.1} {:>8.1} {:>5.0} {:>5.0} \
                         {:>5.0} {:>5.0} {:>4} {:>3.0}",
                        gident.name().unwrap().to_string_lossy(),
                        stats.transfers_per_second_read(),
                        stats.transfers_per_second_write(),
                        stats.mb_per_second_read() * 1024.0,
                        stats.mb_per_second_write() * 1024.0,
                        stats.ms_per_transaction_read(),
                        stats.ms_per_transaction_write(),
                        stats.ms_per_transaction_other()
                            + stats.ms_per_transaction_free(),
                        stats.ms_per_transaction(),
                        stats.queue_length(),
                        stats.busy_pct()
                    )
                }
            }
        }
        previous = Some(current);
        sleep(Duration::from_secs(1));
    }

    Ok(())
}
