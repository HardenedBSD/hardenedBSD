// vim: tw=80

use std::net::{IpAddr, SocketAddr};

use capsicum::casper::Casper;
use clap::{crate_version, CommandFactory, Parser};
use env_logger::{Builder, Env};
use prometheus_exporter::prometheus::{register_gauge, register_gauge_vec};

mod cap_nfs;
mod nfs;

use cap_nfs::CasperExt;

#[derive(Parser, Clone, Debug)]
#[clap(version = crate_version!())]
/// Export NFS statistics to Prometheus
struct Cli {
    /// Bind to this local address
    #[clap(short = 'b', long, default_value = "0.0.0.0", value_name = "ADDR")]
    bind:   String,
    /// Publish NFS client statistics
    #[clap(short = 'c')]
    client: bool,
    /// Publish NFS server statistics
    #[clap(short = 's')]
    server: bool,
    /// TCP port
    #[clap(short = 'p', long, default_value = "9898")]
    port:   u16,
}

fn main() {
    let cli = Cli::parse();
    let (_c, s) = if !cli.client && !cli.server {
        // By default, print everything
        (true, true)
    } else if cli.server {
        (false, true)
    } else {
        Cli::command()
            .error(
                clap::error::ErrorKind::InvalidValue,
                "client stats are TODO",
            )
            .exit()
    };

    // Setup logger with default level info so we can see the messages from
    // prometheus_exporter.
    Builder::from_env(Env::default().default_filter_or("info")).init();

    // Parse address used to bind exporter to.
    let ia: IpAddr = cli.bind.parse().unwrap();
    let sa = SocketAddr::new(ia, cli.port);

    // Start Casper .  Safe because we're still single-threaded.
    let mut casper = unsafe { Casper::new().unwrap() };
    let mut cap_nfs = casper.nfsstat().unwrap();

    // Start exporter, which creates additional threads.
    let exporter = prometheus_exporter::start(sa).unwrap();

    // Enter capability mode.
    capsicum::enter().unwrap();

    // Create metrics
    // Even though these are really counters, we use the Gauge API since the
    // kernel reports their current values and prometheus::Counter only has an
    // inc method, not a set method.
    // And even though they're integers, we must use the f64 gauge type because
    // prometheus::IntCounter wraps i64 instead of u64.  The loss of precision
    // is unavoidable because Prometheus itself treats all metrics as f64
    // anyway.
    let bytes = register_gauge_vec!(
        "nfs_nfsd_total_bytes",
        "Total nfsd bytes per operation",
        &["method"]
    )
    .expect("cannot create gauge");
    let duration = register_gauge_vec!(
        "nfs_nfsd_total_duration",
        "Total nfsd nanoseconds spend processing each operation.  May wrap.",
        &["method"]
    )
    .expect("cannot create gauge");
    let rpcs = register_gauge_vec!(
        "nfs_nfsd_requests_total",
        "Count of server RPCs",
        &["method"]
    )
    .expect("cannot create gauge");
    let startcnt = register_gauge!(
        "nfs_nfsd_start_count",
        "Total number of opreations started since boot"
    )
    .expect("cannot create gauge");
    let donecnt = register_gauge!(
        "nfs_nfsd_done_count",
        "Total number of opreations completed since boot"
    )
    .expect("cannot create gauge");
    let busytime = register_gauge!(
        "nfs_nfsd_busytime",
        "Total time in ns that nfsd was busy with at least one opeartion"
    )
    .expect("cannot create gauge");

    let cache_inprog = register_gauge!(
        "nfs_nfsd_cache_in_progress_hits",
        "Server cache in-progress hits"
    )
    .expect("cannot create gauge");
    // Don't publish Idem.  It's always 0
    let cache_nonidempotent = register_gauge!(
        "nfs_nfsd_cache_nonidempotent_hits",
        "Server cache non-idempotent hits"
    )
    .expect("cannot create gauge");
    let cache_misses =
        register_gauge!("nfs_nfsd_server_cache_misses", "Server cache misses")
            .expect("cannot create gauge");
    let cache_size = register_gauge!(
        "nfs_nfsd_server_cache_size",
        "Server cache size in entries"
    )
    .expect("cannot create gauge");
    let cache_tcppeak = register_gauge!(
        "nfs_nfsd_server_cache_tcp_peak",
        "Peak size of the NFS server's TCP client cache"
    )
    .expect("cannot create gauge");

    let clients = register_gauge!(
        "nfs_nfsd_clients",
        "Number of connected NFS v4.x clients"
    )
    .expect("cannot create gauge");
    let delegs = register_gauge!(
        "nfs_nfsd_delegations",
        "Number of active NFS delegations"
    )
    .expect("cannot create gauge");
    let lock_owner = register_gauge!(
        "nfs_nfsd_lock_owners",
        "Number of active NFS lock owners"
    )
    .expect("cannot create gauge");
    let locks = register_gauge!("nfs_nfsd_locks", "Number of active NFS locks")
        .expect("cannot create gauge");
    let open_owner = register_gauge!(
        "nfs_nfsd_open_owners",
        "Number of active NFS v4.0 Open Owners"
    )
    .expect("cannot create gauge");
    let opens =
        register_gauge!("nfs_nfsd_opens", "Number of NFS v4.x open files?")
            .expect("cannot create gauge");

    loop {
        // Will block until exporter receives http request.
        let _guard = exporter.wait_request();

        // Update metric with random value.
        let nfs_stat = cap_nfs.nfsstat().unwrap();

        if s {
            macro_rules! set_rpcs {
                ($label:ident, $field:ident) => {
                    rpcs.with_label_values(&[stringify!($label)])
                        .set(nfs_stat.server_rpcs.$field as f64);
                };
            }

            bytes
                .with_label_values(&["Read"])
                .set(nfs_stat.bytes.read as f64);
            bytes
                .with_label_values(&["Write"])
                .set(nfs_stat.bytes.write as f64);
            duration
                .with_label_values(&["Read"])
                .set(nfs_stat.duration.read as f64);
            duration
                .with_label_values(&["Write"])
                .set(nfs_stat.duration.write as f64);
            duration
                .with_label_values(&["Commit"])
                .set(nfs_stat.duration.commit as f64);
            startcnt.set(nfs_stat.startcnt as f64);
            donecnt.set(nfs_stat.donecnt as f64);
            busytime.set(nfs_stat.busytime as f64);

            cache_inprog.set(nfs_stat.server_cache.inprog as f64);
            cache_nonidempotent.set(nfs_stat.server_cache.nonidem as f64);
            cache_misses.set(nfs_stat.server_cache.misses as f64);
            cache_size.set(nfs_stat.server_cache.size as f64);
            cache_tcppeak.set(nfs_stat.server_cache.tcp_peak as f64);

            clients.set(nfs_stat.server_misc.clients as f64);
            delegs.set(nfs_stat.server_misc.delegs as f64);
            lock_owner.set(nfs_stat.server_misc.lock_owner as f64);
            locks.set(nfs_stat.server_misc.locks as f64);
            open_owner.set(nfs_stat.server_misc.open_owner as f64);
            opens.set(nfs_stat.server_misc.opens as f64);

            set_rpcs!(Access, access);
            set_rpcs!(BackChannelCtl, backchannelctrl);
            set_rpcs!(BindConnToSess, bindconntosess);
            set_rpcs!(Close, close);
            set_rpcs!(Commit, commit);
            set_rpcs!(Create, v3create);
            set_rpcs!(CreateSession, createsess);
            set_rpcs!(CreateV4, create);
            set_rpcs!(DelegPurge, delegpurge);
            set_rpcs!(DelegReturn, delegreturn);
            set_rpcs!(DestroyClientId, destroyclid);
            set_rpcs!(DestroySession, destroysess);
            set_rpcs!(ExchangeId, exchangeid);
            set_rpcs!(FreeStateId, freestateid);
            set_rpcs!(FsInfo, fsinfo);
            set_rpcs!(FsStat, fsstat);
            set_rpcs!(GetAttr, getattr);
            set_rpcs!(GetDevInfo, getdevinfo);
            set_rpcs!(GetDevList, getdevlist);
            set_rpcs!(GetDirDeleg, getdirdeleg);
            set_rpcs!(GetFH, getfh);
            set_rpcs!(LayoutCommit, layoutcommit);
            set_rpcs!(LayoutGet, layoutget);
            set_rpcs!(LayoutReturn, layoutreturn);
            set_rpcs!(Link, link);
            set_rpcs!(Lock, lock);
            set_rpcs!(LockT, lockt);
            set_rpcs!(LockU, locku);
            set_rpcs!(Lookup, lookup);
            set_rpcs!(LookupP, lookupp);
            set_rpcs!(MkDir, mkdir);
            set_rpcs!(MkNod, mknod);
            set_rpcs!(Nverify, nverify);
            set_rpcs!(Open, open);
            set_rpcs!(OpenAttr, openattr);
            set_rpcs!(OpenConfirm, openconfirm);
            set_rpcs!(OpenDgrd, opendgrd);
            set_rpcs!(PathConf, pathconf);
            set_rpcs!(PutFH, putfh);
            set_rpcs!(Read, read);
            set_rpcs!(ReadDir, readdir);
            set_rpcs!(ReadDirPlus, readdirplus);
            set_rpcs!(ReadLink, readlink);
            set_rpcs!(ReclaimCompl, reclaimcompl);
            set_rpcs!(RelLockOwner, rellckown);
            set_rpcs!(Remove, remove);
            set_rpcs!(Rename, rename);
            set_rpcs!(Renew, renew);
            set_rpcs!(RestoreFH, restorefh);
            set_rpcs!(RmDir, rmdir);
            set_rpcs!(SaveFH, savefh);
            set_rpcs!(SecInfo, secinfo);
            set_rpcs!(SecInfoNoName, secinfononame);
            set_rpcs!(Sequence, sequence);
            set_rpcs!(SetAttr, setattr);
            set_rpcs!(SetClientId, setclid);
            set_rpcs!(SetClientIdConfirm, setclidcf);
            set_rpcs!(SetSSV, setssv);
            set_rpcs!(SymLink, symlink);
            set_rpcs!(TestStateId, teststateid);
            set_rpcs!(Verify, verify);
            set_rpcs!(WantDeleg, wantdeleg);
            set_rpcs!(Write, write);
        }
    }
}
