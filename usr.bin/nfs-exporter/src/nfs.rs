use std::{
    io::{Error, Result},
    os::raw::c_void,
};

use serde_derive::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[allow(dead_code)]
// https://github.com/rust-lang/rust-bindgen/issues/1651
#[allow(deref_nullptr)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

fn bintime_to_ns(bintime: &ffi::bintime) -> u64 {
    (bintime.sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(bintime.frac / (1 << 30) / ((1 << 34) / 1_000_000_000))
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize,
)]
pub struct PerRW {
    pub read:  u64,
    pub write: u64,
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize,
)]
pub struct PerRWC {
    pub read:   u64,
    pub write:  u64,
    pub commit: u64,
}

/// Counts of every RPC processed
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize,
)]
pub struct PerRPC {
    pub access:          u64,
    pub backchannelctrl: u64,
    pub bindconntosess:  u64,
    pub close:           u64,
    pub commit:          u64,
    pub create:          u64,
    pub createsess:      u64,
    pub delegpurge:      u64,
    pub delegreturn:     u64,
    pub destroyclid:     u64,
    pub destroysess:     u64,
    pub exchangeid:      u64,
    pub freestateid:     u64,
    pub fsinfo:          u64,
    pub fsstat:          u64,
    pub getattr:         u64,
    pub getdevinfo:      u64,
    pub getdevlist:      u64,
    pub getdirdeleg:     u64,
    pub getfh:           u64,
    pub layoutcommit:    u64,
    pub layoutget:       u64,
    pub layoutreturn:    u64,
    pub link:            u64,
    pub lock:            u64,
    pub lockt:           u64,
    pub locku:           u64,
    pub lookup:          u64,
    pub lookupp:         u64,
    pub mkdir:           u64,
    pub mknod:           u64,
    pub nverify:         u64,
    pub open:            u64,
    pub openattr:        u64,
    pub openconfirm:     u64,
    pub opendgrd:        u64,
    pub pathconf:        u64,
    pub putfh:           u64,
    pub putpubfh:        u64,
    pub putrootfh:       u64,
    pub read:            u64,
    pub readdir:         u64,
    pub readdirplus:     u64,
    pub readlink:        u64,
    pub reclaimcompl:    u64,
    pub rellckown:       u64,
    pub remove:          u64,
    pub rename:          u64,
    pub renew:           u64,
    pub restorefh:       u64,
    pub rmdir:           u64,
    pub savefh:          u64,
    pub secinfo:         u64,
    pub secinfononame:   u64,
    pub sequence:        u64,
    pub setattr:         u64,
    pub setclid:         u64,
    pub setclidcf:       u64,
    pub setssv:          u64,
    pub symlink:         u64,
    pub teststateid:     u64,
    pub v3create:        u64,
    pub verify:          u64,
    pub wantdeleg:       u64,
    pub write:           u64,
}

/// Server cache statistics
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize,
)]
pub struct ServerCache {
    pub inprog:   u64,
    pub nonidem:  u64,
    pub misses:   u64,
    pub size:     u64,
    pub tcp_peak: u64,
}

/// Miscellaneous NFS server stats
#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize,
)]
pub struct ServerMisc {
    /// Number of currently connected NFS v4.0+ clients?
    pub clients:    u64,
    pub delegs:     u64,
    pub lock_owner: u64,
    pub locks:      u64,
    pub open_owner: u64,
    pub opens:      u64,
}

#[derive(
    Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize,
)]
pub struct NfsStat {
    /// Total time in ns that nfsd was busy with at least one operation.
    /// May wrap!
    pub busytime:     u64,
    /// Total bytes processed by each operation
    pub bytes:        PerRW,
    /// Total number of operations that have completed since boot
    pub donecnt:      u64,
    /// Cumulative duration spent processing each operation, in nanoseconds.
    /// May wrap!
    pub duration:     PerRWC,
    pub server_cache: ServerCache,
    pub server_misc:  ServerMisc,
    /// Count of each RPC processed by the server
    pub server_rpcs:  PerRPC,
    /// Total number of operations that have been started since boot
    pub startcnt:     u64,
}

pub fn collect() -> Result<NfsStat> {
    let mut raw = ffi::nfsstatsv1 {
        vers: ffi::NFSSTATS_V1 as i32,
        ..Default::default()
    };
    let flag = ffi::NFSSVC_GETSTATS | ffi::NFSSVC_NEWSTRUCT;
    let raw = unsafe {
        let r = ffi::nfssvc(flag as i32, &mut raw as *mut _ as *mut c_void);
        if r != 0 {
            return Err(Error::last_os_error());
        }
        raw
    };
    let bytes = PerRW {
        read:  raw.srvbytes[ffi::NFSV4OP_READ as usize],
        write: raw.srvbytes[ffi::NFSV4OP_WRITE as usize],
    };
    let duration = PerRWC {
        read:   bintime_to_ns(&raw.srvduration[ffi::NFSV4OP_READ as usize]),
        write:  bintime_to_ns(&raw.srvduration[ffi::NFSV4OP_WRITE as usize]),
        commit: bintime_to_ns(&raw.srvduration[ffi::NFSV4OP_COMMIT as usize]),
    };
    let server_cache = ServerCache {
        inprog:   raw.srvcache_inproghits,
        nonidem:  raw.srvcache_nonidemdonehits,
        misses:   raw.srvcache_misses,
        size:     i64::max(0, i64::from(raw.srvcache_size)) as u64,
        tcp_peak: raw.srvcache_tcppeak,
    };
    let server_misc = ServerMisc {
        clients:    raw.srvclients,
        delegs:     raw.srvdelegates,
        lock_owner: raw.srvlockowners,
        locks:      raw.srvlocks,
        open_owner: raw.srvopenowners,
        opens:      raw.srvopens,
    };
    let server_rpcs = PerRPC {
        access:          raw.srvrpccnt[ffi::NFSV4OP_ACCESS as usize],
        backchannelctrl: raw.srvrpccnt[ffi::NFSV4OP_BACKCHANNELCTL as usize],
        bindconntosess:  raw.srvrpccnt[ffi::NFSV4OP_BINDCONNTOSESS as usize],
        close:           raw.srvrpccnt[ffi::NFSV4OP_CLOSE as usize],
        commit:          raw.srvrpccnt[ffi::NFSV4OP_COMMIT as usize],
        create:          raw.srvrpccnt[ffi::NFSV4OP_CREATE as usize],
        createsess:      raw.srvrpccnt[ffi::NFSV4OP_CREATESESSION as usize],
        delegpurge:      raw.srvrpccnt[ffi::NFSV4OP_DELEGPURGE as usize],
        delegreturn:     raw.srvrpccnt[ffi::NFSV4OP_DELEGRETURN as usize],
        destroyclid:     raw.srvrpccnt[ffi::NFSV4OP_DESTROYCLIENTID as usize],
        destroysess:     raw.srvrpccnt[ffi::NFSV4OP_DESTROYSESSION as usize],
        exchangeid:      raw.srvrpccnt[ffi::NFSV4OP_EXCHANGEID as usize],
        freestateid:     raw.srvrpccnt[ffi::NFSV4OP_FREESTATEID as usize],
        fsinfo:          raw.srvrpccnt[ffi::NFSV4OP_FSINFO as usize],
        fsstat:          raw.srvrpccnt[ffi::NFSV4OP_FSSTAT as usize],
        getattr:         raw.srvrpccnt[ffi::NFSV4OP_GETATTR as usize],
        getdevinfo:      raw.srvrpccnt[ffi::NFSV4OP_GETDEVINFO as usize],
        getdevlist:      raw.srvrpccnt[ffi::NFSV4OP_GETDEVLIST as usize],
        getdirdeleg:     raw.srvrpccnt[ffi::NFSV4OP_GETDIRDELEG as usize],
        getfh:           raw.srvrpccnt[ffi::NFSV4OP_GETFH as usize],
        layoutcommit:    raw.srvrpccnt[ffi::NFSV4OP_LAYOUTCOMMIT as usize],
        layoutget:       raw.srvrpccnt[ffi::NFSV4OP_LAYOUTGET as usize],
        layoutreturn:    raw.srvrpccnt[ffi::NFSV4OP_LAYOUTRETURN as usize],
        link:            raw.srvrpccnt[ffi::NFSV4OP_LINK as usize],
        lock:            raw.srvrpccnt[ffi::NFSV4OP_LOCK as usize],
        lockt:           raw.srvrpccnt[ffi::NFSV4OP_LOCKT as usize],
        locku:           raw.srvrpccnt[ffi::NFSV4OP_LOCKU as usize],
        lookup:          raw.srvrpccnt[ffi::NFSV4OP_LOOKUP as usize],
        lookupp:         raw.srvrpccnt[ffi::NFSV4OP_LOOKUPP as usize],
        mkdir:           raw.srvrpccnt[ffi::NFSV4OP_MKDIR as usize],
        mknod:           raw.srvrpccnt[ffi::NFSV4OP_MKNOD as usize],
        nverify:         raw.srvrpccnt[ffi::NFSV4OP_NVERIFY as usize],
        open:            raw.srvrpccnt[ffi::NFSV4OP_OPEN as usize],
        openattr:        raw.srvrpccnt[ffi::NFSV4OP_OPENATTR as usize],
        openconfirm:     raw.srvrpccnt[ffi::NFSV4OP_OPENCONFIRM as usize],
        opendgrd:        raw.srvrpccnt[ffi::NFSV4OP_OPENDOWNGRADE as usize],
        pathconf:        raw.srvrpccnt[ffi::NFSV4OP_PATHCONF as usize],
        putfh:           raw.srvrpccnt[ffi::NFSV4OP_PUTFH as usize],
        putpubfh:        raw.srvrpccnt[ffi::NFSV4OP_PUTPUBFH as usize],
        putrootfh:       raw.srvrpccnt[ffi::NFSV4OP_PUTROOTFH as usize],
        read:            raw.srvrpccnt[ffi::NFSV4OP_READ as usize],
        readdir:         raw.srvrpccnt[ffi::NFSV4OP_READDIR as usize],
        readdirplus:     raw.srvrpccnt[ffi::NFSV4OP_READDIRPLUS as usize],
        readlink:        raw.srvrpccnt[ffi::NFSV4OP_READLINK as usize],
        reclaimcompl:    raw.srvrpccnt[ffi::NFSV4OP_RECLAIMCOMPL as usize],
        rellckown:       raw.srvrpccnt[ffi::NFSV4OP_RELEASELCKOWN as usize],
        remove:          raw.srvrpccnt[ffi::NFSV4OP_REMOVE as usize],
        rename:          raw.srvrpccnt[ffi::NFSV4OP_RENAME as usize],
        renew:           raw.srvrpccnt[ffi::NFSV4OP_RENEW as usize],
        restorefh:       raw.srvrpccnt[ffi::NFSV4OP_RESTOREFH as usize],
        rmdir:           raw.srvrpccnt[ffi::NFSV4OP_RMDIR as usize],
        savefh:          raw.srvrpccnt[ffi::NFSV4OP_SAVEFH as usize],
        secinfo:         raw.srvrpccnt[ffi::NFSV4OP_SECINFO as usize],
        secinfononame:   raw.srvrpccnt[ffi::NFSV4OP_SECINFONONAME as usize],
        sequence:        raw.srvrpccnt[ffi::NFSV4OP_SEQUENCE as usize],
        setattr:         raw.srvrpccnt[ffi::NFSV4OP_SETATTR as usize],
        setclid:         raw.srvrpccnt[ffi::NFSV4OP_SETCLIENTID as usize],
        setclidcf:       raw.srvrpccnt[ffi::NFSV4OP_SETCLIENTIDCFRM as usize],
        setssv:          raw.srvrpccnt[ffi::NFSV4OP_SETSSV as usize],
        symlink:         raw.srvrpccnt[ffi::NFSV4OP_SYMLINK as usize],
        teststateid:     raw.srvrpccnt[ffi::NFSV4OP_TESTSTATEID as usize],
        v3create:        raw.srvrpccnt[ffi::NFSV4OP_V3CREATE as usize],
        verify:          raw.srvrpccnt[ffi::NFSV4OP_VERIFY as usize],
        wantdeleg:       raw.srvrpccnt[ffi::NFSV4OP_WANTDELEG as usize],
        write:           raw.srvrpccnt[ffi::NFSV4OP_WRITE as usize],
    };
    Ok(NfsStat {
        bytes,
        duration,
        startcnt: raw.srvstartcnt,
        donecnt: raw.srvdonecnt,
        busytime: bintime_to_ns(&raw.busytime),
        server_cache,
        server_misc,
        server_rpcs,
    })
}
