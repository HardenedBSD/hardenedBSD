//! A Casper service that provides NFS stats to capsicumized programs.
use std::{ffi::CStr, io};

use capsicum::casper::{self, NvError, NvFlag, NvList, ServiceRegisterFlags};

use crate::nfs;

struct CapNfs {}
impl casper::Service for CapNfs {
    const SERVICE_NAME: &'static CStr = c"nfs";

    fn cmd(
        cmd: &str,
        _limits: Option<&NvList>,
        _nvin: Option<&mut NvList>,
        nvout: &mut NvList,
    ) -> io::Result<()> {
        assert_eq!(cmd, "nfsstat");

        let nfsstat = nfs::collect()?;
        nvout
            .insert_binary("nfsstat", &bincode::serialize(&nfsstat).unwrap())
            .unwrap();
        Ok(())
    }
}

casper::service!(
    /// A connection to the Casper 'nfsstat' helper.
    pub CapNfs, CapNfsAgent, nfsstat, ServiceRegisterFlags::NONE
);

impl CapNfsAgent {
    /// Retrieve NFS stats
    pub fn nfsstat(&mut self) -> io::Result<nfs::NfsStat> {
        let mut invl = NvList::new(NvFlag::None).unwrap();
        invl.insert_string("cmd", "nfsstat").unwrap();
        let onvl = self.xfer_nvlist(invl)?;
        match onvl.get_binary("nfsstat") {
            Ok(Some(sl)) => Ok(bincode::deserialize(sl).unwrap()),
            Ok(None) => panic!("zygote did not return the expected value"),
            Err(NvError::NativeError(e)) => {
                Err(io::Error::from_raw_os_error(e))
            }
            Err(NvError::Io(e)) => Err(e),
            _ => unimplemented!(),
        }
    }
}
