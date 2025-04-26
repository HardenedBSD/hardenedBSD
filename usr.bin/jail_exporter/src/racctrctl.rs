#![forbid(unsafe_code)]
#![deny(missing_docs)]
use crate::errors::ExporterError;
use crate::rctlstate::RctlState;
use tracing::debug;

// Checks for the availability of RACCT/RCTL in the kernel.
pub fn is_available() -> Result<(), ExporterError> {
    debug!("Checking RACCT/RCTL status");

    match RctlState::check() {
        RctlState::Disabled => {
            Err(ExporterError::RctlUnavailable(
                "Present, but disabled; enable using \
                 kern.racct.enable=1 tunable".to_owned()
            ))
        },
        RctlState::Enabled => Ok(()),
        RctlState::Jailed => {
            // This isn't strictly true. Jail exporter should be able to run
            // within a jail, for situations where a user has jails within
            // jails. It is just untested at the moment.
            Err(ExporterError::RctlUnavailable(
                "Jail Exporter cannot run within a jail".to_owned()
            ))
        },
        RctlState::NotPresent => {
            Err(ExporterError::RctlUnavailable(
                "Support not present in kernel; see rctl(8) \
                 for details".to_owned()
            ))
        },
    }
}
