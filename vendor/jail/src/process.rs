//! Jail-Specific extensions to the `std::process` module
use crate::{JailError, RunningJail};
use log::trace;
use std::os::unix::process::CommandExt;
use std::process;

/// Extension to the `std::process::Command` builder to run the command in a
/// jail.
///
/// Adds a `before_exec` hook to the `std::process::Command` builder that calls
/// the `jail_attach`(2) syscall.
///
/// # Examples
///
/// ```
/// # use std::process::Command;
/// use jail::process::Jailed;
///
/// # let jail = jail::StoppedJail::new("/rescue")
/// #     .name("testjail_process")
/// #     .start()
/// #     .expect("could not start jail");
/// #
/// let output = Command::new("/hostname")
///              .jail(&jail)
///              .output()
///              .expect("Failed to execute command");
///
/// println!("output: {:?}", output.stdout);
/// # jail.kill().expect("could not stop jail");
/// ```
#[cfg(target_os = "freebsd")]
pub trait Jailed {
    /// Sets the child process to be executed within a jail. This translates
    /// to calling `jail_attach` in the child process. Failure in the
    /// `jail_attach` call will cause the spawn to fail.
    fn jail(&mut self, jail: &RunningJail) -> &mut process::Command;
}

#[cfg(target_os = "freebsd")]
impl Jailed for process::Command {
    fn jail(&mut self, jail: &RunningJail) -> &mut process::Command {
        trace!("process::Command::jail({:?}, jail={:?})", self, jail);
        let jail = *jail;
        unsafe {
            self.pre_exec(move || {
                trace!("pre_exec handler: attaching");
                jail.attach().map_err(|err| match err {
                    JailError::JailAttachError(e) => e,
                    _ => panic!("jail.attach() failed with unexpected error"),
                })
            });
        }

        self
    }
}
