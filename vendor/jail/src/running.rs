use crate::{param, sys, JailError, StoppedJail};
use log::trace;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::{Error, ErrorKind};
use std::net;
use std::path;

/// Represents a running jail.
#[derive(Clone, Copy, PartialEq, PartialOrd, Eq, Ord, Debug, Hash)]
#[cfg(target_os = "freebsd")]
pub struct RunningJail {
    /// The `jid` of the jail
    pub jid: i32,
}

/// Represent a running jail.
#[cfg(target_os = "freebsd")]
impl RunningJail {
    /// Create a [RunningJail](struct.RunningJail.html) instance given a `jid`.
    ///
    /// Returns an [Option] containing a [RunningJail] if a Jail with the given
    /// `jid` exists, or None.
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::RunningJail;
    /// # use jail::StoppedJail;
    /// # let jail = StoppedJail::new("/rescue")
    /// #     .name("testjail_from_jid")
    /// #     .start()
    /// #     .expect("could not start jail");
    /// # let jid = jail.jid;
    ///
    /// let running = RunningJail::from_jid(jid)
    ///     .expect("No Jail with this JID");
    /// # running.kill();
    /// ```
    ///
    /// When given the JID of a non-existent jail, it should panic.
    /// ```should_panic
    /// use jail::RunningJail;
    ///
    /// let running = RunningJail::from_jid(99999)
    ///     .expect("No Jail with this JID");
    /// ```
    pub fn from_jid(jid: i32) -> Option<RunningJail> {
        trace!("RunningJail::from_jid({})", jid);
        match sys::jail_exists(jid) {
            true => Some(Self::from_jid_unchecked(jid)),
            false => None,
        }
    }

    /// Create a [RunningJail](struct.RunningJail.html) instance given a `jid`.
    ///
    /// No checks will be performed. If `jid` is invalid, most method calls will
    /// fail.
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::RunningJail;
    /// # use jail::StoppedJail;
    /// # let jail = StoppedJail::new("/rescue")
    /// #     .name("testjail_from_jid")
    /// #     .start()
    /// #     .expect("could not start jail");
    /// # let jid = jail.jid;
    ///
    /// let running = RunningJail::from_jid_unchecked(jid);
    /// # running.kill();
    /// ```
    pub fn from_jid_unchecked(jid: i32) -> RunningJail {
        trace!("RunningJail::from_jid_unchecked({})", jid);
        RunningJail { jid }
    }

    /// Create a [RunningJail](struct.RunningJail.html) given the jail `name`.
    ///
    /// The `jid` will be internally resolved using
    /// [jail_getid](fn.jail_getid.html).
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::RunningJail;
    /// # use jail::StoppedJail;
    /// # let jail = StoppedJail::new("/rescue")
    /// #     .name("testjail_from_name")
    /// #     .start()
    /// #     .expect("could not start jail");
    ///
    /// let running = RunningJail::from_name("testjail_from_name")
    ///     .expect("Could not get testjail");
    /// #
    /// # running.kill();
    /// ```
    pub fn from_name(name: &str) -> Result<RunningJail, JailError> {
        trace!("RunningJail::from_name({})", name);
        sys::jail_getid(name).map(RunningJail::from_jid_unchecked)
    }

    /// Return the jail's `name`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// #
    /// # let running = StoppedJail::new("/rescue")
    /// #     .name("testjail_name")
    /// #     .start()
    /// #     .expect("Could not start jail");
    /// assert_eq!(running.name().unwrap(), "testjail_name");
    /// #
    /// # running.kill();
    /// ```
    pub fn name(&self) -> Result<String, JailError> {
        trace!("RunningJail::name({:?})", self);
        self.param("name")?.unpack_string()
    }

    /// Return the jail's `path`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// # use std::path::PathBuf;
    /// #
    /// # let running = StoppedJail::new("/rescue")
    /// #     .name("testjail_path")
    /// #     .start()
    /// #     .expect("Could not start jail");
    /// let path = running.path()
    ///     .expect("Could not get path");
    /// # let expected : PathBuf = "/rescue".into();
    /// # assert_eq!(path, expected);
    /// #
    /// # running.kill();
    /// ```
    pub fn path(&self) -> Result<path::PathBuf, JailError> {
        trace!("RunningJail::path({:?})", self);
        Ok(self.param("path")?.unpack_string()?.into())
    }

    /// Return the jail's `name`.
    ///
    /// The name will be internall resolved using
    /// [jail_getname](fn.jail_getname.html).
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// #
    /// # let running = StoppedJail::new("/rescue")
    /// #     .name("testjail_name")
    /// #     .hostname("testjail.example.com")
    /// #     .start()
    /// #     .expect("Could not start jail");
    /// assert_eq!(running.hostname().unwrap(), "testjail.example.com");
    /// #
    /// # running.kill();
    /// ```
    pub fn hostname(&self) -> Result<String, JailError> {
        trace!("RunningJail::hostname({:?})", self);
        self.param("host.hostname")?.unpack_string()
    }

    /// Get the IP addresses
    ///
    /// # Examples
    /// ```
    /// # use jail::StoppedJail;
    /// # use std::net::IpAddr;
    /// # let running = StoppedJail::new("/rescue")
    /// #     .name("testjail_ip")
    /// #     .ip("127.0.1.2".parse().unwrap())
    /// #     .ip("fe80::2".parse().unwrap())
    /// #     .start()
    /// #     .expect("Could not start jail");
    /// let ips = running.ips()
    ///     .expect("could not get ip addresses");
    /// assert_eq!(ips[0], "127.0.1.2".parse::<IpAddr>().unwrap());
    /// assert_eq!(ips[1], "fe80::2".parse::<IpAddr>().unwrap());
    /// # running.kill();
    /// ```
    pub fn ips(&self) -> Result<Vec<net::IpAddr>, JailError> {
        trace!("RunningJail::ips({:?})", self);
        let mut ips: Vec<net::IpAddr> = vec![];
        ips.extend(
            self.param("ip4.addr")?
                .unpack_ipv4()?
                .iter()
                .cloned()
                .map(net::IpAddr::V4),
        );
        ips.extend(
            self.param("ip6.addr")?
                .unpack_ipv6()?
                .iter()
                .cloned()
                .map(net::IpAddr::V6),
        );
        Ok(ips)
    }

    /// Return a jail parameter.
    ///
    /// # Examples
    /// ```
    /// # use jail::StoppedJail;
    /// # let running = StoppedJail::new("/rescue")
    /// #     .start().unwrap();
    /// #
    /// let hostuuid = running.param("host.hostuuid")
    ///     .expect("could not get jail hostuuid");
    /// #
    /// # println!("jail uuid: {:?}", hostuuid);
    /// # running.kill();
    /// ```
    pub fn param(&self, name: &str) -> Result<param::Value, JailError> {
        trace!("RunningJail::param({:?}, name={})", self, name);
        param::get(self.jid, name)
    }

    /// Return a HashMap of all jail parameters.
    ///
    /// # Examples
    /// ```
    /// use jail::param;
    /// # use jail::StoppedJail;
    /// # let running = StoppedJail::new("/rescue")
    /// #     .name("testjail_params")
    /// #     .param("allow.raw_sockets", param::Value::Int(1))
    /// #     .start()
    /// #     .expect("could not start jail");
    ///
    /// let params = running.params()
    ///     .expect("could not get all parameters");
    ///
    /// assert_eq!(
    ///     params.get("allow.raw_sockets"),
    ///     Some(&param::Value::Int(1))
    /// );
    /// # running.kill().expect("could not stop jail");
    /// ```
    pub fn params(&self) -> Result<HashMap<String, param::Value>, JailError> {
        trace!("RunningJail::params({:?})", self);
        param::get_all(self.jid)
    }

    /// Set a jail parameter.
    ///
    /// # Examples
    /// ```
    /// # use jail::StoppedJail;
    /// # let running = StoppedJail::new("/rescue")
    /// #     .start().unwrap();
    /// #
    /// use jail::param;
    /// running.param_set("allow.raw_sockets", param::Value::Int(1))
    ///     .expect("could not set parameter");
    /// # let readback = running.param("allow.raw_sockets")
    /// #   .expect("could not read back value");
    /// # assert_eq!(readback, param::Value::Int(1));
    /// # running.kill();
    /// ```
    pub fn param_set(&self, name: &str, value: param::Value) -> Result<(), JailError> {
        trace!(
            "RunningJail::param_set({:?}, name={:?}, value={:?})",
            self,
            name,
            value
        );
        param::set(self.jid, name, value)
    }

    /// Kill a running jail, consuming it.
    ///
    /// This will kill all processes belonging to the jail, and remove any
    /// children of that jail.
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// # let running = StoppedJail::new("/rescue")
    /// #     .start().unwrap();
    /// running.kill();
    /// ```
    pub fn kill(self) -> Result<(), JailError> {
        trace!("RunningJail::kill({:?})", self);
        let name = self.name()?;
        sys::jail_remove(self.jid)?;

        // Tear down RCTL rules
        {
            if name.is_empty() {
                return Ok(());
            }

            let filter: rctl::Filter = rctl::Subject::jail_name(name).into();
            match filter.remove_rules() {
                Ok(_) => Ok(()),
                Err(rctl::Error::InvalidKernelState(_)) => Ok(()),
                Err(e) => Err(JailError::RctlError(e)),
            }
        }?;

        Ok(())
    }

    /// Create a StoppedJail from a RunningJail, while not consuming the
    /// RunningJail.
    ///
    /// This can be used to clone the config from a RunningJail.
    ///
    /// If RCTL is enabled, then all RCTL rules matching the RunningJail
    /// subject will be saved.
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// # let running = StoppedJail::new("/rescue")
    /// #     .name("testjail_save")
    /// #     .hostname("testjail_save.example.com")
    /// #     .start()
    /// #     .unwrap();
    /// let stopped = running
    ///     .save()
    ///     .expect("could not save jail configuration");
    ///
    /// assert_eq!(stopped.name, Some("testjail_save".into()));
    /// assert_eq!(stopped.hostname, Some("testjail_save.example.com".into()));
    /// # running.kill().unwrap();
    /// ```
    pub fn save(self: &RunningJail) -> Result<StoppedJail, JailError> {
        trace!("RunningJail::save({:?})", self);
        let mut stopped = StoppedJail::new(self.path()?);

        stopped.name = self.name().ok();
        stopped.hostname = self.hostname().ok();
        stopped.ips = self.ips()?;
        stopped.params = self.params()?;

        // Save RCTL rules
        if rctl::State::check().is_enabled() {
            let name = self.name();

            if let Ok(name) = name {
                let filter: rctl::Filter = rctl::Subject::jail_name(name).into();
                for rctl::Rule {
                    subject: _,
                    resource,
                    limit,
                    action,
                } in filter.rules().map_err(JailError::RctlError)?.into_iter()
                {
                    stopped.limits.push((resource, limit, action));
                }
            }
        }

        // Special-Case VNET. Non-VNET jails have the "vnet" parameter set to
        // "inherit" (2).
        if stopped.params.get("vnet") == Some(&param::Value::Int(2)) {
            stopped.params.remove("vnet");
        }

        Ok(stopped)
    }

    /// Stop a jail, keeping its configuration in a StoppedJail.
    ///
    /// This is a wrapper around `save` and `kill`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// # let running = StoppedJail::new("/rescue")
    /// #     .name("testjail_stop")
    /// #     .hostname("testjail_stop.example.com")
    /// #     .start()
    /// #     .unwrap();
    /// let stopped = running
    ///     .stop()
    ///     .expect("failed to stop jail");
    ///
    /// //assert_eq!(stopped.name, Some("testjail_save".into()));
    /// //assert_eq!(stopped.hostname, Some("testjail_save.example.com".into()));
    /// ```
    pub fn stop(self: RunningJail) -> Result<StoppedJail, JailError> {
        trace!("RunningJail::stop({:?})", self);
        let stopped = self.save()?;
        self.kill()?;

        Ok(stopped)
    }

    /// Restart a jail by stopping it and starting it again
    ///
    /// This is a wrapper around `RunningJail::stop` and `StoppedJail::start`
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// # let running = StoppedJail::new("/rescue")
    /// #     .name("testjail_restart")
    /// #     .start()
    /// #     .unwrap();
    ///
    /// let old_jid = running.jid;
    /// let running = running.restart()
    ///     .expect("failed to restart jail");
    /// assert!(running.jid != old_jid);
    ///
    /// # running.kill();
    /// ```
    pub fn restart(self: RunningJail) -> Result<RunningJail, JailError> {
        trace!("RunningJail::restart({:?})", self);
        let stopped = self.stop()?;
        stopped.start()
    }

    /// Returns an Iterator over all running jails on this host.
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::RunningJail;
    /// # use jail::StoppedJail;
    /// # let mut running_jails: Vec<RunningJail> = (1..5)
    /// #     .map(|i| {
    /// #         StoppedJail::new("/rescue")
    /// #             .name(format!("testjail_iterate_{}", i))
    /// #             .start()
    /// #             .expect("failed to start jail")
    /// #     })
    /// #     .collect();
    ///
    /// for running in RunningJail::all() {
    ///     println!("jail: {}", running.name().unwrap());
    /// }
    /// #
    /// # for to_kill in running_jails.drain(..) {
    /// #     to_kill.kill().expect("failed to kill jail");
    /// # }
    /// ```
    pub fn all() -> RunningJails {
        trace!("RunningJail::all()");
        RunningJails::default()
    }

    /// Get the `RCTL` / `RACCT` usage statistics for this jail.
    ///
    /// # Example
    ///
    /// ```
    /// # use jail::{StoppedJail, JailError};
    /// #
    /// # let running = StoppedJail::new("/rescue")
    /// #     .name("testjail_racct")
    /// #     .start()
    /// #     .expect("Could not start jail");
    /// match running.racct_statistics() {
    ///     Ok(stats) => println!("{:#?}", stats),
    ///     Err(e) => println!("Error: {}", e),
    /// };
    /// #
    /// # running.kill();
    /// ```
    pub fn racct_statistics(&self) -> Result<HashMap<rctl::Resource, usize>, JailError> {
        trace!("RunningJail::racct_statistics({:?})", self);
        // First let's try to get the RACCT statistics in the happy path
        rctl::Subject::jail_name(self.name()?)
            .usage()
            .map_err(JailError::RctlError)
    }

    /// Jail the current process into the given jail.
    pub fn attach(&self) -> Result<(), JailError> {
        trace!("RunningJail::attach({:?})", self);
        let ret = unsafe { libc::jail_attach(self.jid) };
        match ret {
            0 => Ok(()),
            -1 => Err(Error::last_os_error()),
            _ => Err(Error::new(
                ErrorKind::Other,
                "invalid return value from jail_attach",
            )),
        }
        .map_err(JailError::JailAttachError)
    }

    /// Clear the `persist` flag on the Jail.
    ///
    /// The kernel keeps track of jails using a per-jail resource counter.
    /// Every running process inside the jail increments this resource counter.
    /// The `persist` flag additionally increments the resource counter so that
    /// the jail will not be removed once all processes within the jail will
    /// have terminated.
    ///
    /// Jails started with [StoppedJail::start] start with this flag set, since
    /// they would otherwise be immediately cleaned up again by the kernel.
    /// This method clears the persist flag and therefore delegates cleanup to
    /// the kernel once all jailed processes have terminated.
    ///
    /// # Example
    ///
    /// ```
    /// use std::process::Command;
    /// use jail::process::Jailed;
    ///
    /// let jail = jail::StoppedJail::new("/rescue")
    ///      .name("testjail_defer_cleanup")
    ///      .start()
    ///      .expect("could not start jail");
    ///
    /// let mut child = Command::new("/sleep")
    ///              .arg("3")
    ///              .jail(&jail)
    ///              .spawn()
    ///              .expect("Failed to execute command");
    ///
    /// jail.defer_cleanup().expect("could not defer cleanup");
    ///
    /// child.wait().expect("Could not wait for child.");
    ///
    /// jail.kill().expect_err("Jail should be dead by now.");
    /// ```
    pub fn defer_cleanup(&self) -> Result<(), JailError> {
        trace!("RunningJail::defer_cleanup({:?})", self);
        sys::jail_clearpersist(self.jid)
    }
}

impl TryFrom<StoppedJail> for RunningJail {
    type Error = JailError;

    fn try_from(stopped: StoppedJail) -> Result<RunningJail, Self::Error> {
        stopped.start()
    }
}

/// An Iterator over running Jails
///
/// See [RunningJail::all()](struct.RunningJail.html#method.all) for a usage
/// example.
#[cfg(target_os = "freebsd")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RunningJails {
    lastjid: i32,
}

#[cfg(target_os = "freebsd")]
impl Default for RunningJails {
    fn default() -> Self {
        trace!("RunningJails::default()");
        RunningJails { lastjid: 0 }
    }
}

#[cfg(target_os = "freebsd")]
impl RunningJails {
    pub fn new() -> Self {
        trace!("RunningJails::new()");
        RunningJails::default()
    }
}

#[cfg(target_os = "freebsd")]
impl Iterator for RunningJails {
    type Item = RunningJail;

    fn next(&mut self) -> Option<RunningJail> {
        trace!("RunningJails::next({:?})", self);
        let jid = match sys::jail_nextjid(self.lastjid) {
            Ok(j) => j,
            Err(_) => return None,
        };

        self.lastjid = jid;

        Some(RunningJail { jid })
    }
}
