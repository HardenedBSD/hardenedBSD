use crate::{param, sys, JailError, RunningJail};
use log::trace;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::net;
use std::path;

#[cfg(feature = "serialize")]
use serde::Serialize;

/// Represent a stopped jail including all information required to start it
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg(target_os = "freebsd")]
#[cfg_attr(feature = "serialize", derive(Serialize))]
pub struct StoppedJail {
    /// The path of root file system of the jail
    pub path: Option<path::PathBuf>,

    /// The jail name
    pub name: Option<String>,

    /// The jail hostname
    pub hostname: Option<String>,

    /// A hashmap of jail parameters and their values
    pub params: HashMap<String, param::Value>,

    /// A list of IP (v4 and v6) addresses to be assigned to this jail
    pub ips: Vec<net::IpAddr>,

    /// A list of resource limits
    pub limits: Vec<(rctl::Resource, rctl::Limit, rctl::Action)>,
}

#[cfg(target_os = "freebsd")]
impl Default for StoppedJail {
    fn default() -> StoppedJail {
        trace!("StoppedJail::default()");
        StoppedJail {
            path: None,
            name: None,
            hostname: None,
            params: HashMap::new(),
            ips: vec![],
            limits: vec![],
        }
    }
}

impl TryFrom<RunningJail> for StoppedJail {
    type Error = JailError;

    fn try_from(running: RunningJail) -> Result<StoppedJail, Self::Error> {
        running.stop()
    }
}

#[cfg(target_os = "freebsd")]
impl StoppedJail {
    /// Create a new Jail instance given a path.
    ///
    /// # Examples
    ///
    /// ```
    /// use jail::StoppedJail;
    ///
    /// let j = StoppedJail::new("/rescue");
    /// ```
    pub fn new<P: Into<path::PathBuf> + fmt::Debug>(path: P) -> StoppedJail {
        trace!("StoppedJail::new(path={:?})", path);

        StoppedJail {
            path: Some(path.into()),
            ..Default::default()
        }
    }

    /// Start the jail
    ///
    /// This will call [jail_create](fn.jail_create.html) internally.
    /// This will consume the [StoppedJail](struct.StoppedJail.html) and return
    /// a Result<[RunningJail](struct.RunningJail.html),Error>.
    ///
    /// Examples
    ///
    /// ```
    /// use jail::StoppedJail;
    ///
    /// let stopped = StoppedJail::new("/rescue");
    /// let running = stopped.start().unwrap();
    /// # running.kill();
    /// ```
    pub fn start(self) -> Result<RunningJail, JailError> {
        trace!("StoppedJail::start({:?})", self);
        let path = match self.path {
            None => return Err(JailError::PathNotGiven),
            Some(ref p) => p.clone(),
        };

        // If we don't have a name, we can't have RCTL rules...
        if self.name.is_none() && !self.limits.is_empty() {
            return Err(JailError::UnnamedButLimited);
        }

        let mut params = self.params.clone();

        let ipv4_addresses: Vec<_> = self
            .ips
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(|ip| match ip {
                net::IpAddr::V4(ip4) => *ip4,
                _ => unreachable!(),
            })
            .collect();

        if !ipv4_addresses.is_empty() {
            // Set the IP Addresses
            let value = param::Value::Ipv4Addrs(ipv4_addresses);
            params.insert("ip4.addr".into(), value);
        }

        let ipv6_addresses: Vec<_> = self
            .ips
            .iter()
            .filter(|ip| ip.is_ipv6())
            .map(|ip| match ip {
                net::IpAddr::V6(ip6) => *ip6,
                _ => unreachable!(),
            })
            .collect();

        if !ipv6_addresses.is_empty() {
            let value = param::Value::Ipv6Addrs(ipv6_addresses);
            params.insert("ip6.addr".into(), value);
        }

        if let Some(ref name) = self.name {
            params.insert("name".into(), param::Value::String(name.clone()));
        }

        if let Some(ref hostname) = self.hostname {
            params.insert(
                "host.hostname".into(),
                param::Value::String(hostname.clone()),
            );
        }

        let ret = sys::jail_create(&path, params).map(RunningJail::from_jid_unchecked)?;

        // Set resource limits
        if !self.limits.is_empty() {
            let subject = rctl::Subject::jail_name(self.name.expect(
                "Unreachable: Should have thrown \
                 JailError::UnnamedButLimited",
            ));
            for (resource, limit, action) in self.limits {
                let rule = rctl::Rule {
                    subject: subject.clone(),
                    resource,
                    limit,
                    action,
                };

                rule.apply().map_err(JailError::RctlError)?;
            }
        }

        Ok(ret)
    }

    /// Set the jail name
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// #
    /// let mut stopped = StoppedJail::new("/rescue")
    ///     .name("test_stopped_name");
    ///
    /// assert_eq!(stopped.name, Some("test_stopped_name".to_string()));
    /// ```
    pub fn name<S: Into<String> + fmt::Debug>(mut self, name: S) -> Self {
        trace!("StoppedJail::start({:?}, name={:?})", self, name);
        self.name = Some(name.into());
        self
    }

    /// Set the jail name
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// #
    /// let mut stopped = StoppedJail::new("/rescue")
    /// #   .name("test_stopped_hostname")
    ///     .hostname("example.com");
    ///
    /// assert_eq!(stopped.hostname, Some("example.com".to_string()));
    /// ```
    pub fn hostname<S: Into<String> + fmt::Debug>(mut self, hostname: S) -> Self {
        trace!("StoppedJail::hostname({:?}, hostname={:?})", self, hostname);
        self.hostname = Some(hostname.into());
        self
    }

    /// Set a jail parameter
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// #
    /// use jail::param;
    ///
    /// let mut stopped = StoppedJail::new("/rescue")
    ///     .param("allow.raw_sockets", param::Value::Int(1));
    /// ```
    pub fn param<S: Into<String> + fmt::Debug>(mut self, param: S, value: param::Value) -> Self {
        trace!(
            "StoppedJail::param({:?}, param={:?}, value={:?})",
            self,
            param,
            value
        );
        self.params.insert(param.into(), value);
        self
    }

    /// Set a resource limit
    ///
    /// # Examples
    ///
    /// ```
    /// extern crate rctl;
    /// # extern crate jail;
    /// # use jail::StoppedJail;
    /// use rctl;
    /// let mut stopped = StoppedJail::new("/rescue").limit(
    ///     rctl::Resource::MemoryUse,
    ///     rctl::Limit::amount_per(100 * 1024 * 1024, rctl::SubjectType::Process),
    ///     rctl::Action::Deny,
    /// );
    pub fn limit(
        mut self,
        resource: rctl::Resource,
        limit: rctl::Limit,
        action: rctl::Action,
    ) -> Self {
        trace!(
            "StoppedJail::limit({:?}, resource={:?}, limit={:?}, action={:?})",
            self,
            resource,
            limit,
            action
        );
        self.limits.push((resource, limit, action));
        self
    }

    /// Add an IP Address
    ///
    /// # Examples
    ///
    /// ```
    /// # use jail::StoppedJail;
    /// # use std::net::IpAddr;
    /// #
    /// let mut stopped = StoppedJail::new("rescue")
    ///     .ip("127.0.1.1".parse().expect("could not parse 127.0.1.1"))
    ///     .ip("fe80::2".parse().expect("could not parse ::1"));
    /// ```
    pub fn ip(mut self, ip: net::IpAddr) -> Self {
        trace!("StoppedJail::ip({:?}, ip={:?})", self, ip);
        self.ips.push(ip);
        self
    }
}
