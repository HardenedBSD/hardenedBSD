// Copyright 2019 Fabian Freyer <fabian.freyer@physik.tu-berlin.de>
// Copyright 2018 David O'Rourke <david.orourke@gmail.com>
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// Note:
// The rctl_api_wrapper function, the usage() function as well as the state
// check are based on code from phyber/jail_exporter:
// https://github.com/phyber/jail_exporter/blob/6498d628143399fc365fad4217ad85db12348e65/src/rctl/mod.rs

//! Resource limits and accounting with `RCTL` and `RACCT`
//!
//! Large parts of this documentation are adapted from the [`rctl(8)`] manpage.
//!
//! [`rctl(8)`]: https://www.freebsd.org/cgi/man.cgi?query=rctl&sektion=8&manpath=FreeBSD+11.2-stable

pub use nix::sys::signal::Signal;
use number_prefix::{NumberPrefix, Prefix};
use std::collections::HashMap;
use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::io;
use std::num;
use std::str;

use sysctl::Sysctl;
use thiserror::Error;

// Set to the same value as found in rctl.c in FreeBSD 11.1
const RCTL_DEFAULT_BUFSIZE: usize = 128 * 1024;

#[derive(Debug, Error, PartialEq, Clone)]
pub enum ParseError {
    #[error("Unknown subject type: {0}")]
    UnknownSubjectType(String),

    #[error("No such user: {0}")]
    UnknownUser(String),

    #[error("Unknown resource: {0}")]
    UnknownResource(String),

    #[error("Unknown action: {0}")]
    UnknownAction(String),

    #[error("Bogus data at end of limit: {0}")]
    LimitBogusData(String),

    #[error("Invalid limit literal: {0}")]
    InvalidLimitLiteral(String),

    #[error("Invalid numeric value: {0}")]
    InvalidNumeral(num::ParseIntError),

    #[error("No subject specified")]
    NoSubjectGiven,

    #[error("Bogus data at end of subject: {0}")]
    SubjectBogusData(String),

    #[error("Invalid Rule syntax: '{0}'")]
    InvalidRuleSyntax(String),
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("Parse Error: {0}")]
    ParseError(ParseError),

    #[error("OS Error: {0}")]
    OsError(io::Error),

    #[error("An interior Nul byte was found while attempting to construct a CString: {0}")]
    CStringError(NulError),

    #[error("The statistics returned by the kernel were invalid.")]
    InvalidStatistics,

    #[error("Invalid RCTL / RACCT kernel state: {0}")]
    InvalidKernelState(State),
}

/// Helper module containing enums representing [Subjects](Subject)
mod subject {
    use super::ParseError;
    use std::fmt;
    use users::{get_user_by_name, get_user_by_uid};

    /// Represents a user subject
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serialize", derive(serde::Serialize))]
    pub struct User(pub users::uid_t);

    impl User {
        pub fn from_uid(uid: libc::uid_t) -> User {
            User(uid as users::uid_t)
        }

        pub fn from_name(name: &str) -> Result<User, ParseError> {
            let uid = get_user_by_name(name)
                .ok_or_else(|| ParseError::UnknownUser(name.into()))?
                .uid();

            Ok(User::from_uid(uid))
        }
    }

    impl fmt::Display for User {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match get_user_by_uid(self.0) {
                Some(user) => write!(f, "user:{}", user.name().to_str().ok_or(fmt::Error)?),
                None => write!(f, "user:{}", self.0),
            }
        }
    }

    impl<'a> From<&'a User> for String {
        fn from(user: &'a User) -> String {
            format!("user:{}", user.0)
        }
    }

    /// Represents a process subject
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serialize", derive(serde::Serialize))]
    pub struct Process(pub libc::pid_t);

    impl fmt::Display for Process {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "process:{}", self.0)
        }
    }

    impl<'a> From<&'a Process> for String {
        fn from(proc: &'a Process) -> String {
            format!("{}", proc)
        }
    }

    /// Represents a jail subject
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serialize", derive(serde::Serialize))]
    pub struct Jail(pub String);

    impl fmt::Display for Jail {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "jail:{}", self.0)
        }
    }

    impl<'a> From<&'a Jail> for String {
        fn from(jail: &'a Jail) -> String {
            format!("{}", jail)
        }
    }

    /// Represents a login class subject
    #[derive(Clone, Debug, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "serialize", derive(serde::Serialize))]
    pub struct LoginClass(pub String);

    impl fmt::Display for LoginClass {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "loginclass:{}", self.0)
        }
    }

    impl<'a> From<&'a LoginClass> for String {
        fn from(login_class: &'a LoginClass) -> String {
            format!("{}", login_class)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn display_jail_name() {
            assert_eq!(
                format!("{}", Jail("testjail_rctl_name".into())),
                "jail:testjail_rctl_name".to_string()
            );
        }

        #[test]
        fn display_user() {
            assert_eq!(
                format!("{}", User::from_name("nobody").expect("no nobody user")),
                "user:nobody".to_string()
            );

            assert_eq!(format!("{}", User::from_uid(4242)), "user:4242".to_string());
        }

        #[test]
        fn display_loginclass() {
            assert_eq!(
                format!("{}", LoginClass("test".into())),
                "loginclass:test".to_string()
            );
        }
    }
}

/// A struct representing an RCTL subject.
///
/// From [`rctl(8)`]:
/// > Subject defines the kind of entity the rule applies to.  It can be either
/// > process, user, login class, or jail.
/// >
/// > Subject ID identifies the subject. It can be user name, numerical user ID
/// > login class name, or jail name.
///
/// [`rctl(8)`]: https://www.freebsd.org/cgi/man.cgi?query=rctl&sektion=8&manpath=FreeBSD+11.2-stable
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum Subject {
    Process(subject::Process),
    Jail(subject::Jail),
    User(subject::User),
    LoginClass(subject::LoginClass),
}

impl Subject {
    pub fn process_id(pid: libc::pid_t) -> Self {
        Subject::Process(subject::Process(pid))
    }

    pub fn user_name(name: &str) -> Result<Self, ParseError> {
        Ok(Subject::User(subject::User::from_name(name)?))
    }

    pub fn user_id(uid: libc::uid_t) -> Self {
        Subject::User(subject::User::from_uid(uid))
    }

    pub fn login_class<S: Into<String>>(name: S) -> Self {
        Subject::LoginClass(subject::LoginClass(name.into()))
    }

    pub fn jail_name<S: Into<String>>(name: S) -> Self {
        Subject::Jail(subject::Jail(name.into()))
    }

    /// Get the resource usage for a specific [Subject].
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate rctl;
    /// # use rctl;
    /// # if !rctl::State::check().is_enabled() {
    /// #     return;
    /// # }
    /// extern crate libc;
    ///
    /// let uid = unsafe { libc::getuid() };
    /// let subject = rctl::Subject::user_id(uid);
    ///
    /// let usage = subject.usage()
    ///     .expect("Could not get RCTL usage");
    ///
    /// println!("{:#?}", usage);
    /// ```
    pub fn usage(&self) -> Result<HashMap<Resource, usize>, Error> {
        extern "C" {
            fn rctl_get_racct(
                inbufp: *const libc::c_char,
                inbuflen: libc::size_t,
                outbufp: *mut libc::c_char,
                outbuflen: libc::size_t,
            ) -> libc::c_int;
        }

        let filter = Filter::new().subject(self);

        let rusage = rctl_api_wrapper(rctl_get_racct, &filter)?;

        let mut map: HashMap<Resource, usize> = HashMap::new();

        for statistic in rusage.split(',') {
            let mut kv = statistic.split('=');

            let resource = kv
                .next()
                .ok_or(Error::InvalidStatistics)?
                .parse::<Resource>()
                .map_err(Error::ParseError)?;

            let value = kv
                .next()
                .ok_or(Error::InvalidStatistics)?
                .parse::<usize>()
                .map_err(ParseError::InvalidNumeral)
                .map_err(Error::ParseError)?;

            map.insert(resource, value);
        }

        Ok(map)
    }

    /// Get an IntoIterator over the rules that apply to this subject.
    pub fn limits(&self) -> Result<RuleParsingIntoIter<String>, Error> {
        extern "C" {
            fn rctl_get_limits(
                inbufp: *const libc::c_char,
                inbuflen: libc::size_t,
                outbufp: *mut libc::c_char,
                outbuflen: libc::size_t,
            ) -> libc::c_int;
        }

        let outbuf = rctl_api_wrapper(rctl_get_limits, self)?;

        Ok(RuleParsingIntoIter { inner: outbuf })
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Subject::Process(p) => write!(f, "{}", p),
            Subject::User(u) => write!(f, "{}", u),
            Subject::Jail(j) => write!(f, "{}", j),
            Subject::LoginClass(c) => write!(f, "{}", c),
        }
    }
}

impl<'a> From<&'a Subject> for String {
    fn from(subject: &'a Subject) -> String {
        match subject {
            Subject::Process(ref p) => p.into(),
            Subject::User(ref u) => u.into(),
            Subject::Jail(ref j) => j.into(),
            Subject::LoginClass(ref c) => c.into(),
        }
    }
}

fn parse_process(s: &str) -> Result<Subject, ParseError> {
    s.parse::<libc::pid_t>()
        .map_err(ParseError::InvalidNumeral)
        .map(Subject::process_id)
}

fn parse_user(s: &str) -> Result<Subject, ParseError> {
    match s.parse::<libc::uid_t>() {
        Ok(uid) => Ok(Subject::user_id(uid)),
        Err(_) => Ok(Subject::user_name(s)?),
    }
}

fn parse_jail(s: &str) -> Subject {
    Subject::jail_name(s)
}

fn parse_login_class(s: &str) -> Subject {
    Subject::login_class(s)
}

impl str::FromStr for Subject {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split(':').collect();

        let subject_type = parts[0].parse::<SubjectType>()?;

        match parts.len() {
            1 => Err(ParseError::NoSubjectGiven),
            2 => match subject_type {
                SubjectType::Process => parse_process(parts[1]),
                SubjectType::User => parse_user(parts[1]),
                SubjectType::LoginClass => Ok(parse_login_class(parts[1])),
                SubjectType::Jail => Ok(parse_jail(parts[1])),
            },
            _ => Err(ParseError::SubjectBogusData(format!(
                ":{}",
                parts[2..].join(":")
            ))),
        }
    }
}

/// The type of a [Subject].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum SubjectType {
    Process,
    Jail,
    User,
    LoginClass,
}

impl str::FromStr for SubjectType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "process" => Ok(SubjectType::Process),
            "jail" => Ok(SubjectType::Jail),
            "user" => Ok(SubjectType::User),
            "loginclass" => Ok(SubjectType::LoginClass),
            _ => Err(ParseError::UnknownSubjectType(s.into())),
        }
    }
}

impl<'a> From<&'a Subject> for SubjectType {
    fn from(subject: &'a Subject) -> Self {
        match subject {
            Subject::Process(_) => SubjectType::Process,
            Subject::Jail(_) => SubjectType::Jail,
            Subject::User(_) => SubjectType::User,
            Subject::LoginClass(_) => SubjectType::LoginClass,
        }
    }
}

impl SubjectType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SubjectType::Process => "process",
            SubjectType::Jail => "jail",
            SubjectType::User => "user",
            SubjectType::LoginClass => "loginclass",
        }
    }
}

impl<'a> From<&'a SubjectType> for &'static str {
    fn from(subject_type: &'a SubjectType) -> &'static str {
        subject_type.as_str()
    }
}

impl<'a> From<&'a SubjectType> for String {
    fn from(subject_type: &'a SubjectType) -> String {
        subject_type.as_str().into()
    }
}

impl fmt::Display for SubjectType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let r: &'static str = self.into();
        write!(f, "{}", r)
    }
}

/// An Enum representing a resource type
#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum Resource {
    /// CPU time, in seconds
    CpuTime,

    /// datasize, in bytes
    DataSize,

    /// stack size, in bytes
    ///
    /// from the [FreeBSD Handbook Chapter 13.13 - Resource Limits]:
    /// > The maximum size of a process stack. This alone is not sufficient to
    /// > limit the amount of memory a program may use, so it should be used in
    /// > conjunction with other limits.
    ///
    /// [FreeBSD Handbook Chapter 13.13 - Resource Limits]:
    ///   https://www.freebsd.org/doc/handbook/security-resourcelimits.html#resource-limits
    StackSize,

    /// coredump size, in bytes
    ///
    /// from the [FreeBSD Handbook Chapter 13.13 - Resource Limits]:
    /// > The limit on the size of a core file generated by a program is
    /// > subordinate to other limits on disk usage, such as filesize or disk
    /// > quotas. This limit is often used as a less severe method of
    /// > controlling disk space consumption. Since users do not generate core
    /// > files and often do not delete them, this setting may save them from
    /// > running out of disk space should a large program crash.
    ///
    /// [FreeBSD Handbook Chapter 13.13 - Resource Limits]:
    ///   https://www.freebsd.org/doc/handbook/security-resourcelimits.html#resource-limits
    CoreDumpSize,

    /// resident setsize, in bytes
    MemoryUse,

    /// locked memory, in bytes
    ///
    /// from the [FreeBSD Handbook Chapter 13.13 - Resource Limits]:
    /// > The maximum amount of memory a process may request to be locked into
    /// > main memory using [`mlock(2)`]. Some system-critical programs, such as
    /// > [`amd(8)`], lock into main memory so that if the system begins to
    /// > swap, they do not contribute to disk thrashing.
    ///
    /// [`mlock(2)`]:
    ///   https://www.freebsd.org/cgi/man.cgi?query=mlock&sektion=2&manpath=freebsd-release-ports
    /// [`amd(8)`]:
    ///   https://www.freebsd.org/cgi/man.cgi?query=amd&sektion=8&manpath=freebsd-release-ports
    /// [FreeBSD Handbook Chapter 13.13 - Resource Limits]:
    ///   https://www.freebsd.org/doc/handbook/security-resourcelimits.html#resource-limits
    MemoryLocked,

    /// number of processes
    MaxProcesses,

    /// File descriptor table size
    OpenFiles,

    /// address space limit, in bytes
    VMemoryUse,

    /// number of PTYs
    PseudoTerminals,

    /// swapspace that may be reserved or used, in bytes
    SwapUse,

    /// number of threads
    NThreads,

    /// number of queued SysV messages
    MsgqQueued,

    /// SysVmessagequeue size, in bytes
    MsgqSize,

    /// number of SysV message queues
    NMsgq,

    /// number of SysV semaphores
    Nsem,

    /// number of SysV semaphores modified in a single `semop(2)` call
    NSemop,

    /// number of SysV shared memorysegments
    NShm,

    /// SysVshared memory size, in bytes
    ShmSize,

    /// wallclock time, in seconds
    Wallclock,

    /// %CPU, in percents of a single CPU core
    PercentCpu,

    /// filesystem reads, in bytes per second
    ReadBps,

    /// filesystem writes, in bytes per second
    WriteBps,

    /// filesystem reads, inoperations per second
    ReadIops,

    /// filesystem writes, in operations persecond
    WriteIops,
}

impl Resource {
    /// Return the string representation of the resource
    ///
    /// # Examples
    /// ```
    /// use rctl::Resource;
    /// assert_eq!(Resource::CpuTime.as_str(), "cputime");
    /// ```
    pub fn as_str(&self) -> &'static str {
        match self {
            Resource::CpuTime => "cputime",
            Resource::DataSize => "datasize",
            Resource::StackSize => "stacksize",
            Resource::CoreDumpSize => "coredumpsize",
            Resource::MemoryUse => "memoryuse",
            Resource::MemoryLocked => "memorylocked",
            Resource::MaxProcesses => "maxproc",
            Resource::OpenFiles => "openfiles",
            Resource::VMemoryUse => "vmemoryuse",
            Resource::PseudoTerminals => "pseudoterminals",
            Resource::SwapUse => "swapuse",
            Resource::NThreads => "nthr",
            Resource::MsgqQueued => "msgqqueued",
            Resource::MsgqSize => "msgqsize",
            Resource::NMsgq => "nmsgq",
            Resource::Nsem => "nsem",
            Resource::NSemop => "nsemop",
            Resource::NShm => "nshm",
            Resource::ShmSize => "shmsize",
            Resource::Wallclock => "wallclock",
            Resource::PercentCpu => "pcpu",
            Resource::ReadBps => "readbps",
            Resource::WriteBps => "writebps",
            Resource::ReadIops => "readiops",
            Resource::WriteIops => "writeiops",
        }
    }
}

impl str::FromStr for Resource {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cputime" => Ok(Resource::CpuTime),
            "datasize" => Ok(Resource::DataSize),
            "stacksize" => Ok(Resource::StackSize),
            "coredumpsize" => Ok(Resource::CoreDumpSize),
            "memoryuse" => Ok(Resource::MemoryUse),
            "memorylocked" => Ok(Resource::MemoryLocked),
            "maxproc" => Ok(Resource::MaxProcesses),
            "openfiles" => Ok(Resource::OpenFiles),
            "vmemoryuse" => Ok(Resource::VMemoryUse),
            "pseudoterminals" => Ok(Resource::PseudoTerminals),
            "swapuse" => Ok(Resource::SwapUse),
            "nthr" => Ok(Resource::NThreads),
            "msgqqueued" => Ok(Resource::MsgqQueued),
            "msgqsize" => Ok(Resource::MsgqSize),
            "nmsgq" => Ok(Resource::NMsgq),
            "nsem" => Ok(Resource::Nsem),
            "nsemop" => Ok(Resource::NSemop),
            "nshm" => Ok(Resource::NShm),
            "shmsize" => Ok(Resource::ShmSize),
            "wallclock" => Ok(Resource::Wallclock),
            "pcpu" => Ok(Resource::PercentCpu),
            "readbps" => Ok(Resource::ReadBps),
            "writebps" => Ok(Resource::WriteBps),
            "readiops" => Ok(Resource::ReadIops),
            "writeiops" => Ok(Resource::WriteIops),
            _ => Err(ParseError::UnknownResource(s.into())),
        }
    }
}

impl<'a> From<&'a Resource> for &'a str {
    fn from(resource: &'a Resource) -> &'a str {
        resource.as_str()
    }
}

impl<'a> From<&'a Resource> for String {
    fn from(resource: &'a Resource) -> String {
        resource.as_str().to_owned()
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Represents the action to be taken when a [Subject] offends against a Rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub enum Action {
    /// Deny the resource allocation
    ///
    /// Not supported for the following [Resources]: [`CpuTime`], [`Wallclock`],
    /// [`ReadBps`], [`WriteBps`], [`ReadIops`], [`WriteIops`]
    ///
    /// [`CpuTime`]: Resource::CpuTime

    /// [`WallClock`]: Resource::Wallclock
    /// [`ReadBps`]: Resource::ReadBps
    /// [`WriteBps`]: Resource::WriteBps
    /// [`ReadIops`]: Resource::ReadIops
    /// [`WriteIops`]: Resource::WriteIops
    /// [Resources]: Resource
    Deny,

    /// Log a warning to the console
    Log,

    /// Send a notification to [`devd(8)`] using `system = "RCTL"`,
    /// `subsystem = "rule"`, `type = "matched"`
    ///
    /// [`devd(8)`]: https://www.freebsd.org/cgi/man.cgi?query=devd&sektion=8&manpath=FreeBSD+11.2-stable
    DevCtl,

    /// Send a [signal] to the offending process.
    ///
    /// # Example
    /// ```
    /// # extern crate rctl;
    /// use rctl::Signal;
    /// use rctl::Action;
    ///
    /// let action = Action::Signal(Signal::SIGTERM);
    /// ```
    ///
    /// [signal]: Signal
    #[cfg_attr(feature = "serialize", serde(serialize_with = "signal_serialize"))]
    Signal(Signal),

    /// Slow down process execution
    ///
    /// Only supported for the following [Resources]:
    /// [`ReadBps`], [`WriteBps`], [`ReadIops`], [`WriteIops`]
    ///
    /// [`ReadBps`]: Resource::ReadBps
    /// [`WriteBps`]: Resource::WriteBps
    /// [`ReadIops`]: Resource::ReadIops
    /// [`WriteIops`]: Resource::WriteIops
    /// [Resources]: Resource
    Throttle,
}

impl Action {
    /// Return the string representation of the Action according to [`rctl(8)`]
    ///
    /// # Examples
    /// ```
    /// use rctl::Action;
    /// assert_eq!(Action::Deny.as_str(), "deny");
    /// ```
    ///
    /// Signals are handled by `rctl::Signal`:
    /// ```
    /// # extern crate rctl;
    /// # use rctl::Action;
    /// use rctl::Signal;
    /// assert_eq!(Action::Signal(Signal::SIGKILL).as_str(), "sigkill");
    /// ```
    ///
    /// [`rctl(8)`]: https://www.freebsd.org/cgi/man.cgi?query=rctl&sektion=8&manpath=FreeBSD+11.2-stable
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Deny => "deny",
            Action::Log => "log",
            Action::DevCtl => "devctl",
            Action::Throttle => "throttle",
            Action::Signal(sig) => match sig {
                Signal::SIGHUP => "sighup",
                Signal::SIGINT => "sigint",
                Signal::SIGQUIT => "sigquit",
                Signal::SIGILL => "sigill",
                Signal::SIGTRAP => "sigtrap",
                Signal::SIGABRT => "sigabrt",
                Signal::SIGBUS => "sigbus",
                Signal::SIGFPE => "sigfpe",
                Signal::SIGKILL => "sigkill",
                Signal::SIGUSR1 => "sigusr1",
                Signal::SIGSEGV => "sigsegv",
                Signal::SIGUSR2 => "sigusr2",
                Signal::SIGPIPE => "sigpipe",
                Signal::SIGALRM => "sigalrm",
                Signal::SIGTERM => "sigterm",
                Signal::SIGCHLD => "sigchld",
                Signal::SIGCONT => "sigcont",
                Signal::SIGSTOP => "sigstop",
                Signal::SIGTSTP => "sigtstp",
                Signal::SIGTTIN => "sigttin",
                Signal::SIGTTOU => "sigttou",
                Signal::SIGURG => "sigurg",
                Signal::SIGXCPU => "sigxcpu",
                Signal::SIGXFSZ => "sigxfsz",
                Signal::SIGVTALRM => "sigvtalrm",
                Signal::SIGPROF => "sigprof",
                Signal::SIGWINCH => "sigwinch",
                Signal::SIGIO => "sigio",
                Signal::SIGSYS => "sigsys",
                Signal::SIGEMT => "sigemt",
                Signal::SIGINFO => "siginfo",
            },
        }
    }
}

impl str::FromStr for Action {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "deny" => Ok(Action::Deny),
            "log" => Ok(Action::Log),
            "devctl" => Ok(Action::DevCtl),
            "throttle" => Ok(Action::Throttle),
            "sighup" => Ok(Action::Signal(Signal::SIGHUP)),
            "sigint" => Ok(Action::Signal(Signal::SIGINT)),
            "sigquit" => Ok(Action::Signal(Signal::SIGQUIT)),
            "sigill" => Ok(Action::Signal(Signal::SIGILL)),
            "sigtrap" => Ok(Action::Signal(Signal::SIGTRAP)),
            "sigabrt" => Ok(Action::Signal(Signal::SIGABRT)),
            "sigbus" => Ok(Action::Signal(Signal::SIGBUS)),
            "sigfpe" => Ok(Action::Signal(Signal::SIGFPE)),
            "sigkill" => Ok(Action::Signal(Signal::SIGKILL)),
            "sigusr1" => Ok(Action::Signal(Signal::SIGUSR1)),
            "sigsegv" => Ok(Action::Signal(Signal::SIGSEGV)),
            "sigusr2" => Ok(Action::Signal(Signal::SIGUSR2)),
            "sigpipe" => Ok(Action::Signal(Signal::SIGPIPE)),
            "sigalrm" => Ok(Action::Signal(Signal::SIGALRM)),
            "sigterm" => Ok(Action::Signal(Signal::SIGTERM)),
            "sigchld" => Ok(Action::Signal(Signal::SIGCHLD)),
            "sigcont" => Ok(Action::Signal(Signal::SIGCONT)),
            "sigstop" => Ok(Action::Signal(Signal::SIGSTOP)),
            "sigtstp" => Ok(Action::Signal(Signal::SIGTSTP)),
            "sigttin" => Ok(Action::Signal(Signal::SIGTTIN)),
            "sigttou" => Ok(Action::Signal(Signal::SIGTTOU)),
            "sigurg" => Ok(Action::Signal(Signal::SIGURG)),
            "sigxcpu" => Ok(Action::Signal(Signal::SIGXCPU)),
            "sigxfsz" => Ok(Action::Signal(Signal::SIGXFSZ)),
            "sigvtalrm" => Ok(Action::Signal(Signal::SIGVTALRM)),
            "sigprof" => Ok(Action::Signal(Signal::SIGPROF)),
            "sigwinch" => Ok(Action::Signal(Signal::SIGWINCH)),
            "sigio" => Ok(Action::Signal(Signal::SIGIO)),
            "sigsys" => Ok(Action::Signal(Signal::SIGSYS)),
            "sigemt" => Ok(Action::Signal(Signal::SIGEMT)),
            "siginfo" => Ok(Action::Signal(Signal::SIGINFO)),
            _ => Err(ParseError::UnknownAction(s.into())),
        }
    }
}

impl<'a> From<&'a Action> for &'a str {
    fn from(action: &'a Action) -> &'a str {
        action.as_str()
    }
}

impl<'a> From<&'a Action> for String {
    fn from(action: &'a Action) -> String {
        action.as_str().into()
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(feature = "serialize")]
fn signal_serialize<S>(signal: &Signal, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let sig_str = format!("{:?}", signal);
    s.serialize_str(&sig_str)
}

/// Defines how much of a [Resource] a process can use beofore the defined
/// [Action] triggers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct Limit {
    amount: usize,
    per: Option<SubjectType>,
}

impl Limit {
    /// Construct a limit representing the amount used before an [Action]
    /// triggers.
    ///
    /// The entity the amount gets accounted for defaults to the type of the
    /// [Subject] of the respective [Rule].
    pub fn amount(amount: usize) -> Limit {
        Limit { amount, per: None }
    }

    /// Limit the amount per [SubjectType].
    ///
    /// This defines what entity the amount gets accounted for.
    ///
    /// # Examples
    ///
    /// For example the following [Rule] means that each process of any user
    /// belonging to the login class "users" may allocate up to 100 MiB of
    /// virtual memory:
    /// ```rust
    /// # use rctl::{Subject, SubjectType, Resource, Action, Limit, Rule};
    /// Rule {
    ///     subject: Subject::login_class("users"),
    ///     resource: Resource::VMemoryUse,
    ///     action: Action::Deny,
    ///     limit: Limit::amount_per(100*1024*1024, SubjectType::Process),
    /// }
    /// # ;
    /// ```
    ///
    /// Setting `per: Some(SubjectType::User)` on the above [Rule] would mean
    /// that for each user belonging to the login class "users", the sum of
    /// virtual memory allocated by all the processes of that user will not
    /// exceed 100 MiB.
    ///
    /// Setting `per: Some(SubjectType::LoginClass)` on the above [Rule] would
    /// mean that the sum of virtual memory allocated by all processes of all
    /// users belonging to that login class will not exceed 100 MiB.
    pub fn amount_per(amount: usize, per: SubjectType) -> Limit {
        Limit {
            amount,
            per: Some(per),
        }
    }
}

fn parse_limit_with_suffix(s: &str) -> Result<usize, ParseError> {
    let s = s.trim().to_lowercase();

    if let Ok(v) = s.parse::<usize>() {
        return Ok(v);
    }

    let suffixes = ["k", "m", "g", "t", "p", "e", "z", "y"];

    for (i, suffix) in suffixes.iter().enumerate() {
        match s
            .split(suffix)
            .next()
            .expect("could not split the suffix off")
            .parse::<usize>()
        {
            Err(_) => continue,
            Ok(v) => return Ok(v * 1024usize.pow((i + 1) as u32)),
        };
    }

    Err(ParseError::InvalidLimitLiteral(s))
}

impl str::FromStr for Limit {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<_> = s.split('/').collect();

        let val = parse_limit_with_suffix(parts[0])?;

        match parts.len() {
            1 => Ok(Limit::amount(val)),
            2 => Ok(Limit::amount_per(val, parts[1].parse::<SubjectType>()?)),
            _ => Err(ParseError::LimitBogusData(format!(
                "/{}",
                parts[2..].join("/")
            ))),
        }
    }
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let amount = match NumberPrefix::binary(self.amount as f64) {
            NumberPrefix::Standalone(amt) => format!("{}", amt),
            NumberPrefix::Prefixed(prefix, amt) => {
                let prefix = match prefix {
                    Prefix::Kibi => "k",
                    Prefix::Mebi => "m",
                    Prefix::Gibi => "g",
                    Prefix::Tebi => "t",
                    Prefix::Pebi => "p",
                    Prefix::Exbi => "e",
                    Prefix::Zebi => "z",
                    Prefix::Yobi => "y",
                    _ => panic!("called binary_prefix but got decimal prefix"),
                };

                format!("{}{}", amt, prefix)
            }
        };

        let per = match &self.per {
            Some(ref s) => format!("/{}", s),
            None => "".to_string(),
        };

        write!(f, "{}{}", amount, per)
    }
}

impl<'a> From<&'a Limit> for String {
    fn from(limit: &'a Limit) -> String {
        let per = match &limit.per {
            Some(ref s) => format!("/{}", s),
            None => "".to_string(),
        };
        format!("{}{}", limit.amount, per)
    }
}

/// A rule represents an [Action] to be taken when a particular [Subject] hits
/// a [Limit] for a [Resource].
///
/// Syntax for the string representation of a rule is
/// `subject:subject-id:resource:action=amount/per`.
///
/// # Examples
///
/// ```rust
/// use rctl::{Subject, SubjectType, Resource, Action, Limit, Rule};
/// let rule = Rule {
///     subject: Subject::user_name("nobody").expect("no user 'nobody'"),
///     resource: Resource::VMemoryUse,
///     action: Action::Deny,
///     limit: Limit::amount(1024*1024*1024),
/// };
///
/// assert_eq!(rule.to_string(), "user:nobody:vmemoryuse:deny=1g".to_string());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serialize", derive(serde::Serialize))]
pub struct Rule {
    pub subject: Subject,
    pub resource: Resource,
    pub limit: Limit,
    pub action: Action,
}

impl Rule {
    /// Add this rule to the resource limits database.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate rctl;
    /// # if !rctl::State::check().is_enabled() {
    /// #     return;
    /// # }
    /// use rctl::{Rule, Subject, Resource, Action, Limit};
    ///
    /// let rule = Rule {
    ///     subject: Subject::jail_name("testjail_rctl_rule_apply_method"),
    ///     resource: Resource::VMemoryUse,
    ///     action: Action::Log,
    ///     limit: Limit::amount(100*1024*1024),
    /// };
    ///
    /// rule.apply();
    /// # rule.remove();
    /// ```
    pub fn apply(&self) -> Result<(), Error> {
        extern "C" {
            fn rctl_add_rule(
                inbufp: *const libc::c_char,
                inbuflen: libc::size_t,
                outbufp: *mut libc::c_char,
                outbuflen: libc::size_t,
            ) -> libc::c_int;
        }

        rctl_api_wrapper(rctl_add_rule, self)?;

        Ok(())
    }

    /// Attempt to remove this rule from the resource limits database.
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate rctl;
    /// # if !rctl::State::check().is_enabled() {
    /// #     return;
    /// # }
    /// use rctl::{Rule, Subject, Resource, Action, Limit};
    ///
    /// let rule = Rule {
    ///     subject: Subject::jail_name("testjail_rctl_rule_remove_method"),
    ///     resource: Resource::VMemoryUse,
    ///     action: Action::Log,
    ///     limit: Limit::amount(100*1024*1024),
    /// };
    ///
    /// # rule.apply();
    /// rule.remove();
    /// ```
    pub fn remove(&self) -> Result<(), Error> {
        let filter: Filter = self.into();
        filter.remove_rules()
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}={}",
            self.subject, self.resource, self.action, self.limit
        )
    }
}

impl<'a> From<&'a Rule> for String {
    fn from(rule: &'a Rule) -> String {
        let subject: String = (&rule.subject).into();
        let resource: &str = (&rule.resource).into();
        let action: &str = (&rule.action).into();
        let limit: String = (&rule.limit).into();
        format!("{}:{}:{}={}", subject, resource, action, limit)
    }
}

impl str::FromStr for Rule {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // subject:subject-id:resource:action=amount/per
        let parts: Vec<_> = s.split(':').collect();

        if parts.len() != 4 {
            return Err(ParseError::InvalidRuleSyntax(s.into()));
        }

        let subject = format!("{}:{}", parts[0], parts[1]).parse::<Subject>()?;
        let resource = parts[2].parse::<Resource>()?;

        let parts: Vec<_> = parts[3].split('=').collect();

        if parts.len() != 2 {
            return Err(ParseError::InvalidRuleSyntax(s.into()));
        }

        let action = parts[0].parse::<Action>()?;
        let limit = parts[1].parse::<Limit>()?;

        Ok(Rule {
            subject,
            resource,
            action,
            limit,
        })
    }
}

/// Adapter over objects parseable into a [Rule]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleParserAdapter<I> {
    inner: I,
}

impl<'a, I> Iterator for RuleParserAdapter<I>
where
    I: Iterator<Item = &'a str>,
{
    type Item = Rule;

    fn next(&mut self) -> Option<Rule> {
        match self.inner.next() {
            Some(item) => item.parse::<Rule>().ok(),
            None => None,
        }
    }
}

/// Owning struct implementing IntoIterator, returning a [RuleParserAdapter].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleParsingIntoIter<S> {
    inner: S,
}

impl<'a> IntoIterator for &'a RuleParsingIntoIter<String> {
    type Item = Rule;
    type IntoIter = RuleParserAdapter<str::Split<'a, char>>;

    fn into_iter(self) -> Self::IntoIter {
        RuleParserAdapter {
            inner: self.inner.split(','),
        }
    }
}

trait RuleParsingExt<'a>: Sized {
    fn parse_rules(self) -> RuleParserAdapter<Self>;
}

impl<'a> RuleParsingExt<'a> for str::Split<'a, &'a str> {
    fn parse_rules(self) -> RuleParserAdapter<Self> {
        RuleParserAdapter { inner: self }
    }
}

/// A filter can match a set of [Rules](Rule).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Filter {
    subject_type: Option<SubjectType>,
    subject: Option<Subject>,

    resource: Option<Resource>,
    limit: Option<Limit>,

    action: Option<Action>,
    limit_per: Option<SubjectType>,
}

impl Filter {
    /// Return the filter that matches all rules
    ///
    /// # Example
    ///
    /// ```
    /// # use rctl::Filter;
    /// let filter = Filter::new();
    /// assert_eq!(filter.to_string(), ":".to_string());
    /// ```
    pub fn new() -> Filter {
        Filter::default()
    }

    /// Constrain the filter to a specific [SubjectType]
    ///
    /// If the filter is already constrained to a subject, this is a No-Op.
    ///
    /// # Example
    ///
    /// ```
    /// # use rctl::{Filter, SubjectType};
    /// let filter = Filter::new()
    ///     .subject_type(&SubjectType::LoginClass);
    /// assert_eq!(filter.to_string(), "loginclass:".to_string());
    /// ```
    pub fn subject_type(mut self: Filter, subject_type: &SubjectType) -> Filter {
        if self.subject.is_none() {
            self.subject_type = Some(*subject_type);
        }
        self
    }

    /// Constrain the filter to a specific [Subject]
    ///
    /// Resets the subject type.
    ///
    /// # Example
    ///
    /// ```
    /// # use rctl::{Filter, Subject};
    /// let filter = Filter::new()
    ///     .subject(&Subject::user_name("nobody").expect("no user 'nobody'"));
    /// assert_eq!(filter.to_string(), "user:nobody".to_string());
    /// ```
    pub fn subject(mut self: Filter, subject: &Subject) -> Filter {
        self.subject = Some(subject.clone());
        self.subject_type = None;
        self
    }

    /// Constrain the filter to a specific [Resource]
    ///
    /// # Example
    ///
    /// ```
    /// # use rctl::{Filter, Resource};
    /// let filter = Filter::new()
    ///     .resource(&Resource::MemoryLocked);
    /// assert_eq!(filter.to_string(), "::memorylocked".to_string());
    /// ```
    pub fn resource(mut self: Filter, resource: &Resource) -> Filter {
        self.resource = Some(*resource);
        self
    }

    /// Constrain the filter to a specific [Action]
    ///
    /// # Example
    ///
    /// ```
    /// # use rctl::{Filter, Action};
    /// let filter = Filter::new()
    ///     .action(&Action::Deny);
    /// assert_eq!(filter.to_string(), ":::deny".to_string());
    /// ```
    pub fn action(mut self: Filter, action: &Action) -> Filter {
        self.action = Some(*action);
        self
    }

    /// Constrain the filter to the [Deny](Action::Deny) [Action]
    ///
    /// # Example
    ///
    /// ```
    /// # use rctl::{Filter, Action};
    /// let filter = Filter::new()
    ///     .deny();
    /// assert_eq!(filter, Filter::new().action(&Action::Deny));
    /// ```
    pub fn deny(self: Filter) -> Filter {
        self.action(&Action::Deny)
    }

    /// Constrain the filter to the [Log](Action::Log) [Action]
    ///
    /// # Example
    ///
    /// ```
    /// # use rctl::{Filter, Action};
    /// let filter = Filter::new()
    ///     .log();
    /// assert_eq!(filter, Filter::new().action(&Action::Log));
    /// ```
    pub fn log(self: Filter) -> Filter {
        self.action(&Action::Log)
    }

    /// Constrain the filter to the [DevCtl](Action::DevCtl) [Action]
    ///
    /// # Example
    ///
    /// ```
    /// # use rctl::{Filter, Action};
    /// let filter = Filter::new()
    ///     .devctl();
    /// assert_eq!(filter, Filter::new().action(&Action::DevCtl));
    /// ```
    pub fn devctl(self: Filter) -> Filter {
        self.action(&Action::DevCtl)
    }

    /// Constrain the filter to the [Signal](Action::Signal) [Action]
    ///
    /// # Example
    ///
    /// ```
    /// # extern crate rctl;
    /// # use rctl::{Filter, Action, Signal};
    /// let filter = Filter::new()
    ///     .signal(Signal::SIGTERM);
    /// assert_eq!(filter.to_string(), ":::sigterm".to_string());
    /// ```
    pub fn signal(self: Filter, signal: Signal) -> Filter {
        self.action(&Action::Signal(signal))
    }

    /// Constrain the filter to a particular [Limit]
    ///
    /// Resets any limit_per, if the given limit has a `per` set.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rctl::{Filter, Limit};
    /// let filter = Filter::new()
    ///     .limit(&Limit::amount(100*1024*1024));
    /// assert_eq!(filter.to_string(), ":::=100m".to_string());
    /// ```
    ///
    /// ```
    /// # use rctl::{Filter, Limit, SubjectType};
    /// let filter = Filter::new()
    ///     .limit(&Limit::amount_per(100*1024*1024, SubjectType::Process));
    /// assert_eq!(filter.to_string(), ":::=100m/process".to_string());
    /// ```
    pub fn limit(mut self: Filter, limit: &Limit) -> Filter {
        let mut limit = limit.clone();

        // if the limit given doesn't have a `per` set, but we do, move it
        // into the limit.
        if let (Some(limit_per), None) = (self.limit_per, limit.per) {
            limit.per = Some(limit_per);
        }

        self.limit_per = None;
        self.limit = Some(limit);
        self
    }

    fn sanity(&self) {
        if let (Some(ref subject), Some(ref subject_type)) = (&self.subject, &self.subject_type) {
            let actual_type: SubjectType = subject.into();
            assert_eq!(&actual_type, subject_type);
        }
    }

    /// Return an [IntoIterator] over all [Rules] matching this [Filter].
    ///
    /// # Example
    ///
    /// List all rules:
    ///
    /// ```
    /// use rctl;
    ///
    /// let filter = rctl::Filter::new();
    /// for rule in filter.rules() {
    ///     println!("{:?}", rule);
    /// }
    /// ```
    ///
    /// [Rules]: Rule
    pub fn rules(&self) -> Result<RuleParsingIntoIter<String>, Error> {
        extern "C" {
            fn rctl_get_rules(
                inbufp: *const libc::c_char,
                inbuflen: libc::size_t,
                outbufp: *mut libc::c_char,
                outbuflen: libc::size_t,
            ) -> libc::c_int;
        }

        let outbuf = rctl_api_wrapper(rctl_get_rules, self)?;

        Ok(RuleParsingIntoIter { inner: outbuf })
    }

    /// Remove all matching [Rules] from the resource limits database.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate rctl;
    /// # if !rctl::State::check().is_enabled() {
    /// #     return;
    /// # }
    /// # use rctl::{Rule, Resource, Action, Limit};
    /// use rctl::{Filter, Subject};
    /// # let rule = Rule {
    /// #     subject: Subject::jail_name("testjail_rctl_filter_remove"),
    /// #     resource: Resource::VMemoryUse,
    /// #     action: Action::Log,
    /// #     limit: Limit::amount(100*1024*1024),
    /// # };
    /// # rule.apply();
    /// # let rule = Rule {
    /// #     subject: Subject::jail_name("testjail_rctl_filter_remove"),
    /// #     resource: Resource::StackSize,
    /// #     action: Action::Log,
    /// #     limit: Limit::amount(100*1024*1024),
    /// # };
    /// # rule.apply();
    /// let filter = Filter::new()
    ///     .subject(&Subject::jail_name("testjail_rctl_filter_remove"))
    ///     .remove_rules()
    ///     .expect("Could not remove rules");
    /// ```
    ///
    /// Remove all rules, clearing the resource limits database by using the
    /// default (`':'`) [Filter]:
    /// ```no_run
    /// # extern crate rctl;
    /// # use rctl::{Rule, Subject, Resource, Action, Limit};
    /// use rctl;
    ///
    /// rctl::Filter::new().remove_rules().expect("Could not remove all rules");
    /// ```
    ///
    /// [Rules]: Rule
    pub fn remove_rules(&self) -> Result<(), Error> {
        extern "C" {
            fn rctl_remove_rule(
                inbufp: *const libc::c_char,
                inbuflen: libc::size_t,
                outbufp: *mut libc::c_char,
                outbuflen: libc::size_t,
            ) -> libc::c_int;
        }

        rctl_api_wrapper(rctl_remove_rule, self)?;

        Ok(())
    }
}

impl fmt::Display for Filter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.sanity();

        match self {
            Filter {
                subject_type: Some(s),
                ..
            } => write!(f, "{}:", s),
            Filter {
                subject_type: None,
                subject: Some(ref s),
                ..
            } => write!(f, "{}", s),
            Filter {
                subject_type: None,
                subject: None,
                ..
            } => write!(f, ":"),
        }?;

        // If Resource, Action, and Limit are unset, leave it at this.
        if let Filter {
            resource: None,
            action: None,
            limit: None,
            limit_per: None,
            ..
        } = self
        {
            return Ok(());
        }

        match &self.resource {
            Some(resource) => write!(f, ":{}", resource),
            None => write!(f, ":"),
        }?;

        // If action, and limit are unset, leave it at this.
        if let Filter {
            action: None,
            limit: None,
            limit_per: None,
            ..
        } = self
        {
            return Ok(());
        }

        match &self.action {
            Some(action) => write!(f, ":{}", action),
            None => write!(f, ":"),
        }?;

        // If limit is unset, leave it at this
        if let Filter {
            limit: None,
            limit_per: None,
            ..
        } = self
        {
            return Ok(());
        }

        match &self.limit {
            Some(limit) => write!(f, "={}", limit),
            None => write!(
                f,
                "=/{}",
                self.limit_per.expect("could not unwrap limit_per")
            ),
        }
    }
}

impl<'a> From<&'a Filter> for String {
    fn from(filter: &'a Filter) -> String {
        let subject: String = match filter.subject {
            Some(ref s) => s.into(),
            None => ":".into(),
        };

        let resource: &str = match filter.resource {
            Some(ref r) => r.into(),
            None => "",
        };

        let action: &str = match filter.action {
            Some(ref a) => a.into(),
            None => "",
        };

        let limit: String = match filter.limit {
            Some(ref l) => l.into(),
            None => "".into(),
        };

        format!("{}:{}:{}={}", subject, resource, action, limit)
    }
}

impl From<Rule> for Filter {
    fn from(rule: Rule) -> Self {
        Filter {
            subject_type: None,
            subject: Some(rule.subject),
            resource: Some(rule.resource),
            limit: Some(rule.limit),
            limit_per: None,
            action: Some(rule.action),
        }
    }
}

impl<'a> From<&'a Rule> for Filter {
    fn from(rule: &'a Rule) -> Self {
        let rule = rule.clone();
        Filter {
            subject_type: None,
            subject: Some(rule.subject),
            resource: Some(rule.resource),
            limit: Some(rule.limit),
            limit_per: None,
            action: Some(rule.action),
        }
    }
}

impl<'a> From<&'a Subject> for Filter {
    fn from(subject: &'a Subject) -> Self {
        Filter::new().subject(subject)
    }
}

impl From<Subject> for Filter {
    fn from(subject: Subject) -> Self {
        Filter::new().subject(&subject)
    }
}

impl<'a> From<&'a SubjectType> for Filter {
    fn from(subject_type: &'a SubjectType) -> Self {
        Filter::new().subject_type(subject_type)
    }
}

impl From<SubjectType> for Filter {
    fn from(subject_type: SubjectType) -> Self {
        Filter::new().subject_type(&subject_type)
    }
}

impl<'a> From<&'a Action> for Filter {
    fn from(action: &'a Action) -> Self {
        Filter::new().action(action)
    }
}

impl From<Action> for Filter {
    fn from(action: Action) -> Self {
        Filter::new().action(&action)
    }
}

impl<'a> From<&'a Limit> for Filter {
    fn from(limit: &'a Limit) -> Self {
        Filter::new().limit(limit)
    }
}

impl From<Limit> for Filter {
    fn from(limit: Limit) -> Self {
        Filter::new().limit(&limit)
    }
}

/// Enum representing the state of `RACCT`/`RCTL` in the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum State {
    /// `RCTL` / `RACCT` is present in the kernel, but is not enabled via the
    /// `kern.racct.enable` tunable.
    Disabled,

    /// `RCTL` / `RACCT` is enabled.
    Enabled,

    /// `RCTL` / `RACCT` is disabled.
    ///
    /// The kernel does not support `RCTL` / `RACCT`. The following options have
    /// to be set in the kernel configuration when compiling the kernel to
    /// add support for `RCTL` / `RACCT`:
    ///
    /// ```ignore
    /// options         RACCT
    /// options         RCTL
    /// ```
    NotPresent,

    /// `RCTL` is not available within a Jail
    Jailed,
}

impl State {
    /// Check the state of the `RCTL` / `RACCT` support.
    ///
    /// This queries the `kern.racct.enable` sysctl. If this fails in any way,
    /// (most probably by the sysctl not being present), the kernel is assumed
    /// to be compiled without the `RCTL` / `RACCT` options.
    ///
    /// # Example
    ///
    /// ```
    /// # use rctl;
    /// let state = rctl::State::check();
    /// ```
    pub fn check() -> State {
        // RCTL is not available in a jail
        let jailed = sysctl::Ctl::new("security.jail.jailed");

        // If the sysctl call fails (unlikely), we assume we're in a Jail.
        if jailed.is_err() {
            return State::Jailed;
        }

        match jailed.unwrap().value() {
            Ok(sysctl::CtlValue::Int(0)) => {}
            _ => return State::Jailed,
        };

        // Check the kern.racct.enable sysctl.
        let enable_racct = sysctl::Ctl::new("kern.racct.enable");

        // If the sysctl call fails, we assume it to be disabled.
        if enable_racct.is_err() {
            return State::NotPresent;
        }

        match enable_racct.unwrap().value() {
            Ok(value) => match value {
                // FreeBSD 13 returns a U8 as the kernel variable is a bool.
                sysctl::CtlValue::U8(1) => State::Enabled,

                // FreeBSD older than 13 returns a Uint as the kernel variable
                // is an int.
                sysctl::CtlValue::Uint(1) => State::Enabled,

                // Other values we assume means RACCT is disabled.
                _ => State::Disabled,
            },

            // If we could not get the sysctl value, assume it to be disabled.
            _ => State::NotPresent,
        }
    }

    /// Return `true` if the `RCTL` / `RACCT` support is [Enabled].
    ///
    /// # Examples
    ///
    /// ```
    /// # use rctl;
    /// if rctl::State::check().is_enabled() {
    ///     // do things requiring `RCTL` / `RACCT` support.
    /// }
    /// ```
    ///
    /// [Enabled]: State::Enabled
    pub fn is_enabled(&self) -> bool {
        matches!(self, State::Enabled)
    }

    /// Return `true` if the kernel has `RCTL` / `RACCT` support compiled in.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rctl;
    /// if ! rctl::State::check().is_present() {
    ///     println!("The kernel does not have RCTL / RACCT support");
    /// }
    /// ```
    pub fn is_present(&self) -> bool {
        !matches!(self, State::NotPresent)
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            State::Enabled => write!(f, "enabled"),
            State::Disabled => write!(f, "disabled"),
            State::NotPresent => write!(f, "not present"),
            State::Jailed => write!(f, "not available in a jail"),
        }
    }
}

fn rctl_api_wrapper<S: Into<String>>(
    api: unsafe extern "C" fn(
        *const libc::c_char,
        libc::size_t,
        *mut libc::c_char,
        libc::size_t,
    ) -> libc::c_int,
    input: S,
) -> Result<String, Error> {
    // Get the input buffer as a C string.
    let input: String = input.into();
    let inputlen = input.len() + 1;
    let inbuf = CString::new(input).map_err(Error::CStringError)?;

    // C compatible output buffer.
    let mut outbuf: Vec<i8> = vec![0; RCTL_DEFAULT_BUFSIZE];

    loop {
        // Unsafe C call to get the jail resource usage.
        if unsafe {
            api(
                inbuf.as_ptr(),
                inputlen,
                outbuf.as_mut_ptr() as *mut libc::c_char,
                outbuf.len(),
            )
        } != 0
        {
            let err = io::Error::last_os_error();

            match err.raw_os_error() {
                Some(libc::ERANGE) => {
                    // if the error code is ERANGE, retry with a larger buffer
                    let current_len = outbuf.len();
                    outbuf.resize(current_len + RCTL_DEFAULT_BUFSIZE, 0);
                    continue;
                }
                Some(libc::EPERM) => {
                    let state = State::check();
                    break match state.is_enabled() {
                        true => Err(Error::OsError(err)),
                        false => Err(Error::InvalidKernelState(State::check())),
                    };
                }
                Some(libc::ENOSYS) => break Err(Error::InvalidKernelState(State::check())),
                Some(libc::ESRCH) => break Ok("".into()),
                _ => break Err(Error::OsError(err)),
            }
        }

        // If everything went well, convert the return C string in the outbuf
        // back into an easily usable Rust string and return.
        break Ok(
            unsafe { CStr::from_ptr(outbuf.as_ptr() as *mut libc::c_char) }
                .to_string_lossy()
                .into(),
        );
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn parse_subject_type() {
        assert_eq!(
            "user"
                .parse::<SubjectType>()
                .expect("could not parse user subject type"),
            SubjectType::User,
        );

        assert_eq!(
            "jail"
                .parse::<SubjectType>()
                .expect("could not parse jail subject type"),
            SubjectType::Jail,
        );

        assert!("bogus".parse::<SubjectType>().is_err());
    }

    #[test]
    fn parse_subject() {
        assert_eq!(
            "user:42"
                .parse::<Subject>()
                .expect("Could not parse 'user:42' as Subject"),
            Subject::user_id(42)
        );

        assert_eq!(
            "user:nobody"
                .parse::<Subject>()
                .expect("Could not parse 'user:nobody' as Subject"),
            Subject::user_name("nobody").expect("no user 'nobody'")
        );

        assert_eq!(
            "process:42"
                .parse::<Subject>()
                .expect("Could not parse 'process:42' as Subject"),
            Subject::process_id(42)
        );

        assert_eq!(
            "jail:www"
                .parse::<Subject>()
                .expect("Could not parse 'jail:www' as Subject"),
            Subject::jail_name("www")
        );

        assert_eq!(
            "loginclass:test"
                .parse::<Subject>()
                .expect("Could not parse 'loginclass:test' as Subject"),
            Subject::login_class("test")
        );

        assert!("".parse::<Subject>().is_err());
        assert!(":".parse::<Subject>().is_err());
        assert!(":1234".parse::<Subject>().is_err());
        assert!("bogus".parse::<Subject>().is_err());
        assert!("user".parse::<Subject>().is_err());
        assert!("process:bogus".parse::<Subject>().is_err());
        assert!("process:".parse::<Subject>().is_err());
        assert!("user:test:bogus".parse::<Subject>().is_err());
    }

    #[test]
    fn parse_resource() {
        assert_eq!(
            "vmemoryuse"
                .parse::<Resource>()
                .expect("could not parse vmemoryuse resource"),
            Resource::VMemoryUse,
        );

        assert!("bogus".parse::<Resource>().is_err());
    }

    #[test]
    fn parse_action() {
        assert_eq!(
            "deny"
                .parse::<Action>()
                .expect("could not parse deny action"),
            Action::Deny
        );

        assert_eq!(
            "log".parse::<Action>().expect("could not parse log action"),
            Action::Log
        );

        assert_eq!(
            "throttle"
                .parse::<Action>()
                .expect("could not parse throttle action"),
            Action::Throttle
        );

        assert_eq!(
            "devctl"
                .parse::<Action>()
                .expect("could not parse devctl action"),
            Action::DevCtl
        );

        assert_eq!(
            "sigterm"
                .parse::<Action>()
                .expect("could not parse sigterm action"),
            Action::Signal(Signal::SIGTERM)
        );

        assert!("bogus".parse::<Action>().is_err());
    }

    #[test]
    fn display_limit() {
        assert_eq!(
            Limit {
                amount: 100 * 1024 * 1024,
                per: None
            }
            .to_string(),
            "100m".to_string()
        );

        assert_eq!(
            Limit {
                amount: 100 * 1024 * 1024,
                per: Some(SubjectType::User)
            }
            .to_string(),
            "100m/user".to_string()
        );

        assert_eq!(
            Limit {
                amount: 42,
                per: Some(SubjectType::LoginClass)
            }
            .to_string(),
            "42/loginclass".to_string()
        );
    }

    #[test]
    fn parse_limit() {
        assert_eq!(
            "100m"
                .parse::<Limit>()
                .expect("Could not parse '100m' as Limit"),
            Limit::amount(100 * 1024 * 1024),
        );

        assert_eq!(
            "100m/user"
                .parse::<Limit>()
                .expect("Could not parse '100m/user' as Limit"),
            Limit::amount_per(100 * 1024 * 1024, SubjectType::User),
        );

        assert!("100m/bogus".parse::<Limit>().is_err());
        assert!("100m/userbogus".parse::<Limit>().is_err());
        assert!("100q".parse::<Limit>().is_err());
        assert!("-42".parse::<Limit>().is_err());
        assert!("".parse::<Limit>().is_err());
        assert!("bogus".parse::<Limit>().is_err());
    }

    #[test]
    fn parse_rule() {
        assert_eq!(
            "user:nobody:vmemoryuse:deny=1g"
                .parse::<Rule>()
                .expect("Could not parse 'user:nobody:vmemoryuse:deny=1g' as Rule"),
            Rule {
                subject: Subject::user_name("nobody").expect("no user 'nobody'"),
                resource: Resource::VMemoryUse,
                action: Action::Deny,
                limit: Limit::amount(1 * 1024 * 1024 * 1024),
            }
        );

        assert!(":::=/".parse::<Rule>().is_err());
        assert!("user:missing_resource:=100m/user".parse::<Rule>().is_err());
        assert!("user:missing_resource=100m/user".parse::<Rule>().is_err());
        assert!("user:too:many:colons:vmemoryuse:deny=100m/user"
            .parse::<Rule>()
            .is_err());
        assert!("loginclass:nolimit:vmemoryuse:deny="
            .parse::<Rule>()
            .is_err());
        assert!("loginclass:nolimit:vmemoryuse:deny"
            .parse::<Rule>()
            .is_err());
        assert!("loginclass:equals:vmemoryuse:deny=123=456"
            .parse::<Rule>()
            .is_err());
        assert!("-42".parse::<Rule>().is_err());
        assert!("".parse::<Rule>().is_err());
        assert!("bogus".parse::<Rule>().is_err());
    }

    #[test]
    fn display_filter() {
        assert_eq!(Filter::new().to_string(), ":".to_string());

        assert_eq!(
            Filter::new()
                .subject_type(&SubjectType::LoginClass)
                .to_string(),
            "loginclass:".to_string()
        );

        assert_eq!(
            Filter::new().subject(&Subject::user_id(42)).to_string(),
            "user:42".to_string()
        );

        assert_eq!(
            Filter::new().resource(&Resource::MaxProcesses).to_string(),
            "::maxproc".to_string()
        );

        assert_eq!(
            Filter::new()
                .subject(&Subject::user_id(42))
                .resource(&Resource::MemoryUse)
                .to_string(),
            "user:42:memoryuse".to_string()
        );

        assert_eq!(Filter::new().deny().to_string(), ":::deny".to_string());
    }

    #[test]
    fn iterate_rules() {
        if !State::check().is_enabled() {
            return;
        }

        let common_subject = Subject::jail_name("testjail_rctl_rules");
        let rule1 = Rule {
            subject: common_subject.clone(),
            resource: Resource::VMemoryUse,
            action: Action::Log,
            limit: Limit::amount(100 * 1024 * 1024),
        };
        rule1.apply().expect("Could not apply rule 1");

        let rule2 = Rule {
            subject: common_subject.clone(),
            resource: Resource::StackSize,
            action: Action::Log,
            limit: Limit::amount(100 * 1024 * 1024),
        };
        rule2.apply().expect("Could not apply rule 2");

        let filter = Filter::new().subject(&common_subject);

        let rules: HashSet<_> = filter
            .rules()
            .expect("Could not get rules matching filter")
            .into_iter()
            .collect();

        assert!(rules.contains(&rule1));
        assert!(rules.contains(&rule2));

        filter.remove_rules().expect("Could not remove rules");
    }

    #[cfg(feature = "serialize")]
    #[test]
    fn serialize_rule() {
        let rule = "process:23:vmemoryuse:sigterm=100m"
            .parse::<Rule>()
            .expect("Could not parse rule");

        let serialized = serde_json::to_string(&rule).expect("Could not serialize rule");

        let rule_map: serde_json::Value =
            serde_json::from_str(&serialized).expect("Could not load serialized rule");

        assert_eq!(rule_map["subject"]["Process"], 23);
        assert_eq!(rule_map["resource"], "VMemoryUse");
        assert_eq!(rule_map["action"]["Signal"], "SIGTERM");
        assert_eq!(rule_map["limit"]["amount"], 100 * 1024 * 1024)
    }
}
