use crate::param;
use std::io;
use thiserror::Error;

/// An enum for error types of the Jail.
#[derive(Error, Debug)]
pub enum JailError {
    #[error("An IO Error occurred: {0:?}")]
    IoError(io::Error),

    #[error("jail_get syscall failed. The error message returned was: {0}")]
    JailGetError(String),

    #[error("jail_set syscall failed. The error message returned was: {0}")]
    JailSetError(String),

    #[error("jail_attach syscall failed. The error message returned was: {0}")]
    JailAttachError(io::Error),

    #[error("invalid return code from jail_remove")]
    JailRemoveFailed,

    #[error("Path not given")]
    PathNotGiven,

    #[error("No such parameter: {0}")]
    NoSuchParameter(String),

    #[error("Generic sysctl error: {0:?}")]
    SysctlError(sysctl::SysctlError),

    #[error("Could not get parameter type: {0:?}")]
    ParameterTypeError(sysctl::SysctlError),

    #[error("Could not get string parameter length: {0:?}")]
    ParameterStringLengthError(sysctl::SysctlError),

    #[error("Could not get structure parameter length: {0:?}")]
    ParameterStructLengthError(sysctl::SysctlError),

    #[error("Cannot set tunable parameter '{0}' at runtime.")]
    ParameterTunableError(String),

    #[error("Could not determine maximum number of IP addresses per family")]
    JailMaxAfIpsFailed(sysctl::SysctlError),

    #[error("Parameter string length returned ('{0}') is not a number.")]
    ParameterLengthNaN(String),

    #[error("Parameter type not supported: {0:?}")]
    ParameterTypeUnsupported(sysctl::CtlType),

    #[error("Unexpected parameter type for '{name}': expected {expected:?}, but got {got:?}")]
    UnexpectedParameterType {
        name: String,
        expected: sysctl::CtlType,
        got: param::Value,
    },

    #[error("Failed to unpack parameter.")]
    ParameterUnpackError,

    #[error("Could not serialize value to bytes")]
    SerializeFailed,

    #[error("RCTL Error: {0}")]
    RctlError(rctl::Error),

    #[error("Jail must have a name if RCTL limits are to be set")]
    UnnamedButLimited,

    #[error("Error creating a CString: {0:?}")]
    CStringError(std::ffi::NulError),
}

impl JailError {
    pub fn from_errno() -> Self {
        JailError::IoError(io::Error::last_os_error())
    }
}
