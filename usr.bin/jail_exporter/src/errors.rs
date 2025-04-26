// errors: This module implements errors used in the rest of the crate.
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
use thiserror::Error;

/// An enum for error types encountered by the `jail_exporter`.
#[derive(Error, Debug)]
pub enum ExporterError {
    /// Raised when a required argument was not set.
    /// Should not be reachable.
    #[error("{0} was not set.")]
    ArgNotSet(String),

    #[cfg(feature = "bcrypt_cmd")]
    /// Raised if there is an error while hashing a password.
    #[error("bcrypt error while hashing password")]
    BcryptHashingError(#[from] bcrypt::BcryptError),

    #[cfg(feature = "auth")]
    /// Raised if there is a problem validating the bcrypt password while
    /// validating the config.
    #[error("bcrypt error with password for user: {0}")]
    BcryptValidationError(String),

    #[error("HttpdError: {0}")]
    HttpdError(#[from] crate::httpd::HttpdError),

    #[cfg(feature = "auth")]
    /// Raised if a configured username is invalid
    #[error("Invalid username: {0}")]
    InvalidUsername(String),

    /// Raised if an `io::Error` occurs
    #[error("std::io::Error")]
    IoError(#[from] std::io::Error),

    /// Raised if there are errors originating within the `jail` crate.
    #[error("could not get jail name")]
    JailError(jail::JailError),

    /// Raised if the `jail_exporter` is not running as root.
    #[error("jail_exporter must be run as root")]
    NotRunningAsRoot,

    #[cfg(feature = "bcrypt_cmd")]
    ///Raised if there is an error during password prompting
    #[error("error during password prompt: {0}")]
    PasswordPromptError(#[from] dialoguer::Error),

    /// Raised when issues occur within the file exporter
    #[error("error occurred while persisting metrics")]
    PersistError(#[from] tempfile::PersistError),

    /// Raised if there are errors originating within the `prometheus` crate.
    //#[error("error within Prometheus library")]
    //PrometheusError(#[from] prometheus::Error),

    /// Raised if there are issues with RACCT/RCTL support.
    #[error("RACCT/RCTL: {0}")]
    RctlUnavailable(String),

    /// Raised if there's an issue converting from UTF-8 to String
    #[error("Failed to convert UTF-8 to String")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    #[cfg(feature = "auth")]
    /// Raised if there is an issue reading the YAML configuration
    #[error("Failed to read YAML configuration")]
    YamlError(#[from] serde_yaml::Error),
}

// There is no as_dyn_error for jail::JailError, so we manually implement From
impl From<jail::JailError> for ExporterError {
    fn from(e: jail::JailError) -> Self {
        Self::JailError(e)
    }
}
