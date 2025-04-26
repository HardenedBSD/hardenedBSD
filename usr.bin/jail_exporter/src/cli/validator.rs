// Command line interface parsing validators
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use crate::file::FileExporterOutput;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use tracing::debug;

#[cfg(feature = "auth")]
use std::path::PathBuf;

#[cfg(feature = "auth")]
// Basic checks for valid filesystem path for web.auth-config existing.
pub fn is_valid_basic_auth_config_path(s: &str) -> Result<PathBuf, String> {
    debug!("Ensuring that web.auth-config is valid");

    // Get a Path from our string and start checking
    let path = Path::new(&s);

    if !path.is_file() {
        return Err("web.auth-config doesn't doesn't exist".to_owned());
    }

    Ok(path.to_path_buf())
}

#[cfg(feature = "bcrypt_cmd")]
// Ensures that a given bcrypt cost is valid
pub fn is_valid_bcrypt_cost(s: &str) -> Result<u32, String> {
    debug!("Ensuring that bcrypt cost is valid");

    let cost = match s.parse::<u32>() {
        Err(_) => return Err("could not parse bcrypt cost as integer".to_owned()),
        Ok(c)  => c,
    };

    // Min and max costs taken from the bcrypt crate. The consts are private so
    // we can't reference them directly.
    if !(4..=31).contains(&cost) {
        return Err("cost cannot be less than 4 or more than 31".to_owned());
    }

    Ok(cost)
}

#[cfg(feature = "bcrypt_cmd")]
// Validates that the incoming value can be used as a password length
pub fn is_valid_length(s: &str) -> Result<usize, String> {
    debug!("Ensuring that bcrypt --length is valid");

    let length = match s.parse::<usize>() {
        Ok(length) => Ok(length),
        Err(_)     => Err(format!("Could not parse '{s}' as valid length")),
    }?;

    if length < 1 {
        return Err("--length cannot be less than 1".into());
    }

    Ok(length)
}

// Basic checks for valid filesystem path for .prom output file
pub fn is_valid_output_file_path(s: &str) -> Result<FileExporterOutput, String> {
    debug!("Ensuring that output.file-path is valid");

    // - is special and is a request for us to output to stdout
    if s == "-" {
        return Ok(FileExporterOutput::Stdout)
    }

    // Get a Path from our string and start checking
    let path = Path::new(&s);

    // We only take absolute paths
    if !path.is_absolute() {
        return Err("output.file-path only accepts absolute paths".to_owned());
    }

    // We can't write to a directory
    if path.is_dir() {
        return Err("output.file-path must not point at a directory".to_owned());
    }

    // Node Exporter textfiles must end with .prom
    if let Some(ext) = path.extension() {
        // Got an extension, ensure that it's .prom
        if ext != "prom" {
            return Err("output.file-path must have .prom extension".to_owned());
        }
    }
    else {
        // Didn't find an extension at all
        return Err("output.file-path must have .prom extension".to_owned());
    }

    // Check that the directory exists
    if let Some(dir) = path.parent() {
        // Got a parent directory, ensure it exists
        if !dir.is_dir() {
            return Err("output.file-path directory must exist".to_owned());
        }
    }
    else {
        // Didn't get a parent directory at all
        return Err("output.file-path directory must exist".to_owned());
    }

    Ok(FileExporterOutput::File(path.to_path_buf()))
}

#[cfg(feature = "bcrypt_cmd")]
// Checks that a password is valid with some basic checks.
pub fn is_valid_password(s: &str) -> Result<String, String> {
    debug!("Ensuring that password is valid");

    let length = s.chars().count();

    if length < 1 {
        return Err("password cannot be empty".into());
    }

   Ok(s.to_string())
}

// Used as a validator for the argument parsing.
// We validate the parse to SocketAddr here but still continue to return a
// string. HttpServer::bind is fine with taking a string there.
// We might change this behaviour later.
pub fn is_valid_socket_addr(s: &str) -> Result<String, String> {
    debug!("Ensuring that web.listen-address is valid");

    match SocketAddr::from_str(s) {
        Ok(_)  => Ok(s.to_string()),
        Err(_) => Err(format!("'{s}' is not a valid ADDR:PORT string")),
    }
}

// Checks that the telemetry_path is valid.
// This check is extremely basic, and there may still be invalid paths that
// could be passed.
pub fn is_valid_telemetry_path(s: &str) -> Result<String, String> {
    debug!("Ensuring that web.telemetry-path is valid");

    // Ensure s isn't empty.
    if s.is_empty() {
        return Err("path must not be empty".to_owned());
    }

    // Ensure that s starts with /
    if !s.starts_with('/') {
        return Err("path must start with /".to_owned());
    }

    // Ensure that s isn't literally /
    if s == "/" {
        return Err("path must not be /".to_owned());
    }

    Ok(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_output_file_path_absolute_path() {
        let res = is_valid_output_file_path("tmp/metrics.prom".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_output_file_path_bad_extension() {
        let res = is_valid_output_file_path("/tmp/metrics.pram".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_output_file_path_bad_parent_dir() {
        let res = is_valid_output_file_path("/tmp/nope/metrics.prom".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_output_file_path_directory() {
        let res = is_valid_output_file_path("/tmp".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_output_file_path_no_extension() {
        let res = is_valid_output_file_path("/tmp/metrics".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_output_file_path_ok() {
        let res = is_valid_output_file_path("/tmp/metrics.prom".into());
        assert!(res.is_ok());
    }

    #[test]
    fn is_valid_output_file_path_root() {
        let res = is_valid_output_file_path("/".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_output_file_path_stdout() {
        let res = is_valid_output_file_path("-".into());
        assert!(res.is_ok());
    }

    #[test]
    fn is_valid_socket_addr_ipv4_with_port() {
        let res = is_valid_socket_addr("127.0.0.1:9452".into());
        assert!(res.is_ok());
    }

    #[test]
    fn is_valid_socket_addr_ipv6_with_port() {
        let res = is_valid_socket_addr("[::1]:9452".into());
        assert!(res.is_ok());
    }

    #[test]
    fn is_valid_socket_addr_ipv4_without_port() {
        let res = is_valid_socket_addr("127.0.0.1".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_socket_addr_ipv6_without_port() {
        let res = is_valid_socket_addr("[::1]".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_socket_addr_no_ip() {
        let res = is_valid_socket_addr("random string".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_telemetry_path_slash() {
        let res = is_valid_telemetry_path("/".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_telemetry_path_empty() {
        let res = is_valid_telemetry_path("".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_telemetry_path_relative() {
        let res = is_valid_telemetry_path("metrics".into());
        assert!(res.is_err());
    }

    #[test]
    fn is_valid_telemetry_path_valid() {
        let res = is_valid_telemetry_path("/metrics".into());
        assert!(res.is_ok());
    }
}
