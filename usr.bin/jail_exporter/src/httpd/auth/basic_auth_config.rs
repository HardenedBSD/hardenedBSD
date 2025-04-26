// auth: This module deal httpd basic authentication.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use crate::errors::ExporterError;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::str::FromStr;

// Invalid username characters as defined in RFC7617.
// 0x00 - 0x1f / 0x7f / :
// These are split up to hopefully make the set easier for a human to validate
const INVALID_USERNAME_CHARS: &[char] = &[
    // 0x00 - 0x09
    '\u{00}', '\u{01}', '\u{02}', '\u{03}', '\u{04}', '\u{05}',
    '\u{06}', '\u{07}', '\u{08}', '\u{09}',
    // 0x0a - 0x0f
    '\u{0a}', '\u{0b}', '\u{0c}', '\u{0d}', '\u{0e}', '\u{0f}',
    // 0x10 - 0x19
    '\u{10}', '\u{11}', '\u{12}', '\u{13}', '\u{14}', '\u{15}',
    '\u{16}', '\u{17}', '\u{18}', '\u{19}',
    // 0x1a - 0x1f
    '\u{1a}', '\u{1b}', '\u{1c}', '\u{1d}', '\u{1e}', '\u{1f}',
    // 0x7f
    '\u{7f}',
    // Colon
    ':',
];

#[derive(Clone, Debug, Default, Deserialize)]
pub struct BasicAuthConfig {
    pub basic_auth_users: Option<HashMap<String, String>>,
}

impl BasicAuthConfig {
    // Loads a YAML config from the given path returning the BasicAuthConfig
    pub fn from_yaml(path: &Path) -> Result<Self, ExporterError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let config: Self = serde_yaml::from_reader(reader)?;

        config.validate()?;

        Ok(config)
    }

    // Returns a boolean indicating if we have any users configured.
    pub fn has_users(&self) -> bool {
        self.basic_auth_users.is_some()
    }

    // Validates that usernames don't contain invalid characters.
    fn validate(&self) -> Result<(), ExporterError> {
        // Not having users is perfectly valid.
        let users = match &self.basic_auth_users {
            None        => return Ok(()),
            Some(users) => users,
        };

        for (username, hashed_password) in users {
            // A username is invalid if it contains any characters from the
            // INVALID_USERNAME_CHARS const.
            let invalid_username = username
                .chars()
                .any(|c| INVALID_USERNAME_CHARS.contains(&c));

            if invalid_username {
                let err = ExporterError::InvalidUsername(username.into());
                return Err(err);
            }

            if let Err(err) = bcrypt::HashParts::from_str(hashed_password) {
                let msg = format!(
                    "bcrypt error '{err}' when validating user {username}",
                );

                let err = ExporterError::BcryptValidationError(msg);
                return Err(err);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests that errors are returned when config contains an invalid username
    #[test]
    fn basic_user_config_from_yaml_invalid() {
        let path = Path::new("test-data/config_invalid.yaml");
        let config = BasicAuthConfig::from_yaml(&path);

        assert!(config.is_err());
    }

    // Config is a null auth users entry.
    #[test]
    fn basic_user_config_from_yaml_null() {
        let path = Path::new("test-data/config_null.yaml");
        let config = BasicAuthConfig::from_yaml(&path);

        assert!(config.is_ok());
    }

    // Config consists of valid usernames
    #[test]
    fn basic_user_config_from_yaml_ok() {
        let path = Path::new("test-data/config_ok.yaml");
        let config = BasicAuthConfig::from_yaml(&path);

        assert!(config.is_ok());
    }
}
