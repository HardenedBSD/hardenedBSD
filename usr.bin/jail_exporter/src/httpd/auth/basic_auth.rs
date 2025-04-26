// auth: This module deal httpd basic authentication.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use axum::http::StatusCode;
use base64::Engine;
use std::str::FromStr;
use tracing::debug;

// Type representing a Basic username and password pair.
#[derive(Debug)]
pub struct BasicAuth {
    password: Option<String>,
    user_id: String,
}

impl BasicAuth {
    pub fn new(user_id: String, password: Option<String>) -> Self {
        Self {
            password,
            user_id,
        }
    }

    pub fn password(&self) -> &Option<String> {
        &self.password
    }

    pub fn user_id(&self) -> &str {
        &self.user_id
    }
}

// This FromStr allows us to get a BasicAuth from the contents of the
// Authorization header.
impl FromStr for BasicAuth {
    type Err = StatusCode;

    // Take an Authorization header and attempt to create a BasicAuth.
    // Any errors will result in Unauthorized.
    fn from_str(header: &str) -> Result<Self, Self::Err> {
        let Some(("Basic", data)) = header.split_once(' ') else {
                debug!("invalid authorization type");
                return Err(StatusCode::UNAUTHORIZED);
        };

        // Decode the incoming base64 and turn it into a String
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|_| {
                debug!("could not decode incoming base64 authorization data");

                StatusCode::UNAUTHORIZED
            })?;

        let decoded = String::from_utf8(decoded)
            .map_err(|_| {
                debug!("could not construct utf8 string from decoded base64");

                StatusCode::UNAUTHORIZED
            })?;

        let (user_id, password) = match decoded.split_once(':') {
            Some((username, password)) => {
                (username.to_string(), Some(password.to_string()))
            },
            _ => (decoded, None),
        };

        Ok(Self::new(user_id, password))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_err() {
        let tests = vec![
            // Only Basic authorization is supported
            "Bearer foobarbaz",

            // Invalid base64
            "Basic foobarbaz",

            // Valid base64, but invalid utf8 string content.
            // This contains the bytes for the "Sparkle Heart" emoji, but the
            // first byte has been changed from f0 to 0.
            "Basic AJ+Slgo=",
        ];

        for test in tests {
            let basic_auth = BasicAuth::from_str(test);

            assert!(basic_auth.is_err());
        }
    }

    #[test]
    fn basic_auth_ok_with_password() {
        let authorization = "Basic Zm9vOmJhcg==";
        let basic_auth = BasicAuth::from_str(authorization).unwrap();

        assert_eq!(basic_auth.user_id(), "foo");
        assert_eq!(basic_auth.password(), &Some("bar".to_string()));
    }

    #[test]
    fn basic_auth_ok_without_password() {
        let authorization = "Basic Zm9v";
        let basic_auth = BasicAuth::from_str(authorization).unwrap();

        assert_eq!(basic_auth.user_id(), "foo");
        assert_eq!(basic_auth.password(), &None);
    }
}
