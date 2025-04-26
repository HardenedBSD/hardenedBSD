// auth: This module deal httpd basic authentication.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use super::AppState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{
    Request,
    StatusCode,
};
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;
use std::str::FromStr;
use std::sync::Arc;
use tracing::debug;

mod basic_auth;
mod basic_auth_config;

use basic_auth::BasicAuth;
pub use basic_auth_config::BasicAuthConfig;

// A hash of the password: "userdoesntexist", used if attempting to
// authenticate a user that doesn't exist.
const FALLBACK_PASSWORD_HASH: &str = "$2b$10$xbVccvFGkGUTkQm5gsSr8uI2byLz2t7pY3wgo9RfQy5rt77l6fyDa";

// Validate HTTP Basic auth credentials.
// Any errors here will result in StatusCode::UNAUTHORIZED being returned to
// the client.
pub async fn validate_credentials(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    debug!("Validating credentials");

    // Get the user database out of the AppState
    // If no users are in the database, authentication is disabled and
    // requests are allowed through.
    let Some(users) = &state.basic_auth_config.basic_auth_users else {
        return Ok(next.run(req).await);
    };

    // If we have users, start working on authenticating the request.
    // Get Authorization header
    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    // Get the BasicAuth from the header if present, otherwise unauthorized.
    let basic_auth = if let Some(auth_header) = auth_header {
        BasicAuth::from_str(auth_header)?
    }
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Get the incoming user_id
    let user_id = basic_auth.user_id();

    // If the user doesn't exist in the users list, they don't exist and we'll
    // return a fake password for them to prevent user enumeration.
    // We also remember that they don't exist, so we can reject the
    // authentication attempt at the end, even if the attempt got the password
    // correct.
    let (user_exists, hashed_password) = match users.get(user_id) {
        Some(hashed_password) => (true, hashed_password.as_str()),
        None                  => (false, FALLBACK_PASSWORD_HASH),
    };

    // We need to get the reference to the Cow str to compare passwords
    // properly, so a little unwrapping is necessary.
    // This also enforces that users must have passwords, although Basic itself
    // does allow a user with no password.
    let Some(password) = basic_auth.password() else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let validated = match bcrypt::verify(password, hashed_password) {
        Ok(b)  => b,
        Err(e) => {
            // We can't easily deal with the original error here, so log it and
            // simply don't validate the user.
            debug!("Couldn't verify password, bcrypt error: {}", e);
            false
        },
    };

    debug!(
        "validation status: validated: {}, exists: {}",
        validated,
        user_exists,
    );

    // If the password was not validated OR the user didn't exist, deny.
    if !validated || !user_exists {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let response = next.run(req).await;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        middleware,
        Router,
    };
    use axum::body::Body;
    use axum::http::{
        self,
        Request,
    };
    use axum::routing::get;
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn app(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/", get(|| async { "Test" }))
            .route_layer(
                middleware::from_fn_with_state(
                    state,
                    validate_credentials,
                ),
            )
    }

    fn get_users_config() -> BasicAuthConfig {
        // User "foo" with password "bar".
        // A very cheap cost is used because this will run in CI.
        let users = HashMap::from([(
            "foo".to_string(),
            "$2b$04$nFPE4cwFjOFGUmdp.o2NTuh/blJDaEwikX1qoitVe144TsS2l5whS".to_string(),
        )]);

        BasicAuthConfig {
            basic_auth_users: Some(users),
        }
    }

    #[tokio::test]
    async fn validate_credentials_users_no_auth() {
        let auth_config = get_users_config();

        let data = AppState {
            basic_auth_config: auth_config,
            index_page:        "test".into(),
        };

        let app = app(Arc::new(data));

        // HTTP request with no auth header.
        let req = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED)
    }

    #[tokio::test]
    async fn validate_credentials_no_users_no_auth() {
        let data = AppState {
            basic_auth_config: BasicAuthConfig::default(),
            index_page:        "test".into(),
        };

        let app = app(Arc::new(data));

        // HTTP request using Basic auth with username "foo" password "bar"
        let req = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn validate_credentials_ok() {
        let auth_config = get_users_config();

        let data = AppState {
            basic_auth_config: auth_config,
            index_page:        "test".into(),
        };

        let app = app(Arc::new(data));

        // HTTP request using Basic auth with username "foo" password "bar"
        let req = Request::builder()
            .uri("/")
            .header(http::header::AUTHORIZATION, "Basic Zm9vOmJhcg==")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK)
    }

    #[tokio::test]
    async fn validate_credentials_unauthorized() {
        let auth_config = get_users_config();

        let data = AppState {
            basic_auth_config: auth_config,
            index_page:        "test".into(),
        };

        let app = app(Arc::new(data));

        // HTTP request using Basic auth with username "bad" password "password"
        let req = Request::builder()
            .uri("/")
            .header(http::header::AUTHORIZATION, "Basic YmFkOnBhc3N3b3Jk")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED)
    }

    // This test attempts to use a non-existant user with our pre-baked
    // password hash when the user doesn't exist.
    // Although the password is correct, login should still fail.
    #[tokio::test]
    async fn validate_credentials_unauthorized_no_user_id() {
        let auth_config = get_users_config();

        let data = AppState {
            basic_auth_config: auth_config,
            index_page:        "test".into(),
        };

        let app = app(Arc::new(data));

        // HTTP request using Basic auth with username "nope" and password
        // "userdoesntexist"
        let req = Request::builder()
            .uri("/")
            .header(http::header::AUTHORIZATION, "Basic bm9wZTp1c2VyZG9lc250ZXhpc3Q=")
            .body(Body::empty())
            .unwrap();

        let res = app.oneshot(req).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED)
    }
}
