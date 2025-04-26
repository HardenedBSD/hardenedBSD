// httpd: This module deals with httpd related tasks.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
use axum::body::Bytes;
use axum::routing;
use axum::Router;
use parking_lot::Mutex;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{
    debug,
    info,
};

#[cfg(feature = "auth")]
use axum::middleware;

#[cfg(feature = "auth")]
pub mod auth;

mod collector;
mod errors;
mod handlers;
mod templates;

#[cfg(feature = "auth")]
pub use auth::BasicAuthConfig;

use handlers::{
    index,
    metrics,
};
use templates::render_index_page;
pub use collector::Collector;
pub use errors::HttpdError;
use super::Exporter;

// This AppState is used to pass the rendered index template to the index
// function.
pub struct AppState {
    index_page: Bytes,

    #[cfg(feature = "auth")]
    basic_auth_config: BasicAuthConfig,
}

pub struct AppExporter {
    exporter: Exporter,
}

// Used for the httpd builder
#[derive(Debug)]
pub struct Server {
    bind_address:   String,
    telemetry_path: String,

    #[cfg(feature = "auth")]
    basic_auth_config: Option<BasicAuthConfig>,
}

impl Default for Server {
    fn default() -> Self {
        Self {
            bind_address:   "127.0.0.1:9452".into(),
            telemetry_path: "/metrics".into(),

            #[cfg(feature = "auth")]
            basic_auth_config: None,
        }
    }
}

// Implements a builder pattern for configuring and running the http server.
impl Server {
    // Returns a new server instance.
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(feature = "auth")]
    // Set the HTTP Basic Auth configuration
    pub fn auth_config(mut self, config: BasicAuthConfig) -> Self {
        debug!("Setting HTTP basic auth config");

        self.basic_auth_config = Some(config);
        self
    }

    // Sets the bind_address of the server.
    pub fn bind_address(mut self, bind_address: String) -> Self {
        debug!("Setting server bind_address to: {}", bind_address);

        self.bind_address = bind_address;
        self
    }

    // Sets the telemetry path for the metrics.
    pub fn telemetry_path(mut self, telemetry_path: String) -> Self {
        debug!("Setting server telemetry_path to: {}", telemetry_path);

        self.telemetry_path = telemetry_path;
        self
    }

    // Run the HTTP server.
    pub async fn run(self, exporter: Exporter) -> Result<(), HttpdError> {
        let index_page = render_index_page(&self.telemetry_path)?;

        #[cfg(feature = "auth")]
        // Unwrap the config if we have one, otherwise use a default.
        let basic_auth_config = self.basic_auth_config.unwrap_or_default();

        #[cfg(feature = "auth")]
        // If there are no users configured, we don't need authentication
        // enabling.
        let enable_http_auth = basic_auth_config.has_users();

        // These states are shared between threads and allows us to pass
        // arbitrary items to request handlers.
        let app_exporter = AppExporter {
            exporter: exporter,
        };

        let app_exporter = Arc::new(Mutex::new(app_exporter));

        let state = AppState {
            index_page: index_page,

            #[cfg(feature = "auth")]
            basic_auth_config: basic_auth_config,
        };

        let state = Arc::new(state);

        // May not be used depending on enable_http_auth
        #[cfg(feature = "auth")]
        let auth_layer = middleware::from_fn_with_state(
            state.clone(),
            auth::validate_credentials,
        );

        // Route handlers
        debug!("Creating HTTP server app");

        // This mut will be unused if not compiled with the auth feature.
        // Silence that warning.
        #[allow(unused_mut)]
        let mut app = Router::new()
            .route("/", routing::get(index))
            .with_state(state)
            .route(&self.telemetry_path, routing::get(metrics))
            .with_state(app_exporter);

        // If we have some users, enable the authentication layer
        #[cfg(feature = "auth")]
        if enable_http_auth {
            app = app.route_layer(auth_layer);
        }

        // Finally add a tracing layer
        let app = app
            .layer(TraceLayer::new_for_http());

        // Create the server
        debug!("Attempting to bind to: {}", &self.bind_address);
        let listener = TcpListener::bind(&self.bind_address)
            .await
            .map_err(|e| {
                let address = &self.bind_address;
                HttpdError::BindAddress(format!("{address}: {e}"))
            })?;

        let server = axum::serve(listener, app.into_make_service());

        // Run it!
        info!("Starting HTTP server on {}", &self.bind_address);
        server.await?;

        Ok(())
    }
}
