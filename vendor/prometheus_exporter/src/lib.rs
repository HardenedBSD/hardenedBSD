//! Helper to export prometheus metrics via http.
//!
//! Information on how to use the prometheus crate can be found at
//! [`prometheus`].
//!
//! # Basic Example
//! The most basic usage of this crate is to just start a http server at the
//! given binding which will export all metrics registered on the global
//! prometheus registry:
//!
//! ```rust
//! use prometheus_exporter::{
//!     self,
//!     prometheus::register_counter,
//! };
//!
//! let binding = "127.0.0.1:9184".parse().unwrap();
//! // Will create an exporter and start the http server using the given binding.
//! // If the webserver can't bind to the given binding it will fail with an error.
//! prometheus_exporter::start(binding).unwrap();
//!
//! // Create a counter using the global prometheus registry and increment it by one.
//! // Notice that the macro is coming from the reexported prometheus crate instead
//! // of the original crate. This is important as different versions of the
//! // prometheus crate have incompatible global registries.
//! let counter = register_counter!("user_exporter_counter", "help").unwrap();
//! counter.inc();
//! ```
//!
//! # Wait for request
//! A probably more useful example in which the exporter waits until a request
//! comes in and then updates the metrics on the fly:
//! ```
//! use prometheus_exporter::{
//!     self,
//!     prometheus::register_counter,
//! };
//! # let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
//! # {
//! #   let barrier = barrier.clone();
//! #   std::thread::spawn(move || {
//! #     println!("client barrier");
//! #     barrier.wait();
//! #     let body = reqwest::blocking::get("http://127.0.0.1:9185").unwrap().text().unwrap();
//! #     println!("body = {:?}", body);
//! #   });
//! # }
//!
//! let binding = "127.0.0.1:9185".parse().unwrap();
//! let exporter = prometheus_exporter::start(binding).unwrap();
//!
//! let counter = register_counter!("example_exporter_counter", "help").unwrap();
//!
//! # barrier.wait();
//! // Wait will return a waitgroup so we need to bind the return value.
//! // The webserver will wait with responding to the request until the
//! // waitgroup has been dropped
//! let guard = exporter.wait_request();
//!
//! // Updates can safely happen after the wait. This has the advantage
//! // that metrics are always in sync with the exporter so you won't
//! // get half updated metrics.
//! counter.inc();
//!
//! // Drop the guard after metrics have been updated.
//! drop(guard);
//! ```
//!
//! # Update periodically
//! Another use case is to update the metrics periodically instead of updating
//! them for each request. This could be useful if the generation of the
//! metrics is expensive and shouldn't happen all the time.
//! ```
//! use prometheus_exporter::{
//!     self,
//!     prometheus::register_counter,
//! };
//! # let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
//! # {
//! #   let barrier = barrier.clone();
//! #   std::thread::spawn(move || {
//! #     println!("client barrier");
//! #     barrier.wait();
//! #     let body = reqwest::blocking::get("http://127.0.0.1:9186").unwrap().text().unwrap();
//! #     println!("body = {:?}", body);
//! #   });
//! # }
//!
//! let binding = "127.0.0.1:9186".parse().unwrap();
//! let exporter = prometheus_exporter::start(binding).unwrap();
//!
//! let counter = register_counter!("example_exporter_counter", "help").unwrap();
//!
//! // Wait for one second and then update the metrics. `wait_duration` will
//! // return a mutex guard which makes sure that the http server won't
//! // respond while the metrics get updated.
//! let guard = exporter.wait_duration(std::time::Duration::from_millis(100));
//! # barrier.wait();
//! counter.inc();
//! drop(guard);
//! ```
//!
//! You can find examples under [`/examples`](https://github.com/AlexanderThaller/prometheus_exporter/tree/master/examples).
//!
//! # Crate Features
//! ## `logging`
//! *Enabled by default*: yes
//!
//! Enables startup logging and failed request logging using the
//! [`log`](https://crates.io/crates/log) crate.
//!
//! ## `internal_metrics`
//! *Enabled by default*: yes
//!
//! Enables the registration of internal metrics used by the crate. Will enable
//! the following metrics:
//! * `prometheus_exporter_requests_total`: Number of HTTP requests received.
//! * `prometheus_exporter_response_size_bytes`: The HTTP response sizes in
//!   bytes.
//! * `prometheus_exporter_request_duration_seconds`: The HTTP request latencies
//!   in seconds.
//!
//! This feature will not work in combination with using a custom registry.

#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![warn(clippy::pedantic)]
#![warn(clippy::unwrap_used)]
#![warn(rust_2018_idioms, unused_lifetimes, missing_debug_implementations)]

#[cfg(test)]
mod test;

// Reexport prometheus so version missmatches don't happen.
pub use prometheus;

#[cfg(feature = "internal_metrics")]
use crate::prometheus::{
    register_histogram,
    register_int_counter,
    register_int_gauge,
    Histogram,
    IntCounter,
    IntGauge,
};
#[cfg(feature = "internal_metrics")]
use lazy_static::lazy_static;
#[cfg(feature = "logging")]
use log::{
    error,
    info,
};

use crate::prometheus::{
    Encoder,
    TextEncoder,
};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{
            AtomicBool,
            Ordering,
        },
        mpsc::{
            sync_channel,
            Receiver,
            SyncSender,
        },
        Arc,
        Barrier,
        Mutex,
        MutexGuard,
    },
    thread,
    time::Duration,
};
use thiserror::Error;
use tiny_http::{
    Header,
    Request,
    Response,
    Server as HTTPServer,
};

#[cfg(feature = "internal_metrics")]
lazy_static! {
    static ref HTTP_COUNTER: IntCounter = register_int_counter!(
        "prometheus_exporter_requests_total",
        "Number of HTTP requests received."
    )
    .expect("can not create HTTP_COUNTER metric. this should never fail");
    static ref HTTP_BODY_GAUGE: IntGauge = register_int_gauge!(
        "prometheus_exporter_response_size_bytes",
        "The HTTP response sizes in bytes."
    )
    .expect("can not create HTTP_BODY_GAUGE metric. this should never fail");
    static ref HTTP_REQ_HISTOGRAM: Histogram = register_histogram!(
        "prometheus_exporter_request_duration_seconds",
        "The HTTP request latencies in seconds."
    )
    .expect("can not create HTTP_REQ_HISTOGRAM metric. this should never fail");
}

/// Errors that can occur while building or running an exporter.
#[derive(Debug, Error)]
pub enum Error {
    /// Returned when trying to start the exporter and
    /// [`tiny_http::Server::http`] fails.
    #[error("can not start http server: {0}")]
    ServerStart(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// Returned when supplying a non-ascii endpoint to
    /// [`Builder::with_endpoint`].
    #[error("supplied endpoint is not valid ascii: {0}")]
    EndpointNotAscii(String),
}

/// Errors that can occur while handling requests.
#[derive(Debug, Error)]
enum HandlerError {
    /// Returned when the encoding of the metrics by
    /// [`prometheus::Encoder::encode`] fails.
    #[error("can not encode metrics: {0}")]
    EncodeMetrics(prometheus::Error),

    /// Returned when returning encoded metrics via response with
    /// [`tiny_http::Request::respond`] fails.
    #[error("can not generate response: {0}")]
    Response(std::io::Error),
}

/// Builder to create a new [`crate::Exporter`].
#[derive(Debug)]
pub struct Builder {
    binding: SocketAddr,
    endpoint: Endpoint,
    registry: prometheus::Registry,
}

#[derive(Debug)]
struct Endpoint(String);
impl Default for Endpoint {
    fn default() -> Self {
        Self("/metrics".to_string())
    }
}

/// Helper to export prometheus metrics via http.
#[derive(Debug)]
pub struct Exporter {
    request_receiver: Receiver<Arc<Barrier>>,
    is_waiting: Arc<AtomicBool>,
    update_lock: Arc<Mutex<()>>,
}

/// Helper to export prometheus metrics via http.
#[derive(Debug)]
struct Server {}

/// Create and start a new exporter which uses the given socket address to
/// export the metrics.
/// # Errors
///
/// Will return [`enum@Error`] if the http server fails to start for any reason.
pub fn start(binding: SocketAddr) -> Result<Exporter, Error> {
    Builder::new(binding).start()
}

impl Builder {
    /// Create a new builder with the given binding.
    #[must_use]
    pub fn new(binding: SocketAddr) -> Builder {
        Self {
            binding,
            endpoint: Endpoint::default(),
            registry: prometheus::default_registry().clone(),
        }
    }

    /// Sets the endpoint that the metrics will be served on. If the endpoint is
    /// not set with this method then the default `/metrics` will be used.
    /// # Errors
    ///
    /// Will return [`enum@Error`] if the supplied string slice is not valid
    /// ascii.
    pub fn with_endpoint(&mut self, endpoint: &str) -> Result<(), Error> {
        if !endpoint.is_ascii() {
            return Err(Error::EndpointNotAscii(endpoint.to_string()));
        }
        let mut clean_endpoint = String::from('/');
        clean_endpoint.push_str(endpoint.trim_matches('/'));
        self.endpoint = Endpoint(clean_endpoint);
        Ok(())
    }

    /// Sets the registry the metrics will be gathered from. If the registry is
    /// not set, the default registry provided by the prometheus crate will be
    /// used. If a custom registry is used, the metrics provided by the
    /// `internal_metrics` feature are not available.
    pub fn with_registry(&mut self, registry: prometheus::Registry) {
        self.registry = registry;
    }

    /// Create and start new exporter based on the information from the builder.
    /// # Errors
    ///
    /// Will return [`enum@Error`] if the http server fails to start for any
    /// reason.
    pub fn start(self) -> Result<Exporter, Error> {
        let (request_sender, request_receiver) = sync_channel(0);
        let is_waiting = Arc::new(AtomicBool::new(false));
        let update_lock = Arc::new(Mutex::new(()));

        let exporter = Exporter {
            request_receiver,
            is_waiting: Arc::clone(&is_waiting),
            update_lock: Arc::clone(&update_lock),
        };

        Server::start(
            self.binding,
            self.endpoint.0,
            request_sender,
            is_waiting,
            update_lock,
            self.registry,
        )?;

        Ok(exporter)
    }
}

impl Exporter {
    /// Return new builder which will create a exporter once built.
    #[must_use]
    pub fn builder(binding: SocketAddr) -> Builder {
        Builder::new(binding)
    }

    /// Wait until a new request comes in. Returns a mutex guard to make the
    /// http server wait until the metrics have been updated.
    #[must_use = "not using the guard will result in the exporter returning the prometheus data \
                  immediately over http"]
    pub fn wait_request(&self) -> MutexGuard<'_, ()> {
        self.is_waiting.store(true, Ordering::SeqCst);

        let update_waitgroup = self
            .request_receiver
            .recv()
            .expect("can not receive from request_receiver channel. this should never happen");

        self.is_waiting.store(false, Ordering::SeqCst);

        let guard = self
            .update_lock
            .lock()
            .expect("poisioned mutex. should never happen");

        update_waitgroup.wait();

        guard
    }

    /// Wait for given duration. Returns a mutex guard to make the http
    /// server wait until the metrics have been updated.
    #[must_use = "not using the guard will result in the exporter returning the prometheus data \
                  immediately over http"]
    pub fn wait_duration(&self, duration: Duration) -> MutexGuard<'_, ()> {
        thread::sleep(duration);

        self.update_lock
            .lock()
            .expect("poisioned mutex. should never happen")
    }
}

impl Server {
    fn start(
        binding: SocketAddr,
        endpoint: String,
        request_sender: SyncSender<Arc<Barrier>>,
        is_waiting: Arc<AtomicBool>,
        update_lock: Arc<Mutex<()>>,
        registry: prometheus::Registry,
    ) -> Result<(), Error> {
        let server = HTTPServer::http(&binding).map_err(Error::ServerStart)?;

        thread::spawn(move || {
            #[cfg(feature = "logging")]
            info!("exporting metrics to http://{}{}", binding, endpoint);

            let encoder = TextEncoder::new();

            for request in server.incoming_requests() {
                if let Err(err) = if request.url() == endpoint {
                    Self::handler_metrics(
                        request,
                        &encoder,
                        &request_sender,
                        &is_waiting,
                        &update_lock,
                        &registry,
                    )
                } else {
                    Self::handler_redirect(request, &endpoint)
                } {
                    #[cfg(feature = "logging")]
                    error!("{}", err);

                    // Just so there are no complains about unused err variable when logging
                    // feature is disabled
                    drop(err);
                }
            }
        });

        Ok(())
    }

    fn handler_metrics(
        request: Request,
        encoder: &TextEncoder,
        request_sender: &SyncSender<Arc<Barrier>>,
        is_waiting: &Arc<AtomicBool>,
        update_lock: &Arc<Mutex<()>>,
        registry: &prometheus::Registry,
    ) -> Result<(), HandlerError> {
        #[cfg(feature = "internal_metrics")]
        HTTP_COUNTER.inc();

        #[cfg(feature = "internal_metrics")]
        let timer = HTTP_REQ_HISTOGRAM.start_timer();

        if is_waiting.load(Ordering::SeqCst) {
            let barrier = Arc::new(Barrier::new(2));

            request_sender
                .send(Arc::clone(&barrier))
                .expect("can not send to request_sender. this should never happen");

            barrier.wait();
        }

        let _lock = update_lock
            .lock()
            .expect("poisioned mutex. should never happen");

        #[cfg(feature = "internal_metrics")]
        drop(timer);

        Self::process_request(request, encoder, registry)
    }

    fn process_request(
        request: Request,
        encoder: &TextEncoder,
        registry: &prometheus::Registry,
    ) -> Result<(), HandlerError> {
        let metric_families = registry.gather();
        let mut buffer = vec![];

        encoder
            .encode(&metric_families, &mut buffer)
            .map_err(HandlerError::EncodeMetrics)?;

        #[cfg(feature = "internal_metrics")]
        HTTP_BODY_GAUGE.set(buffer.len() as i64);

        let response = Response::from_data(buffer);
        request.respond(response).map_err(HandlerError::Response)?;

        Ok(())
    }

    fn handler_redirect(request: Request, endpoint: &str) -> Result<(), HandlerError> {
        let response = Response::from_string(format!("try {} for metrics\n", endpoint))
            .with_status_code(301)
            .with_header(Header {
                field: "Location"
                    .parse()
                    .expect("can not parse location header field. this should never fail"),
                value: ascii::AsciiString::from_ascii(endpoint)
                    .expect("can not parse header value. this should never fail"),
            });

        request.respond(response).map_err(HandlerError::Response)?;

        Ok(())
    }
}
