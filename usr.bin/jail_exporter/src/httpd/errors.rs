// errors: httpd errors
#![forbid(unsafe_code)]
#![forbid(missing_docs)]
use axum::http::{
    header,
    HeaderMap,
    HeaderValue,
    StatusCode,
};
use axum::response::{
    IntoResponse,
    Response,
};
use thiserror::Error;

// Content-Type for the HTTP error responses.
const TEXT_PLAIN_UTF8: &str = "text/plain; charset=utf-8";

#[derive(Debug, Error)]
pub enum HttpdError {
    /// Returned when Httpd cannot bind to the given address.
    #[error("failed to bind to {0}")]
    BindAddress(String),

    /// Returned by the `Collector::collect` trait method when there are
    /// issues.
    #[error("error collecting metrics: {0}")]
    CollectorError(String),

    /// Returned when there are issues running the Httpd.
    #[error("std::io::Error")]
    IoError(#[from] std::io::Error),

    /// Returned when there are issues rendering the index template.
    #[error("failed to render template")]
    RenderTemplate(#[from] askama::Error),

    /// Returned when a server error occurs.
    #[error("server error: {0}")]
    ServerError(#[from] axum::Error),
}

impl IntoResponse for HttpdError {
    fn into_response(self) -> Response {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(TEXT_PLAIN_UTF8),
        );

        (StatusCode::INTERNAL_SERVER_ERROR, headers, self).into_response()
    }
}
