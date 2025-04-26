// Will create an exporter with a single metric that does not change

use env_logger::{
    Builder,
    Env,
};
use log::info;
use prometheus_exporter::prometheus::register_gauge;
use std::net::SocketAddr;

fn main() {
    // Setup logger with default level info so we can see the messages from
    // prometheus_exporter.
    Builder::from_env(Env::default().default_filter_or("info")).init();

    // Parse address used to bind exporter to.
    let addr_raw = "0.0.0.0:9184";
    let addr: SocketAddr = addr_raw.parse().expect("can not parse listen addr");

    // Create metric
    let metric = register_gauge!("simple_the_answer", "to everything")
        .expect("can not create gauge simple_the_answer");

    metric.set(42.0);

    let endpoint = "some/long/path";

    // Start exporter
    let mut builder = prometheus_exporter::Builder::new(addr);
    builder
        .with_endpoint(endpoint)
        .expect("failed to set endpoint");
    builder.start().expect("can not start exporter");

    // Get metrics from exporter
    let body = reqwest::blocking::get(&format!("http://{}/{}", addr_raw, endpoint))
        .expect("can not get metrics from exporter")
        .text()
        .expect("can not body text from request");

    info!("Exporter metrics:\n{}", body);
}
