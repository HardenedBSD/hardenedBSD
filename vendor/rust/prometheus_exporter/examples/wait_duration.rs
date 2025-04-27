// Will create an exporter with a single metric that will randomize the value
// of the metric everytime the exporter duration times out.

use env_logger::{
    Builder,
    Env,
};
use log::info;
use prometheus_exporter::prometheus::register_gauge;
use rand::Rng;
use std::net::SocketAddr;

fn main() {
    // Setup logger with default level info so we can see the messages from
    // prometheus_exporter.
    Builder::from_env(Env::default().default_filter_or("info")).init();

    // Parse address used to bind exporter to.
    let addr_raw = "0.0.0.0:9186";
    let addr: SocketAddr = addr_raw.parse().expect("can not parse listen addr");

    // Start exporter and update metrics every five seconds.
    let exporter = prometheus_exporter::start(addr).expect("can not start exporter");
    let duration = std::time::Duration::from_millis(1000);

    // Create metric
    let random = register_gauge!("run_and_repeat_random", "will set a random value")
        .expect("can not create gauge random_value_metric");

    let mut rng = rand::thread_rng();

    loop {
        {
            // Will block until duration is elapsed.
            let _guard = exporter.wait_duration(duration);

            info!("Updating metrics");

            // Update metric with random value.
            let new_value = rng.gen();
            info!("New random value: {}", new_value);

            random.set(new_value);
        }

        // Get metrics from exporter
        let body = reqwest::blocking::get(&format!("http://{}/metrics", addr_raw))
            .expect("can not get metrics from exporter")
            .text()
            .expect("can not body text from request");

        info!("Exporter metrics:\n{}", body);
    }
}
