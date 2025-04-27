# Migration

## 0.6 to 0.7

* Replace `PrometheusExporter` with `Exporter`.
* Replace usage of `PrometheusExporter::run()` with `prometheus_exporter::start()` or `Exporter::start()`.
* Replace usage of `PrometheusExporter::run_and_notify()` with `Exporter::wait_request()`.
* Replace usage of `PrometheusExporter::run_and_notify()` with `Exporter::wait_duration()`.
