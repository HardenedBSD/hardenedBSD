use crate::prometheus::register_counter;

#[test]
fn wait_request() {
    let binding_raw = "127.0.0.1:9185";
    let metric_name = "test_wait_request";

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

    {
        let barrier = barrier.clone();

        std::thread::spawn(move || {
            println!("client barrier");
            barrier.wait();

            reqwest::blocking::get(&format!("http://{}", binding_raw))
                .expect("can not make request");
        });
    }

    let binding = binding_raw.parse().expect("can not parse binding");
    let exporter = crate::start(binding).expect("can not start exporter");

    let counter = register_counter!(metric_name, "help").unwrap();

    barrier.wait();

    let guard = exporter.wait_request();
    counter.inc();
    drop(guard);

    let body = reqwest::blocking::get(&format!("http://{}", binding_raw))
        .expect("can not make request")
        .text()
        .expect("can not extract body");

    println!("body:\n{}", body);

    assert!(body.contains(&format!("{} 1", metric_name)));
}

#[test]
fn wait_duration() {
    let binding_raw = "127.0.0.1:9186";
    let metric_name = "test_wait_duration_counter";

    let binding = binding_raw.parse().expect("can not parse binding");
    let exporter = crate::start(binding).expect("can not start exporter");

    let counter = register_counter!(metric_name, "help").unwrap();

    let guard = exporter.wait_duration(std::time::Duration::from_millis(100));
    counter.inc();
    drop(guard);

    let body = reqwest::blocking::get(&format!("http://{}", binding_raw))
        .expect("can not make request")
        .text()
        .expect("can not extract body");

    println!("body:\n{}", body);

    assert!(body.contains(&format!("{} 1", metric_name)));
}
