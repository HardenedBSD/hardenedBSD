// macros: This module contains macros for registering metrics with the
//         registry.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Register a Counter Family with the Registry
#[macro_export]
macro_rules! register_counter_with_registry {
    // Counter family with no specific unit
    ($NAME:expr, $HELP:expr, $LABELS:ty, $REGISTRY:ident $(,)?) => {{
        use prometheus_client::metrics::{
            counter::Counter,
            family::Family,
        };

        let family = Family::<$LABELS, Counter>::default();

        $REGISTRY.register($NAME, $HELP, family.clone());

        family
    }};

    // Counter family with a specified unit
    ($NAME:expr, $HELP:expr, $LABELS:ty, $UNIT:expr, $REGISTRY:ident $(,)?) => {{
        use prometheus_client::metrics::{
            counter::Counter,
            family::Family,
        };

        let family = Family::<$LABELS, Counter>::default();

        $REGISTRY.register_with_unit(
            $NAME,
            $HELP,
            $UNIT,
            family.clone(),
        );

        family
    }};
}

/// Register a Gauge with the Registry
#[macro_export]
macro_rules! register_gauge_with_registry {
    // Single gauge with no specified unit
    ($NAME:expr, $HELP:expr, $REGISTRY:ident $(,)?) => {{
        use prometheus_client::metrics::gauge::Gauge;

        let gauge = Gauge::default();

        $REGISTRY.register($NAME, $HELP, gauge.clone());

        gauge
    }};

    // Gauge family with no specified unit
    ($NAME:expr, $HELP:expr, $LABELS:ty, $REGISTRY:ident $(,)?) => {{
        use prometheus_client::metrics::{
            family::Family,
            gauge::Gauge,
        };

        let family = Family::<$LABELS, Gauge>::default();

        $REGISTRY.register($NAME, $HELP, family.clone());

        family
    }};

    // Gauge family with a specified unit
    ($NAME:expr, $HELP:expr, $LABELS:ty, $UNIT:expr, $REGISTRY:ident $(,)?) => {{
        use prometheus_client::metrics::{
            family::Family,
            gauge::Gauge,
        };

        let family = Family::<$LABELS, Gauge>::default();

        $REGISTRY.register_with_unit(
            $NAME,
            $HELP,
            $UNIT,
            family.clone(),
        );

        family
    }};
}

/// Register an Info metric with the Registry
#[macro_export]
macro_rules! register_info_with_registry {
    // Single info metric with specified labels.
    ($NAME:expr, $HELP:expr, $LABELS:expr, $REGISTRY:ident $(,)?) => {{
        use prometheus_client::metrics::info::Info;

        let info = Info::new($LABELS);

        $REGISTRY.register($NAME, $HELP, info);
    }};
}
