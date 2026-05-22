#![no_main]

//! Fuzz harness for
//! `frankenengine_node::observability::metrics::MetricsRegistry::{
//! record_counter, record_gauge, render_prometheus}` at
//! `crates/franken-node/src/observability/metrics.rs:134`, `:146`, `:158`.
//!
//! Background. `MetricsRegistry` is the Prometheus-exporter the runtime
//! uses to surface observability metrics from every subsystem. Each
//! `record_*` call validates the metric name + help + label set against
//! Prometheus naming rules and rejects non-finite values; a regression
//! that accepts `NaN`/`Inf` would let an attacker inject a value that
//! breaks the Prometheus scraper downstream (NaN serializes as `NaN`
//! which most scrapers reject loudly, but `+Inf` serializes as `+Inf`
//! and can pass through into alert thresholds incorrectly).
//!
//! Existing fuzz coverage of this registry: **zero**.
//!
//! Five invariants pinned per call:
//!
//!   (A) **INV-METRICS-PANIC-FREE** — arbitrary name/help/value/label
//!       inputs MUST NOT panic the registry.
//!
//!   (B) **INV-METRICS-NAN-REJECT** — any non-finite value (NaN, ±Inf)
//!       MUST cause `record_counter`/`record_gauge` to return
//!       `Err(NonFiniteValue { .. })`. Catches a regression that drops
//!       the finite-value guard.
//!
//!   (C) **INV-METRICS-CAPACITY-BOUND** — `len()` MUST NEVER exceed
//!       `MAX_METRICS_PER_REGISTRY = 10_000`. The internal
//!       `push_bounded` enforces this; the assertion catches a
//!       regression where push_bounded is swapped for raw `Vec::push`.
//!
//!   (D) **INV-METRICS-RENDER-CONTAINS-NAME** — for every successfully-
//!       recorded metric `m`, `render_prometheus()` MUST contain the
//!       metric's name as a substring. Catches a render-side regression
//!       that drops a metric or mis-renders it.
//!
//!   (E) **INV-METRICS-RENDER-DETERMINISTIC** — `render_prometheus()`
//!       called twice on the same registry returns byte-identical
//!       output. The internal sort by (name, labels) means rendering is
//!       order-independent on the recording side.

use arbitrary::Arbitrary;
use frankenengine_node::observability::metrics::{MetricValidationError, MetricsRegistry};
use libfuzzer_sys::fuzz_target;

const MAX_OPERATIONS: usize = 64;
const MAX_NAME_BYTES: usize = 128;
const MAX_HELP_BYTES: usize = 256;
const MAX_LABELS: usize = 8;
const MAX_LABEL_BYTES: usize = 64;
// Mirrors crates/franken-node/src/observability/metrics.rs:8
const REGISTRY_CAP: usize = 10_000;

#[derive(Debug, Arbitrary)]
enum Op {
    RecordCounter {
        name: String,
        help: String,
        value: f64,
        labels: Vec<(String, String)>,
    },
    RecordGauge {
        name: String,
        help: String,
        value: f64,
        labels: Vec<(String, String)>,
    },
}

#[derive(Debug, Arbitrary)]
struct MetricsFuzzCase {
    ops: Vec<Op>,
}

fuzz_target!(|case: MetricsFuzzCase| {
    let mut registry = MetricsRegistry::new();
    let mut recorded_names: Vec<String> = Vec::new();

    for op in case.ops.into_iter().take(MAX_OPERATIONS) {
        match op {
            Op::RecordCounter {
                name,
                help,
                value,
                labels,
            } => process_record(
                &mut registry,
                &mut recorded_names,
                /*is_counter=*/ true,
                name,
                help,
                value,
                labels,
            ),
            Op::RecordGauge {
                name,
                help,
                value,
                labels,
            } => process_record(
                &mut registry,
                &mut recorded_names,
                /*is_counter=*/ false,
                name,
                help,
                value,
                labels,
            ),
        }

        // ── (C) Capacity bound — registry never exceeds the documented cap.
        assert!(
            registry.len() <= REGISTRY_CAP,
            "INV-METRICS-CAPACITY-BOUND violated: registry grew to {} > {REGISTRY_CAP}",
            registry.len()
        );
    }

    // ── (E) Render determinism ─────────────────────────────────────
    let first_render = registry.render_prometheus();
    let second_render = registry.render_prometheus();
    assert_eq!(
        first_render,
        second_render,
        "INV-METRICS-RENDER-DETERMINISTIC violated: two consecutive renders \
         produced different output ({} vs {} bytes)",
        first_render.len(),
        second_render.len()
    );

    // ── (D) Every successfully-recorded metric appears in the render ─
    for name in &recorded_names {
        assert!(
            first_render.contains(name.as_str()),
            "INV-METRICS-RENDER-CONTAINS-NAME violated: registered metric {name:?} \
             missing from render_prometheus() output"
        );
    }
});

#[allow(clippy::too_many_arguments)]
fn process_record(
    registry: &mut MetricsRegistry,
    recorded_names: &mut Vec<String>,
    is_counter: bool,
    name: String,
    help: String,
    value: f64,
    labels: Vec<(String, String)>,
) {
    let name = bounded(&name, MAX_NAME_BYTES);
    let help = bounded(&help, MAX_HELP_BYTES);
    let bounded_labels: Vec<(String, String)> = labels
        .into_iter()
        .take(MAX_LABELS)
        .map(|(k, v)| (bounded(&k, MAX_LABEL_BYTES), bounded(&v, MAX_LABEL_BYTES)))
        .collect();
    let label_refs: Vec<(&str, &str)> = bounded_labels
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    // ── (A) Panic-freedom: the call IS the assertion ────────────────
    let result = if is_counter {
        registry.record_counter(&name, &help, value, &label_refs)
    } else {
        registry.record_gauge(&name, &help, value, &label_refs)
    };

    // ── (B) NaN/Inf rejection ──────────────────────────────────────
    if !value.is_finite() {
        // The registry MUST reject non-finite values via NonFiniteValue.
        // It may also surface a name/help/label validation error that
        // fires before the finite check — the harness only asserts that
        // a non-finite value cannot land successfully.
        assert!(
            result.is_err(),
            "INV-METRICS-NAN-REJECT violated: registry accepted non-finite \
             value {value} for metric {name:?}"
        );
        // When the value-validation error fires, it MUST be NonFiniteValue.
        // We can't easily assert the error variant when name/help fail
        // FIRST, so the check above is sufficient.
    }

    // Track successful recordings for invariant (D).
    if result.is_ok() {
        // The registry only records metrics whose name passed validation;
        // record the same name we passed so the substring check below
        // matches the production output.
        recorded_names.push(name);
    } else {
        // Non-finite + non-NaN-related errors are accepted as long as
        // they're a documented MetricValidationError variant; that pins
        // the error-class contract.
        let err = result.as_ref().err().expect("checked is_ok above");
        match err {
            MetricValidationError::InvalidMetricName { .. }
            | MetricValidationError::EmptyHelp { .. }
            | MetricValidationError::InvalidLabelName { .. }
            | MetricValidationError::DuplicateLabelName { .. }
            | MetricValidationError::NonFiniteValue { .. } => {
                // All variants are valid rejection signals.
            }
        }
    }
}

fn bounded(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_string();
    }
    let mut out = String::with_capacity(max_bytes);
    for ch in s.chars() {
        if out.len().saturating_add(ch.len_utf8()) > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}
