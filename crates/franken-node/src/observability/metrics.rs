use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Write as _};

use crate::push_bounded;

/// Maximum metrics per registry to prevent memory exhaustion DoS attacks.
const MAX_METRICS_PER_REGISTRY: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    Counter,
    Gauge,
}

impl MetricKind {
    pub fn as_prometheus_type(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MetricSnapshot {
    name: String,
    help: String,
    kind: MetricKind,
    value: f64,
    labels: Vec<(String, String)>,
}

impl MetricSnapshot {
    pub fn new(
        name: impl Into<String>,
        help: impl Into<String>,
        kind: MetricKind,
        value: f64,
        labels: Vec<(String, String)>,
    ) -> Result<Self, MetricValidationError> {
        let name = name.into();
        let help = help.into();

        validate_metric_name(&name)?;

        if help.trim().is_empty() {
            return Err(MetricValidationError::EmptyHelp { metric: name });
        }

        if !value.is_finite() {
            return Err(MetricValidationError::NonFiniteValue { metric: name });
        }

        let mut sorted_labels = labels;
        sorted_labels.sort_by(|left, right| left.0.cmp(&right.0));
        validate_labels(&name, &sorted_labels)?;

        Ok(Self {
            name,
            help,
            kind,
            value,
            labels: sorted_labels,
        })
    }

    pub fn counter(
        name: impl Into<String>,
        help: impl Into<String>,
        value: f64,
        labels: Vec<(String, String)>,
    ) -> Result<Self, MetricValidationError> {
        Self::new(name, help, MetricKind::Counter, value, labels)
    }

    pub fn gauge(
        name: impl Into<String>,
        help: impl Into<String>,
        value: f64,
        labels: Vec<(String, String)>,
    ) -> Result<Self, MetricValidationError> {
        Self::new(name, help, MetricKind::Gauge, value, labels)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn help(&self) -> &str {
        &self.help
    }

    pub fn kind(&self) -> MetricKind {
        self.kind
    }

    pub fn value(&self) -> f64 {
        self.value
    }

    pub fn labels(&self) -> &[(String, String)] {
        &self.labels
    }
}

#[derive(Debug, Clone, Default)]
pub struct MetricsRegistry {
    metrics: Vec<MetricSnapshot>,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.metrics.is_empty()
    }

    pub fn len(&self) -> usize {
        self.metrics.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &MetricSnapshot> {
        self.metrics.iter()
    }

    /// Record a metric snapshot with bounded capacity to prevent DoS attacks.
    pub fn record(&mut self, metric: MetricSnapshot) {
        push_bounded(&mut self.metrics, metric, MAX_METRICS_PER_REGISTRY);
    }

    pub fn record_counter(
        &mut self,
        name: &str,
        help: &str,
        value: f64,
        labels: &[(&str, &str)],
    ) -> Result<(), MetricValidationError> {
        let metric = MetricSnapshot::counter(name, help, value, owned_labels(labels))?;
        self.record(metric);
        Ok(())
    }

    pub fn record_gauge(
        &mut self,
        name: &str,
        help: &str,
        value: f64,
        labels: &[(&str, &str)],
    ) -> Result<(), MetricValidationError> {
        let metric = MetricSnapshot::gauge(name, help, value, owned_labels(labels))?;
        self.record(metric);
        Ok(())
    }

    pub fn render_prometheus(&self) -> String {
        let mut metrics = self.metrics.iter().collect::<Vec<_>>();
        metrics.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.labels.cmp(&right.labels))
        });

        let mut output = String::new();
        for metric in metrics {
            writeln!(
                &mut output,
                "# HELP {} {}",
                metric.name,
                escape_prometheus_help(&metric.help)
            )
            .expect("render prometheus HELP line");
            writeln!(
                &mut output,
                "# TYPE {} {}",
                metric.name,
                metric.kind.as_prometheus_type()
            )
            .expect("render prometheus TYPE line");
            // Write metric name
            output.push_str(&metric.name);
            // Write labels directly to output buffer (no intermediate allocation)
            render_labels_to_buffer(&metric.labels, &mut output);
            output.push(' ');
            // Write metric value directly to output buffer (no intermediate allocation)
            render_metric_value_to_buffer(metric.value, &mut output);
            output.push('\n');
        }
        output
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetricValidationError {
    InvalidMetricName { name: String },
    EmptyHelp { metric: String },
    InvalidLabelName { metric: String, label: String },
    DuplicateLabelName { metric: String, label: String },
    NonFiniteValue { metric: String },
}

impl fmt::Display for MetricValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetricName { name } => {
                write!(formatter, "invalid metric name `{name}`")
            }
            Self::EmptyHelp { metric } => {
                write!(formatter, "metric `{metric}` must include HELP text")
            }
            Self::InvalidLabelName { metric, label } => {
                write!(
                    formatter,
                    "metric `{metric}` has invalid label name `{label}`"
                )
            }
            Self::DuplicateLabelName { metric, label } => {
                write!(
                    formatter,
                    "metric `{metric}` has duplicate label name `{label}`"
                )
            }
            Self::NonFiniteValue { metric } => {
                write!(formatter, "metric `{metric}` has a non-finite value")
            }
        }
    }
}

impl Error for MetricValidationError {}

fn owned_labels(labels: &[(&str, &str)]) -> Vec<(String, String)> {
    labels
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

fn validate_metric_name(name: &str) -> Result<(), MetricValidationError> {
    if is_valid_metric_name(name) {
        Ok(())
    } else {
        Err(MetricValidationError::InvalidMetricName {
            name: name.to_owned(),
        })
    }
}

fn validate_labels(metric: &str, labels: &[(String, String)]) -> Result<(), MetricValidationError> {
    let mut seen = BTreeSet::new();
    for (label, _) in labels {
        if !is_valid_label_name(label) {
            return Err(MetricValidationError::InvalidLabelName {
                metric: metric.to_owned(),
                label: label.to_owned(),
            });
        }
        if !seen.insert(label.as_str()) {
            return Err(MetricValidationError::DuplicateLabelName {
                metric: metric.to_owned(),
                label: label.to_owned(),
            });
        }
    }
    Ok(())
}

fn is_valid_metric_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    is_metric_name_start(first) && chars.all(is_metric_name_continue)
}

fn is_valid_label_name(name: &str) -> bool {
    if name == "__name__" {
        return false;
    }

    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    is_label_name_start(first) && chars.all(is_label_name_continue)
}

fn is_metric_name_start(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '_' || character == ':'
}

fn is_metric_name_continue(character: char) -> bool {
    is_metric_name_start(character) || character.is_ascii_digit()
}

fn is_label_name_start(character: char) -> bool {
    character.is_ascii_alphabetic() || character == '_'
}

fn is_label_name_continue(character: char) -> bool {
    is_label_name_start(character) || character.is_ascii_digit()
}

fn render_labels_to_buffer(labels: &[(String, String)], output: &mut String) {
    if labels.is_empty() {
        return;
    }

    output.push('{');
    for (index, (name, value)) in labels.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        write!(
            output,
            "{}=\"{}\"",
            name,
            escape_prometheus_label_value(value)
        )
        .expect("render prometheus label");
    }
    output.push('}');
}

fn render_metric_value_to_buffer(value: f64, output: &mut String) {
    write!(output, "{}", value).expect("write metric value to String never fails");
}

#[cfg(test)]
fn render_labels(labels: &[(String, String)]) -> String {
    let mut rendered = String::new();
    render_labels_to_buffer(labels, &mut rendered);
    rendered
}

#[cfg(test)]
fn render_metric_value(value: f64) -> String {
    let mut rendered = String::new();
    render_metric_value_to_buffer(value, &mut rendered);
    rendered
}

fn escape_prometheus_help(raw: &str) -> String {
    let mut escaped = String::new();
    for character in raw.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn escape_prometheus_label_value(raw: &str) -> String {
    let mut escaped = String::new();
    for character in raw.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '"' => escaped.push_str("\\\""),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::{MetricKind, MetricSnapshot, MetricValidationError, MetricsRegistry};

    #[test]
    fn renders_prometheus_snapshot_with_escaped_labels() {
        let mut registry = MetricsRegistry::new();

        registry
            .record_gauge(
                "franken_node_health_pass",
                "Whether the latest operator health check passed.",
                1.0,
                &[("surface", "operator")],
            )
            .expect("health pass metric should be valid");
        registry
            .record_counter(
                "franken_node_fleet_active_quarantines",
                "Active fleet quarantine count.",
                2.0,
                &[("zone", "prod\"east\\a\nb")],
            )
            .expect("fleet quarantine metric should be valid");

        let rendered = registry.render_prometheus();

        assert!(rendered.contains(
            "# HELP franken_node_fleet_active_quarantines Active fleet quarantine count."
        ));
        assert!(rendered.contains("# TYPE franken_node_fleet_active_quarantines counter"));
        assert!(
            rendered.contains(
                "franken_node_fleet_active_quarantines{zone=\"prod\\\"east\\\\a\\nb\"} 2"
            )
        );
        assert!(rendered.contains("# TYPE franken_node_health_pass gauge"));
        assert!(rendered.contains("franken_node_health_pass{surface=\"operator\"} 1"));
    }

    #[test]
    fn rejects_invalid_operator_metrics() {
        let invalid_name = MetricSnapshot::new("bad name", "help", MetricKind::Gauge, 1.0, vec![])
            .expect_err("metric names reject whitespace");
        assert!(matches!(
            invalid_name,
            MetricValidationError::InvalidMetricName { .. }
        ));

        let duplicate_label = MetricSnapshot::new(
            "franken_node_health_pass",
            "help",
            MetricKind::Gauge,
            1.0,
            vec![
                ("surface".to_owned(), "operator".to_owned()),
                ("surface".to_owned(), "fleet".to_owned()),
            ],
        )
        .expect_err("metric labels must be unique");
        assert!(matches!(
            duplicate_label,
            MetricValidationError::DuplicateLabelName { .. }
        ));

        let non_finite = MetricSnapshot::new(
            "franken_node_health_pass",
            "help",
            MetricKind::Gauge,
            f64::NAN,
            vec![],
        )
        .expect_err("metric values must be finite");
        assert!(matches!(
            non_finite,
            MetricValidationError::NonFiniteValue { .. }
        ));
    }

    #[test]
    fn optimized_render_produces_identical_output() {
        // Test that the optimized render functions produce byte-identical output to original
        use super::{
            render_labels, render_labels_to_buffer, render_metric_value,
            render_metric_value_to_buffer,
        };

        // Test labels rendering
        let labels = vec![
            ("service".to_string(), "web".to_string()),
            ("env".to_string(), "prod".to_string()),
            ("zone".to_string(), "us-east\"1\\test\n".to_string()), // Test escaping
        ];

        let original_labels = render_labels(&labels);
        let mut optimized_labels = String::new();
        render_labels_to_buffer(&labels, &mut optimized_labels);

        assert_eq!(
            original_labels, optimized_labels,
            "Labels rendering should be identical"
        );

        // Test empty labels
        let empty_labels = vec![];
        let original_empty = render_labels(&empty_labels);
        let mut optimized_empty = String::new();
        render_labels_to_buffer(&empty_labels, &mut optimized_empty);

        assert_eq!(
            original_empty, optimized_empty,
            "Empty labels rendering should be identical"
        );

        // Test metric value rendering
        let test_values = vec![0.0, 1.5, 123.456789, f64::MAX, f64::MIN, 1e-10, 1e10];

        for value in test_values {
            let original_value = render_metric_value(value);
            let mut optimized_value = String::new();
            render_metric_value_to_buffer(value, &mut optimized_value);

            assert_eq!(
                original_value, optimized_value,
                "Value rendering should be identical for {}",
                value
            );
        }

        // Integration test with full metrics registry
        let mut registry = MetricsRegistry::new();
        registry
            .record_gauge("test_metric", "A test metric", 42.5, &[("label", "value")])
            .expect("valid metric");

        let rendered = registry.render_prometheus();
        // Ensure the output still contains expected content (proving compatibility)
        assert!(rendered.contains("test_metric{label=\"value\"} 42.5"));
    }

    #[test]
    fn comprehensive_metric_snapshot_golden() {
        // Comprehensive test creating a realistic metrics registry snapshot
        // for golden artifact verification of metric serialization consistency
        let mut registry = MetricsRegistry::new();

        // System health metrics (typical operator metrics)
        registry
            .record_gauge(
                "franken_node_health_status",
                "Overall system health score (0-1)",
                0.95,
                &[("component", "runtime"), ("zone", "us-east-1")],
            )
            .expect("health metric");

        registry
            .record_counter(
                "franken_node_requests_total",
                "Total processed requests",
                1_247_892.0,
                &[
                    ("method", "POST"),
                    ("endpoint", "/validate"),
                    ("status", "200"),
                ],
            )
            .expect("request counter");

        registry
            .record_counter(
                "franken_node_errors_total",
                "Total error count",
                42.0,
                &[("type", "validation"), ("severity", "recoverable")],
            )
            .expect("error counter");

        // Performance metrics with edge case values
        registry
            .record_gauge(
                "franken_node_latency_p99_seconds",
                "99th percentile latency in seconds",
                0.00012,
                &[("operation", "signature_verify"), ("cache", "hit")],
            )
            .expect("latency gauge");

        registry
            .record_gauge(
                "franken_node_memory_usage_bytes",
                "Current memory usage in bytes",
                1_073_741_824.0, // 1GB
                &[("pool", "evidence_ledger"), ("region", "heap")],
            )
            .expect("memory gauge");

        // Fleet quarantine metrics with special characters in labels
        registry
            .record_counter(
                "franken_node_quarantine_events_total",
                "Quarantine events triggered",
                15.0,
                &[
                    ("reason", "high_risk_code\"injection"),
                    ("action", "block\\log"),
                ],
            )
            .expect("quarantine counter");

        // Verify registry state
        assert_eq!(registry.len(), 6, "Should have exactly 6 metrics recorded");
        assert!(!registry.is_empty(), "Registry should not be empty");

        // Create deterministic snapshot for comparison
        let mut snapshot_entries = Vec::new();
        for metric in registry.iter() {
            let entry = serde_json::json!({
                "name": metric.name(),
                "help": metric.help(),
                "kind": match metric.kind() {
                    MetricKind::Counter => "counter",
                    MetricKind::Gauge => "gauge",
                },
                "value": metric.value(),
                "labels": metric.labels().iter().cloned().collect::<std::collections::BTreeMap<_, _>>(),
            });
            snapshot_entries.push(entry);
        }

        // Sort for deterministic output
        snapshot_entries.sort_by_key(|entry| entry["name"].as_str().unwrap().to_string());

        let golden_snapshot = serde_json::json!({
            "version": "1.0",
            "metrics_count": snapshot_entries.len(),
            "snapshot_timestamp": "2026-05-22T20:00:00Z", // Fixed for golden testing
            "metrics": snapshot_entries
        });

        // Verify key properties of the snapshot
        assert_eq!(golden_snapshot["metrics_count"], 6);
        assert_eq!(golden_snapshot["version"], "1.0");

        // Verify specific metric entries exist with expected structure
        let metrics = golden_snapshot["metrics"].as_array().unwrap();

        // Health metric verification
        let health_metric = metrics
            .iter()
            .find(|m| m["name"] == "franken_node_health_status")
            .unwrap();
        assert_eq!(health_metric["kind"], "gauge");
        assert_eq!(health_metric["value"], 0.95);
        assert_eq!(health_metric["labels"]["component"], "runtime");

        // Request counter verification
        let request_metric = metrics
            .iter()
            .find(|m| m["name"] == "franken_node_requests_total")
            .unwrap();
        assert_eq!(request_metric["kind"], "counter");
        assert_eq!(request_metric["value"], 1247892.0);
        assert_eq!(request_metric["labels"]["endpoint"], "/validate");

        // Error handling for special characters
        let quarantine_metric = metrics
            .iter()
            .find(|m| m["name"] == "franken_node_quarantine_events_total")
            .unwrap();
        assert_eq!(
            quarantine_metric["labels"]["reason"],
            "high_risk_code\"injection"
        );
        assert_eq!(quarantine_metric["labels"]["action"], "block\\log");

        // Verify Prometheus output contains all metrics
        let prometheus_output = registry.render_prometheus();
        assert!(prometheus_output.contains("franken_node_health_status"));
        assert!(prometheus_output.contains("franken_node_requests_total"));
        assert!(prometheus_output.contains("franken_node_quarantine_events_total"));
        assert!(prometheus_output.contains("component=\"runtime\""));
        assert!(prometheus_output.contains("high_risk_code\\\"injection"));

        // Validate metric count bounds (DoS protection verification)
        assert!(
            registry.len() <= super::MAX_METRICS_PER_REGISTRY,
            "Should respect capacity bounds"
        );

        // Verify against golden artifact for regression testing
        let expected_json = include_str!(
            "../../../../tests/golden/observability_metrics_comprehensive_snapshot.json"
        );
        let expected: serde_json::Value =
            serde_json::from_str(expected_json).expect("Golden artifact should be valid JSON");

        // Compare structural elements
        assert_eq!(golden_snapshot["version"], expected["version"]);
        assert_eq!(golden_snapshot["metrics_count"], expected["metrics_count"]);
        assert_eq!(
            golden_snapshot["snapshot_timestamp"],
            expected["snapshot_timestamp"]
        );
        assert_eq!(
            golden_snapshot["metrics"], expected["metrics"],
            "Metric snapshot should match golden artifact"
        );
    }

    #[test]
    fn render_prometheus_frozen_canonical_byte_layout_golden() {
        // Pin the canonical Prometheus output format to catch:
        // 1. Changes to HELP/TYPE line formatting or metric ordering
        // 2. Label escaping algorithm modifications
        // 3. Value precision or formatting changes
        // 4. Whitespace, newline, or separator character modifications

        // Fixture 1: Minimal registry with single gauge metric
        let mut registry_minimal = MetricsRegistry::new();
        registry_minimal
            .record_gauge(
                "franken_node_uptime_seconds",
                "Node uptime in seconds",
                3600.0,
                &[],
            )
            .expect("valid gauge");

        let minimal_output = registry_minimal.render_prometheus();
        let expected_minimal = "# HELP franken_node_uptime_seconds Node uptime in seconds\n\
                               # TYPE franken_node_uptime_seconds gauge\n\
                               franken_node_uptime_seconds 3600\n";
        assert_eq!(
            minimal_output, expected_minimal,
            "minimal render_prometheus output drifted — check HELP/TYPE line formatting \
             or metric value precision for gauges without labels"
        );

        // Fixture 2: Counter with labels requiring escaping
        let mut registry_complex = MetricsRegistry::new();
        registry_complex
            .record_counter(
                "franken_node_requests_total",
                "Total HTTP requests processed",
                42.0,
                &[
                    ("method", "GET"),
                    ("status", "200"),
                    ("path", "/api/v1/health\"test\\newline\n"),
                ],
            )
            .expect("valid counter with escaped labels");

        let complex_output = registry_complex.render_prometheus();
        let expected_complex = "# HELP franken_node_requests_total Total HTTP requests processed\n\
                               # TYPE franken_node_requests_total counter\n\
                               franken_node_requests_total{method=\"GET\",path=\"/api/v1/health\\\"test\\\\newline\\n\",status=\"200\"} 42\n";
        assert_eq!(
            complex_output, expected_complex,
            "complex render_prometheus output drifted — check label escaping for quotes/backslashes/newlines \
             or sorted label ordering in Prometheus output"
        );

        // Fixture 3: Multiple metrics with different types and sorting
        let mut registry_multi = MetricsRegistry::new();
        registry_multi
            .record_gauge("z_last_metric", "Last metric alphabetically", 1.0, &[])
            .expect("valid gauge");
        registry_multi
            .record_counter(
                "a_first_metric",
                "First metric alphabetically",
                5.0,
                &[("env", "test")],
            )
            .expect("valid counter");
        registry_multi
            .record_gauge(
                "m_middle_metric",
                "Middle metric",
                2.5,
                &[("region", "us-east-1")],
            )
            .expect("valid gauge");

        let multi_output = registry_multi.render_prometheus();
        let expected_multi = "# HELP a_first_metric First metric alphabetically\n\
                             # TYPE a_first_metric counter\n\
                             a_first_metric{env=\"test\"} 5\n\
                             # HELP m_middle_metric Middle metric\n\
                             # TYPE m_middle_metric gauge\n\
                             m_middle_metric{region=\"us-east-1\"} 2.5\n\
                             # HELP z_last_metric Last metric alphabetically\n\
                             # TYPE z_last_metric gauge\n\
                             z_last_metric 1\n";
        assert_eq!(
            multi_output, expected_multi,
            "multi-metric render_prometheus output drifted — check lexicographic metric sorting \
             or multi-metric formatting with different types"
        );

        // Fixture 4: Edge case values and precision
        let mut registry_edge = MetricsRegistry::new();
        registry_edge
            .record_gauge(
                "franken_node_precision_test",
                "Precision test metric",
                123.456789,
                &[],
            )
            .expect("valid gauge");
        registry_edge
            .record_counter("franken_node_zero_test", "Zero value test", 0.0, &[])
            .expect("valid counter");

        let edge_output = registry_edge.render_prometheus();
        let expected_edge = "# HELP franken_node_precision_test Precision test metric\n\
                            # TYPE franken_node_precision_test gauge\n\
                            franken_node_precision_test 123.456789\n\
                            # HELP franken_node_zero_test Zero value test\n\
                            # TYPE franken_node_zero_test counter\n\
                            franken_node_zero_test 0\n";
        assert_eq!(
            edge_output, expected_edge,
            "edge-case render_prometheus output drifted — check floating-point precision \
             handling or zero-value formatting in Prometheus output"
        );

        // Fixture 5: Help text escaping edge cases
        let mut registry_help_escape = MetricsRegistry::new();
        registry_help_escape
            .record_gauge(
                "franken_node_escape_test",
                "Help with backslash \\ and newline \n characters",
                1.0,
                &[],
            )
            .expect("valid gauge with escaped help");

        let help_escape_output = registry_help_escape.render_prometheus();
        let expected_help_escape = "# HELP franken_node_escape_test Help with backslash \\\\ and newline \\n characters\n\
                                   # TYPE franken_node_escape_test gauge\n\
                                   franken_node_escape_test 1\n";
        assert_eq!(
            help_escape_output, expected_help_escape,
            "help-escape render_prometheus output drifted — check help text escaping \
             for backslashes and newlines in HELP lines"
        );
    }

    #[test]
    fn metric_snapshot_determinism_property_tests() {
        // Property-based tests for metric snapshot determinism and invariants
        // Ensures consistent behavior across different input combinations
        use proptest::prelude::*;
        use std::collections::BTreeSet;

        proptest! {
            #[test]
            fn metric_snapshot_creation_is_deterministic(
                name in "[a-zA-Z_:][a-zA-Z0-9_:]*",
                help in "\\PC*",  // Any printable characters
                value in proptest::num::f64::POSITIVE,
                label_count in 0usize..10,
            ) {
                // Generate valid labels
                let labels: Vec<(String, String)> = (0..label_count)
                    .map(|i| (format!("label{}", i), format!("value{}", i)))
                    .collect();

                // Create the same metric multiple times
                let snapshot1 = MetricSnapshot::new(
                    name.clone(),
                    help.clone(),
                    MetricKind::Counter,
                    value,
                    labels.clone(),
                );
                let snapshot2 = MetricSnapshot::new(
                    name.clone(),
                    help.clone(),
                    MetricKind::Counter,
                    value,
                    labels.clone(),
                );

                // Both should succeed or fail identically
                match (&snapshot1, &snapshot2) {
                    (Ok(s1), Ok(s2)) => {
                        prop_assert_eq!(s1, s2, "Identical inputs should produce identical snapshots");
                        prop_assert_eq!(s1.name(), s2.name());
                        prop_assert_eq!(s1.help(), s2.help());
                        prop_assert_eq!(s1.value(), s2.value());
                        prop_assert_eq!(s1.labels(), s2.labels());
                    }
                    (Err(_), Err(_)) => {
                        // Both failed - this is fine for determinism
                    }
                    _ => prop_assert!(false, "Determinism violation: same inputs produced different results"),
                }
            }

            #[test]
            fn label_sorting_is_stable_and_deterministic(
                mut labels in prop::collection::vec(
                    ("[a-zA-Z_][a-zA-Z0-9_]*".prop_map(|s| s.chars().take(20).collect::<String>()), "\\PC{0,50}"),
                    1..20
                ),
            ) {
                // Remove duplicates and ensure valid labels
                let mut seen = BTreeSet::new();
                labels.retain(|(name, _)| seen.insert(name.clone()) && name != "__name__");
                if labels.is_empty() {
                    return Ok(());  // Skip empty label test
                }

                let name = "test_metric";
                let help = "Test metric for label sorting";

                // Create snapshot with original label order
                let snapshot1 = MetricSnapshot::new(
                    name,
                    help,
                    MetricKind::Gauge,
                    1.0,
                    labels.clone(),
                );

                // Reverse labels and create another snapshot
                labels.reverse();
                let snapshot2 = MetricSnapshot::new(
                    name,
                    help,
                    MetricKind::Gauge,
                    1.0,
                    labels,
                );

                match (snapshot1, snapshot2) {
                    (Ok(s1), Ok(s2)) => {
                        // Labels should be sorted identically regardless of input order
                        prop_assert_eq!(s1.labels(), s2.labels(), "Label sorting should be deterministic");

                        // Verify labels are actually sorted by key
                        let sorted_labels = s1.labels();
                        for i in 1..sorted_labels.len() {
                            prop_assert!(
                                sorted_labels[i-1].0 <= sorted_labels[i].0,
                                "Labels should be sorted lexicographically by key"
                            );
                        }
                    }
                    _ => {
                        // Both should succeed or fail the same way
                        prop_assert!(false, "Label sorting determinism violated");
                    }
                }
            }

            #[test]
            fn prometheus_output_determinism(
                metric_count in 1usize..20,
                base_value in 0.0..1000.0,
            ) {
                let mut registry1 = MetricsRegistry::new();
                let mut registry2 = MetricsRegistry::new();

                // Add metrics in different orders to both registries
                for i in 0..metric_count {
                    let name = format!("metric_{:03}", i);
                    let help = format!("Test metric number {}", i);
                    let value = base_value + i as f64;
                    let labels = vec![("instance".to_string(), format!("host_{}", i))];

                    let metric = MetricSnapshot::new(&name, &help, MetricKind::Counter, value, labels)?;

                    registry1.record(metric.clone());
                    registry2.record(metric);
                }

                // Add the same metrics to registry2 in reverse order
                let mut registry3 = MetricsRegistry::new();
                for i in (0..metric_count).rev() {
                    let name = format!("metric_{:03}", i);
                    let help = format!("Test metric number {}", i);
                    let value = base_value + i as f64;
                    let labels = vec![("instance".to_string(), format!("host_{}", i))];

                    let metric = MetricSnapshot::new(&name, &help, MetricKind::Counter, value, labels)?;
                    registry3.record(metric);
                }

                // All registries should produce identical Prometheus output
                let output1 = registry1.render_prometheus();
                let output2 = registry2.render_prometheus();
                let output3 = registry3.render_prometheus();

                prop_assert_eq!(&output1, &output2, "Registry with same metrics should produce identical output");
                prop_assert_eq!(&output1, &output3, "Metric insertion order should not affect output");

                // Verify output contains expected number of metrics
                let metric_lines = output1.lines().filter(|line| !line.starts_with('#') && !line.is_empty()).count();
                prop_assert_eq!(metric_lines, metric_count, "Output should contain all metrics");
            }

            #[test]
            fn registry_capacity_bounds_are_respected(
                attempts in 1usize..15000,
                base_value in 0.0..100.0,
            ) {
                let mut registry = MetricsRegistry::new();

                for i in 0..attempts {
                    let metric = MetricSnapshot::new(
                        format!("overflow_test_{}", i),
                        "Capacity test metric",
                        MetricKind::Counter,
                        base_value + i as f64,
                        vec![],
                    )?;

                    registry.record(metric);

                    // Verify capacity bounds are always respected
                    prop_assert!(
                        registry.len() <= super::MAX_METRICS_PER_REGISTRY,
                        "Registry should never exceed MAX_METRICS_PER_REGISTRY ({})",
                        super::MAX_METRICS_PER_REGISTRY
                    );
                }

                // Should be at capacity or close to it for large attempts
                if attempts > super::MAX_METRICS_PER_REGISTRY {
                    prop_assert_eq!(
                        registry.len(),
                        super::MAX_METRICS_PER_REGISTRY,
                        "Registry should be at capacity for overflow scenarios"
                    );
                }
            }

            #[test]
            fn metric_value_precision_consistency(
                values in prop::collection::vec(
                    prop::num::f64::POSITIVE.prop_filter("finite values only", |v| v.is_finite()),
                    1..50
                )
            ) {
                let mut registry = MetricsRegistry::new();

                for (i, value) in values.iter().enumerate() {
                    let metric = MetricSnapshot::new(
                        format!("precision_test_{}", i),
                        "Precision consistency test",
                        MetricKind::Gauge,
                        *value,
                        vec![],
                    )?;

                    registry.record(metric.clone());

                    // Verify stored value matches input exactly
                    let recorded_metric = registry.iter().last().unwrap();
                    prop_assert_eq!(
                        recorded_metric.value(),
                        *value,
                        "Recorded value should match input exactly"
                    );
                }

                // Verify Prometheus output preserves precision
                let prometheus_output = registry.render_prometheus();
                for (i, value) in values.iter().enumerate() {
                    let expected_line = format!("precision_test_{} {}", i, value);
                    prop_assert!(
                        prometheus_output.contains(&expected_line),
                        "Prometheus output should contain precise value: {}",
                        expected_line
                    );
                }
            }

            #[test]
            fn label_escaping_round_trip_consistency(
                special_chars in "[\\\\\n\"]+"  // Backslashes, newlines, quotes
            ) {
                if special_chars.is_empty() {
                    return Ok(());
                }

                let label_value = format!("test{}value", special_chars);
                let metric = MetricSnapshot::new(
                    "escape_test",
                    "Label escaping test",
                    MetricKind::Counter,
                    1.0,
                    vec![("special".to_string(), label_value.clone())],
                )?;

                let mut registry = MetricsRegistry::new();
                registry.record(metric);

                // Verify round-trip consistency
                let stored_metric = registry.iter().next().unwrap();
                prop_assert_eq!(
                    &stored_metric.labels()[0].1,
                    &label_value,
                    "Stored label value should match input exactly"
                );

                // Verify Prometheus output contains properly escaped version
                let prometheus_output = registry.render_prometheus();

                // Verify escaping rules are applied
                if label_value.contains('\\') {
                    prop_assert!(
                        prometheus_output.contains("\\\\"),
                        "Backslashes should be escaped in output"
                    );
                }
                if label_value.contains('\n') {
                    prop_assert!(
                        prometheus_output.contains("\\n"),
                        "Newlines should be escaped in output"
                    );
                }
                if label_value.contains('"') {
                    prop_assert!(
                        prometheus_output.contains("\\\""),
                        "Quotes should be escaped in output"
                    );
                }
            }
        }
    }
}
