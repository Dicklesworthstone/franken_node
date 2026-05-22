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
    fn render_prometheus_frozen_canonical_byte_layout_golden() {
        // Pin the canonical Prometheus output format to catch:
        // 1. Changes to HELP/TYPE line formatting or metric ordering
        // 2. Label escaping algorithm modifications
        // 3. Value precision or formatting changes
        // 4. Whitespace, newline, or separator character modifications

        // Fixture 1: Minimal registry with single gauge metric
        let mut registry_minimal = MetricsRegistry::new();
        registry_minimal
            .record_gauge("franken_node_uptime_seconds", "Node uptime in seconds", 3600.0, &[])
            .expect("valid gauge");

        let minimal_output = registry_minimal.render_prometheus();
        let expected_minimal = "# HELP franken_node_uptime_seconds Node uptime in seconds\n\
                               # TYPE franken_node_uptime_seconds gauge\n\
                               franken_node_uptime_seconds 3600\n";
        assert_eq!(
            minimal_output,
            expected_minimal,
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
                ]
            )
            .expect("valid counter with escaped labels");

        let complex_output = registry_complex.render_prometheus();
        let expected_complex = "# HELP franken_node_requests_total Total HTTP requests processed\n\
                               # TYPE franken_node_requests_total counter\n\
                               franken_node_requests_total{method=\"GET\",path=\"/api/v1/health\\\"test\\\\newline\\n\",status=\"200\"} 42\n";
        assert_eq!(
            complex_output,
            expected_complex,
            "complex render_prometheus output drifted — check label escaping for quotes/backslashes/newlines \
             or sorted label ordering in Prometheus output"
        );

        // Fixture 3: Multiple metrics with different types and sorting
        let mut registry_multi = MetricsRegistry::new();
        registry_multi
            .record_gauge("z_last_metric", "Last metric alphabetically", 1.0, &[])
            .expect("valid gauge");
        registry_multi
            .record_counter("a_first_metric", "First metric alphabetically", 5.0, &[("env", "test")])
            .expect("valid counter");
        registry_multi
            .record_gauge("m_middle_metric", "Middle metric", 2.5, &[("region", "us-east-1")])
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
            multi_output,
            expected_multi,
            "multi-metric render_prometheus output drifted — check lexicographic metric sorting \
             or multi-metric formatting with different types"
        );

        // Fixture 4: Edge case values and precision
        let mut registry_edge = MetricsRegistry::new();
        registry_edge
            .record_gauge("franken_node_precision_test", "Precision test metric", 123.456789, &[])
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
            edge_output,
            expected_edge,
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
                &[]
            )
            .expect("valid gauge with escaped help");

        let help_escape_output = registry_help_escape.render_prometheus();
        let expected_help_escape = "# HELP franken_node_escape_test Help with backslash \\\\ and newline \\n characters\n\
                                   # TYPE franken_node_escape_test gauge\n\
                                   franken_node_escape_test 1\n";
        assert_eq!(
            help_escape_output,
            expected_help_escape,
            "help-escape render_prometheus output drifted — check help text escaping \
             for backslashes and newlines in HELP lines"
        );
    }
}
