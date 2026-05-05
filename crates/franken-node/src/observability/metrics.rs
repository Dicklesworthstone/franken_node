use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Write as _};

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

    pub fn record(&mut self, metric: MetricSnapshot) {
        self.metrics.push(metric);
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
            writeln!(
                &mut output,
                "{}{} {}",
                metric.name,
                render_labels(&metric.labels),
                render_metric_value(metric.value)
            )
            .expect("render prometheus sample line");
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

fn render_labels(labels: &[(String, String)]) -> String {
    if labels.is_empty() {
        return String::new();
    }

    let mut rendered = String::from("{");
    for (index, (name, value)) in labels.iter().enumerate() {
        if index > 0 {
            rendered.push(',');
        }
        write!(
            &mut rendered,
            "{}=\"{}\"",
            name,
            escape_prometheus_label_value(value)
        )
        .expect("render prometheus label");
    }
    rendered.push('}');
    rendered
}

fn render_metric_value(value: f64) -> String {
    value.to_string()
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
}
