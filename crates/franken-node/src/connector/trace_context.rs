//! bd-1gnb: Distributed trace correlation IDs across connector execution.
//!
//! Every high-impact flow carries a `TraceContext` with `trace_id`, `span_id`,
//! and optional `parent_span_id`.  Missing context is a conformance failure.
//! Traces can be stitched across services via shared `trace_id`.

use std::collections::HashMap;
use std::fmt;

// ── Trace context ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub timestamp: String,
}

impl TraceContext {
    /// Validate this context against format rules.
    pub fn validate(&self) -> Result<(), TraceError> {
        if self.trace_id.is_empty() {
            return Err(TraceError::MissingTraceId);
        }
        if self.span_id.is_empty() {
            return Err(TraceError::MissingSpanId);
        }
        if !is_hex(&self.trace_id, 32) {
            return Err(TraceError::InvalidFormat(format!(
                "trace_id must be 32 hex chars, got '{}'",
                self.trace_id
            )));
        }
        if !is_hex(&self.span_id, 16) {
            return Err(TraceError::InvalidFormat(format!(
                "span_id must be 16 hex chars, got '{}'",
                self.span_id
            )));
        }
        if let Some(ref parent) = self.parent_span_id {
            if !is_hex(parent, 16) {
                return Err(TraceError::InvalidFormat(format!(
                    "parent_span_id must be 16 hex chars, got '{parent}'"
                )));
            }
        }
        Ok(())
    }

    /// Create a child span inheriting this trace_id.
    pub fn child(&self, span_id: &str, timestamp: &str) -> TraceContext {
        TraceContext {
            trace_id: self.trace_id.clone(),
            span_id: span_id.to_string(),
            parent_span_id: Some(self.span_id.clone()),
            timestamp: timestamp.to_string(),
        }
    }
}

fn is_hex(s: &str, expected_len: usize) -> bool {
    s.len() == expected_len && s.chars().all(|c| c.is_ascii_hexdigit())
}

// ── Traced artifact ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TracedArtifact {
    pub artifact_id: String,
    pub artifact_type: String,
    pub trace_context: Option<TraceContext>,
}

// ── Violations & report ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TraceViolation {
    pub artifact_id: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct ConformanceReport {
    pub trace_id: String,
    pub total_artifacts: usize,
    pub violations: Vec<TraceViolation>,
    pub verdict: String,
}

// ── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceError {
    /// TRC_MISSING_TRACE_ID
    MissingTraceId,
    /// TRC_MISSING_SPAN_ID
    MissingSpanId,
    /// TRC_INVALID_FORMAT
    InvalidFormat(String),
    /// TRC_PARENT_NOT_FOUND
    ParentNotFound(String),
    /// TRC_CONFORMANCE_FAILED
    ConformanceFailed(String),
}

impl TraceError {
    pub fn code(&self) -> &'static str {
        match self {
            TraceError::MissingTraceId => "TRC_MISSING_TRACE_ID",
            TraceError::MissingSpanId => "TRC_MISSING_SPAN_ID",
            TraceError::InvalidFormat(_) => "TRC_INVALID_FORMAT",
            TraceError::ParentNotFound(_) => "TRC_PARENT_NOT_FOUND",
            TraceError::ConformanceFailed(_) => "TRC_CONFORMANCE_FAILED",
        }
    }
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceError::MissingTraceId => write!(f, "TRC_MISSING_TRACE_ID"),
            TraceError::MissingSpanId => write!(f, "TRC_MISSING_SPAN_ID"),
            TraceError::InvalidFormat(d) => write!(f, "TRC_INVALID_FORMAT: {d}"),
            TraceError::ParentNotFound(s) => write!(f, "TRC_PARENT_NOT_FOUND: {s}"),
            TraceError::ConformanceFailed(d) => write!(f, "TRC_CONFORMANCE_FAILED: {d}"),
        }
    }
}

// ── Trace store (for stitching) ─────────────────────────────────────────────

#[derive(Debug)]
pub struct TraceStore {
    /// trace_id → list of spans in insertion order.
    traces: HashMap<String, Vec<TraceContext>>,
}

impl TraceStore {
    pub fn new() -> Self {
        Self {
            traces: HashMap::new(),
        }
    }

    /// Record a span.  Validates context first.
    pub fn record(&mut self, ctx: &TraceContext) -> Result<(), TraceError> {
        ctx.validate()?;

        // If parent_span_id is set, verify parent exists in this trace.
        if let Some(ref parent) = ctx.parent_span_id {
            if let Some(spans) = self.traces.get(&ctx.trace_id) {
                if !spans.iter().any(|s| s.span_id == *parent) {
                    return Err(TraceError::ParentNotFound(parent.clone()));
                }
            } else {
                return Err(TraceError::ParentNotFound(parent.clone()));
            }
        }

        self.traces
            .entry(ctx.trace_id.clone())
            .or_default()
            .push(ctx.clone());
        Ok(())
    }

    /// Retrieve all spans for a trace_id (INV-TRC-STITCHABLE).
    pub fn stitch(&self, trace_id: &str) -> Vec<&TraceContext> {
        self.traces
            .get(trace_id)
            .map(|spans| spans.iter().collect())
            .unwrap_or_default()
    }

    /// Check conformance: every artifact in the list must have valid trace context.
    pub fn check_conformance(artifacts: &[TracedArtifact]) -> ConformanceReport {
        let mut violations = Vec::new();
        let trace_id = artifacts
            .first()
            .and_then(|a| a.trace_context.as_ref())
            .map(|tc| tc.trace_id.clone())
            .unwrap_or_default();

        for art in artifacts {
            match &art.trace_context {
                None => violations.push(TraceViolation {
                    artifact_id: art.artifact_id.clone(),
                    reason: "missing trace context".to_string(),
                }),
                Some(tc) => {
                    if let Err(e) = tc.validate() {
                        violations.push(TraceViolation {
                            artifact_id: art.artifact_id.clone(),
                            reason: e.to_string(),
                        });
                    }
                }
            }
        }

        let verdict = if violations.is_empty() {
            "PASS".to_string()
        } else {
            "FAIL".to_string()
        };

        ConformanceReport {
            trace_id,
            total_artifacts: artifacts.len(),
            violations,
            verdict,
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tid() -> String {
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".to_string()
    }
    fn sid(n: u8) -> String {
        format!("00000000000000{n:02x}")
    }

    fn ctx(parent: Option<String>) -> TraceContext {
        TraceContext {
            trace_id: tid(),
            span_id: sid(1),
            parent_span_id: parent,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn validate_valid_context() {
        ctx(None).validate().unwrap();
    }

    #[test]
    fn validate_with_parent() {
        ctx(Some(sid(0))).validate().unwrap();
    }

    #[test]
    fn reject_missing_trace_id() {
        let mut c = ctx(None);
        c.trace_id = String::new();
        assert_eq!(c.validate().unwrap_err().code(), "TRC_MISSING_TRACE_ID");
    }

    #[test]
    fn reject_missing_span_id() {
        let mut c = ctx(None);
        c.span_id = String::new();
        assert_eq!(c.validate().unwrap_err().code(), "TRC_MISSING_SPAN_ID");
    }

    #[test]
    fn reject_invalid_trace_id_format() {
        let mut c = ctx(None);
        c.trace_id = "not-hex-at-all!!".to_string();
        assert_eq!(c.validate().unwrap_err().code(), "TRC_INVALID_FORMAT");
    }

    #[test]
    fn reject_wrong_length_span_id() {
        let mut c = ctx(None);
        c.span_id = "0011".to_string();
        assert_eq!(c.validate().unwrap_err().code(), "TRC_INVALID_FORMAT");
    }

    #[test]
    fn child_inherits_trace_id() {
        let parent = ctx(None);
        let child = parent.child(&sid(2), "2026-01-01T00:00:01Z");
        assert_eq!(child.trace_id, parent.trace_id);
        assert_eq!(child.parent_span_id, Some(parent.span_id));
    }

    #[test]
    fn store_record_and_stitch() {
        let mut store = TraceStore::new();
        let root = ctx(None);
        store.record(&root).unwrap();
        let child = root.child(&sid(2), "ts2");
        store.record(&child).unwrap();

        let spans = store.stitch(&tid());
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0].span_id, sid(1));
        assert_eq!(spans[1].span_id, sid(2));
    }

    #[test]
    fn store_rejects_orphan_parent() {
        let mut store = TraceStore::new();
        let c = TraceContext {
            trace_id: tid(),
            span_id: sid(5),
            parent_span_id: Some(sid(99)),
            timestamp: "ts".into(),
        };
        assert_eq!(store.record(&c).unwrap_err().code(), "TRC_PARENT_NOT_FOUND");
    }

    #[test]
    fn stitch_empty_trace() {
        let store = TraceStore::new();
        assert!(store.stitch("nonexistent").is_empty());
    }

    #[test]
    fn conformance_pass() {
        let arts = vec![
            TracedArtifact {
                artifact_id: "a1".into(),
                artifact_type: "invoke".into(),
                trace_context: Some(ctx(None)),
            },
        ];
        let report = TraceStore::check_conformance(&arts);
        assert_eq!(report.verdict, "PASS");
        assert!(report.violations.is_empty());
    }

    #[test]
    fn conformance_fail_missing() {
        let arts = vec![
            TracedArtifact {
                artifact_id: "a1".into(),
                artifact_type: "invoke".into(),
                trace_context: None,
            },
        ];
        let report = TraceStore::check_conformance(&arts);
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].artifact_id, "a1");
    }

    #[test]
    fn conformance_fail_invalid() {
        let mut bad = ctx(None);
        bad.trace_id = "short".into();
        let arts = vec![
            TracedArtifact {
                artifact_id: "a2".into(),
                artifact_type: "receipt".into(),
                trace_context: Some(bad),
            },
        ];
        let report = TraceStore::check_conformance(&arts);
        assert_eq!(report.verdict, "FAIL");
    }

    #[test]
    fn all_error_codes_present() {
        let errors = vec![
            TraceError::MissingTraceId,
            TraceError::MissingSpanId,
            TraceError::InvalidFormat("x".into()),
            TraceError::ParentNotFound("x".into()),
            TraceError::ConformanceFailed("x".into()),
        ];
        let codes: Vec<_> = errors.iter().map(|e| e.code()).collect();
        assert!(codes.contains(&"TRC_MISSING_TRACE_ID"));
        assert!(codes.contains(&"TRC_MISSING_SPAN_ID"));
        assert!(codes.contains(&"TRC_INVALID_FORMAT"));
        assert!(codes.contains(&"TRC_PARENT_NOT_FOUND"));
        assert!(codes.contains(&"TRC_CONFORMANCE_FAILED"));
    }

    #[test]
    fn error_display() {
        let e = TraceError::MissingTraceId;
        assert!(e.to_string().contains("TRC_MISSING_TRACE_ID"));
    }
}
