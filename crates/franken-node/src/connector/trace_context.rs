//! bd-1gnb: Distributed trace correlation IDs across connector execution.
//!
//! Every high-impact flow carries a `TraceContext` with `trace_id`, `span_id`,
//! and optional `parent_span_id`.  Missing context is a conformance failure.
//! Traces can be stitched across services via shared `trace_id`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

const MAX_SPANS_PER_TRACE: usize = 4096;
const RESERVED_ARTIFACT_ID: &str = "<unknown>";

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

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
        if let Some(ref parent) = self.parent_span_id
            && !is_hex(parent, 16)
        {
            return Err(TraceError::InvalidFormat(format!(
                "parent_span_id must be 16 hex chars, got '{parent}'"
            )));
        }
        if self.parent_span_id.as_deref() == Some(self.span_id.as_str()) {
            return Err(TraceError::InvalidFormat(
                "parent_span_id must not equal span_id".to_string(),
            ));
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

fn invalid_artifact_id_reason(artifact_id: &str) -> Option<String> {
    let trimmed = artifact_id.trim();
    if trimmed.is_empty() {
        return Some("artifact_id must not be empty".to_string());
    }
    if artifact_id.as_bytes().contains(&b'\0') {
        return Some("artifact_id must not contain NUL bytes".to_string());
    }
    if trimmed == RESERVED_ARTIFACT_ID {
        return Some(format!("artifact_id is reserved: {:?}", artifact_id));
    }
    if trimmed != artifact_id {
        return Some("artifact_id contains leading or trailing whitespace".to_string());
    }
    None
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
    /// TRC_DUPLICATE_SPAN_ID
    DuplicateSpanId(String),
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
            TraceError::DuplicateSpanId(_) => "TRC_DUPLICATE_SPAN_ID",
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
            TraceError::DuplicateSpanId(s) => write!(f, "TRC_DUPLICATE_SPAN_ID: {s}"),
            TraceError::ConformanceFailed(d) => write!(f, "TRC_CONFORMANCE_FAILED: {d}"),
        }
    }
}

// ── Trace store (for stitching) ─────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct TraceStore {
    /// trace_id → list of spans in insertion order.
    traces: BTreeMap<String, Vec<TraceContext>>,
}

impl TraceStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a span.  Validates context first.
    pub fn record(&mut self, ctx: &TraceContext) -> Result<(), TraceError> {
        ctx.validate()?;

        if self
            .traces
            .get(&ctx.trace_id)
            .is_some_and(|spans| spans.iter().any(|s| s.span_id == ctx.span_id))
        {
            return Err(TraceError::DuplicateSpanId(ctx.span_id.clone()));
        }

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

        let spans = self.traces.entry(ctx.trace_id.clone()).or_default();
        push_bounded(spans, ctx.clone(), MAX_SPANS_PER_TRACE);
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
        let mut trace_id = None;
        let mut valid_contexts = Vec::new();

        for art in artifacts {
            if let Some(reason) = invalid_artifact_id_reason(&art.artifact_id) {
                violations.push(TraceViolation {
                    artifact_id: art.artifact_id.clone(),
                    reason,
                });
                continue;
            }

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
                        continue;
                    }

                    let flow_trace_id = trace_id.get_or_insert_with(|| tc.trace_id.clone());
                    if tc.trace_id != *flow_trace_id {
                        violations.push(TraceViolation {
                            artifact_id: art.artifact_id.clone(),
                            reason: TraceError::ConformanceFailed(format!(
                                "trace_id '{}' does not match flow trace_id '{}'",
                                tc.trace_id, flow_trace_id
                            ))
                            .to_string(),
                        });
                        continue;
                    }

                    valid_contexts.push((art.artifact_id.clone(), tc.clone()));
                }
            }
        }

        let known_spans: BTreeSet<String> = valid_contexts
            .iter()
            .map(|(_, tc)| tc.span_id.clone())
            .collect();
        let mut seen_spans = BTreeSet::new();
        for (artifact_id, tc) in &valid_contexts {
            if !seen_spans.insert(tc.span_id.clone()) {
                violations.push(TraceViolation {
                    artifact_id: artifact_id.clone(),
                    reason: TraceError::DuplicateSpanId(tc.span_id.clone()).to_string(),
                });
                continue;
            }
            if let Some(parent) = &tc.parent_span_id
                && !known_spans.contains(parent)
            {
                violations.push(TraceViolation {
                    artifact_id: artifact_id.clone(),
                    reason: TraceError::ParentNotFound(parent.clone()).to_string(),
                });
            }
        }

        let verdict = if violations.is_empty() {
            "PASS".to_string()
        } else {
            "FAIL".to_string()
        };

        ConformanceReport {
            trace_id: trace_id.unwrap_or_default(),
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
        let arts = vec![TracedArtifact {
            artifact_id: "a1".into(),
            artifact_type: "invoke".into(),
            trace_context: Some(ctx(None)),
        }];
        let report = TraceStore::check_conformance(&arts);
        assert_eq!(report.verdict, "PASS");
        assert!(report.violations.is_empty());
    }

    #[test]
    fn conformance_fail_missing() {
        let arts = vec![TracedArtifact {
            artifact_id: "a1".into(),
            artifact_type: "invoke".into(),
            trace_context: None,
        }];
        let report = TraceStore::check_conformance(&arts);
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].artifact_id, "a1");
    }

    #[test]
    fn conformance_fail_invalid_artifact_id() {
        let arts = vec![TracedArtifact {
            artifact_id: " art-1 ".into(),
            artifact_type: "invoke".into(),
            trace_context: Some(ctx(None)),
        }];
        let report = TraceStore::check_conformance(&arts);
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].artifact_id, " art-1 ");
        assert!(
            report.violations[0]
                .reason
                .contains("leading or trailing whitespace")
        );
    }

    #[test]
    fn conformance_fail_empty_artifact_id() {
        let arts = vec![TracedArtifact {
            artifact_id: "   ".into(),
            artifact_type: "invoke".into(),
            trace_context: Some(ctx(None)),
        }];
        let report = TraceStore::check_conformance(&arts);
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].reason.contains("must not be empty"));
    }

    #[test]
    fn conformance_fail_reserved_artifact_id() {
        let arts = vec![TracedArtifact {
            artifact_id: RESERVED_ARTIFACT_ID.to_string(),
            artifact_type: "invoke".into(),
            trace_context: Some(ctx(None)),
        }];
        let report = TraceStore::check_conformance(&arts);
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].reason.contains("reserved"));
    }

    #[test]
    fn conformance_fail_invalid() {
        let mut bad = ctx(None);
        bad.trace_id = "short".into();
        let arts = vec![TracedArtifact {
            artifact_id: "a2".into(),
            artifact_type: "receipt".into(),
            trace_context: Some(bad),
        }];
        let report = TraceStore::check_conformance(&arts);
        assert_eq!(report.verdict, "FAIL");
    }

    #[test]
    fn conformance_fail_mixed_trace_ids() {
        let mut other = ctx(None);
        other.trace_id = "ffffffffffffffffffffffffffffffff".into();
        let arts = vec![
            TracedArtifact {
                artifact_id: "a1".into(),
                artifact_type: "invoke".into(),
                trace_context: Some(ctx(None)),
            },
            TracedArtifact {
                artifact_id: "a2".into(),
                artifact_type: "receipt".into(),
                trace_context: Some(other),
            },
        ];
        let report = TraceStore::check_conformance(&arts);
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.trace_id, tid());
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].artifact_id, "a2");
        assert!(
            report.violations[0]
                .reason
                .contains("TRC_CONFORMANCE_FAILED")
        );
    }

    #[test]
    fn conformance_fail_orphan_parent_in_flow() {
        let orphan = TraceContext {
            trace_id: tid(),
            span_id: sid(2),
            parent_span_id: Some(sid(99)),
            timestamp: "ts2".into(),
        };
        let arts = vec![
            TracedArtifact {
                artifact_id: "a1".into(),
                artifact_type: "invoke".into(),
                trace_context: Some(ctx(None)),
            },
            TracedArtifact {
                artifact_id: "a2".into(),
                artifact_type: "receipt".into(),
                trace_context: Some(orphan),
            },
        ];
        let report = TraceStore::check_conformance(&arts);
        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.trace_id, tid());
        assert_eq!(report.violations.len(), 1);
        assert_eq!(report.violations[0].artifact_id, "a2");
        assert!(report.violations[0].reason.contains("TRC_PARENT_NOT_FOUND"));
    }

    #[test]
    fn reject_trace_id_with_non_hex_character_at_valid_length() {
        let mut c = ctx(None);
        c.trace_id = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5dg".to_string();

        let err = c.validate().unwrap_err();

        assert_eq!(err.code(), "TRC_INVALID_FORMAT");
        assert!(err.to_string().contains("trace_id must be 32 hex chars"));
    }

    #[test]
    fn reject_span_id_with_non_hex_character_at_valid_length() {
        let mut c = ctx(None);
        c.span_id = "00000000000000xz".to_string();

        let err = c.validate().unwrap_err();

        assert_eq!(err.code(), "TRC_INVALID_FORMAT");
        assert!(err.to_string().contains("span_id must be 16 hex chars"));
    }

    #[test]
    fn reject_empty_parent_span_id() {
        let mut c = ctx(None);
        c.parent_span_id = Some(String::new());

        let err = c.validate().unwrap_err();

        assert_eq!(err.code(), "TRC_INVALID_FORMAT");
        assert!(
            err.to_string()
                .contains("parent_span_id must be 16 hex chars")
        );
    }

    #[test]
    fn record_invalid_context_does_not_create_trace_entry() {
        let mut store = TraceStore::new();
        let mut c = ctx(None);
        c.span_id = "invalid-span".to_string();

        let err = store.record(&c).unwrap_err();

        assert_eq!(err.code(), "TRC_INVALID_FORMAT");
        assert!(store.stitch(&tid()).is_empty());
    }

    #[test]
    fn record_parent_from_different_trace_is_not_accepted() {
        let mut store = TraceStore::new();
        let root = ctx(None);
        store.record(&root).unwrap();
        let child = TraceContext {
            trace_id: "ffffffffffffffffffffffffffffffff".to_string(),
            span_id: sid(2),
            parent_span_id: Some(root.span_id),
            timestamp: "ts2".into(),
        };

        let err = store.record(&child).unwrap_err();

        assert_eq!(err.code(), "TRC_PARENT_NOT_FOUND");
        assert!(store.stitch("ffffffffffffffffffffffffffffffff").is_empty());
    }

    #[test]
    fn conformance_with_only_invalid_artifact_id_has_empty_trace_id() {
        let arts = vec![TracedArtifact {
            artifact_id: "\nartifact-1".into(),
            artifact_type: "invoke".into(),
            trace_context: Some(ctx(None)),
        }];

        let report = TraceStore::check_conformance(&arts);

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.trace_id, "");
        assert_eq!(report.total_artifacts, 1);
        assert!(report.violations[0].reason.contains("whitespace"));
    }

    #[test]
    fn conformance_reports_missing_and_invalid_contexts_separately() {
        let mut bad = ctx(None);
        bad.span_id = "bad".into();
        let arts = vec![
            TracedArtifact {
                artifact_id: "missing-context".into(),
                artifact_type: "invoke".into(),
                trace_context: None,
            },
            TracedArtifact {
                artifact_id: "bad-context".into(),
                artifact_type: "receipt".into(),
                trace_context: Some(bad),
            },
        ];

        let report = TraceStore::check_conformance(&arts);

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.violations.len(), 2);
        assert!(report.violations.iter().any(|violation| {
            violation.artifact_id == "missing-context"
                && violation.reason == "missing trace context"
        }));
        assert!(report.violations.iter().any(|violation| {
            violation.artifact_id == "bad-context"
                && violation.reason.contains("TRC_INVALID_FORMAT")
        }));
    }

    #[test]
    fn child_with_invalid_generated_span_still_fails_validation() {
        let parent = ctx(None);
        let child = parent.child("not-a-span-id", "ts-child");

        let err = child.validate().unwrap_err();

        assert_eq!(err.code(), "TRC_INVALID_FORMAT");
        assert_eq!(child.parent_span_id, Some(parent.span_id));
    }

    #[test]
    fn reject_parent_span_equal_to_span_id() {
        let span = sid(7);
        let c = TraceContext {
            trace_id: tid(),
            span_id: span.clone(),
            parent_span_id: Some(span),
            timestamp: "ts-self-parent".into(),
        };

        let err = c.validate().unwrap_err();

        assert_eq!(err.code(), "TRC_INVALID_FORMAT");
        assert!(err.to_string().contains("must not equal span_id"));
    }

    #[test]
    fn record_duplicate_root_span_id_is_rejected() {
        let mut store = TraceStore::new();
        let first = ctx(None);
        let duplicate = first.clone();
        store.record(&first).unwrap();

        let err = store.record(&duplicate).unwrap_err();

        assert_eq!(err.code(), "TRC_DUPLICATE_SPAN_ID");
        assert_eq!(store.stitch(&tid()).len(), 1);
    }

    #[test]
    fn record_duplicate_child_span_id_is_rejected_without_dropping_original() {
        let mut store = TraceStore::new();
        let root = ctx(None);
        let child = root.child(&sid(2), "ts-child");
        let duplicate_child = root.child(&sid(2), "ts-duplicate");
        store.record(&root).unwrap();
        store.record(&child).unwrap();

        let err = store.record(&duplicate_child).unwrap_err();

        assert_eq!(err.code(), "TRC_DUPLICATE_SPAN_ID");
        let spans = store.stitch(&tid());
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[1].timestamp, "ts-child");
    }

    #[test]
    fn conformance_fails_duplicate_span_id_in_same_flow() {
        let root = ctx(None);
        let duplicate = TraceContext {
            trace_id: tid(),
            span_id: root.span_id.clone(),
            parent_span_id: None,
            timestamp: "ts-duplicate".into(),
        };
        let arts = vec![
            TracedArtifact {
                artifact_id: "root".into(),
                artifact_type: "invoke".into(),
                trace_context: Some(root),
            },
            TracedArtifact {
                artifact_id: "duplicate".into(),
                artifact_type: "receipt".into(),
                trace_context: Some(duplicate),
            },
        ];

        let report = TraceStore::check_conformance(&arts);

        assert_eq!(report.verdict, "FAIL");
        assert!(report.violations.iter().any(|violation| {
            violation.artifact_id == "duplicate"
                && violation.reason.contains("TRC_DUPLICATE_SPAN_ID")
        }));
    }

    #[test]
    fn conformance_fails_self_parent_span_id() {
        let span = sid(8);
        let self_parent = TraceContext {
            trace_id: tid(),
            span_id: span.clone(),
            parent_span_id: Some(span),
            timestamp: "ts-self-parent".into(),
        };
        let arts = vec![TracedArtifact {
            artifact_id: "self-parent".into(),
            artifact_type: "receipt".into(),
            trace_context: Some(self_parent),
        }];

        let report = TraceStore::check_conformance(&arts);

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.violations.len(), 1);
        assert!(
            report.violations[0]
                .reason
                .contains("must not equal span_id")
        );
    }

    #[test]
    fn child_reusing_parent_span_id_fails_validation() {
        let parent = ctx(None);
        let child = parent.child(&parent.span_id, "ts-child");

        let err = child.validate().unwrap_err();

        assert_eq!(err.code(), "TRC_INVALID_FORMAT");
        assert!(err.to_string().contains("must not equal span_id"));
    }

    #[test]
    fn duplicate_span_error_display_includes_span_id() {
        let err = TraceError::DuplicateSpanId(sid(9));

        assert_eq!(err.code(), "TRC_DUPLICATE_SPAN_ID");
        assert!(err.to_string().contains("TRC_DUPLICATE_SPAN_ID"));
        assert!(err.to_string().contains(&sid(9)));
    }

    #[test]
    fn push_bounded_zero_capacity_clears_without_adding_span() {
        let mut spans = vec![ctx(None)];
        let replacement = TraceContext {
            trace_id: tid(),
            span_id: sid(2),
            parent_span_id: None,
            timestamp: "ts-replacement".into(),
        };

        push_bounded(&mut spans, replacement, 0);

        assert!(spans.is_empty());
    }

    #[test]
    fn push_bounded_single_capacity_replaces_oldest_span() {
        let mut spans = vec![ctx(None)];
        let replacement = TraceContext {
            trace_id: tid(),
            span_id: sid(2),
            parent_span_id: None,
            timestamp: "ts-replacement".into(),
        };

        push_bounded(&mut spans, replacement, 1);

        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].span_id, sid(2));
        assert_eq!(spans[0].timestamp, "ts-replacement");
    }

    #[test]
    fn conformance_rejects_artifact_id_with_nul_byte() {
        let arts = vec![TracedArtifact {
            artifact_id: "artifact\0id".into(),
            artifact_type: "invoke".into(),
            trace_context: Some(ctx(None)),
        }];

        let report = TraceStore::check_conformance(&arts);

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.trace_id, "");
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].reason.contains("NUL"));
    }

    #[test]
    fn conformance_rejects_nul_artifact_id_before_context_validation() {
        let mut bad_context = ctx(None);
        bad_context.trace_id = "short".into();
        let arts = vec![TracedArtifact {
            artifact_id: "artifact\0id".into(),
            artifact_type: "invoke".into(),
            trace_context: Some(bad_context),
        }];

        let report = TraceStore::check_conformance(&arts);

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.trace_id, "");
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].reason.contains("NUL"));
        assert!(!report.violations[0].reason.contains("TRC_INVALID_FORMAT"));
    }

    #[test]
    fn record_rejects_nul_trace_id_without_creating_trace_entry() {
        let mut store = TraceStore::new();
        let mut c = ctx(None);
        c.trace_id = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5\0".to_string();
        let bad_trace_id = c.trace_id.clone();

        let err = store.record(&c).unwrap_err();

        assert_eq!(err.code(), "TRC_INVALID_FORMAT");
        assert!(store.stitch(&bad_trace_id).is_empty());
        assert!(store.stitch(&tid()).is_empty());
    }

    #[test]
    fn record_rejects_nul_span_id_without_creating_trace_entry() {
        let mut store = TraceStore::new();
        let mut c = ctx(None);
        c.span_id = "00000000000000\0x".to_string();

        let err = store.record(&c).unwrap_err();

        assert_eq!(err.code(), "TRC_INVALID_FORMAT");
        assert!(store.stitch(&tid()).is_empty());
    }

    #[test]
    fn conformance_rejects_nul_parent_span_id() {
        let mut bad_parent = ctx(None);
        bad_parent.span_id = sid(2);
        bad_parent.parent_span_id = Some("00000000000000\0x".to_string());
        let arts = vec![TracedArtifact {
            artifact_id: "bad-parent".into(),
            artifact_type: "receipt".into(),
            trace_context: Some(bad_parent),
        }];

        let report = TraceStore::check_conformance(&arts);

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.violations.len(), 1);
        assert!(
            report.violations[0]
                .reason
                .contains("parent_span_id must be 16 hex chars")
        );
    }

    #[test]
    fn validate_rejects_trace_id_with_trailing_space_at_valid_length() {
        let mut c = ctx(None);
        c.trace_id.pop();
        c.trace_id.push(' ');

        let err = c.validate().unwrap_err();

        assert_eq!(c.trace_id.len(), 32);
        assert_eq!(err.code(), "TRC_INVALID_FORMAT");
        assert!(err.to_string().contains("trace_id must be 32 hex chars"));
    }

    #[test]
    fn validate_rejects_parent_span_id_that_is_too_long() {
        let mut c = ctx(None);
        c.parent_span_id = Some("00000000000000000".to_string());

        let err = c.validate().unwrap_err();

        assert_eq!(err.code(), "TRC_INVALID_FORMAT");
        assert!(
            err.to_string()
                .contains("parent_span_id must be 16 hex chars")
        );
    }

    #[test]
    fn record_rejects_child_before_parent_without_partial_insert() {
        let mut store = TraceStore::new();
        let root = ctx(None);
        let child = root.child(&sid(2), "ts-child");

        let err = store.record(&child).unwrap_err();

        assert_eq!(err.code(), "TRC_PARENT_NOT_FOUND");
        assert!(store.stitch(&tid()).is_empty());
    }

    #[test]
    fn record_rejects_self_parent_without_partial_insert() {
        let mut store = TraceStore::new();
        let span = sid(3);
        let c = TraceContext {
            trace_id: tid(),
            span_id: span.clone(),
            parent_span_id: Some(span),
            timestamp: "ts-self-parent".into(),
        };

        let err = store.record(&c).unwrap_err();

        assert_eq!(err.code(), "TRC_INVALID_FORMAT");
        assert!(store.stitch(&tid()).is_empty());
    }

    #[test]
    fn record_duplicate_span_with_different_parent_is_rejected_without_overwrite() {
        let mut store = TraceStore::new();
        let root = ctx(None);
        let first_child = root.child(&sid(2), "ts-first-child");
        let other_parent = root.child(&sid(3), "ts-other-parent");
        let duplicate_with_other_parent = TraceContext {
            trace_id: tid(),
            span_id: sid(2),
            parent_span_id: Some(sid(3)),
            timestamp: "ts-duplicate-other-parent".into(),
        };
        store.record(&root).unwrap();
        store.record(&first_child).unwrap();
        store.record(&other_parent).unwrap();

        let err = store.record(&duplicate_with_other_parent).unwrap_err();

        assert_eq!(err.code(), "TRC_DUPLICATE_SPAN_ID");
        let spans = store.stitch(&tid());
        assert_eq!(spans.len(), 3);
        assert_eq!(spans[1].timestamp, "ts-first-child");
    }

    #[test]
    fn conformance_rejects_invalid_parent_artifact_and_child_orphan() {
        let root = ctx(None);
        let child = root.child(&sid(2), "ts-child");
        let arts = vec![
            TracedArtifact {
                artifact_id: " root ".into(),
                artifact_type: "invoke".into(),
                trace_context: Some(root),
            },
            TracedArtifact {
                artifact_id: "child".into(),
                artifact_type: "receipt".into(),
                trace_context: Some(child),
            },
        ];

        let report = TraceStore::check_conformance(&arts);

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.trace_id, tid());
        assert_eq!(report.violations.len(), 2);
        assert!(report.violations.iter().any(|violation| {
            violation.artifact_id == " root " && violation.reason.contains("whitespace")
        }));
        assert!(report.violations.iter().any(|violation| {
            violation.artifact_id == "child" && violation.reason.contains("TRC_PARENT_NOT_FOUND")
        }));
    }

    #[test]
    fn conformance_rejects_invalid_artifact_id_before_missing_context() {
        let arts = vec![TracedArtifact {
            artifact_id: " \t ".into(),
            artifact_type: "invoke".into(),
            trace_context: None,
        }];

        let report = TraceStore::check_conformance(&arts);

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.trace_id, "");
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].reason.contains("must not be empty"));
        assert!(
            !report.violations[0]
                .reason
                .contains("missing trace context")
        );
    }

    #[test]
    fn conformance_rejects_padded_reserved_artifact_id_as_reserved() {
        let arts = vec![TracedArtifact {
            artifact_id: " <unknown> ".into(),
            artifact_type: "invoke".into(),
            trace_context: Some(ctx(None)),
        }];

        let report = TraceStore::check_conformance(&arts);

        assert_eq!(report.verdict, "FAIL");
        assert_eq!(report.trace_id, "");
        assert_eq!(report.violations.len(), 1);
        assert!(report.violations[0].reason.contains("reserved"));
    }

    #[test]
    fn all_error_codes_present() {
        let errors = [
            TraceError::MissingTraceId,
            TraceError::MissingSpanId,
            TraceError::InvalidFormat("x".into()),
            TraceError::ParentNotFound("x".into()),
            TraceError::DuplicateSpanId("x".into()),
            TraceError::ConformanceFailed("x".into()),
        ];
        let codes: Vec<_> = errors.iter().map(|e| e.code()).collect();
        assert!(codes.contains(&"TRC_MISSING_TRACE_ID"));
        assert!(codes.contains(&"TRC_MISSING_SPAN_ID"));
        assert!(codes.contains(&"TRC_INVALID_FORMAT"));
        assert!(codes.contains(&"TRC_PARENT_NOT_FOUND"));
        assert!(codes.contains(&"TRC_DUPLICATE_SPAN_ID"));
        assert!(codes.contains(&"TRC_CONFORMANCE_FAILED"));
    }

    #[test]
    fn error_display() {
        let e = TraceError::MissingTraceId;
        assert!(e.to_string().contains("TRC_MISSING_TRACE_ID"));
    }
}
