//! bd-w0jq: Degraded-mode audit events for stale revocation overrides.
//!
//! Every stale-frontier override emits a structured audit event with
//! required schema fields. The log is append-only and immutable.

/// A degraded-mode audit event emitted on stale revocation override.
#[derive(Debug, Clone)]
pub struct DegradedModeEvent {
    pub event_type: String,
    pub action_id: String,
    pub actor: String,
    pub tier: String,
    pub revocation_age_secs: u64,
    pub max_age_secs: u64,
    pub override_reason: String,
    pub trace_id: String,
    pub timestamp: String,
}

/// Error codes for degraded-mode audit.
///
/// - `DM_MISSING_FIELD`
/// - `DM_EVENT_NOT_FOUND`
/// - `DM_SCHEMA_VIOLATION`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    MissingField { field: String },
    EventNotFound { action_id: String },
    SchemaViolation { reason: String },
}

impl AuditError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingField { .. } => "DM_MISSING_FIELD",
            Self::EventNotFound { .. } => "DM_EVENT_NOT_FOUND",
            Self::SchemaViolation { .. } => "DM_SCHEMA_VIOLATION",
        }
    }
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField { field } => write!(f, "DM_MISSING_FIELD: {field}"),
            Self::EventNotFound { action_id } => write!(f, "DM_EVENT_NOT_FOUND: {action_id}"),
            Self::SchemaViolation { reason } => write!(f, "DM_SCHEMA_VIOLATION: {reason}"),
        }
    }
}

/// Validate that a DegradedModeEvent has all required schema fields.
///
/// INV-DM-SCHEMA-COMPLETE: all fields must be non-empty.
pub fn validate_schema(event: &DegradedModeEvent) -> Result<(), AuditError> {
    if event.event_type.trim().is_empty() {
        return Err(AuditError::MissingField {
            field: "event_type".into(),
        });
    }
    if event.event_type != "degraded_mode_override" {
        return Err(AuditError::SchemaViolation {
            reason: format!(
                "event_type must be 'degraded_mode_override', got '{}'",
                event.event_type
            ),
        });
    }
    if event.action_id.trim().is_empty() {
        return Err(AuditError::MissingField {
            field: "action_id".into(),
        });
    }
    if event.actor.trim().is_empty() {
        return Err(AuditError::MissingField {
            field: "actor".into(),
        });
    }
    if event.tier.trim().is_empty() {
        return Err(AuditError::MissingField {
            field: "tier".into(),
        });
    }
    if event.override_reason.trim().is_empty() {
        return Err(AuditError::MissingField {
            field: "override_reason".into(),
        });
    }
    if event.trace_id.trim().is_empty() {
        return Err(AuditError::MissingField {
            field: "trace_id".into(),
        });
    }
    if event.timestamp.trim().is_empty() {
        return Err(AuditError::MissingField {
            field: "timestamp".into(),
        });
    }
    Ok(())
}

use crate::capacity_defaults::aliases::MAX_EVENTS;

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

/// Append-only audit log for degraded-mode events.
///
/// INV-DM-IMMUTABLE: events cannot be modified or deleted.
#[derive(Default)]
pub struct DegradedModeAuditLog {
    events: Vec<DegradedModeEvent>,
}

impl DegradedModeAuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Emit a degraded-mode event. Validates schema before appending.
    ///
    /// INV-DM-EVENT-REQUIRED: every override must call this.
    /// INV-DM-SCHEMA-COMPLETE: validated before append.
    pub fn emit(&mut self, event: DegradedModeEvent) -> Result<(), AuditError> {
        validate_schema(&event)?;
        push_bounded(&mut self.events, event, MAX_EVENTS);
        Ok(())
    }

    /// Find events by action_id.
    ///
    /// INV-DM-CORRELATION: correlate by action_id.
    pub fn find_by_action(&self, action_id: &str) -> Vec<&DegradedModeEvent> {
        self.events
            .iter()
            .filter(|e| e.action_id == action_id)
            .collect()
    }

    /// Find events by trace_id.
    ///
    /// INV-DM-CORRELATION: correlate by trace_id.
    pub fn find_by_trace(&self, trace_id: &str) -> Vec<&DegradedModeEvent> {
        self.events
            .iter()
            .filter(|e| e.trace_id == trace_id)
            .collect()
    }

    /// Assert that an event exists for a given action_id.
    /// Returns error if not found (for conformance testing).
    pub fn assert_event_exists(&self, action_id: &str) -> Result<(), AuditError> {
        if self.find_by_action(action_id).is_empty() {
            return Err(AuditError::EventNotFound {
                action_id: action_id.into(),
            });
        }
        Ok(())
    }

    /// Total number of events.
    pub fn count(&self) -> usize {
        self.events.len()
    }

    /// Access all events (read-only).
    pub fn events(&self) -> &[DegradedModeEvent] {
        &self.events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_event() -> DegradedModeEvent {
        DegradedModeEvent {
            event_type: "degraded_mode_override".into(),
            action_id: "act-1".into(),
            actor: "admin".into(),
            tier: "Risky".into(),
            revocation_age_secs: 7200,
            max_age_secs: 3600,
            override_reason: "emergency".into(),
            trace_id: "tr-1".into(),
            timestamp: "2026-01-01T00:00:00Z".into(),
        }
    }

    #[test]
    fn emit_valid_event() {
        let mut log = DegradedModeAuditLog::new();
        assert!(log.emit(valid_event()).is_ok());
        assert_eq!(log.count(), 1);
    }

    #[test]
    fn schema_rejects_empty_event_type() {
        let mut e = valid_event();
        e.event_type = String::new();
        assert_eq!(validate_schema(&e).unwrap_err().code(), "DM_MISSING_FIELD");
    }

    #[test]
    fn schema_rejects_wrong_event_type() {
        let mut e = valid_event();
        e.event_type = "wrong".into();
        assert_eq!(
            validate_schema(&e).unwrap_err().code(),
            "DM_SCHEMA_VIOLATION"
        );
    }

    #[test]
    fn schema_rejects_empty_action_id() {
        let mut e = valid_event();
        e.action_id = String::new();
        assert_eq!(validate_schema(&e).unwrap_err().code(), "DM_MISSING_FIELD");
    }

    #[test]
    fn schema_rejects_empty_actor() {
        let mut e = valid_event();
        e.actor = String::new();
        assert_eq!(validate_schema(&e).unwrap_err().code(), "DM_MISSING_FIELD");
    }

    #[test]
    fn schema_rejects_empty_tier() {
        let mut e = valid_event();
        e.tier = String::new();
        assert_eq!(validate_schema(&e).unwrap_err().code(), "DM_MISSING_FIELD");
    }

    #[test]
    fn schema_rejects_empty_override_reason() {
        let mut e = valid_event();
        e.override_reason = String::new();
        assert_eq!(validate_schema(&e).unwrap_err().code(), "DM_MISSING_FIELD");
    }

    #[test]
    fn schema_rejects_empty_trace_id() {
        let mut e = valid_event();
        e.trace_id = String::new();
        assert_eq!(validate_schema(&e).unwrap_err().code(), "DM_MISSING_FIELD");
    }

    #[test]
    fn schema_rejects_empty_timestamp() {
        let mut e = valid_event();
        e.timestamp = String::new();
        assert_eq!(validate_schema(&e).unwrap_err().code(), "DM_MISSING_FIELD");
    }

    #[test]
    fn schema_rejects_whitespace_event_type() {
        let mut event = valid_event();
        event.event_type = " \t\n ".into();

        let err = validate_schema(&event).unwrap_err();

        assert_eq!(err.code(), "DM_MISSING_FIELD");
        assert_eq!(
            err,
            AuditError::MissingField {
                field: "event_type".into()
            }
        );
    }

    #[test]
    fn schema_rejects_whitespace_action_id() {
        let mut event = valid_event();
        event.action_id = "\n\t ".into();

        let err = validate_schema(&event).unwrap_err();

        assert_eq!(err.code(), "DM_MISSING_FIELD");
        assert_eq!(
            err,
            AuditError::MissingField {
                field: "action_id".into()
            }
        );
    }

    #[test]
    fn schema_rejects_whitespace_actor() {
        let mut event = valid_event();
        event.actor = "\r\n ".into();

        let err = validate_schema(&event).unwrap_err();

        assert_eq!(err.code(), "DM_MISSING_FIELD");
        assert_eq!(
            err,
            AuditError::MissingField {
                field: "actor".into()
            }
        );
    }

    #[test]
    fn schema_rejects_whitespace_tier() {
        let mut event = valid_event();
        event.tier = "   ".into();

        let err = validate_schema(&event).unwrap_err();

        assert_eq!(err.code(), "DM_MISSING_FIELD");
        assert_eq!(
            err,
            AuditError::MissingField {
                field: "tier".into()
            }
        );
    }

    #[test]
    fn schema_rejects_whitespace_override_reason() {
        let mut event = valid_event();
        event.override_reason = "\t ".into();

        let err = validate_schema(&event).unwrap_err();

        assert_eq!(err.code(), "DM_MISSING_FIELD");
        assert_eq!(
            err,
            AuditError::MissingField {
                field: "override_reason".into()
            }
        );
    }

    #[test]
    fn schema_rejects_whitespace_trace_id() {
        let mut event = valid_event();
        event.trace_id = " \n".into();

        let err = validate_schema(&event).unwrap_err();

        assert_eq!(err.code(), "DM_MISSING_FIELD");
        assert_eq!(
            err,
            AuditError::MissingField {
                field: "trace_id".into()
            }
        );
    }

    #[test]
    fn schema_rejects_whitespace_timestamp() {
        let mut event = valid_event();
        event.timestamp = "\t\r\n".into();

        let err = validate_schema(&event).unwrap_err();

        assert_eq!(err.code(), "DM_MISSING_FIELD");
        assert_eq!(
            err,
            AuditError::MissingField {
                field: "timestamp".into()
            }
        );
    }

    #[test]
    fn emit_rejects_whitespace_field_without_appending() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();
        let mut invalid = valid_event();
        invalid.action_id = "act-2".into();
        invalid.actor = " \n\t ".into();

        let err = log.emit(invalid).unwrap_err();

        assert_eq!(err.code(), "DM_MISSING_FIELD");
        assert_eq!(log.count(), 1);
        assert!(log.find_by_action("act-2").is_empty());
    }

    #[test]
    fn find_by_action() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();
        let mut e2 = valid_event();
        e2.action_id = "act-2".into();
        log.emit(e2).unwrap();
        assert_eq!(log.find_by_action("act-1").len(), 1);
        assert_eq!(log.find_by_action("act-2").len(), 1);
        assert_eq!(log.find_by_action("act-3").len(), 0);
    }

    #[test]
    fn find_by_trace() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();
        assert_eq!(log.find_by_trace("tr-1").len(), 1);
        assert_eq!(log.find_by_trace("tr-other").len(), 0);
    }

    #[test]
    fn assert_event_exists_ok() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();
        assert!(log.assert_event_exists("act-1").is_ok());
    }

    #[test]
    fn assert_event_missing_errors() {
        let log = DegradedModeAuditLog::new();
        assert_eq!(
            log.assert_event_exists("act-1").unwrap_err().code(),
            "DM_EVENT_NOT_FOUND"
        );
    }

    #[test]
    fn emit_rejects_invalid_schema() {
        let mut log = DegradedModeAuditLog::new();
        let mut e = valid_event();
        e.actor = String::new();
        assert!(log.emit(e).is_err());
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn multiple_events_same_action() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();
        let mut e2 = valid_event();
        e2.trace_id = "tr-2".into();
        log.emit(e2).unwrap();
        assert_eq!(log.find_by_action("act-1").len(), 2);
    }

    #[test]
    fn events_read_only() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();
        let events = log.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action_id, "act-1");
    }

    #[test]
    fn error_display() {
        let e = AuditError::MissingField {
            field: "actor".into(),
        };
        assert!(e.to_string().contains("DM_MISSING_FIELD"));
    }

    #[test]
    fn error_codes_all_present() {
        assert_eq!(
            AuditError::MissingField { field: "x".into() }.code(),
            "DM_MISSING_FIELD"
        );
        assert_eq!(
            AuditError::EventNotFound {
                action_id: "x".into()
            }
            .code(),
            "DM_EVENT_NOT_FOUND"
        );
        assert_eq!(
            AuditError::SchemaViolation { reason: "x".into() }.code(),
            "DM_SCHEMA_VIOLATION"
        );
    }

    #[test]
    fn valid_event_passes_schema() {
        assert!(validate_schema(&valid_event()).is_ok());
    }

    #[test]
    fn invalid_emit_after_existing_event_preserves_existing_log() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();
        let mut invalid = valid_event();
        invalid.trace_id = String::new();

        let err = log.emit(invalid).unwrap_err();

        assert_eq!(err.code(), "DM_MISSING_FIELD");
        assert_eq!(log.count(), 1);
        assert_eq!(log.events()[0].trace_id, "tr-1");
    }

    #[test]
    fn wrong_event_type_emit_does_not_append_event() {
        let mut log = DegradedModeAuditLog::new();
        let mut invalid = valid_event();
        invalid.event_type = "degraded_mode_override_v2".into();

        let err = log.emit(invalid).unwrap_err();

        assert_eq!(err.code(), "DM_SCHEMA_VIOLATION");
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn validation_reports_event_type_before_later_missing_fields() {
        let mut event = valid_event();
        event.event_type = "wrong".into();
        event.action_id = String::new();
        event.actor = String::new();

        let err = validate_schema(&event).unwrap_err();

        assert!(matches!(err, AuditError::SchemaViolation { .. }));
        assert_eq!(err.code(), "DM_SCHEMA_VIOLATION");
    }

    #[test]
    fn action_lookup_is_exact_and_case_sensitive() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();

        assert!(log.find_by_action("ACT-1").is_empty());
        assert!(log.find_by_action("act").is_empty());
        assert!(log.assert_event_exists("ACT-1").is_err());
    }

    #[test]
    fn trace_lookup_does_not_match_action_id_or_actor_fields() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();

        assert!(log.find_by_trace("act-1").is_empty());
        assert!(log.find_by_trace("admin").is_empty());
    }

    #[test]
    fn assert_event_exists_rejects_empty_action_id() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();

        let err = log.assert_event_exists("").unwrap_err();

        assert_eq!(
            err,
            AuditError::EventNotFound {
                action_id: String::new()
            }
        );
    }

    #[test]
    fn missing_timestamp_emit_does_not_hide_existing_action_lookup() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();
        let mut invalid = valid_event();
        invalid.action_id = "act-2".into();
        invalid.timestamp = String::new();

        let err = log.emit(invalid).unwrap_err();

        assert_eq!(err.code(), "DM_MISSING_FIELD");
        assert_eq!(log.find_by_action("act-1").len(), 1);
        assert!(log.find_by_action("act-2").is_empty());
    }

    #[test]
    fn schema_violation_display_includes_rejected_event_type() {
        let mut event = valid_event();
        event.event_type = "unexpected_override".into();

        let rendered = validate_schema(&event).unwrap_err().to_string();

        assert!(rendered.contains("DM_SCHEMA_VIOLATION"));
        assert!(rendered.contains("unexpected_override"));
    }

    #[test]
    fn event_type_with_surrounding_whitespace_is_schema_violation() {
        let mut event = valid_event();
        event.event_type = " degraded_mode_override ".into();

        let err = validate_schema(&event).unwrap_err();

        assert!(matches!(err, AuditError::SchemaViolation { .. }));
        assert_eq!(err.code(), "DM_SCHEMA_VIOLATION");
    }

    #[test]
    fn event_type_with_trailing_newline_does_not_append() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();
        let mut invalid = valid_event();
        invalid.action_id = "act-2".into();
        invalid.event_type = "degraded_mode_override\n".into();

        let err = log.emit(invalid).unwrap_err();

        assert_eq!(err.code(), "DM_SCHEMA_VIOLATION");
        assert_eq!(log.count(), 1);
        assert!(log.find_by_action("act-2").is_empty());
    }

    #[test]
    fn repeated_invalid_emits_preserve_existing_log_order() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();
        let mut missing_actor = valid_event();
        missing_actor.actor.clear();
        let mut missing_trace = valid_event();
        missing_trace.trace_id.clear();

        assert!(log.emit(missing_actor).is_err());
        assert!(log.emit(missing_trace).is_err());

        assert_eq!(log.count(), 1);
        assert_eq!(log.events()[0].action_id, "act-1");
        assert_eq!(log.events()[0].trace_id, "tr-1");
    }

    #[test]
    fn assert_event_exists_does_not_trim_lookup_key() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();

        let err = log.assert_event_exists(" act-1 ").unwrap_err();

        assert_eq!(
            err,
            AuditError::EventNotFound {
                action_id: " act-1 ".into()
            }
        );
    }

    #[test]
    fn trace_lookup_is_exact_for_case_and_whitespace() {
        let mut log = DegradedModeAuditLog::new();
        log.emit(valid_event()).unwrap();

        assert!(log.find_by_trace("TR-1").is_empty());
        assert!(log.find_by_trace(" tr-1 ").is_empty());
        assert!(log.find_by_trace("tr-1\n").is_empty());
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_items_without_panic() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_over_capacity_drops_oldest_batch() {
        let mut items = vec![1, 2, 3, 4];

        push_bounded(&mut items, 5, 3);

        assert_eq!(items, vec![3, 4, 5]);
    }
}
