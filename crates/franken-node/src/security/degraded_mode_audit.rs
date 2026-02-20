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
    if event.event_type.is_empty() {
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
    if event.action_id.is_empty() {
        return Err(AuditError::MissingField {
            field: "action_id".into(),
        });
    }
    if event.actor.is_empty() {
        return Err(AuditError::MissingField {
            field: "actor".into(),
        });
    }
    if event.tier.is_empty() {
        return Err(AuditError::MissingField {
            field: "tier".into(),
        });
    }
    if event.override_reason.is_empty() {
        return Err(AuditError::MissingField {
            field: "override_reason".into(),
        });
    }
    if event.trace_id.is_empty() {
        return Err(AuditError::MissingField {
            field: "trace_id".into(),
        });
    }
    if event.timestamp.is_empty() {
        return Err(AuditError::MissingField {
            field: "timestamp".into(),
        });
    }
    Ok(())
}

/// Append-only audit log for degraded-mode events.
///
/// INV-DM-IMMUTABLE: events cannot be modified or deleted.
pub struct DegradedModeAuditLog {
    events: Vec<DegradedModeEvent>,
}

impl DegradedModeAuditLog {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Emit a degraded-mode event. Validates schema before appending.
    ///
    /// INV-DM-EVENT-REQUIRED: every override must call this.
    /// INV-DM-SCHEMA-COMPLETE: validated before append.
    pub fn emit(&mut self, event: DegradedModeEvent) -> Result<(), AuditError> {
        validate_schema(&event)?;
        self.events.push(event);
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
}
