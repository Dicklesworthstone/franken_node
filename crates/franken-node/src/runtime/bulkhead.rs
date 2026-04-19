//! bd-lus: Product-layer global bulkhead for lane-aware runtime scheduling.
//!
//! Provides deterministic overload behavior with stable structured events and
//! retry hints so callers can fail fast instead of hanging under saturation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use crate::capacity_defaults::aliases::MAX_EVENTS;

const MAX_OPERATION_ID_LEN: usize = 256;
const MAX_PERMIT_ID_LEN: usize = 64;

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

fn validate_identifier(field: &str, value: &str, max_len: usize) -> Result<(), BulkheadError> {
    if value.trim().is_empty() {
        return Err(BulkheadError::InvalidConfig {
            detail: format!("{field} must not be empty"),
        });
    }
    if value.len() > max_len {
        return Err(BulkheadError::InvalidConfig {
            detail: format!("{field} length {} exceeds max {max_len}", value.len()),
        });
    }
    if value != value.trim() || value.chars().any(|ch| ch.is_control()) {
        return Err(BulkheadError::InvalidConfig {
            detail: format!(
                "{field} must not contain control characters or surrounding whitespace"
            ),
        });
    }
    Ok(())
}

pub mod event_codes {
    pub const BULKHEAD_PERMIT_ACQUIRED: &str = "BULKHEAD_PERMIT_ACQUIRED";
    pub const BULKHEAD_PERMIT_RELEASED: &str = "BULKHEAD_PERMIT_RELEASED";
    pub const BULKHEAD_OVERLOAD: &str = "BULKHEAD_OVERLOAD";
    pub const BULKHEAD_CONFIG_RELOAD: &str = "BULKHEAD_CONFIG_RELOAD";
}

pub mod error_codes {
    pub const BULKHEAD_OVERLOAD: &str = "BULKHEAD_OVERLOAD";
    pub const BULKHEAD_UNKNOWN_PERMIT: &str = "BULKHEAD_UNKNOWN_PERMIT";
    pub const BULKHEAD_PERMIT_ID_REUSED: &str = "BULKHEAD_PERMIT_ID_REUSED";
    pub const BULKHEAD_PERMIT_ID_EXHAUSTED: &str = "BULKHEAD_PERMIT_ID_EXHAUSTED";
    pub const BULKHEAD_PERMIT_OPERATION_MISMATCH: &str = "BULKHEAD_PERMIT_OPERATION_MISMATCH";
    pub const BULKHEAD_INVALID_CONFIG: &str = "BULKHEAD_INVALID_CONFIG";
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkheadEvent {
    pub event_code: String,
    pub operation_id: String,
    pub now_ms: u64,
    pub in_flight: usize,
    pub max_in_flight: usize,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkheadPermit {
    pub permit_id: String,
    pub issued_at_ms: u64,
    pub max_in_flight_snapshot: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BulkheadError {
    BulkheadOverload {
        max_in_flight: usize,
        current_in_flight: usize,
        retry_after_ms: u64,
    },
    UnknownPermit {
        permit_id: String,
    },
    PermitIdReused {
        permit_id: String,
        existing_operation_id: String,
        requested_operation_id: String,
    },
    PermitIdExhausted {
        requested_operation_id: String,
    },
    PermitOperationMismatch {
        permit_id: String,
        expected_operation_id: String,
        provided_operation_id: String,
    },
    InvalidConfig {
        detail: String,
    },
}

impl BulkheadError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BulkheadOverload { .. } => error_codes::BULKHEAD_OVERLOAD,
            Self::UnknownPermit { .. } => error_codes::BULKHEAD_UNKNOWN_PERMIT,
            Self::PermitIdReused { .. } => error_codes::BULKHEAD_PERMIT_ID_REUSED,
            Self::PermitIdExhausted { .. } => error_codes::BULKHEAD_PERMIT_ID_EXHAUSTED,
            Self::PermitOperationMismatch { .. } => error_codes::BULKHEAD_PERMIT_OPERATION_MISMATCH,
            Self::InvalidConfig { .. } => error_codes::BULKHEAD_INVALID_CONFIG,
        }
    }
}

impl fmt::Display for BulkheadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BulkheadOverload {
                max_in_flight,
                current_in_flight,
                retry_after_ms,
            } => write!(
                f,
                "{}: in_flight={}/{} retry_after_ms={}",
                self.code(),
                current_in_flight,
                max_in_flight,
                retry_after_ms
            ),
            Self::UnknownPermit { permit_id } => {
                write!(f, "{}: permit_id={permit_id}", self.code())
            }
            Self::PermitIdReused {
                permit_id,
                existing_operation_id,
                requested_operation_id,
            } => write!(
                f,
                "{}: permit_id={} existing_operation_id={} requested_operation_id={}",
                self.code(),
                permit_id,
                existing_operation_id,
                requested_operation_id
            ),
            Self::PermitIdExhausted {
                requested_operation_id,
            } => write!(
                f,
                "{}: requested_operation_id={}",
                self.code(),
                requested_operation_id
            ),
            Self::PermitOperationMismatch {
                permit_id,
                expected_operation_id,
                provided_operation_id,
            } => write!(
                f,
                "{}: permit_id={} expected_operation_id={} provided_operation_id={}",
                self.code(),
                permit_id,
                expected_operation_id,
                provided_operation_id
            ),
            Self::InvalidConfig { detail } => write!(f, "{}: {detail}", self.code()),
        }
    }
}

impl std::error::Error for BulkheadError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalBulkhead {
    max_in_flight: usize,
    retry_after_ms: u64,
    in_flight: usize,
    next_permit_seq: u64,
    permit_ids_exhausted: bool,
    active_permits: BTreeMap<String, String>,
    rejection_count: u64,
    events: Vec<BulkheadEvent>,
}

impl GlobalBulkhead {
    pub fn new(max_in_flight: usize, retry_after_ms: u64) -> Result<Self, BulkheadError> {
        if max_in_flight == 0 {
            return Err(BulkheadError::InvalidConfig {
                detail: "max_in_flight must be > 0".to_string(),
            });
        }
        if retry_after_ms == 0 {
            return Err(BulkheadError::InvalidConfig {
                detail: "retry_after_ms must be > 0".to_string(),
            });
        }

        Ok(Self {
            max_in_flight,
            retry_after_ms,
            in_flight: 0,
            next_permit_seq: 1,
            permit_ids_exhausted: false,
            active_permits: BTreeMap::new(),
            rejection_count: 0,
            events: Vec::new(),
        })
    }

    #[must_use]
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.in_flight
    }

    #[must_use]
    pub fn retry_after_ms(&self) -> u64 {
        self.retry_after_ms
    }

    #[must_use]
    pub fn rejection_count(&self) -> u64 {
        self.rejection_count
    }

    #[must_use]
    pub fn events(&self) -> &[BulkheadEvent] {
        &self.events
    }

    fn emit_event(&mut self, event: BulkheadEvent) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }

    pub fn try_acquire(
        &mut self,
        operation_id: &str,
        now_ms: u64,
    ) -> Result<BulkheadPermit, BulkheadError> {
        validate_identifier("operation_id", operation_id, MAX_OPERATION_ID_LEN)?;

        if self.in_flight >= self.max_in_flight {
            self.rejection_count = self.rejection_count.saturating_add(1);
            self.emit_event(BulkheadEvent {
                event_code: event_codes::BULKHEAD_OVERLOAD.to_string(),
                operation_id: operation_id.to_string(),
                now_ms,
                in_flight: self.in_flight,
                max_in_flight: self.max_in_flight,
                detail: format!(
                    "retry_after_ms={} reason=global-capacity",
                    self.retry_after_ms
                ),
            });
            return Err(BulkheadError::BulkheadOverload {
                max_in_flight: self.max_in_flight,
                current_in_flight: self.in_flight,
                retry_after_ms: self.retry_after_ms,
            });
        }

        if self.permit_ids_exhausted {
            return Err(BulkheadError::PermitIdExhausted {
                requested_operation_id: operation_id.to_string(),
            });
        }

        let permit_id = format!("permit-{:08}", self.next_permit_seq);
        if let Some(existing_operation_id) = self.active_permits.get(&permit_id) {
            return Err(BulkheadError::PermitIdReused {
                permit_id,
                existing_operation_id: existing_operation_id.clone(),
                requested_operation_id: operation_id.to_string(),
            });
        }

        self.active_permits
            .insert(permit_id.clone(), operation_id.to_string());
        if self.next_permit_seq == u64::MAX {
            self.permit_ids_exhausted = true;
        } else {
            self.next_permit_seq = self.next_permit_seq.saturating_add(1);
        }
        self.in_flight = self.in_flight.saturating_add(1);

        self.emit_event(BulkheadEvent {
            event_code: event_codes::BULKHEAD_PERMIT_ACQUIRED.to_string(),
            operation_id: operation_id.to_string(),
            now_ms,
            in_flight: self.in_flight,
            max_in_flight: self.max_in_flight,
            detail: format!("permit_id={permit_id}"),
        });

        Ok(BulkheadPermit {
            permit_id,
            issued_at_ms: now_ms,
            max_in_flight_snapshot: self.max_in_flight,
        })
    }

    pub fn release(
        &mut self,
        permit_id: &str,
        operation_id: &str,
        now_ms: u64,
    ) -> Result<(), BulkheadError> {
        validate_identifier("permit_id", permit_id, MAX_PERMIT_ID_LEN)?;
        validate_identifier("operation_id", operation_id, MAX_OPERATION_ID_LEN)?;

        let Some(expected_operation_id) = self.active_permits.get(permit_id).cloned() else {
            return Err(BulkheadError::UnknownPermit {
                permit_id: permit_id.to_string(),
            });
        };
        if expected_operation_id != operation_id {
            return Err(BulkheadError::PermitOperationMismatch {
                permit_id: permit_id.to_string(),
                expected_operation_id,
                provided_operation_id: operation_id.to_string(),
            });
        }
        self.active_permits.remove(permit_id);

        self.in_flight = self.in_flight.saturating_sub(1);
        self.emit_event(BulkheadEvent {
            event_code: event_codes::BULKHEAD_PERMIT_RELEASED.to_string(),
            operation_id: operation_id.to_string(),
            now_ms,
            in_flight: self.in_flight,
            max_in_flight: self.max_in_flight,
            detail: format!("permit_id={permit_id}"),
        });
        Ok(())
    }

    pub fn reload_limits(
        &mut self,
        new_max_in_flight: usize,
        new_retry_after_ms: u64,
        now_ms: u64,
    ) -> Result<(), BulkheadError> {
        if new_max_in_flight == 0 {
            return Err(BulkheadError::InvalidConfig {
                detail: "new_max_in_flight must be > 0".to_string(),
            });
        }
        if new_retry_after_ms == 0 {
            return Err(BulkheadError::InvalidConfig {
                detail: "new_retry_after_ms must be > 0".to_string(),
            });
        }

        self.max_in_flight = new_max_in_flight;
        self.retry_after_ms = new_retry_after_ms;

        self.emit_event(BulkheadEvent {
            event_code: event_codes::BULKHEAD_CONFIG_RELOAD.to_string(),
            operation_id: "config-reload".to_string(),
            now_ms,
            in_flight: self.in_flight,
            max_in_flight: self.max_in_flight,
            detail: format!(
                "new_max_in_flight={} new_retry_after_ms={}",
                new_max_in_flight, new_retry_after_ms
            ),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn acquire_release_happy_path() {
        let mut b = GlobalBulkhead::new(2, 25).expect("bulkhead");
        let p = b.try_acquire("op-1", 10).expect("acquire");
        assert_eq!(b.in_flight(), 1);
        b.release(&p.permit_id, "op-1", 20).expect("release");
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn overload_returns_stable_error_and_retry_hint() {
        let mut b = GlobalBulkhead::new(1, 40).expect("bulkhead");
        let _held = b.try_acquire("op-1", 10).expect("acquire first");
        let err = b.try_acquire("op-2", 11).expect_err("expected overload");
        assert_eq!(err.code(), error_codes::BULKHEAD_OVERLOAD);
        assert!(matches!(
            err,
            BulkheadError::BulkheadOverload {
                max_in_flight: 1,
                current_in_flight: 1,
                retry_after_ms: 40
            }
        ));
        assert_eq!(b.rejection_count(), 1);
    }

    #[test]
    fn release_unknown_permit_fails_closed() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        let err = b
            .release("permit-00000099", "op-x", 22)
            .expect_err("unknown permit");
        assert_eq!(err.code(), error_codes::BULKHEAD_UNKNOWN_PERMIT);
    }

    #[test]
    fn unknown_permit_release_does_not_emit_event_or_change_in_flight() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        let event_count = b.events().len();

        let err = b
            .release("permit-404", "op-missing", 22)
            .expect_err("unknown permit");

        assert_eq!(err.code(), error_codes::BULKHEAD_UNKNOWN_PERMIT);
        assert_eq!(b.in_flight(), 0);
        assert_eq!(b.events().len(), event_count);
    }

    #[test]
    fn release_with_mismatched_operation_is_rejected_without_releasing_permit() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        let permit = b.try_acquire("op-expected", 10).expect("acquire");

        let err = b
            .release(&permit.permit_id, "op-wrong", 11)
            .expect_err("mismatch should fail closed");
        assert_eq!(err.code(), error_codes::BULKHEAD_PERMIT_OPERATION_MISMATCH);
        assert_eq!(b.in_flight(), 1, "permit must remain active after mismatch");

        b.release(&permit.permit_id, "op-expected", 12)
            .expect("release with expected operation");
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn reused_generated_permit_id_is_rejected_without_overwriting_original_permit() {
        let mut b = GlobalBulkhead::new(2, 10).expect("bulkhead");
        let original = b.try_acquire("op-original", 10).expect("original permit");
        b.next_permit_seq = 1;

        let err = b
            .try_acquire("op-reused", 11)
            .expect_err("reused generated permit id must fail closed");
        assert_eq!(err.code(), error_codes::BULKHEAD_PERMIT_ID_REUSED);
        assert!(matches!(
            err,
            BulkheadError::PermitIdReused {
                ref permit_id,
                ref existing_operation_id,
                ref requested_operation_id,
            } if permit_id == "permit-00000001"
                && existing_operation_id == "op-original"
                && requested_operation_id == "op-reused"
        ));
        assert_eq!(b.next_permit_seq, 1);
        assert_eq!(b.in_flight(), 1);
        assert_eq!(b.events().len(), 1);

        b.release(&original.permit_id, "op-original", 12)
            .expect("original permit must remain releasable");
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn reload_limits_changes_capacity_for_new_acquires() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        let _held = b.try_acquire("op-1", 1).expect("acquire");
        b.reload_limits(2, 50, 2).expect("reload");
        let p2 = b.try_acquire("op-2", 3).expect("acquire second");
        assert_eq!(b.in_flight(), 2);
        b.release(&p2.permit_id, "op-2", 4).expect("release second");
    }

    #[test]
    fn invalid_reload_preserves_existing_limits_and_emits_no_event() {
        let mut b = GlobalBulkhead::new(2, 25).expect("bulkhead");
        let event_count = b.events().len();

        let max_err = b
            .reload_limits(0, 30, 10)
            .expect_err("zero max should be rejected");
        let retry_err = b
            .reload_limits(3, 0, 11)
            .expect_err("zero retry should be rejected");

        assert_eq!(max_err.code(), error_codes::BULKHEAD_INVALID_CONFIG);
        assert_eq!(retry_err.code(), error_codes::BULKHEAD_INVALID_CONFIG);
        assert_eq!(b.max_in_flight(), 2);
        assert_eq!(b.retry_after_ms(), 25);
        assert_eq!(b.events().len(), event_count);
    }

    #[test]
    fn reject_invalid_constructor_values() {
        assert!(GlobalBulkhead::new(0, 10).is_err());
        assert!(GlobalBulkhead::new(1, 0).is_err());
    }

    #[test]
    fn invalid_constructor_errors_have_stable_codes_and_details() {
        let max_err = GlobalBulkhead::new(0, 10).expect_err("zero max");
        let retry_err = GlobalBulkhead::new(1, 0).expect_err("zero retry");

        assert_eq!(max_err.code(), error_codes::BULKHEAD_INVALID_CONFIG);
        assert_eq!(retry_err.code(), error_codes::BULKHEAD_INVALID_CONFIG);
        assert!(max_err.to_string().contains("max_in_flight must be > 0"));
        assert!(retry_err.to_string().contains("retry_after_ms must be > 0"));
    }

    #[test]
    fn reject_invalid_reload_values() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        assert!(b.reload_limits(0, 10, 1).is_err());
        assert!(b.reload_limits(1, 0, 1).is_err());
    }

    #[test]
    fn overload_does_not_change_in_flight_or_replace_active_permit() {
        let mut b = GlobalBulkhead::new(1, 40).expect("bulkhead");
        let permit = b.try_acquire("op-held", 10).expect("acquire first");

        let err = b
            .try_acquire("op-overloaded", 11)
            .expect_err("capacity exceeded");

        assert_eq!(err.code(), error_codes::BULKHEAD_OVERLOAD);
        assert_eq!(b.in_flight(), 1);
        b.release(&permit.permit_id, "op-held", 12)
            .expect("original permit remains releasable");
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn overload_event_records_rejected_operation_and_retry_hint() {
        let mut b = GlobalBulkhead::new(1, 75).expect("bulkhead");
        let _permit = b.try_acquire("op-held", 10).expect("acquire first");

        let _err = b
            .try_acquire("op-rejected", 11)
            .expect_err("capacity exceeded");

        let event = b.events().last().expect("overload event");
        assert_eq!(event.event_code, event_codes::BULKHEAD_OVERLOAD);
        assert_eq!(event.operation_id, "op-rejected");
        assert_eq!(event.in_flight, 1);
        assert!(event.detail.contains("retry_after_ms=75"));
    }

    #[test]
    fn duplicate_release_after_success_is_unknown_permit() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        let permit = b.try_acquire("op-once", 10).expect("acquire");
        b.release(&permit.permit_id, "op-once", 11)
            .expect("first release");

        let err = b
            .release(&permit.permit_id, "op-once", 12)
            .expect_err("second release must fail closed");

        assert_eq!(err.code(), error_codes::BULKHEAD_UNKNOWN_PERMIT);
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn lowering_capacity_below_current_in_flight_blocks_next_acquire() {
        let mut b = GlobalBulkhead::new(2, 10).expect("bulkhead");
        let _p1 = b.try_acquire("op-1", 1).expect("p1");
        let _p2 = b.try_acquire("op-2", 2).expect("p2");
        b.reload_limits(1, 30, 3).expect("lower capacity");

        let err = b
            .try_acquire("op-3", 4)
            .expect_err("current in-flight exceeds lowered capacity");

        assert!(matches!(
            err,
            BulkheadError::BulkheadOverload {
                max_in_flight: 1,
                current_in_flight: 2,
                retry_after_ms: 30
            }
        ));
        assert_eq!(b.in_flight(), 2);
    }

    #[test]
    fn error_display_preserves_mismatch_context() {
        let err = BulkheadError::PermitOperationMismatch {
            permit_id: "permit-00000007".to_string(),
            expected_operation_id: "expected-op".to_string(),
            provided_operation_id: "provided-op".to_string(),
        };
        let rendered = err.to_string();

        assert!(rendered.contains(error_codes::BULKHEAD_PERMIT_OPERATION_MISMATCH));
        assert!(rendered.contains("permit-00000007"));
        assert!(rendered.contains("expected-op"));
        assert!(rendered.contains("provided-op"));
    }

    #[test]
    fn push_bounded_zero_capacity_drops_new_item_without_panic() {
        let mut values = vec![1, 2, 3];

        push_bounded(&mut values, 4, 0);

        assert!(values.is_empty());
    }

    #[test]
    fn events_include_stable_codes() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        let p = b.try_acquire("op-1", 1).expect("acquire");
        let _overload = b.try_acquire("op-2", 2).expect_err("overload");
        b.release(&p.permit_id, "op-1", 3).expect("release");

        let codes: Vec<_> = b.events().iter().map(|e| e.event_code.as_str()).collect();
        assert!(codes.contains(&event_codes::BULKHEAD_PERMIT_ACQUIRED));
        assert!(codes.contains(&event_codes::BULKHEAD_OVERLOAD));
        assert!(codes.contains(&event_codes::BULKHEAD_PERMIT_RELEASED));
    }

    #[test]
    fn permit_ids_monotonic() {
        let mut b = GlobalBulkhead::new(2, 10).expect("bulkhead");
        let p1 = b.try_acquire("op-1", 1).expect("p1");
        let p2 = b.try_acquire("op-2", 2).expect("p2");
        assert!(p2.permit_id > p1.permit_id);
    }

    #[test]
    fn release_decrements_in_flight_safely() {
        let mut b = GlobalBulkhead::new(2, 10).expect("bulkhead");
        let p1 = b.try_acquire("op-1", 1).expect("p1");
        let p2 = b.try_acquire("op-2", 2).expect("p2");
        b.release(&p2.permit_id, "op-2", 3).expect("release p2");
        b.release(&p1.permit_id, "op-1", 4).expect("release p1");
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn invalid_operation_ids_fail_before_state_or_event_mutation() {
        let invalid_ids = vec![
            String::new(),
            "   ".to_string(),
            "\t\n".to_string(),
            " op-leading-space".to_string(),
            "op-trailing-space ".to_string(),
            "op\0null".to_string(),
            "op\r\ninjection".to_string(),
            "op\x1B[31mansi".to_string(),
            "x".repeat(MAX_OPERATION_ID_LEN + 1),
        ];

        for operation_id in invalid_ids {
            let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
            let err = b
                .try_acquire(&operation_id, 1)
                .expect_err("invalid operation_id must fail closed");

            assert_eq!(err.code(), error_codes::BULKHEAD_INVALID_CONFIG);
            assert_eq!(b.in_flight(), 0);
            assert!(b.events().is_empty());
            assert!(b.active_permits.is_empty());
        }
    }

    #[test]
    fn invalid_release_identifiers_do_not_release_or_emit_events() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        let permit = b.try_acquire("op-held", 1).expect("acquire");
        let event_count = b.events().len();
        let overlong_operation_id = "x".repeat(MAX_OPERATION_ID_LEN + 1);
        let overlong_permit_id = "p".repeat(MAX_PERMIT_ID_LEN + 1);

        let invalid_cases = vec![
            ("", "op-held"),
            ("   ", "op-held"),
            ("permit-00000001", ""),
            ("permit-00000001", "op\0held"),
            ("permit-00000001", "op-held\n"),
            ("permit-00000001", overlong_operation_id.as_str()),
            (overlong_permit_id.as_str(), "op-held"),
        ];

        for (permit_id, operation_id) in invalid_cases {
            let err = b
                .release(permit_id, operation_id, 2)
                .expect_err("invalid release identifier must fail closed");

            assert_eq!(err.code(), error_codes::BULKHEAD_INVALID_CONFIG);
            assert_eq!(b.in_flight(), 1);
            assert_eq!(b.events().len(), event_count);
        }

        b.release(&permit.permit_id, "op-held", 3)
            .expect("valid release remains possible");
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn invalid_reload_after_acquire_preserves_active_permit_and_limits() {
        let mut b = GlobalBulkhead::new(1, 25).expect("bulkhead");
        let permit = b.try_acquire("op-held", 10).expect("acquire");
        let event_count = b.events().len();

        let err = b
            .reload_limits(0, 50, 11)
            .expect_err("invalid reload must fail closed");

        assert_eq!(err.code(), error_codes::BULKHEAD_INVALID_CONFIG);
        assert_eq!(b.max_in_flight(), 1);
        assert_eq!(b.retry_after_ms(), 25);
        assert_eq!(b.in_flight(), 1);
        assert_eq!(b.events().len(), event_count);
        b.release(&permit.permit_id, "op-held", 12)
            .expect("held permit should remain releasable");
    }

    #[test]
    fn mismatched_release_emits_no_event_and_preserves_active_permit() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        let permit = b.try_acquire("op-owner", 1).expect("acquire");
        let event_count = b.events().len();

        let err = b
            .release(&permit.permit_id, "op-intruder", 2)
            .expect_err("mismatched operation must fail closed");

        assert_eq!(err.code(), error_codes::BULKHEAD_PERMIT_OPERATION_MISMATCH);
        assert_eq!(b.events().len(), event_count);
        assert_eq!(b.in_flight(), 1);
        b.release(&permit.permit_id, "op-owner", 3)
            .expect("owner can still release");
    }

    #[test]
    fn unknown_release_does_not_increment_rejection_count() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");

        let err = b
            .release("permit-missing", "op-missing", 1)
            .expect_err("unknown release should fail closed");

        assert_eq!(err.code(), error_codes::BULKHEAD_UNKNOWN_PERMIT);
        assert_eq!(b.rejection_count(), 0);
        assert_eq!(b.in_flight(), 0);
        assert!(b.events().is_empty());
    }

    #[test]
    fn overload_takes_precedence_over_reused_generated_permit_id() {
        let mut b = GlobalBulkhead::new(1, 40).expect("bulkhead");
        let permit = b.try_acquire("op-held", 1).expect("acquire");
        b.next_permit_seq = 1;

        let err = b
            .try_acquire("op-reused-and-overloaded", 2)
            .expect_err("capacity check should run before permit reuse check");

        assert_eq!(err.code(), error_codes::BULKHEAD_OVERLOAD);
        assert_eq!(b.rejection_count(), 1);
        assert_eq!(b.next_permit_seq, 1);
        assert_eq!(b.in_flight(), 1);
        b.release(&permit.permit_id, "op-held", 3)
            .expect("original permit should remain releasable");
    }

    #[test]
    fn terminal_permit_id_is_issued_once_then_acquire_fails_closed() {
        let mut b = GlobalBulkhead::new(2, 10).expect("bulkhead");
        b.next_permit_seq = u64::MAX;
        let permit = b
            .try_acquire("op-max-seq", 1)
            .expect("first max-sequence acquire");

        let err = b
            .try_acquire("op-max-seq-reuse", 2)
            .expect_err("exhausted permit sequence must fail closed");

        assert_eq!(permit.permit_id, format!("permit-{}", u64::MAX));
        assert_eq!(err.code(), error_codes::BULKHEAD_PERMIT_ID_EXHAUSTED);
        assert!(matches!(
            err,
            BulkheadError::PermitIdExhausted {
                ref requested_operation_id
            } if requested_operation_id == "op-max-seq-reuse"
        ));
        assert_eq!(b.in_flight(), 1);
        assert_eq!(b.events().len(), 1);
        b.release(&permit.permit_id, "op-max-seq", 3)
            .expect("active max permit should remain releasable");

        let err = b
            .try_acquire("op-after-terminal-release", 4)
            .expect_err("released terminal permit id must not be reissued");
        assert_eq!(err.code(), error_codes::BULKHEAD_PERMIT_ID_EXHAUSTED);
        assert_eq!(b.in_flight(), 0);
    }

    #[test]
    fn event_buffer_retains_latest_entries_when_over_capacity() {
        let mut events = Vec::new();

        for index in 0..MAX_EVENTS.saturating_add(2) {
            push_bounded(
                &mut events,
                BulkheadEvent {
                    event_code: event_codes::BULKHEAD_OVERLOAD.to_string(),
                    operation_id: format!("op-{index}"),
                    now_ms: u64::try_from(index).unwrap_or(u64::MAX),
                    in_flight: index,
                    max_in_flight: MAX_EVENTS,
                    detail: "bounded-test".to_string(),
                },
                MAX_EVENTS,
            );
        }

        assert_eq!(events.len(), MAX_EVENTS);
        assert_eq!(events.first().expect("first retained").operation_id, "op-2");
        assert_eq!(
            events.last().expect("last retained").operation_id,
            format!("op-{}", MAX_EVENTS.saturating_add(1))
        );
    }

    #[test]
    fn reload_event_is_recorded() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        b.reload_limits(3, 45, 9).expect("reload");
        let last = b.events().last().expect("event");
        assert_eq!(last.event_code, event_codes::BULKHEAD_CONFIG_RELOAD);
        assert!(last.detail.contains("new_max_in_flight=3"));
    }

    /// Comprehensive negative-path test module covering edge cases and attack vectors.
    ///
    /// These tests validate robustness against malicious inputs, resource exhaustion,
    /// timing attacks, and arithmetic edge cases in global bulkhead permit management.
    #[cfg(test)]
    mod bulkhead_comprehensive_negative_tests {
        use super::*;

        #[test]
        fn unicode_injection_in_operation_identifiers_handled_safely() {
            let mut bulkhead = GlobalBulkhead::new(10, 100).expect("bulkhead creation");

            let accepted_operation_ids = vec![
                "op\u{200B}zero_width_space",
                "op\u{FEFF}bom_attack",
                "op/../../../etc/passwd",
                "op\u{202E}rtl_override\u{202D}direction",
                "op\u{1F4A9}emoji_flood",
            ];

            for malicious_op_id in &accepted_operation_ids {
                let permit_result = bulkhead.try_acquire(malicious_op_id, 1000);
                assert!(
                    permit_result.is_ok(),
                    "should acquire printable operation id: {}",
                    malicious_op_id
                );

                let permit = permit_result.unwrap();
                assert!(permit.permit_id.starts_with("permit-"));

                // Release should work normally
                let release_result = bulkhead.release(&permit.permit_id, malicious_op_id, 1001);
                assert!(
                    release_result.is_ok(),
                    "Should release permit for: {}",
                    malicious_op_id
                );
            }

            let rejected_operation_ids = vec![
                "op\u{0000}null_injection",
                "op\x1B[H\x1B[2J",
                "op\u{0001}\u{0002}\u{0003}control_chars",
                "op\r\nheader-injection",
            ];

            for malicious_op_id in &rejected_operation_ids {
                let err = bulkhead
                    .try_acquire(malicious_op_id, 1000)
                    .expect_err("control operation id must fail closed");
                assert_eq!(err.code(), error_codes::BULKHEAD_INVALID_CONFIG);
            }

            // Verify isolation - no cross-contamination between operations
            assert_eq!(bulkhead.in_flight(), 0);
            assert_eq!(bulkhead.events().len(), accepted_operation_ids.len() * 2);
            // acquire + release each
        }

        #[test]
        fn arithmetic_overflow_protection_in_sequence_and_timing() {
            let mut bulkhead = GlobalBulkhead::new(5, 50).expect("bulkhead creation");

            // Test near u64::MAX boundaries for sequence numbers
            bulkhead.next_permit_seq = u64::MAX - 2;

            let edge_times = vec![u64::MAX - 10, u64::MAX - 1, u64::MAX];

            for &edge_time in &edge_times {
                let permit_result = bulkhead.try_acquire("overflow_test", edge_time);
                assert!(
                    permit_result.is_ok(),
                    "Should handle edge time: {}",
                    edge_time
                );

                let permit = permit_result.unwrap();
                assert_eq!(permit.issued_at_ms, edge_time);

                // Sequence should use saturating arithmetic
                assert!(bulkhead.next_permit_seq <= u64::MAX);

                // Release should work with edge times
                let release_result =
                    bulkhead.release(&permit.permit_id, "overflow_test", edge_time);
                assert!(
                    release_result.is_ok(),
                    "Should release at edge time: {}",
                    edge_time
                );
            }

            // Test rejection count overflow protection
            let mut saturated = GlobalBulkhead::new(1, 10).expect("bulkhead creation");
            let held = saturated.try_acquire("held", 1000).expect("held permit");
            for _ in 0..10 {
                saturated.rejection_count = u64::MAX - 1;
                let err = saturated
                    .try_acquire("rejection_overflow", 1000)
                    .expect_err("saturated bulkhead should reject");
                assert_eq!(err.code(), error_codes::BULKHEAD_OVERLOAD);
                // Should saturate at u64::MAX, not wrap around
                assert_eq!(saturated.rejection_count, u64::MAX);
            }
            saturated
                .release(&held.permit_id, "held", 1001)
                .expect("held permit should remain releasable");
        }

        #[test]
        fn memory_exhaustion_through_massive_permit_creation() {
            let mut bulkhead = GlobalBulkhead::new(1000, 100).expect("bulkhead creation");

            // Simulate memory pressure attack with massive permit requests
            let massive_operation_count: u64 = 5000;
            let mut active_permits = Vec::new();

            for op_idx in 0..massive_operation_count {
                let operation_id = format!("flood_op_{op_idx:05}");
                let now_ms = 1000u64.saturating_add(op_idx);

                if op_idx < 1000 {
                    // First 1000 should succeed (within capacity)
                    let permit = bulkhead.try_acquire(&operation_id, now_ms).expect("permit");
                    active_permits.push((permit, operation_id));
                } else {
                    // Rest should be rejected due to capacity
                    let result = bulkhead.try_acquire(&operation_id, now_ms);
                    assert!(
                        result.is_err(),
                        "Should reject overload at index {}",
                        op_idx
                    );

                    match result.unwrap_err() {
                        BulkheadError::BulkheadOverload { .. } => {
                            // Expected overload error
                        }
                        other => panic!("Unexpected error type: {:?}", other),
                    }
                }
            }

            // Verify bounded memory usage
            assert_eq!(bulkhead.in_flight(), 1000);
            assert!(bulkhead.rejection_count() > 0);
            assert_eq!(bulkhead.active_permits.len(), 1000);

            // Events should be bounded by MAX_EVENTS
            assert!(bulkhead.events().len() <= MAX_EVENTS);

            // Cleanup - releases should work efficiently
            for (permit, operation_id) in active_permits {
                bulkhead
                    .release(&permit.permit_id, &operation_id, 2000)
                    .expect("cleanup release");
            }
            assert_eq!(bulkhead.in_flight(), 0);
        }

        #[test]
        fn concurrent_operations_simulation_race_conditions() {
            let mut bulkhead = GlobalBulkhead::new(3, 75).expect("bulkhead creation");

            // Simulate concurrent permit acquisition and release
            // (In real concurrency this would need proper synchronization)
            let mut active_permits = Vec::new();

            // Rapid burst of acquisitions as if from concurrent threads
            for i in 0..10 {
                let operation_id = format!("race_op_{i}");
                let base_time = 1000u64.saturating_add(i);

                let acquire_result = bulkhead.try_acquire(&operation_id, base_time);

                match acquire_result {
                    Ok(permit) => {
                        active_permits.push((permit, operation_id, base_time));
                    }
                    Err(BulkheadError::BulkheadOverload { .. }) => {
                        // Expected when capacity exceeded
                    }
                    Err(other) => panic!("Unexpected error during concurrent acquire: {:?}", other),
                }

                // Interleaved releases during acquisition
                if i % 2 == 1 && !active_permits.is_empty() {
                    let idx = active_permits.len() - 1;
                    let (permit, op_id, _) = active_permits.remove(idx);
                    let release_result =
                        bulkhead.release(&permit.permit_id, &op_id, base_time.saturating_add(50));
                    assert!(release_result.is_ok(), "Concurrent release should succeed");
                }
            }

            // Verify consistent state
            assert_eq!(bulkhead.in_flight(), active_permits.len());
            assert!(bulkhead.in_flight() <= 3); // Within capacity
        }

        #[test]
        fn configuration_extreme_edge_cases() {
            // Test configurations with extreme values
            let edge_configs = vec![
                (1, 1),
                (usize::MAX, 1),
                (1, u64::MAX),
                (usize::MAX, u64::MAX),
            ];

            for (max_in_flight, retry_after_ms) in edge_configs {
                let bulkhead = GlobalBulkhead::new(max_in_flight, retry_after_ms)
                    .expect("Should handle extreme config values");

                // Basic operations should not panic
                assert_eq!(bulkhead.max_in_flight(), max_in_flight);
                assert_eq!(bulkhead.retry_after_ms(), retry_after_ms);
                assert_eq!(bulkhead.in_flight(), 0);
                assert_eq!(bulkhead.rejection_count(), 0);
                assert!(bulkhead.events().is_empty());
            }

            // Test invalid configurations
            let invalid_configs = vec![
                (0, 1), // Zero capacity
                (1, 0), // Zero retry time
                (0, 0), // Both zero
            ];

            for (max_in_flight, retry_after_ms) in invalid_configs {
                let result = GlobalBulkhead::new(max_in_flight, retry_after_ms);
                assert!(
                    result.is_err(),
                    "Should reject config: ({}, {})",
                    max_in_flight,
                    retry_after_ms
                );

                match result.unwrap_err() {
                    BulkheadError::InvalidConfig { .. } => {
                        // Expected
                    }
                    other => panic!("Unexpected error for invalid config: {:?}", other),
                }
            }
        }

        #[test]
        fn event_audit_flooding_capacity_boundaries() {
            let mut bulkhead = GlobalBulkhead::new(1, 50).expect("bulkhead creation");

            // Generate events beyond MAX_EVENTS capacity to test bounded storage
            let flood_event_count = MAX_EVENTS.saturating_mul(2);

            for event_idx in 0..flood_event_count {
                let operation_id = format!("flood_event_{event_idx}");
                let event_idx_ms = u64::try_from(event_idx).unwrap_or(u64::MAX);
                let now_ms = 1000u64.saturating_add(event_idx_ms);

                if event_idx == 0 {
                    bulkhead
                        .try_acquire(&operation_id, now_ms)
                        .expect("first acquire should emit event");
                } else {
                    let err = bulkhead
                        .try_acquire(&operation_id, now_ms)
                        .expect_err("saturated bulkhead should emit overload event");
                    assert_eq!(err.code(), error_codes::BULKHEAD_OVERLOAD);
                }
            }

            // Should respect MAX_EVENTS bounds
            assert!(bulkhead.events().len() <= MAX_EVENTS);

            // Should retain most recent events
            let recent_events: Vec<_> = bulkhead
                .events()
                .iter()
                .filter(|e| {
                    e.operation_id
                        .contains(&format!("_{}", flood_event_count - 10))
                })
                .collect();
            assert!(!recent_events.is_empty(), "Should retain recent events");
        }

        #[test]
        fn timing_attack_resistance_in_permit_lifecycle() {
            let mut bulkhead = GlobalBulkhead::new(2, 100).expect("bulkhead creation");

            // Test consistent behavior across timing boundaries
            let base_time = 1000;
            let permit1 = bulkhead
                .try_acquire("timing_op_1", base_time)
                .expect("permit 1");
            let permit2 = bulkhead
                .try_acquire("timing_op_2", base_time.saturating_add(1))
                .expect("permit 2");

            // Fill capacity
            assert_eq!(bulkhead.in_flight(), 2);

            // Test overload behavior consistency at different times
            for offset in [0u64, 1, 5, 10, 100, 1000, u64::MAX / 2] {
                let test_time = base_time.saturating_add(100).saturating_add(offset);
                let overload_result = bulkhead.try_acquire("timing_overflow", test_time);

                assert!(
                    overload_result.is_err(),
                    "Should consistently reject at time {}",
                    test_time
                );

                match overload_result.unwrap_err() {
                    BulkheadError::BulkheadOverload {
                        max_in_flight,
                        current_in_flight,
                        retry_after_ms,
                    } => {
                        assert_eq!(max_in_flight, 2);
                        assert_eq!(current_in_flight, 2);
                        assert_eq!(retry_after_ms, 100);
                    }
                    other => panic!("Unexpected error type: {:?}", other),
                }
            }

            // Releases should work consistently regardless of timing
            bulkhead
                .release(
                    &permit1.permit_id,
                    "timing_op_1",
                    base_time.saturating_add(10000),
                )
                .expect("release 1");
            bulkhead
                .release(&permit2.permit_id, "timing_op_2", u64::MAX)
                .expect("release 2");
            assert_eq!(bulkhead.in_flight(), 0);
        }

        #[test]
        fn configuration_reload_boundary_attack_scenarios() {
            let mut bulkhead = GlobalBulkhead::new(5, 100).expect("bulkhead creation");

            // Acquire permits up to capacity
            let mut permits = Vec::new();
            for i in 0..5 {
                let permit = bulkhead
                    .try_acquire(&format!("boundary_op_{i}"), 1000u64.saturating_add(i))
                    .expect("permit");
                permits.push((permit, format!("boundary_op_{i}")));
            }

            // Test boundary conditions when lowering capacity below current in-flight
            let reload_result = bulkhead.reload_limits(2, 200, 2000);
            assert!(reload_result.is_ok(), "Valid reload should succeed");

            // New acquisitions should be blocked (current > new capacity)
            let blocked_result = bulkhead.try_acquire("blocked_op", 2001);
            assert!(
                blocked_result.is_err(),
                "Should block when current > new capacity"
            );

            match blocked_result.unwrap_err() {
                BulkheadError::BulkheadOverload {
                    max_in_flight,
                    current_in_flight,
                    retry_after_ms,
                } => {
                    assert_eq!(max_in_flight, 2);
                    assert_eq!(current_in_flight, 5);
                    assert_eq!(retry_after_ms, 200);
                }
                other => panic!("Unexpected error: {:?}", other),
            }

            // Test extreme reload attempts
            let extreme_reloads = vec![
                (0, 300),        // Zero capacity
                (10, 0),         // Zero retry time
                (usize::MAX, 1), // Maximum capacity
                (1, u64::MAX),   // Maximum retry time
            ];

            for (new_capacity, new_retry) in extreme_reloads {
                let reload_result = bulkhead.reload_limits(new_capacity, new_retry, 3000);

                if new_capacity == 0 || new_retry == 0 {
                    assert!(
                        reload_result.is_err(),
                        "Should reject invalid reload: ({}, {})",
                        new_capacity,
                        new_retry
                    );
                } else {
                    assert!(
                        reload_result.is_ok(),
                        "Should accept valid reload: ({}, {})",
                        new_capacity,
                        new_retry
                    );
                }
            }

            // Cleanup
            for (permit, op_id) in permits {
                bulkhead
                    .release(&permit.permit_id, &op_id, 4000)
                    .expect("cleanup");
            }
        }
    }
}
