//! bd-lus: Product-layer global bulkhead for lane-aware runtime scheduling.
//!
//! Provides deterministic overload behavior with stable structured events and
//! retry hints so callers can fail fast instead of hanging under saturation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use crate::capacity_defaults::aliases::MAX_EVENTS;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
    }
    items.push(item);
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
        self.next_permit_seq = self.next_permit_seq.saturating_add(1);
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
        let _ = b.try_acquire("op-1", 10).expect("acquire first");
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
        let _ = b.try_acquire("op-1", 1).expect("acquire");
        b.reload_limits(2, 50, 2).expect("reload");
        let p2 = b.try_acquire("op-2", 3).expect("acquire second");
        assert_eq!(b.in_flight(), 2);
        b.release(&p2.permit_id, "op-2", 4).expect("release second");
    }

    #[test]
    fn reject_invalid_constructor_values() {
        assert!(GlobalBulkhead::new(0, 10).is_err());
        assert!(GlobalBulkhead::new(1, 0).is_err());
    }

    #[test]
    fn reject_invalid_reload_values() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        assert!(b.reload_limits(0, 10, 1).is_err());
        assert!(b.reload_limits(1, 0, 1).is_err());
    }

    #[test]
    fn events_include_stable_codes() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        let p = b.try_acquire("op-1", 1).expect("acquire");
        let _ = b.try_acquire("op-2", 2).expect_err("overload");
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
    fn reload_event_is_recorded() {
        let mut b = GlobalBulkhead::new(1, 10).expect("bulkhead");
        b.reload_limits(3, 45, 9).expect("reload");
        let last = b.events().last().expect("event");
        assert_eq!(last.event_code, event_codes::BULKHEAD_CONFIG_RELOAD);
        assert!(last.detail.contains("new_max_in_flight=3"));
    }
}
