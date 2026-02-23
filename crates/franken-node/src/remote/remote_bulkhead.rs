//! bd-v4l0: Global remote bulkhead with deterministic backpressure.
//!
//! This module provides a capability-gated concurrency limiter for
//! network-bound operations. It supports explicit backpressure policy,
//! deterministic queue behavior, runtime cap changes with drain semantics,
//! and foreground latency tracking.
//!
//! Key event codes:
//! - `RB_PERMIT_ACQUIRED`
//! - `RB_PERMIT_RELEASED`
//! - `RB_AT_CAPACITY`
//! - `RB_REQUEST_QUEUED`
//! - `RB_REQUEST_REJECTED`
//! - `RB_CAP_CHANGED`
//! - `RB_DRAIN_ACTIVE`
//! - `RB_LATENCY_REPORT`

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, VecDeque};
use std::fmt;

/// Stable event codes for bulkhead telemetry.
pub mod event_codes {
    pub const RB_PERMIT_ACQUIRED: &str = "RB_PERMIT_ACQUIRED";
    pub const RB_PERMIT_RELEASED: &str = "RB_PERMIT_RELEASED";
    pub const RB_AT_CAPACITY: &str = "RB_AT_CAPACITY";
    pub const RB_REQUEST_QUEUED: &str = "RB_REQUEST_QUEUED";
    pub const RB_REQUEST_REJECTED: &str = "RB_REQUEST_REJECTED";
    pub const RB_CAP_CHANGED: &str = "RB_CAP_CHANGED";
    pub const RB_DRAIN_ACTIVE: &str = "RB_DRAIN_ACTIVE";
    pub const RB_LATENCY_REPORT: &str = "RB_LATENCY_REPORT";
}

/// Deterministic backpressure strategy when the bulkhead is at capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "snake_case")]
pub enum BackpressurePolicy {
    /// Reject immediately when full.
    Reject,
    /// Queue up to `max_depth` with bounded wait (`timeout_ms`).
    Queue { max_depth: usize, timeout_ms: u64 },
}

impl BackpressurePolicy {
    fn validate(self) -> Result<(), BulkheadError> {
        match self {
            Self::Reject => Ok(()),
            Self::Queue {
                max_depth,
                timeout_ms,
            } => {
                if max_depth == 0 {
                    return Err(BulkheadError::InvalidConfig {
                        reason: "queue max_depth must be > 0".to_string(),
                    });
                }
                if timeout_ms == 0 {
                    return Err(BulkheadError::InvalidConfig {
                        reason: "queue timeout_ms must be > 0".to_string(),
                    });
                }
                Ok(())
            }
        }
    }
}

/// Issued permit representing one in-flight remote operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkheadPermit {
    permit_id: u64,
    issued_at_ms: u64,
    cap_snapshot: usize,
}

impl BulkheadPermit {
    #[must_use]
    pub fn permit_id(&self) -> u64 {
        self.permit_id
    }

    #[must_use]
    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }

    #[must_use]
    pub fn cap_snapshot(&self) -> usize {
        self.cap_snapshot
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct QueuedRequest {
    request_id: String,
    enqueued_at_ms: u64,
    expires_at_ms: u64,
    timeout_ms: u64,
}

/// Structured event record emitted by the bulkhead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkheadEvent {
    pub event_code: String,
    pub now_ms: u64,
    pub in_flight: usize,
    pub max_in_flight: usize,
    pub detail: String,
}

/// Foreground latency sample captured under bulkhead load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForegroundLatencySample {
    pub in_flight: usize,
    pub latency_ms: u64,
}

/// Errors from bulkhead acquire/release/policy actions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BulkheadError {
    RemoteCapRequired,
    AtCapacity {
        cap: usize,
        in_flight: usize,
    },
    QueueSaturated {
        max_depth: usize,
    },
    Queued {
        request_id: String,
        position: usize,
        timeout_ms: u64,
    },
    QueueTimeout {
        request_id: String,
    },
    UnknownRequest {
        request_id: String,
    },
    UnknownPermit {
        permit_id: u64,
    },
    Draining {
        in_flight: usize,
        target_cap: usize,
    },
    InvalidConfig {
        reason: String,
    },
}

impl BulkheadError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::RemoteCapRequired => "RB_ERR_NO_REMOTECAP",
            Self::AtCapacity { .. } => "RB_ERR_AT_CAPACITY",
            Self::QueueSaturated { .. } => "RB_ERR_QUEUE_SATURATED",
            Self::Queued { .. } => "RB_ERR_QUEUED",
            Self::QueueTimeout { .. } => "RB_ERR_QUEUE_TIMEOUT",
            Self::UnknownRequest { .. } => "RB_ERR_UNKNOWN_REQUEST",
            Self::UnknownPermit { .. } => "RB_ERR_UNKNOWN_PERMIT",
            Self::Draining { .. } => "RB_ERR_DRAINING",
            Self::InvalidConfig { .. } => "RB_ERR_INVALID_CONFIG",
        }
    }
}

impl fmt::Display for BulkheadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RemoteCapRequired => write!(f, "{}: RemoteCap required", self.code()),
            Self::AtCapacity { cap, in_flight } => {
                write!(f, "{}: at capacity ({in_flight}/{cap})", self.code())
            }
            Self::QueueSaturated { max_depth } => {
                write!(f, "{}: queue is full (max_depth={max_depth})", self.code())
            }
            Self::Queued {
                request_id,
                position,
                timeout_ms,
            } => write!(
                f,
                "{}: queued request_id={request_id} position={position} timeout_ms={timeout_ms}",
                self.code()
            ),
            Self::QueueTimeout { request_id } => {
                write!(f, "{}: queue timeout request_id={request_id}", self.code())
            }
            Self::UnknownRequest { request_id } => {
                write!(f, "{}: unknown request_id={request_id}", self.code())
            }
            Self::UnknownPermit { permit_id } => {
                write!(f, "{}: unknown permit_id={permit_id}", self.code())
            }
            Self::Draining {
                in_flight,
                target_cap,
            } => write!(
                f,
                "{}: draining active in_flight={in_flight} target_cap={target_cap}",
                self.code()
            ),
            Self::InvalidConfig { reason } => {
                write!(f, "{}: {reason}", self.code())
            }
        }
    }
}

impl std::error::Error for BulkheadError {}

/// Global remote concurrency limiter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteBulkhead {
    max_in_flight: usize,
    in_flight: usize,
    policy: BackpressurePolicy,
    queue: VecDeque<QueuedRequest>,
    outstanding_permits: BTreeSet<u64>,
    next_permit_id: u64,
    draining_target: Option<usize>,
    p99_target_ms: u64,
    latency_samples: Vec<ForegroundLatencySample>,
    events: Vec<BulkheadEvent>,
}

impl RemoteBulkhead {
    /// Create a new bulkhead.
    pub fn new(
        max_in_flight: usize,
        policy: BackpressurePolicy,
        p99_target_ms: u64,
    ) -> Result<Self, BulkheadError> {
        if max_in_flight == 0 {
            return Err(BulkheadError::InvalidConfig {
                reason: "max_in_flight must be > 0".to_string(),
            });
        }
        if p99_target_ms == 0 {
            return Err(BulkheadError::InvalidConfig {
                reason: "p99_target_ms must be > 0".to_string(),
            });
        }
        policy.validate()?;

        Ok(Self {
            max_in_flight,
            in_flight: 0,
            policy,
            queue: VecDeque::new(),
            outstanding_permits: BTreeSet::new(),
            next_permit_id: 1,
            draining_target: None,
            p99_target_ms,
            latency_samples: Vec::new(),
            events: Vec::new(),
        })
    }

    #[must_use]
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    #[must_use]
    pub fn current_in_flight(&self) -> usize {
        self.in_flight
    }

    #[must_use]
    pub fn queue_depth(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    pub fn policy(&self) -> BackpressurePolicy {
        self.policy
    }

    #[must_use]
    pub fn draining_target(&self) -> Option<usize> {
        self.draining_target
    }

    #[must_use]
    pub fn p99_target_ms(&self) -> u64 {
        self.p99_target_ms
    }

    #[must_use]
    pub fn events(&self) -> &[BulkheadEvent] {
        &self.events
    }

    #[must_use]
    pub fn latency_samples(&self) -> &[ForegroundLatencySample] {
        &self.latency_samples
    }

    fn log_event(&mut self, event_code: &str, now_ms: u64, detail: impl Into<String>) {
        self.events.push(BulkheadEvent {
            event_code: event_code.to_string(),
            now_ms,
            in_flight: self.in_flight,
            max_in_flight: self.max_in_flight,
            detail: detail.into(),
        });
    }

    fn issue_permit(&mut self, now_ms: u64) -> BulkheadPermit {
        let permit = BulkheadPermit {
            permit_id: self.next_permit_id,
            issued_at_ms: now_ms,
            cap_snapshot: self.max_in_flight,
        };
        self.next_permit_id = self.next_permit_id.saturating_add(1);
        self.outstanding_permits.insert(permit.permit_id);
        self.in_flight = self.in_flight.saturating_add(1);
        permit
    }

    fn evict_expired_queue_entries(&mut self, now_ms: u64) {
        while let Some(front) = self.queue.front() {
            if now_ms < front.expires_at_ms {
                break;
            }
            let expired = self.queue.pop_front().expect("front existed");
            self.log_event(
                event_codes::RB_REQUEST_REJECTED,
                now_ms,
                format!("queue timeout request_id={}", expired.request_id),
            );
        }
    }

    /// Hot-reload max concurrency cap.
    ///
    /// If cap is reduced below current in-flight count, the bulkhead enters
    /// draining mode and rejects new acquires until in-flight drops below the
    /// target cap.
    pub fn set_max_in_flight(&mut self, new_cap: usize, now_ms: u64) -> Result<(), BulkheadError> {
        if new_cap == 0 {
            return Err(BulkheadError::InvalidConfig {
                reason: "new cap must be > 0".to_string(),
            });
        }
        self.max_in_flight = new_cap;
        self.log_event(
            event_codes::RB_CAP_CHANGED,
            now_ms,
            format!("new_cap={new_cap}"),
        );

        if self.in_flight > new_cap {
            self.draining_target = Some(new_cap);
            self.log_event(
                event_codes::RB_DRAIN_ACTIVE,
                now_ms,
                format!(
                    "drain required in_flight={} target_cap={new_cap}",
                    self.in_flight
                ),
            );
        } else {
            self.draining_target = None;
        }
        Ok(())
    }

    /// Acquire a permit for a remote operation.
    ///
    /// Queue policy returns `BulkheadError::Queued` when a request is accepted
    /// into queue but not yet admitted. Call `poll_queued()` to retry admission.
    pub fn acquire(
        &mut self,
        has_remote_cap: bool,
        request_id: &str,
        now_ms: u64,
    ) -> Result<BulkheadPermit, BulkheadError> {
        if !has_remote_cap {
            self.log_event(
                event_codes::RB_REQUEST_REJECTED,
                now_ms,
                "missing RemoteCap",
            );
            return Err(BulkheadError::RemoteCapRequired);
        }

        self.evict_expired_queue_entries(now_ms);

        if let Some(target_cap) = self.draining_target {
            if self.in_flight >= target_cap {
                self.log_event(
                    event_codes::RB_DRAIN_ACTIVE,
                    now_ms,
                    format!("acquire blocked by drain target={target_cap}"),
                );
                return Err(BulkheadError::Draining {
                    in_flight: self.in_flight,
                    target_cap,
                });
            }
            self.draining_target = None;
        }

        if self.in_flight < self.max_in_flight {
            let permit = self.issue_permit(now_ms);
            self.log_event(
                event_codes::RB_PERMIT_ACQUIRED,
                now_ms,
                format!("request_id={request_id} permit_id={}", permit.permit_id()),
            );
            return Ok(permit);
        }

        self.log_event(
            event_codes::RB_AT_CAPACITY,
            now_ms,
            format!("request_id={request_id} in_flight={}", self.in_flight),
        );

        match self.policy {
            BackpressurePolicy::Reject => {
                self.log_event(
                    event_codes::RB_REQUEST_REJECTED,
                    now_ms,
                    format!("request_id={request_id} policy=reject"),
                );
                Err(BulkheadError::AtCapacity {
                    cap: self.max_in_flight,
                    in_flight: self.in_flight,
                })
            }
            BackpressurePolicy::Queue {
                max_depth,
                timeout_ms,
            } => {
                if self.queue.len() >= max_depth {
                    self.log_event(
                        event_codes::RB_REQUEST_REJECTED,
                        now_ms,
                        format!("request_id={request_id} queue saturated max_depth={max_depth}"),
                    );
                    return Err(BulkheadError::QueueSaturated { max_depth });
                }

                let queued = QueuedRequest {
                    request_id: request_id.to_string(),
                    enqueued_at_ms: now_ms,
                    expires_at_ms: now_ms.saturating_add(timeout_ms),
                    timeout_ms,
                };
                self.queue.push_back(queued);
                let position = self.queue.len();
                self.log_event(
                    event_codes::RB_REQUEST_QUEUED,
                    now_ms,
                    format!("request_id={request_id} position={position}"),
                );
                Err(BulkheadError::Queued {
                    request_id: request_id.to_string(),
                    position,
                    timeout_ms,
                })
            }
        }
    }

    /// Retry admission for a queued request.
    pub fn poll_queued(
        &mut self,
        request_id: &str,
        now_ms: u64,
    ) -> Result<BulkheadPermit, BulkheadError> {
        self.evict_expired_queue_entries(now_ms);

        let Some(position) = self.queue.iter().position(|q| q.request_id == request_id) else {
            return Err(BulkheadError::UnknownRequest {
                request_id: request_id.to_string(),
            });
        };

        let queued = &self.queue[position];
        if now_ms >= queued.expires_at_ms {
            return Err(BulkheadError::QueueTimeout {
                request_id: request_id.to_string(),
            });
        }

        if position != 0 || self.in_flight >= self.max_in_flight {
            return Err(BulkheadError::Queued {
                request_id: request_id.to_string(),
                position: position + 1,
                timeout_ms: queued.timeout_ms,
            });
        }

        let _popped = self.queue.pop_front().expect("position 0 must exist");
        let permit = self.issue_permit(now_ms);
        self.log_event(
            event_codes::RB_PERMIT_ACQUIRED,
            now_ms,
            format!(
                "queued request promoted request_id={request_id} permit_id={}",
                permit.permit_id()
            ),
        );
        Ok(permit)
    }

    /// Release a previously issued permit.
    pub fn release(&mut self, permit: BulkheadPermit, now_ms: u64) -> Result<(), BulkheadError> {
        if !self.outstanding_permits.remove(&permit.permit_id) {
            return Err(BulkheadError::UnknownPermit {
                permit_id: permit.permit_id,
            });
        }

        self.in_flight = self.in_flight.saturating_sub(1);
        self.log_event(
            event_codes::RB_PERMIT_RELEASED,
            now_ms,
            format!("permit_id={}", permit.permit_id()),
        );

        if let Some(target_cap) = self.draining_target {
            if self.in_flight <= target_cap {
                self.draining_target = None;
            } else {
                self.log_event(
                    event_codes::RB_DRAIN_ACTIVE,
                    now_ms,
                    format!(
                        "draining continues in_flight={} target_cap={target_cap}",
                        self.in_flight
                    ),
                );
            }
        }

        Ok(())
    }

    /// Record foreground latency observation.
    pub fn record_foreground_latency(&mut self, latency_ms: u64) {
        self.latency_samples.push(ForegroundLatencySample {
            in_flight: self.in_flight,
            latency_ms,
        });
        self.log_event(
            event_codes::RB_LATENCY_REPORT,
            0,
            format!("latency_ms={latency_ms}"),
        );
    }

    /// Compute p99 latency from current sample set.
    #[must_use]
    pub fn p99_foreground_latency_ms(&self) -> Option<u64> {
        if self.latency_samples.is_empty() {
            return None;
        }
        let mut values = self
            .latency_samples
            .iter()
            .map(|sample| sample.latency_ms)
            .collect::<Vec<_>>();
        values.sort_unstable();
        let len = values.len();
        let rank = (99 * len).div_ceil(100).max(1) - 1;
        Some(values[rank])
    }

    /// Whether measured p99 remains within configured target.
    #[must_use]
    pub fn latency_within_target(&self) -> bool {
        match self.p99_foreground_latency_ms() {
            Some(p99) => p99 <= self.p99_target_ms,
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bulkhead_reject(cap: usize) -> RemoteBulkhead {
        RemoteBulkhead::new(cap, BackpressurePolicy::Reject, 50).expect("valid bulkhead")
    }

    fn bulkhead_queue(cap: usize, max_depth: usize, timeout_ms: u64) -> RemoteBulkhead {
        RemoteBulkhead::new(
            cap,
            BackpressurePolicy::Queue {
                max_depth,
                timeout_ms,
            },
            50,
        )
        .expect("valid queue policy")
    }

    #[test]
    fn acquire_and_release_within_cap_succeeds() {
        let mut b = bulkhead_reject(2);
        let p1 = b.acquire(true, "r1", 1).expect("permit 1");
        let p2 = b.acquire(true, "r2", 2).expect("permit 2");
        assert_eq!(b.current_in_flight(), 2);
        b.release(p1, 3).expect("release p1");
        b.release(p2, 4).expect("release p2");
        assert_eq!(b.current_in_flight(), 0);
    }

    #[test]
    fn cap_never_exceeded_under_reject_policy() {
        let mut b = bulkhead_reject(1);
        let _p1 = b.acquire(true, "a", 1).expect("permit");
        let err = b.acquire(true, "b", 2).expect_err("should reject");
        assert!(matches!(err, BulkheadError::AtCapacity { .. }));
        assert_eq!(b.current_in_flight(), 1);
    }

    #[test]
    fn queue_policy_enqueues_and_promotes_after_release() {
        let mut b = bulkhead_queue(1, 4, 500);
        let p1 = b.acquire(true, "r1", 1).expect("first permit");
        let q = b.acquire(true, "r2", 2).expect_err("should queue");
        assert!(matches!(q, BulkheadError::Queued { .. }));
        assert_eq!(b.queue_depth(), 1);

        b.release(p1, 3).expect("release");
        let p2 = b.poll_queued("r2", 4).expect("promote queued");
        assert_eq!(b.current_in_flight(), 1);
        b.release(p2, 5).expect("release promoted permit");
        assert_eq!(b.current_in_flight(), 0);
    }

    #[test]
    fn queue_policy_saturates_max_depth() {
        let mut b = bulkhead_queue(1, 1, 100);
        let _p = b.acquire(true, "r1", 1).expect("permit");
        let _queued = b.acquire(true, "r2", 2).expect_err("queued");
        let err = b.acquire(true, "r3", 3).expect_err("queue should be full");
        assert!(matches!(err, BulkheadError::QueueSaturated { .. }));
    }

    #[test]
    fn queue_timeout_is_enforced() {
        let mut b = bulkhead_queue(1, 2, 2);
        let _p = b.acquire(true, "r1", 10).expect("permit");
        let _queued = b.acquire(true, "r2", 11).expect_err("queued");
        let err = b.poll_queued("r2", 20).expect_err("should time out");
        assert!(matches!(err, BulkheadError::UnknownRequest { .. }));
    }

    #[test]
    fn runtime_cap_reduction_enters_draining_mode() {
        let mut b = bulkhead_reject(3);
        let p1 = b.acquire(true, "a", 1).expect("a");
        let p2 = b.acquire(true, "b", 2).expect("b");
        let p3 = b.acquire(true, "c", 3).expect("c");
        b.set_max_in_flight(2, 4).expect("cap reduce");
        let err = b.acquire(true, "d", 5).expect_err("draining should block");
        assert!(matches!(err, BulkheadError::Draining { .. }));
        b.release(p1, 6).expect("release p1");
        b.release(p2, 7).expect("release p2");
        b.release(p3, 8).expect("release p3");
        assert_eq!(b.draining_target(), None);
    }

    #[test]
    fn runtime_cap_increase_allows_new_acquires() {
        let mut b = bulkhead_reject(1);
        let p1 = b.acquire(true, "a", 1).expect("a");
        let _err = b.acquire(true, "b", 2).expect_err("at cap");
        b.set_max_in_flight(2, 3).expect("cap increase");
        let p2 = b.acquire(true, "b", 4).expect("acquire after increase");
        assert_eq!(b.current_in_flight(), 2);
        b.release(p1, 5).expect("release p1");
        b.release(p2, 6).expect("release p2");
    }

    #[test]
    fn remote_cap_is_required() {
        let mut b = bulkhead_reject(2);
        let err = b
            .acquire(false, "no-cap", 1)
            .expect_err("must require capability");
        assert!(matches!(err, BulkheadError::RemoteCapRequired));
    }

    #[test]
    fn p99_is_computed_deterministically() {
        let mut b = bulkhead_reject(4);
        for latency in [10_u64, 11, 12, 13, 14, 15, 100] {
            b.record_foreground_latency(latency);
        }
        assert_eq!(b.p99_foreground_latency_ms(), Some(100));
    }

    #[test]
    fn latency_target_gate_reflects_samples() {
        let mut b = bulkhead_reject(4);
        for latency in [20_u64, 25, 30, 45] {
            b.record_foreground_latency(latency);
        }
        assert!(b.latency_within_target());

        b.record_foreground_latency(80);
        assert!(!b.latency_within_target());
    }

    #[test]
    fn releasing_unknown_permit_fails_closed() {
        let mut b = bulkhead_reject(1);
        let err = b
            .release(
                BulkheadPermit {
                    permit_id: 999,
                    issued_at_ms: 0,
                    cap_snapshot: 1,
                },
                1,
            )
            .expect_err("unknown permit");
        assert!(matches!(err, BulkheadError::UnknownPermit { .. }));
    }

    #[test]
    fn event_log_contains_expected_codes() {
        let mut b = bulkhead_queue(1, 2, 100);
        let p1 = b.acquire(true, "x", 1).expect("permit");
        let _q = b.acquire(true, "y", 2).expect_err("queued");
        b.release(p1, 3).expect("release");
        let _p2 = b.poll_queued("y", 4).expect("promote");

        let codes = b
            .events()
            .iter()
            .map(|event| event.event_code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&event_codes::RB_PERMIT_ACQUIRED));
        assert!(codes.contains(&event_codes::RB_REQUEST_QUEUED));
        assert!(codes.contains(&event_codes::RB_PERMIT_RELEASED));
    }
}
