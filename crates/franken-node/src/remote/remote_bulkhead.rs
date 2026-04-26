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
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::capacity_defaults::aliases::{MAX_BULKHEAD_EVENTS, MAX_LATENCY_SAMPLES};
use crate::remote::eviction_saga::RemoteCapLookup;

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
struct OutstandingPermit {
    request_id: String,
    issued_at_ms: u64,
    cap_snapshot: usize,
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
    DuplicateRequest {
        request_id: String,
    },
    UnknownPermit {
        permit_id: u64,
    },
    InvalidPermit {
        permit_id: u64,
    },
    PermitIdExhausted {
        request_id: String,
    },
    InvalidRequestId {
        detail: String,
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
            Self::DuplicateRequest { .. } => "RB_ERR_DUPLICATE_REQUEST",
            Self::UnknownPermit { .. } => "RB_ERR_UNKNOWN_PERMIT",
            Self::InvalidPermit { .. } => "RB_ERR_INVALID_PERMIT",
            Self::PermitIdExhausted { .. } => "RB_ERR_PERMIT_ID_EXHAUSTED",
            Self::InvalidRequestId { .. } => "RB_ERR_INVALID_REQUEST_ID",
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
            Self::DuplicateRequest { request_id } => {
                write!(f, "{}: duplicate request_id={request_id}", self.code())
            }
            Self::UnknownPermit { permit_id } => {
                write!(f, "{}: unknown permit_id={permit_id}", self.code())
            }
            Self::InvalidPermit { permit_id } => {
                write!(f, "{}: invalid permit_id={permit_id}", self.code())
            }
            Self::PermitIdExhausted { request_id } => {
                write!(
                    f,
                    "{}: permit id space exhausted request_id={request_id}",
                    self.code()
                )
            }
            Self::InvalidRequestId { detail } => {
                write!(f, "{}: {detail}", self.code())
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
    outstanding_permits: BTreeMap<u64, OutstandingPermit>,
    active_request_ids: BTreeSet<String>,
    next_permit_id: u64,
    permit_ids_exhausted: bool,
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
            outstanding_permits: BTreeMap::new(),
            active_request_ids: BTreeSet::new(),
            next_permit_id: 1,
            permit_ids_exhausted: false,
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

    fn log_event(&mut self, event_code: &str, now_ms: u64, detail: impl Into<String>) {
        Self::push_bounded(
            &mut self.events,
            BulkheadEvent {
                event_code: event_code.to_string(),
                now_ms,
                in_flight: self.in_flight,
                max_in_flight: self.max_in_flight,
                detail: detail.into(),
            },
            MAX_BULKHEAD_EVENTS,
        );
    }

    fn push_latency_sample(&mut self, latency_ms: u64) {
        Self::push_bounded(
            &mut self.latency_samples,
            ForegroundLatencySample {
                in_flight: self.in_flight,
                latency_ms,
            },
            MAX_LATENCY_SAMPLES,
        );
    }

    fn validate_request_id(request_id: &str) -> Result<(), BulkheadError> {
        if request_id.trim().is_empty() {
            return Err(BulkheadError::InvalidRequestId {
                detail: "request_id must not be empty".to_string(),
            });
        }
        if request_id.trim() != request_id {
            return Err(BulkheadError::InvalidRequestId {
                detail: "request_id must not contain leading or trailing whitespace".to_string(),
            });
        }
        if request_id.chars().any(char::is_control) {
            return Err(BulkheadError::InvalidRequestId {
                detail: "request_id must not contain control characters".to_string(),
            });
        }
        Ok(())
    }

    fn request_id_in_use(&self, request_id: &str) -> bool {
        self.active_request_ids.contains(request_id)
            || self
                .queue
                .iter()
                .any(|queued| queued.request_id == request_id)
    }

    fn queue_has_waiters(&self) -> bool {
        matches!(self.policy, BackpressurePolicy::Queue { .. }) && !self.queue.is_empty()
    }

    fn issue_permit(&mut self, now_ms: u64, request_id: &str) -> BulkheadPermit {
        let permit = BulkheadPermit {
            permit_id: self.next_permit_id,
            issued_at_ms: now_ms,
            cap_snapshot: self.max_in_flight,
        };
        if self.next_permit_id == u64::MAX {
            self.permit_ids_exhausted = true;
        } else {
            self.next_permit_id = self.next_permit_id.saturating_add(1);
        }
        self.outstanding_permits.insert(
            permit.permit_id,
            OutstandingPermit {
                request_id: request_id.to_string(),
                issued_at_ms: permit.issued_at_ms,
                cap_snapshot: permit.cap_snapshot,
            },
        );
        self.active_request_ids.insert(request_id.to_string());
        self.in_flight = self.in_flight.saturating_add(1);
        permit
    }

    fn permit_id_exhausted_error(
        &mut self,
        request_id: impl Into<String>,
        now_ms: u64,
    ) -> BulkheadError {
        let request_id = request_id.into();
        self.log_event(
            event_codes::RB_REQUEST_REJECTED,
            now_ms,
            format!("request_id={request_id} permit_id space exhausted"),
        );
        BulkheadError::PermitIdExhausted { request_id }
    }

    fn evict_expired_queue_entries(&mut self, now_ms: u64) {
        while let Some(front) = self.queue.front() {
            if now_ms < front.expires_at_ms {
                break;
            }
            let Some(expired) = self.queue.pop_front() else {
                break;
            };
            self.log_event(
                event_codes::RB_REQUEST_REJECTED,
                now_ms,
                format!("queue timeout request_id={}", expired.request_id),
            );
        }
    }

    fn reject_expired_queued_request(
        &mut self,
        position: usize,
        now_ms: u64,
    ) -> Option<BulkheadError> {
        let expired = self.queue.remove(position)?;
        self.log_event(
            event_codes::RB_REQUEST_REJECTED,
            now_ms,
            format!("queue timeout request_id={}", expired.request_id),
        );
        Some(BulkheadError::QueueTimeout {
            request_id: expired.request_id,
        })
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
        remote_cap: RemoteCapLookup,
        request_id: &str,
        now_ms: u64,
    ) -> Result<BulkheadPermit, BulkheadError> {
        Self::validate_request_id(request_id)?;
        match remote_cap {
            RemoteCapLookup::Granted => {
                // Capability granted - proceed with acquisition
            }
            RemoteCapLookup::Denied | RemoteCapLookup::NotPresent => {
                self.log_event(
                    event_codes::RB_REQUEST_REJECTED,
                    now_ms,
                    "missing or denied RemoteCap",
                );
                return Err(BulkheadError::RemoteCapRequired);
            }
        }

        self.evict_expired_queue_entries(now_ms);

        if self.request_id_in_use(request_id) {
            self.log_event(
                event_codes::RB_REQUEST_REJECTED,
                now_ms,
                format!("duplicate request_id={request_id}"),
            );
            return Err(BulkheadError::DuplicateRequest {
                request_id: request_id.to_string(),
            });
        }

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

        if self.permit_ids_exhausted {
            return Err(self.permit_id_exhausted_error(request_id, now_ms));
        }

        if self.in_flight < self.max_in_flight && !self.queue_has_waiters() {
            let permit = self.issue_permit(now_ms, request_id);
            self.log_event(
                event_codes::RB_PERMIT_ACQUIRED,
                now_ms,
                format!("request_id={request_id} permit_id={}", permit.permit_id()),
            );
            return Ok(permit);
        }

        match self.policy {
            BackpressurePolicy::Reject => {
                self.log_event(
                    event_codes::RB_AT_CAPACITY,
                    now_ms,
                    format!("request_id={request_id} in_flight={}", self.in_flight),
                );
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
                let waiters_ahead = self.queue_has_waiters();
                if !waiters_ahead {
                    self.log_event(
                        event_codes::RB_AT_CAPACITY,
                        now_ms,
                        format!("request_id={request_id} in_flight={}", self.in_flight),
                    );
                }
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
                    format!(
                        "request_id={request_id} position={position} waiters_ahead={waiters_ahead}"
                    ),
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
        Self::validate_request_id(request_id)?;
        let Some(position) = self.queue.iter().position(|q| q.request_id == request_id) else {
            self.evict_expired_queue_entries(now_ms);
            return Err(BulkheadError::UnknownRequest {
                request_id: request_id.to_string(),
            });
        };

        let expires_at_ms = self.queue[position].expires_at_ms;
        if now_ms >= expires_at_ms {
            let Some(timeout_error) = self.reject_expired_queued_request(position, now_ms) else {
                return Err(BulkheadError::UnknownRequest {
                    request_id: request_id.to_string(),
                });
            };
            self.evict_expired_queue_entries(now_ms);
            return Err(timeout_error);
        }

        self.evict_expired_queue_entries(now_ms);

        let Some(position) = self.queue.iter().position(|q| q.request_id == request_id) else {
            return Err(BulkheadError::UnknownRequest {
                request_id: request_id.to_string(),
            });
        };
        let timeout_ms = self.queue[position].timeout_ms;

        if self.active_request_ids.contains(request_id) {
            self.log_event(
                event_codes::RB_REQUEST_REJECTED,
                now_ms,
                format!("queued request_id already active request_id={request_id}"),
            );
            return Err(BulkheadError::DuplicateRequest {
                request_id: request_id.to_string(),
            });
        }

        if self.permit_ids_exhausted {
            let Some(expired_request) = self.queue.remove(position) else {
                return Err(BulkheadError::UnknownRequest {
                    request_id: request_id.to_string(),
                });
            };
            return Err(self.permit_id_exhausted_error(expired_request.request_id, now_ms));
        }

        if position != 0 || self.in_flight >= self.max_in_flight {
            return Err(BulkheadError::Queued {
                request_id: request_id.to_string(),
                position: position.saturating_add(1),
                timeout_ms,
            });
        }

        let Some(_popped) = self.queue.pop_front() else {
            return Err(BulkheadError::Queued {
                request_id: request_id.to_string(),
                position: 1,
                timeout_ms,
            });
        };
        let permit = self.issue_permit(now_ms, request_id);
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
        let Some(record) = self.outstanding_permits.remove(&permit.permit_id) else {
            return Err(BulkheadError::UnknownPermit {
                permit_id: permit.permit_id,
            });
        };
        if record.issued_at_ms != permit.issued_at_ms || record.cap_snapshot != permit.cap_snapshot
        {
            self.outstanding_permits.insert(permit.permit_id, record);
            return Err(BulkheadError::InvalidPermit {
                permit_id: permit.permit_id,
            });
        }

        let request_id = record.request_id;
        self.active_request_ids.remove(&request_id);

        self.in_flight = self.in_flight.saturating_sub(1);
        self.log_event(
            event_codes::RB_PERMIT_RELEASED,
            now_ms,
            format!("request_id={request_id} permit_id={}", permit.permit_id()),
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
    pub fn record_foreground_latency(&mut self, latency_ms: u64, now_ms: u64) {
        self.push_latency_sample(latency_ms);
        self.log_event(
            event_codes::RB_LATENCY_REPORT,
            now_ms,
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
        let rank = (99usize.saturating_mul(len))
            .div_ceil(100)
            .max(1)
            .saturating_sub(1);
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
        let p1 = b
            .acquire(RemoteCapLookup::Granted, "r1", 1)
            .expect("permit 1");
        let p2 = b
            .acquire(RemoteCapLookup::Granted, "r2", 2)
            .expect("permit 2");
        assert_eq!(b.current_in_flight(), 2);
        b.release(p1, 3).expect("release p1");
        b.release(p2, 4).expect("release p2");
        assert_eq!(b.current_in_flight(), 0);
    }

    #[test]
    fn cap_never_exceeded_under_reject_policy() {
        let mut b = bulkhead_reject(1);
        let _p1 = b.acquire(RemoteCapLookup::Granted, "a", 1).expect("permit");
        let err = b
            .acquire(RemoteCapLookup::Granted, "b", 2)
            .expect_err("should reject");
        assert!(matches!(err, BulkheadError::AtCapacity { .. }));
        assert_eq!(b.current_in_flight(), 1);
    }

    #[test]
    fn queue_policy_enqueues_and_promotes_after_release() {
        let mut b = bulkhead_queue(1, 4, 500);
        let p1 = b
            .acquire(RemoteCapLookup::Granted, "r1", 1)
            .expect("first permit");
        let q = b
            .acquire(RemoteCapLookup::Granted, "r2", 2)
            .expect_err("should queue");
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
        let _p = b
            .acquire(RemoteCapLookup::Granted, "r1", 1)
            .expect("permit");
        let _queued = b
            .acquire(RemoteCapLookup::Granted, "r2", 2)
            .expect_err("queued");
        let err = b
            .acquire(RemoteCapLookup::Granted, "r3", 3)
            .expect_err("queue should be full");
        assert!(matches!(err, BulkheadError::QueueSaturated { .. }));
    }

    #[test]
    fn queue_timeout_is_enforced() {
        let mut b = bulkhead_queue(1, 2, 2);
        let _p = b
            .acquire(RemoteCapLookup::Granted, "r1", 10)
            .expect("permit");
        let _queued = b
            .acquire(RemoteCapLookup::Granted, "r2", 11)
            .expect_err("queued");
        let err = b.poll_queued("r2", 20).expect_err("should time out");
        assert!(matches!(
            err,
            BulkheadError::QueueTimeout { ref request_id } if request_id == "r2"
        ));
        assert_eq!(b.queue_depth(), 0);
        let rejection = b
            .events()
            .iter()
            .rev()
            .find(|event| event.event_code == event_codes::RB_REQUEST_REJECTED)
            .expect("timeout rejection should be logged");
        assert!(rejection.detail.contains("request_id=r2"));
    }

    #[test]
    fn later_live_request_survives_front_timeout_eviction() {
        let mut b = bulkhead_queue(1, 3, 10);
        let p1 = b
            .acquire(RemoteCapLookup::Granted, "r1", 10)
            .expect("permit");
        let _queued = b
            .acquire(RemoteCapLookup::Granted, "r2", 11)
            .expect_err("queue r2");
        let _queued = b
            .acquire(RemoteCapLookup::Granted, "r3", 13)
            .expect_err("queue r3");

        b.release(p1, 22).expect("release");
        let promoted = b.poll_queued("r3", 22).expect("r3 should promote");
        assert_eq!(b.queue_depth(), 0);
        assert_eq!(b.current_in_flight(), 1);
        b.release(promoted, 23).expect("release promoted");
    }

    #[test]
    fn runtime_cap_reduction_enters_draining_mode() {
        let mut b = bulkhead_reject(3);
        let p1 = b.acquire(RemoteCapLookup::Granted, "a", 1).expect("a");
        let p2 = b.acquire(RemoteCapLookup::Granted, "b", 2).expect("b");
        let p3 = b.acquire(RemoteCapLookup::Granted, "c", 3).expect("c");
        b.set_max_in_flight(2, 4).expect("cap reduce");
        let err = b
            .acquire(RemoteCapLookup::Granted, "d", 5)
            .expect_err("draining should block");
        assert!(matches!(err, BulkheadError::Draining { .. }));
        b.release(p1, 6).expect("release p1");
        b.release(p2, 7).expect("release p2");
        b.release(p3, 8).expect("release p3");
        assert_eq!(b.draining_target(), None);
    }

    #[test]
    fn runtime_cap_increase_allows_new_acquires() {
        let mut b = bulkhead_reject(1);
        let p1 = b.acquire(RemoteCapLookup::Granted, "a", 1).expect("a");
        let _err = b
            .acquire(RemoteCapLookup::Granted, "b", 2)
            .expect_err("at cap");
        b.set_max_in_flight(2, 3).expect("cap increase");
        let p2 = b
            .acquire(RemoteCapLookup::Granted, "b", 4)
            .expect("acquire after increase");
        assert_eq!(b.current_in_flight(), 2);
        b.release(p1, 5).expect("release p1");
        b.release(p2, 6).expect("release p2");
    }

    #[test]
    fn remote_cap_is_required() {
        let mut b = bulkhead_reject(2);
        let err = b
            .acquire(RemoteCapLookup::Denied, "no-cap", 1)
            .expect_err("must require capability");
        assert!(matches!(err, BulkheadError::RemoteCapRequired));
    }

    #[test]
    fn empty_request_id_is_rejected_fail_closed() {
        let mut b = bulkhead_reject(2);
        let err = b
            .acquire(true, "   ", 1)
            .expect_err("empty request id must fail closed");
        assert!(matches!(err, BulkheadError::InvalidRequestId { .. }));
        assert_eq!(b.current_in_flight(), 0);
    }

    #[test]
    fn duplicate_active_request_id_is_rejected_without_second_permit() {
        let mut b = bulkhead_reject(2);
        let permit = b
            .acquire(RemoteCapLookup::Granted, "dup", 1)
            .expect("first permit");
        let err = b
            .acquire(true, "dup", 2)
            .expect_err("duplicate active request id must fail closed");
        assert!(matches!(
            err,
            BulkheadError::DuplicateRequest { ref request_id } if request_id == "dup"
        ));
        assert_eq!(b.current_in_flight(), 1);
        b.release(permit, 3).expect("release original permit");
        assert_eq!(b.current_in_flight(), 0);
    }

    #[test]
    fn duplicate_queued_request_id_is_rejected_without_adding_second_queue_entry() {
        let mut b = bulkhead_queue(1, 4, 100);
        let permit = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        let queued = b
            .acquire(true, "queued", 2)
            .expect_err("first queued request");
        assert!(matches!(queued, BulkheadError::Queued { .. }));
        let duplicate = b
            .acquire(true, "queued", 3)
            .expect_err("duplicate queued request must fail closed");
        assert!(matches!(
            duplicate,
            BulkheadError::DuplicateRequest { ref request_id } if request_id == "queued"
        ));
        assert_eq!(b.queue_depth(), 1);

        b.release(permit, 4).expect("release active permit");
        let promoted = b.poll_queued("queued", 5).expect("promote queued");
        b.release(promoted, 6).expect("release promoted");
        assert_eq!(b.current_in_flight(), 0);
        assert_eq!(b.queue_depth(), 0);
    }

    #[test]
    fn terminal_permit_id_is_issued_once_then_direct_acquire_fails_closed() {
        let mut b = bulkhead_reject(1);
        b.next_permit_id = u64::MAX;

        let terminal = b
            .acquire(true, "terminal", 1)
            .expect("terminal permit id should still be issued once");
        assert_eq!(terminal.permit_id(), u64::MAX);
        b.release(terminal, 2).expect("release terminal permit");

        let err = b
            .acquire(true, "after-terminal", 3)
            .expect_err("permit id exhaustion must fail closed");
        assert!(matches!(
            err,
            BulkheadError::PermitIdExhausted { ref request_id } if request_id == "after-terminal"
        ));
        let rejection = b
            .events()
            .iter()
            .rev()
            .find(|event| event.event_code == event_codes::RB_REQUEST_REJECTED)
            .expect("exhaustion rejection should be logged");
        assert!(rejection.detail.contains("request_id=after-terminal"));
    }

    #[test]
    fn queued_request_is_rejected_after_terminal_permit_id_is_consumed() {
        let mut b = bulkhead_queue(1, 3, 100);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        let _queued = b
            .acquire(true, "queued-1", 2)
            .expect_err("queue first waiter");
        let _queued = b
            .acquire(true, "queued-2", 3)
            .expect_err("queue second waiter");

        b.next_permit_id = u64::MAX;
        b.release(active, 4).expect("release active permit");

        let terminal = b
            .poll_queued("queued-1", 5)
            .expect("front queued request should get terminal permit id");
        assert_eq!(terminal.permit_id(), u64::MAX);
        b.release(terminal, 6).expect("release terminal permit");

        let err = b
            .poll_queued("queued-2", 7)
            .expect_err("remaining queued request must fail closed after exhaustion");
        assert!(matches!(
            err,
            BulkheadError::PermitIdExhausted { ref request_id } if request_id == "queued-2"
        ));
        assert_eq!(b.queue_depth(), 0);
    }

    #[test]
    fn serde_round_trip_preserves_permit_id_exhaustion_state() {
        let mut b = bulkhead_reject(1);
        b.next_permit_id = u64::MAX;

        let terminal = b
            .acquire(true, "terminal", 1)
            .expect("terminal permit id should still be issued once");
        b.release(terminal, 2).expect("release terminal permit");
        assert!(b.permit_ids_exhausted);

        let json = serde_json::to_string(&b).expect("serialize bulkhead");
        let mut restored: RemoteBulkhead =
            serde_json::from_str(&json).expect("deserialize bulkhead");

        assert!(restored.permit_ids_exhausted);
        let err = restored
            .acquire(true, "after-round-trip", 3)
            .expect_err("exhaustion must survive serde round-trip");
        assert!(matches!(
            err,
            BulkheadError::PermitIdExhausted { ref request_id } if request_id == "after-round-trip"
        ));
    }

    #[test]
    fn fresh_acquire_cannot_leapfrog_existing_queue_waiter() {
        let mut b = bulkhead_queue(1, 4, 100);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        let queued = b
            .acquire(true, "queued-1", 2)
            .expect_err("first queued request");
        assert!(matches!(queued, BulkheadError::Queued { position: 1, .. }));

        b.release(active, 3).expect("release active permit");

        let newer = b
            .acquire(true, "queued-2", 4)
            .expect_err("new request must queue behind existing waiter");
        assert!(matches!(
            newer,
            BulkheadError::Queued {
                ref request_id,
                position: 2,
                ..
            } if request_id == "queued-2"
        ));

        let promoted_first = b
            .poll_queued("queued-1", 5)
            .expect("front queued request should promote first");
        assert_eq!(b.current_in_flight(), 1);

        let still_waiting = b
            .poll_queued("queued-2", 6)
            .expect_err("second queued request should still wait");
        assert!(matches!(
            still_waiting,
            BulkheadError::Queued {
                ref request_id,
                position: 1,
                ..
            } if request_id == "queued-2"
        ));

        b.release(promoted_first, 7)
            .expect("release first promoted permit");
        let promoted_second = b
            .poll_queued("queued-2", 8)
            .expect("second queued request should promote after first releases");
        b.release(promoted_second, 9)
            .expect("release second promoted permit");
        assert_eq!(b.current_in_flight(), 0);
        assert_eq!(b.queue_depth(), 0);
    }

    #[test]
    fn p99_is_computed_deterministically() {
        let mut b = bulkhead_reject(4);
        for (idx, latency) in [10_u64, 11, 12, 13, 14, 15, 100].into_iter().enumerate() {
            b.record_foreground_latency(
                latency,
                u64::try_from(idx + 1).expect("usize->u64 conversion should not overflow"),
            );
        }
        assert_eq!(b.p99_foreground_latency_ms(), Some(100));
    }

    #[test]
    fn latency_target_gate_reflects_samples() {
        let mut b = bulkhead_reject(4);
        for (idx, latency) in [20_u64, 25, 30, 45].into_iter().enumerate() {
            b.record_foreground_latency(
                latency,
                u64::try_from(idx + 1).expect("usize->u64 conversion should not overflow"),
            );
        }
        assert!(b.latency_within_target());

        b.record_foreground_latency(80, 10);
        assert!(!b.latency_within_target());
    }

    #[test]
    fn latency_report_event_preserves_supplied_timestamp() {
        let mut b = bulkhead_reject(1);
        b.record_foreground_latency(42, 777);

        let event = b.events().last().expect("latency event should be recorded");
        assert_eq!(event.event_code, event_codes::RB_LATENCY_REPORT);
        assert_eq!(event.now_ms, 777);
        assert_eq!(event.detail, "latency_ms=42");
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
    fn deserialized_permit_with_tampered_metadata_fails_closed() {
        let mut b = bulkhead_reject(1);
        let permit = b
            .acquire(RemoteCapLookup::Granted, "victim", 10)
            .expect("permit");
        let forged_json = format!(
            r#"{{"permit_id":{},"issued_at_ms":{},"cap_snapshot":{}}}"#,
            permit.permit_id(),
            permit.issued_at_ms().saturating_add(1),
            permit.cap_snapshot()
        );
        let forged: BulkheadPermit =
            serde_json::from_str(&forged_json).expect("forged permit should deserialize");

        let err = b
            .release(forged, 11)
            .expect_err("tampered permit must fail closed");

        assert!(matches!(
            err,
            BulkheadError::InvalidPermit { permit_id } if permit_id == permit.permit_id()
        ));
        assert_eq!(b.current_in_flight(), 1);
        assert!(b.active_request_ids.contains("victim"));
        assert!(b.outstanding_permits.contains_key(&permit.permit_id()));
        b.release(permit, 12)
            .expect("original permit should still release");
        assert_eq!(b.current_in_flight(), 0);
    }

    #[test]
    fn event_log_contains_expected_codes() {
        let mut b = bulkhead_queue(1, 2, 100);
        let p1 = b.acquire(RemoteCapLookup::Granted, "x", 1).expect("permit");
        let _q = b
            .acquire(RemoteCapLookup::Granted, "y", 2)
            .expect_err("queued");
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

    #[test]
    fn event_log_is_bounded_with_oldest_first_eviction() {
        let mut b = bulkhead_reject(1);
        let total = MAX_BULKHEAD_EVENTS + 7;
        for idx in 0..total {
            let latency = u64::try_from(idx).expect("usize->u64 conversion should not overflow");
            b.record_foreground_latency(latency, latency);
        }

        assert_eq!(b.events().len(), MAX_BULKHEAD_EVENTS);
        let dropped = total - MAX_BULKHEAD_EVENTS;
        let expected_first = format!("latency_ms={dropped}");
        let expected_last = format!("latency_ms={}", total - 1);
        let first = b.events().first().expect("event log should not be empty");
        let last = b.events().last().expect("event log should not be empty");
        assert_eq!(first.detail, expected_first);
        assert_eq!(last.detail, expected_last);
        assert!(
            b.events()
                .iter()
                .all(|event| event.event_code == event_codes::RB_LATENCY_REPORT)
        );
    }

    #[test]
    fn latency_samples_are_bounded_with_oldest_first_eviction() {
        let mut b = bulkhead_reject(1);
        let total = MAX_LATENCY_SAMPLES + 11;
        for idx in 0..total {
            let latency = u64::try_from(idx).expect("usize->u64 conversion should not overflow");
            b.record_foreground_latency(latency, latency);
        }

        assert_eq!(b.latency_samples().len(), MAX_LATENCY_SAMPLES);
        let dropped = total - MAX_LATENCY_SAMPLES;
        let first = b
            .latency_samples()
            .first()
            .expect("latency samples should not be empty");
        let last = b
            .latency_samples()
            .last()
            .expect("latency samples should not be empty");
        assert_eq!(
            first.latency_ms,
            u64::try_from(dropped).expect("usize->u64 conversion should not overflow")
        );
        assert_eq!(
            last.latency_ms,
            u64::try_from(total - 1).expect("usize->u64 conversion should not overflow")
        );
    }

    #[test]
    fn zero_max_in_flight_config_is_rejected() {
        let err = RemoteBulkhead::new(0, BackpressurePolicy::Reject, 50)
            .expect_err("zero max_in_flight must fail closed");

        assert!(matches!(
            err,
            BulkheadError::InvalidConfig { ref reason } if reason.contains("max_in_flight")
        ));
        assert_eq!(err.code(), "RB_ERR_INVALID_CONFIG");
    }

    #[test]
    fn zero_p99_target_config_is_rejected() {
        let err = RemoteBulkhead::new(1, BackpressurePolicy::Reject, 0)
            .expect_err("zero p99 target must fail closed");

        assert!(matches!(
            err,
            BulkheadError::InvalidConfig { ref reason } if reason.contains("p99_target_ms")
        ));
        assert_eq!(err.code(), "RB_ERR_INVALID_CONFIG");
    }

    #[test]
    fn queue_policy_zero_depth_config_is_rejected() {
        let err = RemoteBulkhead::new(
            1,
            BackpressurePolicy::Queue {
                max_depth: 0,
                timeout_ms: 10,
            },
            50,
        )
        .expect_err("zero queue depth must fail closed");

        assert!(matches!(
            err,
            BulkheadError::InvalidConfig { ref reason } if reason.contains("max_depth")
        ));
        assert_eq!(err.code(), "RB_ERR_INVALID_CONFIG");
    }

    #[test]
    fn queue_policy_zero_timeout_config_is_rejected() {
        let err = RemoteBulkhead::new(
            1,
            BackpressurePolicy::Queue {
                max_depth: 1,
                timeout_ms: 0,
            },
            50,
        )
        .expect_err("zero queue timeout must fail closed");

        assert!(matches!(
            err,
            BulkheadError::InvalidConfig { ref reason } if reason.contains("timeout_ms")
        ));
        assert_eq!(err.code(), "RB_ERR_INVALID_CONFIG");
    }

    #[test]
    fn invalid_acquire_request_id_does_not_log_or_change_capacity() {
        let mut b = bulkhead_reject(2);

        let err = b
            .acquire(true, "\t\n", 10)
            .expect_err("blank request id must fail before admission");

        assert!(matches!(err, BulkheadError::InvalidRequestId { .. }));
        assert_eq!(b.current_in_flight(), 0);
        assert_eq!(b.max_in_flight(), 2);
        assert!(b.events().is_empty());
    }

    #[test]
    fn invalid_poll_request_id_does_not_evict_existing_waiter() {
        let mut b = bulkhead_queue(1, 2, 5);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        let queued = b
            .acquire(true, "queued", 2)
            .expect_err("request should queue");
        assert!(matches!(queued, BulkheadError::Queued { .. }));

        let err = b
            .poll_queued("   ", 100)
            .expect_err("blank poll request id must fail before queue eviction");

        assert!(matches!(err, BulkheadError::InvalidRequestId { .. }));
        assert_eq!(b.queue_depth(), 1);
        b.release(active, 101).expect("release active permit");
    }

    #[test]
    fn unknown_poll_evicts_expired_front_waiter_without_promoting_anything() {
        let mut b = bulkhead_queue(1, 2, 5);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        let queued = b
            .acquire(true, "queued", 2)
            .expect_err("request should queue");
        assert!(matches!(queued, BulkheadError::Queued { .. }));

        let err = b
            .poll_queued("missing", 10)
            .expect_err("unknown request should not promote expired waiter");

        assert!(matches!(
            err,
            BulkheadError::UnknownRequest { ref request_id } if request_id == "missing"
        ));
        assert_eq!(b.queue_depth(), 0);
        assert_eq!(b.current_in_flight(), 1);
        b.release(active, 11).expect("release active permit");
    }

    #[test]
    fn release_same_permit_twice_fails_without_underflow_or_event() {
        let mut b = bulkhead_reject(1);
        let permit = b
            .acquire(RemoteCapLookup::Granted, "req", 1)
            .expect("permit");
        b.release(permit.clone(), 2).expect("first release");
        let events_after_release = b.events().len();

        let err = b
            .release(permit, 3)
            .expect_err("second release must fail closed");

        assert!(matches!(err, BulkheadError::UnknownPermit { .. }));
        assert_eq!(b.current_in_flight(), 0);
        assert_eq!(b.events().len(), events_after_release);
    }

    #[test]
    fn invalid_runtime_cap_change_preserves_existing_cap_and_drain_state() {
        let mut b = bulkhead_reject(2);
        let permit = b
            .acquire(RemoteCapLookup::Granted, "req", 1)
            .expect("permit");

        let err = b
            .set_max_in_flight(0, 2)
            .expect_err("zero runtime cap must fail closed");

        assert!(matches!(
            err,
            BulkheadError::InvalidConfig { ref reason } if reason.contains("new cap")
        ));
        assert_eq!(b.max_in_flight(), 2);
        assert_eq!(b.draining_target(), None);
        assert_eq!(b.current_in_flight(), 1);
        b.release(permit, 3).expect("release permit");
    }

    #[test]
    fn push_bounded_zero_capacity_clears_existing_items() {
        let mut items = vec![1, 2, 3];

        RemoteBulkhead::push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn request_id_with_outer_whitespace_is_rejected_without_event() {
        let mut b = bulkhead_reject(1);

        let err = b
            .acquire(true, " req ", 1)
            .expect_err("outer whitespace should fail closed");

        assert!(matches!(
            err,
            BulkheadError::InvalidRequestId { ref detail }
                if detail.contains("leading or trailing whitespace")
        ));
        assert_eq!(b.current_in_flight(), 0);
        assert!(b.events().is_empty());
    }

    #[test]
    fn request_id_with_nul_byte_is_rejected_without_event() {
        let mut b = bulkhead_reject(1);

        let err = b
            .acquire(true, "req\0hidden", 1)
            .expect_err("control byte should fail closed");

        assert!(matches!(
            err,
            BulkheadError::InvalidRequestId { ref detail } if detail.contains("control")
        ));
        assert_eq!(b.current_in_flight(), 0);
        assert!(b.events().is_empty());
    }

    #[test]
    fn remote_cap_missing_under_queue_policy_does_not_enqueue() {
        let mut b = bulkhead_queue(1, 2, 100);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");

        let err = b
            .acquire(RemoteCapLookup::Denied, "no-cap-waiter", 2)
            .expect_err("missing RemoteCap should reject before queue admission");

        assert!(matches!(err, BulkheadError::RemoteCapRequired));
        assert_eq!(b.queue_depth(), 0);
        assert_eq!(b.current_in_flight(), 1);
        b.release(active, 3).expect("release active permit");
    }

    #[test]
    fn exact_queue_timeout_boundary_rejects_and_removes_waiter() {
        let mut b = bulkhead_queue(1, 2, 10);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 10)
            .expect("active permit");
        assert!(matches!(
            b.acquire(RemoteCapLookup::Granted, "waiter", 12),
            Err(BulkheadError::Queued { .. })
        ));

        let err = b
            .poll_queued("waiter", 22)
            .expect_err("exact expiry boundary must time out");

        assert!(matches!(
            err,
            BulkheadError::QueueTimeout { ref request_id } if request_id == "waiter"
        ));
        assert_eq!(b.queue_depth(), 0);
        assert!(!b.request_id_in_use("waiter"));
        b.release(active, 23).expect("release active permit");
    }

    #[test]
    fn acquire_evicts_expired_waiter_before_granting_new_request() {
        let mut b = bulkhead_queue(1, 2, 5);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        assert!(matches!(
            b.acquire(RemoteCapLookup::Granted, "expired-waiter", 2),
            Err(BulkheadError::Queued { .. })
        ));
        b.release(active, 3).expect("release active permit");

        let fresh = b
            .acquire(true, "fresh", 7)
            .expect("expired waiter should be evicted before fresh acquire");

        assert_eq!(b.queue_depth(), 0);
        assert_eq!(b.current_in_flight(), 1);
        assert!(!b.request_id_in_use("expired-waiter"));
        b.release(fresh, 8).expect("release fresh permit");
    }

    #[test]
    fn active_queued_request_id_fails_poll_without_removing_waiter() {
        let mut b = bulkhead_queue(1, 2, 100);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        assert!(matches!(
            b.acquire(RemoteCapLookup::Granted, "waiter", 2),
            Err(BulkheadError::Queued { .. })
        ));
        b.active_request_ids.insert("waiter".to_string());
        b.release(active, 3).expect("release active permit");

        let err = b
            .poll_queued("waiter", 4)
            .expect_err("queued id already active should fail closed");

        assert!(matches!(
            err,
            BulkheadError::DuplicateRequest { ref request_id } if request_id == "waiter"
        ));
        assert_eq!(b.queue_depth(), 1);
    }

    #[test]
    fn permit_exhaustion_during_poll_removes_waiter_without_marking_active() {
        let mut b = bulkhead_queue(1, 2, 100);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        assert!(matches!(
            b.acquire(RemoteCapLookup::Granted, "waiter", 2),
            Err(BulkheadError::Queued { .. })
        ));
        b.release(active, 3).expect("release active permit");
        b.permit_ids_exhausted = true;

        let err = b
            .poll_queued("waiter", 4)
            .expect_err("exhausted permit ids should reject queued waiter");

        assert!(matches!(
            err,
            BulkheadError::PermitIdExhausted { ref request_id } if request_id == "waiter"
        ));
        assert_eq!(b.queue_depth(), 0);
        assert!(!b.active_request_ids.contains("waiter"));
        assert_eq!(b.current_in_flight(), 0);
    }

    #[test]
    fn drain_rejection_does_not_enqueue_request_under_queue_policy() {
        let mut b = bulkhead_queue(2, 2, 100);
        let first = b
            .acquire(RemoteCapLookup::Granted, "first", 1)
            .expect("first permit");
        let second = b
            .acquire(RemoteCapLookup::Granted, "second", 2)
            .expect("second permit");
        b.set_max_in_flight(1, 3).expect("reduce cap");

        let err = b
            .acquire(true, "drained-waiter", 4)
            .expect_err("draining should reject before queue admission");

        assert!(matches!(err, BulkheadError::Draining { .. }));
        assert_eq!(b.queue_depth(), 0);
        assert!(!b.request_id_in_use("drained-waiter"));
        b.release(first, 5).expect("release first");
        b.release(second, 6).expect("release second");
    }

    #[test]
    fn unknown_poll_before_expiry_keeps_waiter_and_logs_no_rejection() {
        let mut b = bulkhead_queue(1, 2, 100);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        assert!(matches!(
            b.acquire(RemoteCapLookup::Granted, "waiter", 2),
            Err(BulkheadError::Queued { .. })
        ));
        let events_before = b.events().len();

        let err = b
            .poll_queued("missing", 50)
            .expect_err("unknown request should not mutate live waiter");

        assert!(matches!(
            err,
            BulkheadError::UnknownRequest { ref request_id } if request_id == "missing"
        ));
        assert_eq!(b.queue_depth(), 1);
        assert_eq!(b.events().len(), events_before);
        b.release(active, 51).expect("release active permit");
    }

    #[test]
    fn non_front_waiter_poll_cannot_leapfrog_after_capacity_frees() {
        let mut b = bulkhead_queue(1, 3, 100);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        assert!(matches!(
            b.acquire(RemoteCapLookup::Granted, "front", 2),
            Err(BulkheadError::Queued { .. })
        ));
        assert!(matches!(
            b.acquire(RemoteCapLookup::Granted, "second", 3),
            Err(BulkheadError::Queued { .. })
        ));
        b.release(active, 4).expect("release active permit");

        let err = b
            .poll_queued("second", 5)
            .expect_err("second waiter must not leapfrog front waiter");

        assert!(matches!(
            err,
            BulkheadError::Queued {
                ref request_id,
                position,
                ..
            } if request_id == "second" && position == 2
        ));
        assert_eq!(b.queue_depth(), 2);
        assert_eq!(b.current_in_flight(), 0);
    }

    #[test]
    fn queue_saturated_does_not_mark_rejected_request_in_use() {
        let mut b = bulkhead_queue(1, 1, 100);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        assert!(matches!(
            b.acquire(RemoteCapLookup::Granted, "waiter", 2),
            Err(BulkheadError::Queued { .. })
        ));

        let err = b
            .acquire(true, "overflow", 3)
            .expect_err("full queue must reject overflow");

        assert!(matches!(
            err,
            BulkheadError::QueueSaturated { max_depth: 1 }
        ));
        assert_eq!(b.queue_depth(), 1);
        assert!(!b.request_id_in_use("overflow"));
        b.release(active, 4).expect("release active permit");
    }

    #[test]
    fn poll_request_id_with_trailing_space_does_not_evict_expired_waiter() {
        let mut b = bulkhead_queue(1, 2, 5);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        assert!(matches!(
            b.acquire(RemoteCapLookup::Granted, "waiter", 2),
            Err(BulkheadError::Queued { .. })
        ));

        let err = b
            .poll_queued("waiter ", 99)
            .expect_err("invalid poll id must fail before eviction");

        assert!(matches!(
            err,
            BulkheadError::InvalidRequestId { ref detail }
                if detail.contains("leading or trailing whitespace")
        ));
        assert_eq!(b.queue_depth(), 1);
        assert!(b.request_id_in_use("waiter"));
        b.release(active, 100).expect("release active permit");
    }

    #[test]
    fn request_id_with_delete_control_byte_is_rejected_without_event() {
        let mut b = bulkhead_reject(1);

        let err = b
            .acquire(true, "req\u{7f}", 1)
            .expect_err("delete control byte must fail closed");

        assert!(matches!(
            err,
            BulkheadError::InvalidRequestId { ref detail } if detail.contains("control")
        ));
        assert_eq!(b.current_in_flight(), 0);
        assert!(b.events().is_empty());
    }

    #[test]
    fn saturating_queue_deadline_does_not_timeout_before_u64_max() {
        let mut b = bulkhead_queue(1, 2, 10);
        let active = b
            .acquire(true, "active", u64::MAX - 5)
            .expect("active permit");
        assert!(matches!(
            b.acquire(RemoteCapLookup::Granted, "waiter", u64::MAX - 5),
            Err(BulkheadError::Queued { .. })
        ));

        let still_waiting = b
            .poll_queued("waiter", u64::MAX - 1)
            .expect_err("saturating deadline should not expire early");

        assert!(matches!(
            still_waiting,
            BulkheadError::Queued {
                ref request_id, ..
            } if request_id == "waiter"
        ));
        assert_eq!(b.queue_depth(), 1);

        let timed_out = b
            .poll_queued("waiter", u64::MAX)
            .expect_err("exact saturating deadline should timeout");

        assert!(matches!(
            timed_out,
            BulkheadError::QueueTimeout { ref request_id } if request_id == "waiter"
        ));
        assert_eq!(b.queue_depth(), 0);
        b.release(active, u64::MAX).expect("release active permit");
    }

    #[test]
    fn unknown_permit_release_does_not_change_queue_or_event_log() {
        let mut b = bulkhead_queue(1, 2, 100);
        let active = b
            .acquire(RemoteCapLookup::Granted, "active", 1)
            .expect("active permit");
        assert!(matches!(
            b.acquire(RemoteCapLookup::Granted, "waiter", 2),
            Err(BulkheadError::Queued { .. })
        ));
        let events_before = b.events().len();

        let err = b
            .release(
                BulkheadPermit {
                    permit_id: 999,
                    issued_at_ms: 0,
                    cap_snapshot: 1,
                },
                3,
            )
            .expect_err("unknown permit must fail closed");

        assert!(matches!(
            err,
            BulkheadError::UnknownPermit { permit_id: 999 }
        ));
        assert_eq!(b.current_in_flight(), 1);
        assert_eq!(b.queue_depth(), 1);
        assert_eq!(b.events().len(), events_before);
        b.release(active, 4).expect("release active permit");
    }
}
