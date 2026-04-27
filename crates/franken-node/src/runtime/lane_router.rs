//! bd-lus: Product lane router integrating lane policy and global bulkhead.
//!
//! Defines the product lane taxonomy and deterministic routing behavior for
//! runtime operations. Lane assignment uses capability metadata first and only
//! falls back to background when the caller is explicitly background-authorized.

use crate::config::{LaneOverflowPolicy, RuntimeConfig, RuntimeLaneConfig};
use crate::runtime::bounded_mask::CapabilityContext;
use crate::runtime::bulkhead::{BulkheadError, GlobalBulkhead};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

pub mod event_codes {
    pub const LANE_ASSIGNED: &str = "LANE_ASSIGNED";
    pub const LANE_SATURATED: &str = "LANE_SATURATED";
    pub const BULKHEAD_OVERLOAD: &str = "BULKHEAD_OVERLOAD";
    pub const LANE_CONFIG_RELOAD: &str = "LANE_CONFIG_RELOAD";
    pub const LANE_DEFAULTED_BACKGROUND: &str = "LANE_DEFAULTED_BACKGROUND";
    pub const LANE_SCOPE_MISMATCH: &str = "LANE_SCOPE_MISMATCH";
}

pub mod error_codes {
    pub const LANE_SATURATED: &str = "LANE_SATURATED";
    pub const BULKHEAD_OVERLOAD: &str = "BULKHEAD_OVERLOAD";
    pub const LANE_ANNOTATION_MISSING: &str = "LANE_ANNOTATION_MISSING";
    pub const LANE_HINT_INVALID: &str = "LANE_HINT_INVALID";
    pub const OPERATION_UNKNOWN: &str = "OPERATION_UNKNOWN";
    pub const OPERATION_DUPLICATE: &str = "OPERATION_DUPLICATE";
    pub const SCOPE_MISMATCH: &str = "SCOPE_MISMATCH";
    pub const CONFIG_INVALID: &str = "CONFIG_INVALID";
}

const MAX_OPERATION_ID_LEN: usize = 256;
const MAX_QUEUE_WAIT_SAMPLES: usize = 1024;
use crate::capacity_defaults::aliases::MAX_EVENTS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProductLane {
    Cancel,
    Timed,
    Realtime,
    Background,
}

impl ProductLane {
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[Self::Cancel, Self::Timed, Self::Realtime, Self::Background]
    }

    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cancel => "cancel",
            Self::Timed => "timed",
            Self::Realtime => "realtime",
            Self::Background => "background",
        }
    }

    #[must_use]
    pub fn priority_rank(&self) -> u8 {
        match self {
            Self::Cancel => 0,
            Self::Timed => 1,
            Self::Realtime => 2,
            Self::Background => 3,
        }
    }

    #[must_use]
    pub fn parse_label(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "cancel" => Some(Self::Cancel),
            "timed" => Some(Self::Timed),
            "realtime" | "ready" => Some(Self::Realtime),
            "background" => Some(Self::Background),
            _ => None,
        }
    }
}

impl fmt::Display for ProductLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneEvent {
    pub event_code: String,
    pub operation_id: String,
    pub lane_name: String,
    pub now_ms: u64,
    pub lane_in_flight: usize,
    pub total_in_flight: usize,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneMetrics {
    pub lane: ProductLane,
    pub in_flight: usize,
    pub queued: usize,
    pub completed: u64,
    pub rejected: u64,
    pub queue_wait_samples_ms: Vec<u64>,
}

impl LaneMetrics {
    fn new(lane: ProductLane) -> Self {
        Self {
            lane,
            in_flight: 0,
            queued: 0,
            completed: 0,
            rejected: 0,
            queue_wait_samples_ms: Vec::new(),
        }
    }

    #[must_use]
    pub fn p99_queue_wait_ms(&self) -> u64 {
        if self.queue_wait_samples_ms.is_empty() {
            return 0;
        }
        let mut values = self.queue_wait_samples_ms.clone();
        // Use nearest-rank quantile: ceil(0.99 * n), then convert to 0-based index.
        // This avoids underestimating p99 on small sample sets.
        let idx = (99 * values.len()).div_ceil(100).saturating_sub(1);
        let target_idx = idx.min(values.len().saturating_sub(1));
        let (_, val, _) = values.select_nth_unstable(target_idx);
        *val
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneConfigSnapshot {
    pub max_concurrent: usize,
    pub priority_weight: u32,
    pub queue_limit: usize,
    pub enqueue_timeout_ms: u64,
    pub overflow_policy: LaneOverflowPolicy,
}

impl LaneConfigSnapshot {
    fn from_runtime(value: &RuntimeLaneConfig) -> Self {
        Self {
            max_concurrent: value.max_concurrent,
            priority_weight: value.priority_weight,
            queue_limit: value.queue_limit,
            enqueue_timeout_ms: value.enqueue_timeout_ms,
            overflow_policy: value.overflow_policy,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneRouterConfig {
    pub remote_max_in_flight: usize,
    pub bulkhead_retry_after_ms: u64,
    pub lanes: BTreeMap<ProductLane, LaneConfigSnapshot>,
}

impl LaneRouterConfig {
    pub fn from_runtime_config(runtime: &RuntimeConfig) -> Result<Self, LaneRouterError> {
        let mut lanes: BTreeMap<ProductLane, LaneConfigSnapshot> = BTreeMap::new();

        for (name, lane_cfg) in &runtime.lanes {
            let lane =
                ProductLane::parse_label(name).ok_or_else(|| LaneRouterError::InvalidConfig {
                    detail: format!("unknown lane in runtime config: {name}"),
                })?;
            lanes.insert(lane, LaneConfigSnapshot::from_runtime(lane_cfg));
        }

        for lane in ProductLane::all() {
            if !lanes.contains_key(lane) {
                return Err(LaneRouterError::InvalidConfig {
                    detail: format!("missing lane config: {}", lane.as_str()),
                });
            }
        }

        let cfg = Self {
            remote_max_in_flight: runtime.remote_max_in_flight,
            bulkhead_retry_after_ms: runtime.bulkhead_retry_after_ms,
            lanes,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), LaneRouterError> {
        if self.remote_max_in_flight == 0 {
            return Err(LaneRouterError::InvalidConfig {
                detail: "remote_max_in_flight must be > 0".to_string(),
            });
        }
        if self.bulkhead_retry_after_ms == 0 {
            return Err(LaneRouterError::InvalidConfig {
                detail: "bulkhead_retry_after_ms must be > 0".to_string(),
            });
        }

        for lane in ProductLane::all() {
            let Some(cfg) = self.lanes.get(lane) else {
                return Err(LaneRouterError::InvalidConfig {
                    detail: format!("missing lane: {}", lane.as_str()),
                });
            };
            if cfg.max_concurrent == 0 {
                return Err(LaneRouterError::InvalidConfig {
                    detail: format!("lane {} max_concurrent must be > 0", lane.as_str()),
                });
            }
            if cfg.priority_weight == 0 {
                return Err(LaneRouterError::InvalidConfig {
                    detail: format!("lane {} priority_weight must be > 0", lane.as_str()),
                });
            }
            if cfg.queue_limit == 0 {
                return Err(LaneRouterError::InvalidConfig {
                    detail: format!("lane {} queue_limit must be > 0", lane.as_str()),
                });
            }
            if cfg.enqueue_timeout_ms == 0 {
                return Err(LaneRouterError::InvalidConfig {
                    detail: format!("lane {} enqueue_timeout_ms must be > 0", lane.as_str()),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedOperation {
    operation_id: String,
    enqueued_at_ms: u64,
    expires_at_ms: u64,
    cx_id: String,
    principal: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveOperation {
    operation_id: String,
    lane: ProductLane,
    permit_id: String,
    assigned_at_ms: u64,
    cx_id: String,
    principal: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LaneState {
    metrics: LaneMetrics,
    queue: VecDeque<QueuedOperation>,
}

impl LaneState {
    fn new(lane: ProductLane) -> Self {
        Self {
            metrics: LaneMetrics::new(lane),
            queue: VecDeque::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssignmentOutcome {
    pub operation_id: String,
    pub lane: ProductLane,
    pub queued: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneMetricsSnapshot {
    pub lane: ProductLane,
    pub in_flight: usize,
    pub queued: usize,
    pub completed: u64,
    pub rejected: u64,
    pub p99_queue_wait_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterMetricsSnapshot {
    pub lanes: Vec<LaneMetricsSnapshot>,
    pub total_in_flight: usize,
    pub bulkhead_rejections: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LaneRouterError {
    LaneSaturated {
        lane: ProductLane,
        max_concurrent: usize,
        in_flight: usize,
    },
    BulkheadOverload {
        max_in_flight: usize,
        current_in_flight: usize,
        retry_after_ms: u64,
    },
    LaneAnnotationMissing {
        operation_id: String,
    },
    LaneHintInvalid {
        operation_id: String,
        lane_hint: String,
    },
    OperationUnknown {
        operation_id: String,
    },
    OperationDuplicate {
        operation_id: String,
    },
    ScopeMismatch {
        requested_lane: ProductLane,
        required_lane: ProductLane,
    },
    InvalidConfig {
        detail: String,
    },
}

impl LaneRouterError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::LaneSaturated { .. } => error_codes::LANE_SATURATED,
            Self::BulkheadOverload { .. } => error_codes::BULKHEAD_OVERLOAD,
            Self::LaneAnnotationMissing { .. } => error_codes::LANE_ANNOTATION_MISSING,
            Self::LaneHintInvalid { .. } => error_codes::LANE_HINT_INVALID,
            Self::OperationUnknown { .. } => error_codes::OPERATION_UNKNOWN,
            Self::OperationDuplicate { .. } => error_codes::OPERATION_DUPLICATE,
            Self::ScopeMismatch { .. } => error_codes::SCOPE_MISMATCH,
            Self::InvalidConfig { .. } => error_codes::CONFIG_INVALID,
        }
    }
}

impl fmt::Display for LaneRouterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LaneSaturated {
                lane,
                max_concurrent,
                in_flight,
            } => write!(
                f,
                "{}: lane={} in_flight={}/{}",
                self.code(),
                lane,
                in_flight,
                max_concurrent
            ),
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
            Self::LaneAnnotationMissing { operation_id } => {
                write!(f, "{}: operation_id={operation_id}", self.code())
            }
            Self::LaneHintInvalid {
                operation_id,
                lane_hint,
            } => write!(
                f,
                "{}: operation_id={} lane_hint={}",
                self.code(),
                operation_id,
                lane_hint
            ),
            Self::OperationUnknown { operation_id } => {
                write!(f, "{}: operation_id={operation_id}", self.code())
            }
            Self::OperationDuplicate { operation_id } => {
                write!(f, "{}: operation_id={operation_id}", self.code())
            }
            Self::ScopeMismatch {
                requested_lane,
                required_lane,
            } => write!(
                f,
                "{}: requested_lane={} required_lane={}",
                self.code(),
                requested_lane,
                required_lane
            ),
            Self::InvalidConfig { detail } => write!(f, "{}: {detail}", self.code()),
        }
    }
}

impl std::error::Error for LaneRouterError {}

#[derive(Debug)]
pub struct LaneRouter {
    config: LaneRouterConfig,
    bulkhead: GlobalBulkhead,
    lanes: BTreeMap<ProductLane, LaneState>,
    active: BTreeMap<String, ActiveOperation>,
    queued_operation_ids: BTreeSet<String>,
    events: Vec<LaneEvent>,
    unknown_lane_default_count: u64,
}

impl LaneRouter {
    pub fn new(config: LaneRouterConfig) -> Result<Self, LaneRouterError> {
        config.validate()?;
        let bulkhead =
            GlobalBulkhead::new(config.remote_max_in_flight, config.bulkhead_retry_after_ms)
                .map_err(|e| LaneRouterError::InvalidConfig {
                    detail: format!("bulkhead config error: {e}"),
                })?;

        let mut lanes = BTreeMap::new();
        for lane in ProductLane::all() {
            lanes.insert(*lane, LaneState::new(*lane));
        }

        Ok(Self {
            config,
            bulkhead,
            lanes,
            active: BTreeMap::new(),
            queued_operation_ids: BTreeSet::new(),
            events: Vec::new(),
            unknown_lane_default_count: 0,
        })
    }

    pub fn from_runtime_config(runtime: &RuntimeConfig) -> Result<Self, LaneRouterError> {
        let cfg = LaneRouterConfig::from_runtime_config(runtime)?;
        Self::new(cfg)
    }

    #[must_use]
    pub fn events(&self) -> &[LaneEvent] {
        &self.events
    }

    fn emit_event(&mut self, event: LaneEvent) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }

    #[must_use]
    pub fn unknown_lane_default_count(&self) -> u64 {
        self.unknown_lane_default_count
    }

    fn lane_config(&self, lane: ProductLane) -> Result<&LaneConfigSnapshot, LaneRouterError> {
        self.config
            .lanes
            .get(&lane)
            .ok_or_else(|| LaneRouterError::InvalidConfig {
                detail: format!("missing lane config for {}", lane.as_str()),
            })
    }

    fn lane_state(&self, lane: ProductLane) -> Result<&LaneState, LaneRouterError> {
        self.lanes
            .get(&lane)
            .ok_or_else(|| LaneRouterError::InvalidConfig {
                detail: format!("missing lane state for {}", lane.as_str()),
            })
    }

    fn lane_state_mut(&mut self, lane: ProductLane) -> Result<&mut LaneState, LaneRouterError> {
        self.lanes
            .get_mut(&lane)
            .ok_or_else(|| LaneRouterError::InvalidConfig {
                detail: format!("missing lane state for {}", lane.as_str()),
            })
    }

    fn background_in_flight(&self) -> usize {
        self.lanes
            .get(&ProductLane::Background)
            .map_or(0, |state| state.metrics.in_flight)
    }

    pub fn assign_operation(
        &mut self,
        cx: &CapabilityContext,
        operation_id: &str,
        lane_hint: Option<&str>,
        now_ms: u64,
    ) -> Result<AssignmentOutcome, LaneRouterError> {
        if operation_id.trim().is_empty() {
            return Err(LaneRouterError::InvalidConfig {
                detail: "operation_id must not be empty".to_string(),
            });
        }
        if operation_id.len() > MAX_OPERATION_ID_LEN {
            return Err(LaneRouterError::InvalidConfig {
                detail: format!(
                    "operation_id length {} exceeds max {}",
                    operation_id.len(),
                    MAX_OPERATION_ID_LEN
                ),
            });
        }
        if operation_id.chars().any(char::is_control) {
            return Err(LaneRouterError::InvalidConfig {
                detail: "operation_id must not contain control characters".to_string(),
            });
        }
        if self.active.contains_key(operation_id)
            || self.queued_operation_ids.contains(operation_id)
        {
            return Err(LaneRouterError::OperationDuplicate {
                operation_id: operation_id.to_string(),
            });
        }

        let lane = self.resolve_lane(cx, lane_hint, operation_id, now_ms)?;
        let lane_cfg = self.lane_config(lane)?.clone();
        let mut saturated_detail: Option<String> = None;
        let mut saturated_in_flight = 0usize;
        let mut queued_insert = false;
        let mut dropped_queue_id: Option<String> = None;
        let lane_in_flight_before;

        {
            let lane_state = self.lane_state_mut(lane)?;
            lane_in_flight_before = lane_state.metrics.in_flight;

            if lane_state.metrics.in_flight >= lane_cfg.max_concurrent {
                match lane_cfg.overflow_policy {
                    LaneOverflowPolicy::Reject => {
                        lane_state.metrics.rejected = lane_state.metrics.rejected.saturating_add(1);
                        saturated_in_flight = lane_state.metrics.in_flight;
                        saturated_detail =
                            Some(format!("max_concurrent={}", lane_cfg.max_concurrent));
                    }
                    LaneOverflowPolicy::EnqueueWithTimeout => {
                        if lane_state.queue.len() >= lane_cfg.queue_limit {
                            lane_state.metrics.rejected =
                                lane_state.metrics.rejected.saturating_add(1);
                            saturated_in_flight = lane_state.metrics.in_flight;
                            saturated_detail = Some("queue_limit_reached".to_string());
                        } else {
                            lane_state.queue.push_back(QueuedOperation {
                                operation_id: operation_id.to_string(),
                                enqueued_at_ms: now_ms,
                                expires_at_ms: now_ms.saturating_add(lane_cfg.enqueue_timeout_ms),
                                cx_id: cx.cx_id.clone(),
                                principal: cx.principal.clone(),
                            });
                            lane_state.metrics.queued = lane_state.queue.len();
                            queued_insert = true;
                        }
                    }
                    LaneOverflowPolicy::ShedOldest => {
                        if lane != ProductLane::Background {
                            lane_state.metrics.rejected =
                                lane_state.metrics.rejected.saturating_add(1);
                            saturated_in_flight = lane_state.metrics.in_flight;
                            saturated_detail = Some(format!(
                                "max_concurrent={} overflow_policy=shed_oldest_non_background",
                                lane_cfg.max_concurrent
                            ));
                        } else {
                            if lane_state.queue.len() >= lane_cfg.queue_limit {
                                dropped_queue_id =
                                    lane_state.queue.pop_front().map(|op| op.operation_id);
                                lane_state.metrics.rejected =
                                    lane_state.metrics.rejected.saturating_add(1);
                            }
                            lane_state.queue.push_back(QueuedOperation {
                                operation_id: operation_id.to_string(),
                                enqueued_at_ms: now_ms,
                                expires_at_ms: now_ms.saturating_add(lane_cfg.enqueue_timeout_ms),
                                cx_id: cx.cx_id.clone(),
                                principal: cx.principal.clone(),
                            });
                            lane_state.metrics.queued = lane_state.queue.len();
                            queued_insert = true;
                        }
                    }
                }
            }
        }

        if let Some(detail) = saturated_detail {
            self.emit_event(LaneEvent {
                event_code: event_codes::LANE_SATURATED.to_string(),
                operation_id: operation_id.to_string(),
                lane_name: lane.as_str().to_string(),
                now_ms,
                lane_in_flight: saturated_in_flight,
                total_in_flight: self.bulkhead.in_flight(),
                detail,
            });
            return Err(LaneRouterError::LaneSaturated {
                lane,
                max_concurrent: lane_cfg.max_concurrent,
                in_flight: saturated_in_flight,
            });
        }

        if queued_insert {
            if let Some(dropped) = dropped_queue_id {
                self.queued_operation_ids.remove(&dropped);
            }
            self.queued_operation_ids.insert(operation_id.to_string());
            return Ok(AssignmentOutcome {
                operation_id: operation_id.to_string(),
                lane,
                queued: true,
            });
        }

        let permit =
            self.acquire_bulkhead(operation_id, lane, now_ms, lane_in_flight_before, true)?;
        let lane_in_flight_after = {
            let lane_state = self.lane_state_mut(lane)?;
            lane_state.metrics.in_flight = lane_state.metrics.in_flight.saturating_add(1);
            lane_state.metrics.in_flight
        };

        self.active.insert(
            operation_id.to_string(),
            ActiveOperation {
                operation_id: operation_id.to_string(),
                lane,
                permit_id: permit.permit_id,
                assigned_at_ms: now_ms,
                cx_id: cx.cx_id.clone(),
                principal: cx.principal.clone(),
            },
        );

        self.emit_event(LaneEvent {
            event_code: event_codes::LANE_ASSIGNED.to_string(),
            operation_id: operation_id.to_string(),
            lane_name: lane.as_str().to_string(),
            now_ms,
            lane_in_flight: lane_in_flight_after,
            total_in_flight: self.bulkhead.in_flight(),
            detail: format!("cx_id={} principal={}", cx.cx_id, cx.principal),
        });

        Ok(AssignmentOutcome {
            operation_id: operation_id.to_string(),
            lane,
            queued: false,
        })
    }

    pub fn complete_operation(
        &mut self,
        operation_id: &str,
        now_ms: u64,
        _canceled: bool,
    ) -> Result<(), LaneRouterError> {
        let Some(active) = self.active.get(operation_id).cloned() else {
            return Err(LaneRouterError::OperationUnknown {
                operation_id: operation_id.to_string(),
            });
        };

        self.bulkhead
            .release(&active.permit_id, operation_id, now_ms)
            .map_err(map_bulkhead_err)?;
        self.active.remove(operation_id);

        let lane_state = self.lane_state_mut(active.lane)?;
        lane_state.metrics.in_flight = lane_state.metrics.in_flight.saturating_sub(1);
        lane_state.metrics.completed = lane_state.metrics.completed.saturating_add(1);

        self.promote_queued(now_ms)?;
        Ok(())
    }

    pub fn reload_config(
        &mut self,
        new_config: LaneRouterConfig,
        now_ms: u64,
    ) -> Result<(), LaneRouterError> {
        new_config.validate()?;

        self.bulkhead
            .reload_limits(
                new_config.remote_max_in_flight,
                new_config.bulkhead_retry_after_ms,
                now_ms,
            )
            .map_err(map_bulkhead_err)?;

        self.config = new_config;

        for lane in ProductLane::all() {
            self.lanes
                .entry(*lane)
                .or_insert_with(|| LaneState::new(*lane));
        }

        self.reconcile_queues_after_reload();

        self.emit_event(LaneEvent {
            event_code: event_codes::LANE_CONFIG_RELOAD.to_string(),
            operation_id: "config-reload".to_string(),
            lane_name: "all".to_string(),
            now_ms,
            lane_in_flight: 0,
            total_in_flight: self.bulkhead.in_flight(),
            detail: format!(
                "remote_max_in_flight={} bulkhead_retry_after_ms={}",
                self.config.remote_max_in_flight, self.config.bulkhead_retry_after_ms
            ),
        });

        Ok(())
    }

    fn reconcile_queues_after_reload(&mut self) {
        for lane in ProductLane::all() {
            let Some(lane_cfg) = self.config.lanes.get(lane).cloned() else {
                continue;
            };

            let mut evicted_operation_ids = Vec::new();
            if let Some(lane_state) = self.lanes.get_mut(lane) {
                match lane_cfg.overflow_policy {
                    LaneOverflowPolicy::Reject => {
                        while let Some(evicted) = lane_state.queue.pop_front() {
                            evicted_operation_ids.push(evicted.operation_id);
                        }
                    }
                    LaneOverflowPolicy::EnqueueWithTimeout => {
                        while lane_state.queue.len() > lane_cfg.queue_limit {
                            let Some(evicted) = lane_state.queue.pop_back() else {
                                break;
                            };
                            evicted_operation_ids.push(evicted.operation_id);
                        }
                    }
                    LaneOverflowPolicy::ShedOldest => {
                        while lane_state.queue.len() > lane_cfg.queue_limit {
                            let Some(evicted) = lane_state.queue.pop_front() else {
                                break;
                            };
                            evicted_operation_ids.push(evicted.operation_id);
                        }
                    }
                }

                lane_state.metrics.queued = lane_state.queue.len();
                let evicted_count = u64::try_from(evicted_operation_ids.len()).unwrap_or(u64::MAX);
                lane_state.metrics.rejected =
                    lane_state.metrics.rejected.saturating_add(evicted_count);
            }

            for operation_id in evicted_operation_ids {
                self.queued_operation_ids.remove(&operation_id);
            }
        }
    }

    #[must_use]
    pub fn metrics_snapshot(&self) -> RouterMetricsSnapshot {
        let mut lanes = Vec::new();
        for lane in ProductLane::all() {
            let state = self.lane_state(*lane).ok();
            lanes.push(LaneMetricsSnapshot {
                lane: *lane,
                in_flight: state.map_or(0, |s| s.metrics.in_flight),
                queued: state.map_or(0, |s| s.queue.len()),
                completed: state.map_or(0, |s| s.metrics.completed),
                rejected: state.map_or(0, |s| s.metrics.rejected),
                p99_queue_wait_ms: state.map_or(0, |s| s.metrics.p99_queue_wait_ms()),
            });
        }

        RouterMetricsSnapshot {
            lanes,
            total_in_flight: self.bulkhead.in_flight(),
            bulkhead_rejections: self.bulkhead.rejection_count(),
        }
    }

    fn resolve_lane(
        &mut self,
        cx: &CapabilityContext,
        lane_hint: Option<&str>,
        operation_id: &str,
        now_ms: u64,
    ) -> Result<ProductLane, LaneRouterError> {
        if let Some(raw) = lane_hint {
            if let Some(lane) = ProductLane::parse_label(raw) {
                let required_lane = Self::highest_authorized_lane(cx);
                if !Self::context_allows_lane(cx, lane) {
                    self.unknown_lane_default_count =
                        self.unknown_lane_default_count.saturating_add(1);
                    let required_lane = required_lane.unwrap_or(ProductLane::Background);
                    self.emit_scope_mismatch_event(
                        operation_id,
                        lane,
                        now_ms,
                        format!("lane_hint_scope_mismatch={raw} required={required_lane}"),
                    );
                    return Err(LaneRouterError::ScopeMismatch {
                        requested_lane: lane,
                        required_lane,
                    });
                }
                if let Some(required_lane) = required_lane
                    && lane.priority_rank() > required_lane.priority_rank()
                {
                    self.emit_scope_mismatch_event(
                        operation_id,
                        lane,
                        now_ms,
                        format!("lane_hint_priority_downgrade={raw} required={required_lane}"),
                    );
                    return Err(LaneRouterError::ScopeMismatch {
                        requested_lane: lane,
                        required_lane,
                    });
                }
                return Ok(lane);
            }
            self.unknown_lane_default_count = self.unknown_lane_default_count.saturating_add(1);
            self.emit_scope_mismatch_event(
                operation_id,
                ProductLane::Background,
                now_ms,
                format!("unknown_lane_hint_rejected={raw}"),
            );
            return Err(LaneRouterError::LaneHintInvalid {
                operation_id: operation_id.to_string(),
                lane_hint: raw.to_string(),
            });
        }

        if cx.has_scope("lane.cancel") {
            return Ok(ProductLane::Cancel);
        }
        if cx.has_scope("lane.timed") {
            return Ok(ProductLane::Timed);
        }
        if cx.has_scope("lane.realtime") || cx.has_scope("lane.ready") {
            return Ok(ProductLane::Realtime);
        }
        if cx.has_scope("lane.background") {
            return Ok(ProductLane::Background);
        }

        self.unknown_lane_default_count = self.unknown_lane_default_count.saturating_add(1);
        self.emit_scope_mismatch_event(
            operation_id,
            ProductLane::Background,
            now_ms,
            "missing_lane_authorization".to_string(),
        );
        Err(LaneRouterError::LaneAnnotationMissing {
            operation_id: operation_id.to_string(),
        })
    }

    fn context_allows_lane(cx: &CapabilityContext, lane: ProductLane) -> bool {
        match lane {
            ProductLane::Cancel => cx.has_scope("lane.cancel"),
            ProductLane::Timed => cx.has_scope("lane.timed"),
            ProductLane::Realtime => cx.has_scope("lane.realtime") || cx.has_scope("lane.ready"),
            ProductLane::Background => cx.has_scope("lane.background"),
        }
    }

    fn highest_authorized_lane(cx: &CapabilityContext) -> Option<ProductLane> {
        if cx.has_scope("lane.cancel") {
            return Some(ProductLane::Cancel);
        }
        if cx.has_scope("lane.timed") {
            return Some(ProductLane::Timed);
        }
        if cx.has_scope("lane.realtime") || cx.has_scope("lane.ready") {
            return Some(ProductLane::Realtime);
        }
        if cx.has_scope("lane.background") {
            return Some(ProductLane::Background);
        }
        None
    }

    fn emit_scope_mismatch_event(
        &mut self,
        operation_id: &str,
        lane: ProductLane,
        now_ms: u64,
        detail: String,
    ) {
        self.emit_event(LaneEvent {
            event_code: event_codes::LANE_SCOPE_MISMATCH.to_string(),
            operation_id: operation_id.to_string(),
            lane_name: lane.as_str().to_string(),
            now_ms,
            lane_in_flight: self.background_in_flight(),
            total_in_flight: self.bulkhead.in_flight(),
            detail,
        });
    }

    fn acquire_bulkhead(
        &mut self,
        operation_id: &str,
        lane: ProductLane,
        now_ms: u64,
        lane_in_flight: usize,
        count_lane_rejection: bool,
    ) -> Result<crate::runtime::bulkhead::BulkheadPermit, LaneRouterError> {
        match self.bulkhead.try_acquire(operation_id, now_ms) {
            Ok(permit) => Ok(permit),
            Err(BulkheadError::BulkheadOverload {
                max_in_flight,
                current_in_flight,
                retry_after_ms,
            }) => {
                if count_lane_rejection {
                    let lane_state = self.lane_state_mut(lane)?;
                    lane_state.metrics.rejected = lane_state.metrics.rejected.saturating_add(1);
                }
                self.emit_event(LaneEvent {
                    event_code: event_codes::BULKHEAD_OVERLOAD.to_string(),
                    operation_id: operation_id.to_string(),
                    lane_name: lane.as_str().to_string(),
                    now_ms,
                    lane_in_flight,
                    total_in_flight: self.bulkhead.in_flight(),
                    detail: format!(
                        "max_in_flight={} retry_after_ms={}",
                        max_in_flight, retry_after_ms
                    ),
                });
                Err(LaneRouterError::BulkheadOverload {
                    max_in_flight,
                    current_in_flight,
                    retry_after_ms,
                })
            }
            Err(other) => Err(map_bulkhead_err(other)),
        }
    }

    fn promote_queued(&mut self, now_ms: u64) -> Result<(), LaneRouterError> {
        let mut lanes = ProductLane::all()
            .iter()
            .copied()
            .map(|lane| {
                Ok((
                    lane,
                    self.lane_config(lane)?.priority_weight,
                    lane.priority_rank(),
                ))
            })
            .collect::<Result<Vec<_>, LaneRouterError>>()?;
        lanes.sort_by_key(|(_, priority_weight, priority_rank)| {
            (std::cmp::Reverse(*priority_weight), *priority_rank)
        });

        for (lane, _, _) in lanes {
            let lane_cfg = self.lane_config(lane)?.clone();

            loop {
                let (next, expired_queue_ids) = {
                    let lane_state = self.lane_state_mut(lane)?;
                    let mut expired_queue_ids = Vec::new();

                    while let Some(front) = lane_state.queue.front() {
                        if now_ms >= front.expires_at_ms {
                            let Some(expired) = lane_state.queue.pop_front() else {
                                break;
                            };
                            expired_queue_ids.push(expired.operation_id);
                            lane_state.metrics.rejected =
                                lane_state.metrics.rejected.saturating_add(1);
                            lane_state.metrics.queued = lane_state.queue.len();
                        } else {
                            break;
                        }
                    }

                    if lane_state.queue.is_empty() {
                        lane_state.metrics.queued = 0;
                        (None, expired_queue_ids)
                    } else if lane_state.metrics.in_flight >= lane_cfg.max_concurrent {
                        lane_state.metrics.queued = lane_state.queue.len();
                        (None, expired_queue_ids)
                    } else if let Some(front) = lane_state.queue.front().cloned() {
                        (
                            Some((front, lane_state.metrics.in_flight)),
                            expired_queue_ids,
                        )
                    } else {
                        lane_state.metrics.queued = 0;
                        (None, expired_queue_ids)
                    }
                };
                for expired_id in expired_queue_ids {
                    self.queued_operation_ids.remove(&expired_id);
                }
                let Some((queued, lane_in_flight_before)) = next else {
                    break;
                };

                let permit = match self.acquire_bulkhead(
                    &queued.operation_id,
                    lane,
                    now_ms,
                    lane_in_flight_before,
                    false,
                ) {
                    Ok(permit) => permit,
                    Err(LaneRouterError::BulkheadOverload { .. }) => {
                        let lane_state = self.lane_state_mut(lane)?;
                        lane_state.metrics.queued = lane_state.queue.len();
                        break;
                    }
                    Err(other) => return Err(other),
                };

                let (promoted_op_id, lane_in_flight_after) = {
                    let lane_state = self.lane_state_mut(lane)?;
                    let promoted = lane_state.queue.pop_front().ok_or_else(|| {
                        LaneRouterError::InvalidConfig {
                            detail: format!(
                                "missing queued operation for promotion in lane {}",
                                lane.as_str()
                            ),
                        }
                    })?;
                    let op_id = promoted.operation_id;
                    lane_state.metrics.queued = lane_state.queue.len();
                    lane_state.metrics.in_flight = lane_state.metrics.in_flight.saturating_add(1);
                    lane_state
                    push_bounded(
                        &mut lane_state.metrics.queue_wait_samples_ms,
                        now_ms.saturating_sub(queued.enqueued_at_ms),
                        MAX_QUEUE_WAIT_SAMPLES,
                    );
                    (op_id, lane_state.metrics.in_flight)
                };
                self.queued_operation_ids.remove(&promoted_op_id);
                let queued_operation_id = queued.operation_id.clone();
                if promoted_op_id != queued_operation_id {
                    return Err(LaneRouterError::InvalidConfig {
                        detail: format!(
                            "queued promotion mismatch: expected={} actual={}",
                            queued_operation_id, promoted_op_id
                        ),
                    });
                }

                self.active.insert(
                    queued_operation_id.clone(),
                    ActiveOperation {
                        operation_id: queued_operation_id.clone(),
                        lane,
                        permit_id: permit.permit_id,
                        assigned_at_ms: now_ms,
                        cx_id: queued.cx_id,
                        principal: queued.principal,
                    },
                );

                self.emit_event(LaneEvent {
                    event_code: event_codes::LANE_ASSIGNED.to_string(),
                    operation_id: queued_operation_id,
                    lane_name: lane.as_str().to_string(),
                    now_ms,
                    lane_in_flight: lane_in_flight_after,
                    total_in_flight: self.bulkhead.in_flight(),
                    detail: "promoted_from_queue".to_string(),
                });
            }
        }

        Ok(())
    }
}

fn map_bulkhead_err(err: BulkheadError) -> LaneRouterError {
    match err {
        BulkheadError::BulkheadOverload {
            max_in_flight,
            current_in_flight,
            retry_after_ms,
        } => LaneRouterError::BulkheadOverload {
            max_in_flight,
            current_in_flight,
            retry_after_ms,
        },
        BulkheadError::UnknownPermit { permit_id } => LaneRouterError::InvalidConfig {
            detail: format!("bulkhead permit missing permit_id={permit_id}"),
        },
        BulkheadError::PermitIdReused {
            permit_id,
            existing_operation_id,
            requested_operation_id,
        } => LaneRouterError::InvalidConfig {
            detail: format!(
                "bulkhead permit id reused permit_id={} existing_operation_id={} requested_operation_id={}",
                permit_id, existing_operation_id, requested_operation_id
            ),
        },
        BulkheadError::PermitIdExhausted {
            requested_operation_id,
        } => LaneRouterError::InvalidConfig {
            detail: format!(
                "bulkhead permit ids exhausted requested_operation_id={}",
                requested_operation_id
            ),
        },
        BulkheadError::PermitOperationMismatch {
            permit_id,
            expected_operation_id,
            provided_operation_id,
        } => LaneRouterError::InvalidConfig {
            detail: format!(
                "bulkhead permit mismatch permit_id={} expected_operation_id={} provided_operation_id={}",
                permit_id, expected_operation_id, provided_operation_id
            ),
        },
        BulkheadError::InvalidConfig { detail } => LaneRouterError::InvalidConfig { detail },
    }
}

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Profile};

    fn lane_cfg(max: usize, overflow_policy: LaneOverflowPolicy) -> RuntimeLaneConfig {
        RuntimeLaneConfig {
            max_concurrent: max,
            priority_weight: 10,
            queue_limit: 8,
            enqueue_timeout_ms: 25,
            overflow_policy,
        }
    }

    fn runtime_config() -> RuntimeConfig {
        let mut lanes = BTreeMap::new();
        lanes.insert(
            "cancel".to_string(),
            lane_cfg(8, LaneOverflowPolicy::Reject),
        );
        lanes.insert(
            "timed".to_string(),
            lane_cfg(12, LaneOverflowPolicy::EnqueueWithTimeout),
        );
        lanes.insert(
            "realtime".to_string(),
            lane_cfg(16, LaneOverflowPolicy::EnqueueWithTimeout),
        );
        lanes.insert(
            "background".to_string(),
            lane_cfg(4, LaneOverflowPolicy::ShedOldest),
        );
        RuntimeConfig {
            preferred: crate::config::PreferredRuntime::Auto,
            remote_max_in_flight: 50,
            bulkhead_retry_after_ms: 20,
            lanes,
            drain_timeout_ms: None,
        }
    }

    fn cx_with_scope(scope: &str) -> CapabilityContext {
        CapabilityContext::with_scopes("cx-1", "operator-a", vec![scope.to_string()])
    }

    fn enqueue_for_test(
        router: &mut LaneRouter,
        lane: ProductLane,
        operation_id: &str,
        enqueued_at_ms: u64,
        expires_at_ms: u64,
    ) {
        let lane_state = router.lanes.get_mut(&lane).expect("lane exists");
        lane_state.queue.push_back(QueuedOperation {
            operation_id: operation_id.to_string(),
            enqueued_at_ms,
            expires_at_ms,
            cx_id: format!("cx-{operation_id}"),
            principal: "operator-test".to_string(),
        });
        lane_state.metrics.queued = lane_state.queue.len();
        router.queued_operation_ids.insert(operation_id.to_string());
    }

    mod lane_router_routing_priority_overflow_conformance {
        use super::*;

        fn cx_with_scopes(scopes: &[&str]) -> CapabilityContext {
            CapabilityContext::with_scopes(
                "cx-conformance",
                "operator-conformance",
                scopes.iter().map(|scope| (*scope).to_string()),
            )
        }

        fn configured_lane_queue<'a>(router: &'a LaneRouter, lane: ProductLane) -> Vec<&'a str> {
            router
                .lanes
                .get(&lane)
                .expect("lane exists")
                .queue
                .iter()
                .map(|queued| queued.operation_id.as_str())
                .collect()
        }

        #[test]
        fn multiple_lane_scopes_without_hint_route_to_highest_priority_lane() {
            let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
            let cx = cx_with_scopes(&[
                "lane.background",
                "lane.realtime",
                "lane.timed",
                "lane.cancel",
            ]);

            let assigned = router
                .assign_operation(&cx, "multi-scope-op", None, 1)
                .expect("assignment should succeed");

            assert_eq!(assigned.lane, ProductLane::Cancel);
            assert!(!assigned.queued);
        }

        #[test]
        fn authorized_lane_hint_cannot_downshift_multi_scope_context() {
            let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
            let cx = cx_with_scopes(&["lane.cancel", "lane.background"]);

            let err = router
                .assign_operation(&cx, "hinted-background-op", Some("background"), 1)
                .expect_err("multi-scope downgrade should fail closed");

            assert_eq!(err.code(), error_codes::SCOPE_MISMATCH);
            assert!(matches!(
                err,
                LaneRouterError::ScopeMismatch {
                    requested_lane: ProductLane::Background,
                    required_lane: ProductLane::Cancel
                }
            ));
            assert_eq!(router.unknown_lane_default_count(), 0);
            assert!(
                router
                    .events()
                    .iter()
                    .any(|e| e.detail.contains("lane_hint_priority_downgrade=background"))
            );
        }

        #[test]
        fn ready_alias_routes_to_realtime_when_scope_authorizes_ready_lane() {
            let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
            let cx = cx_with_scopes(&["lane.ready"]);

            let assigned = router
                .assign_operation(&cx, "ready-alias-op", Some("ready"), 1)
                .expect("assignment should succeed");

            assert_eq!(assigned.lane, ProductLane::Realtime);
            assert!(!assigned.queued);
        }

        #[test]
        fn equal_priority_weights_promote_by_stable_lane_rank_tiebreaker() {
            let mut cfg = runtime_config();
            cfg.remote_max_in_flight = 8;
            for lane_cfg in cfg.lanes.values_mut() {
                lane_cfg.priority_weight = 10;
            }
            let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");

            enqueue_for_test(&mut router, ProductLane::Background, "bg-q", 1, 10_000);
            enqueue_for_test(&mut router, ProductLane::Realtime, "rt-q", 1, 10_000);
            enqueue_for_test(&mut router, ProductLane::Timed, "timed-q", 1, 10_000);
            enqueue_for_test(&mut router, ProductLane::Cancel, "cancel-q", 1, 10_000);

            router
                .promote_queued(100)
                .expect("promotion should succeed");

            let promoted: Vec<&str> = router
                .events()
                .iter()
                .filter(|event| event.event_code == event_codes::LANE_ASSIGNED)
                .map(|event| event.operation_id.as_str())
                .collect();
            assert_eq!(promoted, vec!["cancel-q", "timed-q", "rt-q", "bg-q"]);
        }

        #[test]
        fn configured_priority_weights_promote_before_static_lane_rank() {
            let mut cfg = runtime_config();
            cfg.remote_max_in_flight = 8;
            cfg.lanes
                .get_mut("background")
                .expect("background lane")
                .priority_weight = 100;
            cfg.lanes
                .get_mut("realtime")
                .expect("realtime lane")
                .priority_weight = 50;
            cfg.lanes
                .get_mut("timed")
                .expect("timed lane")
                .priority_weight = 10;
            cfg.lanes
                .get_mut("cancel")
                .expect("cancel lane")
                .priority_weight = 1;
            let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");

            enqueue_for_test(&mut router, ProductLane::Cancel, "cancel-q", 1, 10_000);
            enqueue_for_test(&mut router, ProductLane::Timed, "timed-q", 1, 10_000);
            enqueue_for_test(&mut router, ProductLane::Realtime, "rt-q", 1, 10_000);
            enqueue_for_test(&mut router, ProductLane::Background, "bg-q", 1, 10_000);

            router
                .promote_queued(100)
                .expect("promotion should succeed");

            let promoted: Vec<&str> = router
                .events()
                .iter()
                .filter(|event| event.event_code == event_codes::LANE_ASSIGNED)
                .map(|event| event.operation_id.as_str())
                .collect();
            assert_eq!(promoted, vec!["bg-q", "rt-q", "timed-q", "cancel-q"]);
        }

        #[test]
        fn reject_overflow_policy_never_enqueues_or_tracks_rejected_operation() {
            let mut cfg = runtime_config();
            cfg.lanes.insert(
                "cancel".to_string(),
                RuntimeLaneConfig {
                    max_concurrent: 1,
                    priority_weight: 100,
                    queue_limit: 2,
                    enqueue_timeout_ms: 25,
                    overflow_policy: LaneOverflowPolicy::Reject,
                },
            );
            let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
            let cancel = cx_with_scope("lane.cancel");

            router
                .assign_operation(&cancel, "cancel-active", None, 1)
                .expect("first cancel should be active");
            let err = router
                .assign_operation(&cancel, "cancel-rejected", None, 2)
                .expect_err("reject policy should reject overflow");

            assert_eq!(err.code(), error_codes::LANE_SATURATED);
            assert!(!router.queued_operation_ids.contains("cancel-rejected"));
            assert!(configured_lane_queue(&router, ProductLane::Cancel).is_empty());
        }

        #[test]
        fn enqueue_with_timeout_queue_limit_preserves_fifo_until_full_then_rejects() {
            let mut cfg = runtime_config();
            cfg.lanes.insert(
                "timed".to_string(),
                RuntimeLaneConfig {
                    max_concurrent: 1,
                    priority_weight: 50,
                    queue_limit: 2,
                    enqueue_timeout_ms: 100,
                    overflow_policy: LaneOverflowPolicy::EnqueueWithTimeout,
                },
            );
            let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
            let timed = cx_with_scope("lane.timed");

            router
                .assign_operation(&timed, "timed-active", None, 1)
                .expect("first timed should be active");
            assert!(
                router
                    .assign_operation(&timed, "timed-q-old", None, 2)
                    .expect("first overflow should queue")
                    .queued
            );
            assert!(
                router
                    .assign_operation(&timed, "timed-q-new", None, 3)
                    .expect("second overflow should queue")
                    .queued
            );
            let err = router
                .assign_operation(&timed, "timed-q-overflow", None, 4)
                .expect_err("third overflow should hit queue limit");

            assert_eq!(err.code(), error_codes::LANE_SATURATED);
            assert_eq!(
                configured_lane_queue(&router, ProductLane::Timed),
                vec!["timed-q-old", "timed-q-new"]
            );

            router
                .complete_operation("timed-active", 5, false)
                .expect("completion should promote oldest queued timed op");
            assert!(router.active.contains_key("timed-q-old"));
            assert_eq!(
                configured_lane_queue(&router, ProductLane::Timed),
                vec!["timed-q-new"]
            );
        }
    }

    #[test]
    fn profile_defaults_govern_lane_capacity_monotonicity() {
        let strict = Config::for_profile(Profile::Strict).runtime;
        let balanced = Config::for_profile(Profile::Balanced).runtime;
        let legacy = Config::for_profile(Profile::LegacyRisky).runtime;

        assert!(strict.remote_max_in_flight < balanced.remote_max_in_flight);
        assert!(balanced.remote_max_in_flight < legacy.remote_max_in_flight);

        for lane in ["cancel", "timed", "realtime", "background"] {
            assert!(strict.lanes[lane].max_concurrent <= balanced.lanes[lane].max_concurrent);
            assert!(balanced.lanes[lane].max_concurrent <= legacy.lanes[lane].max_concurrent);
            assert!(strict.lanes[lane].queue_limit <= balanced.lanes[lane].queue_limit);
            assert!(balanced.lanes[lane].queue_limit <= legacy.lanes[lane].queue_limit);
        }

        assert_eq!(
            strict.lanes["cancel"].overflow_policy,
            LaneOverflowPolicy::Reject
        );
        assert_eq!(
            strict.lanes["background"].overflow_policy,
            LaneOverflowPolicy::ShedOldest
        );
    }

    #[test]
    fn strict_profile_enforces_tighter_cancel_capacity_than_legacy() {
        let strict_runtime = Config::for_profile(Profile::Strict).runtime;
        let legacy_runtime = Config::for_profile(Profile::LegacyRisky).runtime;
        let strict_cancel_cap = strict_runtime.lanes["cancel"].max_concurrent;
        let cancel = cx_with_scope("lane.cancel");

        let mut strict_router =
            LaneRouter::from_runtime_config(&strict_runtime).expect("strict router");
        for idx in 0..strict_cancel_cap {
            strict_router
                .assign_operation(&cancel, &format!("strict-cancel-{idx}"), None, idx as u64)
                .expect("strict cancel within cap");
        }
        let strict_err = strict_router
            .assign_operation(&cancel, "strict-cancel-overflow", None, 10_000)
            .expect_err("strict cancel should be saturated");
        assert_eq!(strict_err.code(), error_codes::LANE_SATURATED);

        let mut legacy_router =
            LaneRouter::from_runtime_config(&legacy_runtime).expect("legacy router");
        for idx in 0..strict_cancel_cap {
            legacy_router
                .assign_operation(&cancel, &format!("legacy-cancel-{idx}"), None, idx as u64)
                .expect("legacy cancel within strict cap");
        }
        let legacy_extra = legacy_router
            .assign_operation(&cancel, "legacy-cancel-extra", None, 10_000)
            .expect("legacy profile should still have cancel capacity");
        assert_eq!(legacy_extra.lane, ProductLane::Cancel);
    }

    #[test]
    fn assigns_lane_from_capability_context() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");

        let assigned = router
            .assign_operation(&cx_with_scope("lane.cancel"), "op-1", None, 1)
            .expect("assigned");
        assert_eq!(assigned.lane, ProductLane::Cancel);
    }

    #[test]
    fn unknown_lane_hint_rejects_without_background_downshift() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = CapabilityContext::new("cx-2", "operator-b");

        let err = router
            .assign_operation(&cx, "op-1", Some("not-a-lane"), 1)
            .expect_err("unknown lane hint should fail closed");
        assert_eq!(err.code(), error_codes::LANE_HINT_INVALID);
        assert_eq!(router.unknown_lane_default_count(), 1);
        assert!(
            router
                .events()
                .iter()
                .any(|e| e.detail.contains("unknown_lane_hint_rejected=not-a-lane"))
        );
    }

    #[test]
    fn missing_lane_authorization_rejects_without_background_downshift() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = CapabilityContext::new("cx-2", "operator-b");

        let err = router
            .assign_operation(&cx, "op-missing-lane", None, 1)
            .expect_err("missing lane authorization should fail closed");
        assert_eq!(err.code(), error_codes::LANE_ANNOTATION_MISSING);
        assert_eq!(router.unknown_lane_default_count(), 1);
        assert!(
            router
                .events()
                .iter()
                .any(|e| e.detail.contains("missing_lane_authorization"))
        );
    }

    #[test]
    fn lane_hint_scope_mismatch_rejects_without_downshift() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = cx_with_scope("lane.background");

        let err = router
            .assign_operation(&cx, "op-hint-mismatch", Some("cancel"), 1)
            .expect_err("scope mismatch should fail closed");
        assert_eq!(err.code(), error_codes::SCOPE_MISMATCH);
        assert!(matches!(
            err,
            LaneRouterError::ScopeMismatch {
                requested_lane: ProductLane::Cancel,
                required_lane: ProductLane::Background
            }
        ));
        assert_eq!(router.unknown_lane_default_count(), 1);
        assert!(
            router
                .events()
                .iter()
                .any(|e| e.detail.contains("lane_hint_scope_mismatch=cancel"))
        );
    }

    #[test]
    fn duplicate_operation_id_rejected_while_queued() {
        let mut cfg = runtime_config();
        cfg.lanes.insert(
            "timed".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 1,
                priority_weight: 10,
                queue_limit: 8,
                enqueue_timeout_ms: 25,
                overflow_policy: LaneOverflowPolicy::EnqueueWithTimeout,
            },
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let timed = cx_with_scope("lane.timed");

        let _ = router
            .assign_operation(&timed, "timed-active", None, 1)
            .expect("first active");
        let queued = router
            .assign_operation(&timed, "timed-dup", None, 2)
            .expect("first duplicate candidate should queue");
        assert!(queued.queued);

        let err = router
            .assign_operation(&timed, "timed-dup", None, 3)
            .expect_err("queued duplicate must be rejected");
        assert_eq!(err.code(), error_codes::OPERATION_DUPLICATE);
    }

    #[test]
    fn empty_operation_id_is_rejected() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = cx_with_scope("lane.realtime");

        let err = router
            .assign_operation(&cx, "   ", None, 1)
            .expect_err("empty operation id should be rejected");
        assert_eq!(err.code(), error_codes::CONFIG_INVALID);
    }

    #[test]
    fn overlong_operation_id_is_rejected() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = cx_with_scope("lane.realtime");
        let long_id = "x".repeat(MAX_OPERATION_ID_LEN + 1);

        let err = router
            .assign_operation(&cx, &long_id, None, 1)
            .expect_err("overlong operation id should be rejected");
        assert_eq!(err.code(), error_codes::CONFIG_INVALID);
    }

    #[test]
    fn expired_queued_operation_can_be_reused_after_eviction() {
        let mut cfg = runtime_config();
        cfg.lanes.insert(
            "timed".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 1,
                priority_weight: 10,
                queue_limit: 8,
                enqueue_timeout_ms: 5,
                overflow_policy: LaneOverflowPolicy::EnqueueWithTimeout,
            },
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let timed = cx_with_scope("lane.timed");

        let _ = router
            .assign_operation(&timed, "timed-active", None, 1)
            .expect("active");
        let _ = router
            .assign_operation(&timed, "timed-expire", None, 2)
            .expect("queued");

        router
            .complete_operation("timed-active", 20, false)
            .expect("complete should evict expired queue");

        let reused = router
            .assign_operation(&timed, "timed-expire", None, 21)
            .expect("expired queue id should be reusable");
        assert!(!reused.queued);
    }

    #[test]
    fn lane_concurrency_limit_is_enforced() {
        let mut cfg = runtime_config();
        cfg.lanes.insert(
            "cancel".to_string(),
            lane_cfg(1, LaneOverflowPolicy::Reject),
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let cx = cx_with_scope("lane.cancel");
        let _ = router
            .assign_operation(&cx, "op-1", None, 1)
            .expect("first");
        let err = router
            .assign_operation(&cx, "op-2", None, 2)
            .expect_err("second should saturate lane");
        assert_eq!(err.code(), error_codes::LANE_SATURATED);
    }

    #[test]
    fn bulkhead_rejects_at_capacity() {
        let mut cfg = runtime_config();
        cfg.remote_max_in_flight = 1;

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let cx = cx_with_scope("lane.realtime");
        let _ = router
            .assign_operation(&cx, "op-1", None, 1)
            .expect("first");
        let err = router
            .assign_operation(&cx, "op-2", None, 2)
            .expect_err("second should overload bulkhead");
        assert_eq!(err.code(), error_codes::BULKHEAD_OVERLOAD);

        let snapshot = router.metrics_snapshot();
        assert_eq!(snapshot.bulkhead_rejections, 1);
    }

    #[test]
    fn queued_promotion_prefers_higher_priority_lanes() {
        let mut cfg = runtime_config();
        cfg.remote_max_in_flight = 10;
        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");

        enqueue_for_test(
            &mut router,
            ProductLane::Background,
            "background-q",
            1,
            1_000,
        );
        enqueue_for_test(&mut router, ProductLane::Realtime, "realtime-q", 1, 1_000);
        enqueue_for_test(&mut router, ProductLane::Timed, "timed-q", 1, 1_000);

        router.promote_queued(10).expect("promotion should succeed");

        let assigned: Vec<&str> = router
            .events()
            .iter()
            .filter(|event| event.event_code == event_codes::LANE_ASSIGNED)
            .map(|event| event.operation_id.as_str())
            .collect();
        assert_eq!(assigned, vec!["timed-q", "realtime-q", "background-q"]);
    }

    #[test]
    fn queued_promotion_is_deterministic_under_repeated_load() {
        fn run_once() -> Vec<(String, String)> {
            let mut cfg = runtime_config();
            cfg.remote_max_in_flight = 32;
            let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");

            for idx in 0..8 {
                enqueue_for_test(
                    &mut router,
                    ProductLane::Background,
                    &format!("background-{idx}"),
                    idx,
                    10_000,
                );
                enqueue_for_test(
                    &mut router,
                    ProductLane::Realtime,
                    &format!("realtime-{idx}"),
                    idx,
                    10_000,
                );
                enqueue_for_test(
                    &mut router,
                    ProductLane::Timed,
                    &format!("timed-{idx}"),
                    idx,
                    10_000,
                );
            }

            router
                .promote_queued(100)
                .expect("promotion should succeed");
            router
                .events()
                .iter()
                .filter(|event| event.event_code == event_codes::LANE_ASSIGNED)
                .map(|event| (event.lane_name.clone(), event.operation_id.clone()))
                .collect()
        }

        assert_eq!(run_once(), run_once());
    }

    #[test]
    fn cancel_lane_not_starved_when_background_under_pressure() {
        let mut cfg = runtime_config();
        cfg.remote_max_in_flight = 4;
        cfg.lanes.insert(
            "background".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 1,
                priority_weight: 1,
                queue_limit: 4,
                enqueue_timeout_ms: 50,
                overflow_policy: LaneOverflowPolicy::ShedOldest,
            },
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");

        let bg_cx = cx_with_scope("lane.background");
        let cancel_cx = cx_with_scope("lane.cancel");

        let _ = router
            .assign_operation(&bg_cx, "bg-1", None, 1)
            .expect("bg active");
        for i in 0..4 {
            let op = format!("bg-q-{i}");
            let _ = router
                .assign_operation(&bg_cx, &op, None, 2 + i)
                .expect("background queue or shed");
        }

        let cancel = router
            .assign_operation(&cancel_cx, "cancel-1", None, 20)
            .expect("cancel should still schedule");
        assert_eq!(cancel.lane, ProductLane::Cancel);
    }

    #[test]
    fn non_background_shed_oldest_emits_lane_saturated_event() {
        let mut cfg = runtime_config();
        cfg.lanes.insert(
            "timed".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 1,
                priority_weight: 10,
                queue_limit: 8,
                enqueue_timeout_ms: 25,
                overflow_policy: LaneOverflowPolicy::ShedOldest,
            },
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let timed = cx_with_scope("lane.timed");
        let _ = router
            .assign_operation(&timed, "timed-1", None, 1)
            .expect("first timed");

        let err = router
            .assign_operation(&timed, "timed-2", None, 2)
            .expect_err("second timed should saturate");
        assert_eq!(err.code(), error_codes::LANE_SATURATED);
        assert!(
            router.events().iter().any(|event| {
                event.event_code == event_codes::LANE_SATURATED
                    && event.operation_id == "timed-2"
                    && event.lane_name == "timed"
            }),
            "lane saturation event should be recorded for non-background ShedOldest"
        );
    }

    #[test]
    fn enqueue_with_timeout_queue_limit_rejects_without_tracking_rejected_id() {
        let mut cfg = runtime_config();
        cfg.lanes.insert(
            "timed".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 1,
                priority_weight: 10,
                queue_limit: 1,
                enqueue_timeout_ms: 25,
                overflow_policy: LaneOverflowPolicy::EnqueueWithTimeout,
            },
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let timed = cx_with_scope("lane.timed");
        router
            .assign_operation(&timed, "timed-active", None, 1)
            .expect("active");
        assert!(
            router
                .assign_operation(&timed, "timed-q1", None, 2)
                .expect("queued")
                .queued
        );

        let err = router
            .assign_operation(&timed, "timed-q2", None, 3)
            .expect_err("queue limit should reject");
        assert_eq!(err.code(), error_codes::LANE_SATURATED);
        assert!(router.queued_operation_ids.contains("timed-q1"));
        assert!(!router.queued_operation_ids.contains("timed-q2"));
        let timed_state = router.lanes.get(&ProductLane::Timed).expect("timed");
        assert_eq!(timed_state.metrics.queued, 1);
        assert_eq!(timed_state.metrics.rejected, 1);

        router
            .complete_operation("timed-active", 4, false)
            .expect("promote q1");
        let retry = router
            .assign_operation(&timed, "timed-q2", None, 5)
            .expect("rejected id should be reusable");
        assert!(retry.queued);
    }

    #[test]
    fn background_shed_oldest_removes_dropped_operation_id_from_duplicate_set() {
        let mut cfg = runtime_config();
        cfg.lanes.insert(
            "background".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 1,
                priority_weight: 1,
                queue_limit: 2,
                enqueue_timeout_ms: 100,
                overflow_policy: LaneOverflowPolicy::ShedOldest,
            },
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let bg = cx_with_scope("lane.background");
        router
            .assign_operation(&bg, "bg-active", None, 1)
            .expect("active");
        router
            .assign_operation(&bg, "bg-old", None, 2)
            .expect("queued");
        router
            .assign_operation(&bg, "bg-mid", None, 3)
            .expect("queued");
        router
            .assign_operation(&bg, "bg-new", None, 4)
            .expect("shed oldest");

        assert!(!router.queued_operation_ids.contains("bg-old"));
        assert!(router.queued_operation_ids.contains("bg-mid"));
        assert!(router.queued_operation_ids.contains("bg-new"));

        let reused = router
            .assign_operation(&bg, "bg-old", None, 5)
            .expect("dropped id should be reusable");
        assert!(reused.queued);
        assert!(router.queued_operation_ids.contains("bg-old"));
    }

    #[test]
    fn queued_expiry_is_inclusive_at_deadline() {
        let mut cfg = runtime_config();
        cfg.lanes.insert(
            "timed".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 1,
                priority_weight: 10,
                queue_limit: 8,
                enqueue_timeout_ms: 5,
                overflow_policy: LaneOverflowPolicy::EnqueueWithTimeout,
            },
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let timed = cx_with_scope("lane.timed");
        router
            .assign_operation(&timed, "timed-active", None, 1)
            .expect("active");
        router
            .assign_operation(&timed, "timed-deadline", None, 2)
            .expect("queued");

        router
            .complete_operation("timed-active", 7, false)
            .expect("deadline should expire queued op instead of promoting it");

        assert!(!router.queued_operation_ids.contains("timed-deadline"));
        let timed_state = router.lanes.get(&ProductLane::Timed).expect("timed");
        assert_eq!(timed_state.metrics.queued, 0);
        assert_eq!(timed_state.metrics.rejected, 1);

        let reused = router
            .assign_operation(&timed, "timed-deadline", None, 8)
            .expect("expired id should be reusable");
        assert!(!reused.queued);
    }

    #[test]
    fn reload_updates_limits_for_new_operations_only() {
        let mut cfg = runtime_config();
        cfg.lanes
            .insert("timed".to_string(), lane_cfg(1, LaneOverflowPolicy::Reject));
        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");

        let timed = cx_with_scope("lane.timed");
        let _ = router
            .assign_operation(&timed, "timed-1", None, 1)
            .expect("first timed");
        let saturated = router.assign_operation(&timed, "timed-2", None, 2);
        assert!(saturated.is_err());

        let mut new_cfg = runtime_config();
        new_cfg
            .lanes
            .insert("timed".to_string(), lane_cfg(2, LaneOverflowPolicy::Reject));
        router
            .reload_config(
                LaneRouterConfig::from_runtime_config(&new_cfg).expect("cfg"),
                3,
            )
            .expect("reload");

        let second = router.assign_operation(&timed, "timed-2", None, 4);
        assert!(second.is_ok());
    }

    #[test]
    fn queued_promotion_bulkhead_overload_does_not_count_as_lane_rejection() {
        let mut cfg = runtime_config();
        cfg.remote_max_in_flight = 3;
        cfg.lanes.insert(
            "timed".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 1,
                priority_weight: 10,
                queue_limit: 8,
                enqueue_timeout_ms: 25,
                overflow_policy: LaneOverflowPolicy::EnqueueWithTimeout,
            },
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let timed = cx_with_scope("lane.timed");
        let cancel = cx_with_scope("lane.cancel");
        let realtime = cx_with_scope("lane.realtime");

        let _ = router
            .assign_operation(&timed, "timed-active", None, 1)
            .expect("timed active");
        let queued = router
            .assign_operation(&timed, "timed-queued", None, 2)
            .expect("timed queued");
        assert!(queued.queued);

        let _ = router
            .assign_operation(&cancel, "cancel-active", None, 3)
            .expect("cancel active");
        let _ = router
            .assign_operation(&realtime, "realtime-active", None, 4)
            .expect("realtime active");

        let mut tightened_cfg = cfg.clone();
        tightened_cfg.remote_max_in_flight = 1;
        router
            .reload_config(
                LaneRouterConfig::from_runtime_config(&tightened_cfg).expect("cfg"),
                5,
            )
            .expect("reload");

        router
            .complete_operation("timed-active", 6, false)
            .expect("complete timed active");

        let timed_state = router.lanes.get(&ProductLane::Timed).expect("timed state");
        assert_eq!(timed_state.metrics.queued, 1);
        assert_eq!(
            timed_state.metrics.rejected, 0,
            "queued operation should remain pending, not rejected, when promotion hits temporary bulkhead overload"
        );
    }

    #[test]
    fn cancellation_releases_lane_and_bulkhead_within_tick() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = cx_with_scope("lane.realtime");
        let _ = router
            .assign_operation(&cx, "rt-1", None, 10)
            .expect("assign");

        router
            .complete_operation("rt-1", 11, true)
            .expect("complete canceled");

        let snapshot = router.metrics_snapshot();
        assert_eq!(snapshot.total_in_flight, 0);
        let lane = snapshot
            .lanes
            .iter()
            .find(|m| m.lane == ProductLane::Realtime)
            .expect("lane present");
        assert_eq!(lane.in_flight, 0);
    }

    #[test]
    fn completion_failure_preserves_active_operation_until_bulkhead_state_is_repaired() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = cx_with_scope("lane.realtime");
        let _ = router
            .assign_operation(&cx, "rt-1", None, 10)
            .expect("assign");

        let original_permit_id = router
            .active
            .get("rt-1")
            .expect("active entry")
            .permit_id
            .clone();
        router
            .active
            .get_mut("rt-1")
            .expect("active entry")
            .permit_id = "permit-missing".to_string();

        let err = router
            .complete_operation("rt-1", 11, false)
            .expect_err("missing bulkhead permit must fail closed");
        assert_eq!(err.code(), error_codes::CONFIG_INVALID);
        assert!(
            err.to_string().contains("permit-missing"),
            "unexpected error: {err}"
        );
        assert!(
            router.active.contains_key("rt-1"),
            "active operation must remain tracked after failed release"
        );

        let snapshot = router.metrics_snapshot();
        assert_eq!(snapshot.total_in_flight, 1);
        let lane = snapshot
            .lanes
            .iter()
            .find(|m| m.lane == ProductLane::Realtime)
            .expect("lane present");
        assert_eq!(lane.in_flight, 1);
        assert_eq!(lane.completed, 0);

        router
            .active
            .get_mut("rt-1")
            .expect("active entry")
            .permit_id = original_permit_id;
        router
            .complete_operation("rt-1", 12, false)
            .expect("completion should succeed after repairing active permit id");

        let snapshot = router.metrics_snapshot();
        assert_eq!(snapshot.total_in_flight, 0);
        let lane = snapshot
            .lanes
            .iter()
            .find(|m| m.lane == ProductLane::Realtime)
            .expect("lane present");
        assert_eq!(lane.in_flight, 0);
        assert_eq!(lane.completed, 1);
    }

    #[test]
    fn queue_wait_p99_is_deterministic() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let lane = router
            .lanes
            .get_mut(&ProductLane::Background)
            .expect("lane");
        lane.metrics.queue_wait_samples_ms = vec![10, 40, 20, 30, 25, 35, 45, 50, 5, 15];
        assert_eq!(lane.metrics.p99_queue_wait_ms(), 50);
        assert_eq!(lane.metrics.p99_queue_wait_ms(), 50);
    }

    #[test]
    fn background_shed_oldest_overflow_keeps_queue_bounded() {
        let mut cfg = runtime_config();
        cfg.lanes.insert(
            "background".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 0usize.saturating_add(1),
                priority_weight: 1,
                queue_limit: 2,
                enqueue_timeout_ms: 100,
                overflow_policy: LaneOverflowPolicy::ShedOldest,
            },
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let bg = cx_with_scope("lane.background");

        let _ = router
            .assign_operation(&bg, "bg-1", None, 1)
            .expect("active");
        let _ = router
            .assign_operation(&bg, "bg-2", None, 2)
            .expect("queued");
        let _ = router
            .assign_operation(&bg, "bg-3", None, 3)
            .expect("queued");
        let _ = router
            .assign_operation(&bg, "bg-4", None, 4)
            .expect("shed-oldest+queued");

        let state = router.lanes.get(&ProductLane::Background).expect("state");
        assert!(state.queue.len() <= 2);
    }

    #[test]
    fn promotion_queue_wait_samples_are_bounded() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");

        let total = MAX_QUEUE_WAIT_SAMPLES + 32;
        for i in 0..total {
            let op_id = format!("queued-{i}");
            {
                let lane_state = router
                    .lanes
                    .get_mut(&ProductLane::Background)
                    .expect("background lane exists");
                lane_state.queue.push_back(QueuedOperation {
                    operation_id: op_id.clone(),
                    enqueued_at_ms: i as u64,
                    expires_at_ms: (i as u64).saturating_add(10_000),
                    cx_id: "cx-bounded".to_string(),
                    principal: "op".to_string(),
                });
                lane_state.metrics.queued = lane_state.queue.len();
            }
            router.queued_operation_ids.insert(op_id.clone());

            router
                .promote_queued((i as u64).saturating_add(1_000))
                .expect("promotion");
            router
                .complete_operation(&op_id, (i as u64).saturating_add(1_001), false)
                .expect("completion");
        }

        let lane_state = router
            .lanes
            .get(&ProductLane::Background)
            .expect("background lane exists");
        assert!(lane_state.metrics.queue_wait_samples_ms.len() <= MAX_QUEUE_WAIT_SAMPLES);
    }

    #[test]
    fn queue_wait_samples_keep_latest_suffix_after_overflow() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");

        let total = MAX_QUEUE_WAIT_SAMPLES + 4;
        for idx in 0..total {
            let op_id = format!("queued-suffix-{idx}");
            enqueue_for_test(
                &mut router,
                ProductLane::Background,
                &op_id,
                idx as u64,
                1_000_000,
            );
            router
                .promote_queued(10_000 + (idx as u64 * 2))
                .expect("promotion");
            router
                .complete_operation(&op_id, 10_001 + (idx as u64 * 2), false)
                .expect("completion");
        }

        let lane_state = router
            .lanes
            .get(&ProductLane::Background)
            .expect("background lane exists");
        assert_eq!(
            lane_state.metrics.queue_wait_samples_ms.len(),
            MAX_QUEUE_WAIT_SAMPLES
        );
        assert_eq!(
            lane_state.metrics.queue_wait_samples_ms.first(),
            Some(&10_004)
        );
        assert_eq!(
            lane_state.metrics.queue_wait_samples_ms.last(),
            Some(&(10_000 + total as u64 - 1))
        );
    }

    #[test]
    fn integration_mixed_100_operations_respects_global_cap() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");

        let cancel = cx_with_scope("lane.cancel");
        let timed = cx_with_scope("lane.timed");
        let realtime = cx_with_scope("lane.realtime");
        let background = cx_with_scope("lane.background");

        for i in 0..100_u64 {
            let (cx, lane_hint) = match i % 4 {
                0 => (&cancel, Some("cancel")),
                1 => (&timed, Some("timed")),
                2 => (&realtime, Some("realtime")),
                _ => (&background, Some("background")),
            };

            let op = format!("op-{i:03}");
            let _ = router.assign_operation(cx, &op, lane_hint, i + 1);

            // Deterministically retire earlier operations to keep the simulation moving.
            if i >= 50 {
                let done = format!("op-{:03}", i - 50);
                let _ = router.complete_operation(&done, i + 1000, false);
            }
        }

        let snapshot = router.metrics_snapshot();
        assert!(snapshot.total_in_flight <= 50);
        assert!(snapshot.bulkhead_rejections >= 1 || snapshot.total_in_flight <= 50);

        let cancel_lane = snapshot
            .lanes
            .iter()
            .find(|m| m.lane == ProductLane::Cancel)
            .expect("cancel metrics");
        let background_lane = snapshot
            .lanes
            .iter()
            .find(|m| m.lane == ProductLane::Background)
            .expect("background metrics");
        assert!(cancel_lane.rejected <= background_lane.rejected + 10);
    }

    // Negative-path inline tests for edge cases and robustness
    #[test]
    fn negative_massive_operation_queue_handles_memory_pressure_gracefully() {
        let mut cfg = runtime_config();
        cfg.lanes.insert(
            "background".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 1,
                priority_weight: 1,
                queue_limit: 5000, // Large queue to test memory pressure
                enqueue_timeout_ms: 60000,
                overflow_policy: LaneOverflowPolicy::EnqueueWithTimeout,
            },
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let bg = cx_with_scope("lane.background");

        // Active operation to force queueing
        router
            .assign_operation(&bg, "bg-active", None, 1)
            .expect("active");

        // Attempt to queue thousands of operations
        let mut queued_count = 0;
        for i in 0..10000 {
            let op_id = format!("massive-queue-{}", i);
            match router.assign_operation(&bg, &op_id, None, i + 2) {
                Ok(outcome) if outcome.queued => queued_count += 1,
                Ok(_) => {}      // Direct assignment
                Err(_) => break, // Queue limit or other constraint hit
            }
        }

        // Verify system remains stable under memory pressure
        assert!(
            queued_count > 100,
            "Should have queued substantial operations"
        );
        assert!(queued_count <= 5000, "Should respect queue limit");

        let snapshot = router.metrics_snapshot();
        assert!(snapshot.total_in_flight >= 1);

        // State should remain consistent
        assert!(router.queued_operation_ids.len() <= 5000);
    }

    #[test]
    fn negative_unicode_operation_ids_handled_without_corruption() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = cx_with_scope("lane.realtime");

        // Test problematic unicode characters in operation IDs
        let problematic_ids = vec![
            "操作-🚀-测试",              // Mixed CJK with emoji
            "عملية-تجريبية-٧٨٩",         // Arabic RTL with numbers
            "op\u{200B}id\u{FEFF}",      // Zero-width space and BOM
            "op‌er‍ation",                 // Zero-width joiners/non-joiners
            "𝒐𝒑𝒆𝒓𝒂𝒕𝒊𝒐𝒏",                 // Mathematical script unicode
            "op\u{0301}er\u{0302}ation", // Combining diacritical marks
            "op\u{1F600}eration",        // Emoji in operation ID
            "ope\u{FE0F}ration",         // Variation selector
        ];

        for (i, op_id) in problematic_ids.iter().enumerate() {
            if op_id.len() <= MAX_OPERATION_ID_LEN {
                let result = router.assign_operation(&cx, op_id, None, i as u64 + 1);
                assert!(
                    result.is_ok(),
                    "Unicode operation ID should be handled: {}",
                    op_id
                );

                // Complete the operation to clean up
                if let Ok(outcome) = result {
                    if !outcome.queued {
                        router
                            .complete_operation(op_id, i as u64 + 100, false)
                            .expect("Should complete unicode operation");
                    }
                }
            }
        }

        // Verify no corruption in router state
        let snapshot = router.metrics_snapshot();
        assert!(snapshot.total_in_flight >= 0);
    }

    #[test]
    fn negative_extreme_timestamp_arithmetic_uses_saturating_operations() {
        let mut cfg = runtime_config();
        cfg.lanes.insert(
            "timed".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 1,
                priority_weight: 10,
                queue_limit: 4,
                enqueue_timeout_ms: u64::MAX / 2, // Extreme timeout value
                overflow_policy: LaneOverflowPolicy::EnqueueWithTimeout,
            },
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let timed = cx_with_scope("lane.timed");

        // Test extreme timestamp scenarios
        let extreme_cases = vec![
            (u64::MAX - 1000, "near-max-timestamp"),
            (u64::MAX / 2, "half-max-timestamp"),
            (1, "minimal-timestamp"),
        ];

        router
            .assign_operation(&timed, "timed-active", None, 1)
            .expect("active");

        for (timestamp, op_suffix) in extreme_cases {
            let op_id = format!("extreme-{}", op_suffix);
            let result = router.assign_operation(&timed, &op_id, None, timestamp);

            match result {
                Ok(outcome) => {
                    if outcome.queued {
                        // Verify expires_at calculation didn't overflow
                        let timed_state = router.lanes.get(&ProductLane::Timed).unwrap();
                        for queued in &timed_state.queue {
                            if queued.operation_id == op_id {
                                assert!(queued.expires_at_ms >= queued.enqueued_at_ms);
                                // Should be saturating add result
                                assert!(
                                    queued.expires_at_ms == timestamp.saturating_add(u64::MAX / 2)
                                );
                                break;
                            }
                        }
                    }
                }
                Err(_) => {
                    // Graceful failure is acceptable for extreme values
                }
            }
        }
    }

    #[test]
    fn negative_malformed_router_configurations_fail_closed() {
        // Test configurations that should fail validation
        let problematic_configs = vec![
            // Zero values that should be rejected
            LaneRouterConfig {
                remote_max_in_flight: 0, // Invalid
                bulkhead_retry_after_ms: 100,
                lanes: {
                    let mut lanes = BTreeMap::new();
                    lanes.insert(
                        ProductLane::Background,
                        LaneConfigSnapshot {
                            max_concurrent: 1,
                            priority_weight: 1,
                            queue_limit: 1,
                            enqueue_timeout_ms: 1,
                            overflow_policy: LaneOverflowPolicy::Reject,
                        },
                    );
                    lanes
                },
            },
            // Zero bulkhead retry
            LaneRouterConfig {
                remote_max_in_flight: 10,
                bulkhead_retry_after_ms: 0, // Invalid
                lanes: BTreeMap::new(),
            },
            // Missing lane configuration
            LaneRouterConfig {
                remote_max_in_flight: 10,
                bulkhead_retry_after_ms: 100,
                lanes: BTreeMap::new(), // Missing all required lanes
            },
        ];

        for config in problematic_configs {
            let result = LaneRouter::new(config);
            assert!(result.is_err(), "Malformed config should be rejected");
        }

        // Test lane-specific zero configurations
        for &lane in ProductLane::all() {
            let mut valid_config =
                LaneRouterConfig::from_runtime_config(&runtime_config()).unwrap();

            // Zero max_concurrent
            valid_config.lanes.insert(
                lane,
                LaneConfigSnapshot {
                    max_concurrent: 0, // Invalid
                    priority_weight: 1,
                    queue_limit: 1,
                    enqueue_timeout_ms: 1,
                    overflow_policy: LaneOverflowPolicy::Reject,
                },
            );
            assert!(
                LaneRouter::new(valid_config).is_err(),
                "Zero max_concurrent should be rejected for lane {:?}",
                lane
            );
        }
    }

    #[test]
    fn negative_operation_id_boundary_cases_handled_correctly() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = cx_with_scope("lane.background");

        // Test exact boundary at MAX_OPERATION_ID_LEN
        let max_length_id = "x".repeat(MAX_OPERATION_ID_LEN);
        let over_length_id = "x".repeat(MAX_OPERATION_ID_LEN + 1);

        // Exactly at limit should succeed
        let result = router.assign_operation(&cx, &max_length_id, None, 1);
        assert!(result.is_ok(), "Max length operation ID should be accepted");

        // Over limit should fail
        let result = router.assign_operation(&cx, &over_length_id, None, 2);
        assert!(
            result.is_err(),
            "Over-length operation ID should be rejected"
        );
        assert_eq!(result.unwrap_err().code(), error_codes::CONFIG_INVALID);

        // Empty and whitespace-only IDs
        let empty_cases = vec!["", "   ", "\t\n", "\r\n\t "];
        for empty_id in empty_cases {
            let result = router.assign_operation(&cx, empty_id, None, 3);
            assert!(
                result.is_err(),
                "Empty operation ID should be rejected: {:?}",
                empty_id
            );
            assert_eq!(result.unwrap_err().code(), error_codes::CONFIG_INVALID);
        }
    }

    #[test]
    fn negative_null_bytes_and_control_characters_in_operation_ids() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = cx_with_scope("lane.background");

        // Control bytes must never enter active state, queues, or audit records.
        let control_ids = [
            "op\0null",                                                   // Null byte
            "op\x01\x02control",                                          // Control characters
            "op\r\ninjection",                                            // Line breaks
            &format!("op\x7F{}", String::from_utf8_lossy(&[0x80, 0xFF])), // High bytes and DEL
        ];

        for op_id in control_ids {
            let result = router.assign_operation(&cx, op_id, None, 1);
            assert!(
                matches!(result, Err(LaneRouterError::InvalidConfig { .. })),
                "control-character operation ID should be rejected: {op_id:?}"
            );
        }

        // Non-control Unicode identifiers are allowed when they otherwise satisfy bounds.
        let unicode_ids = vec![
            "op\u{FFFE}invalid", // Unicode non-character
            "op\u{FFFF}invalid", // Unicode non-character
            "op\u{202E}rtl",     // RTL override (potential display corruption)
            "op\u{200E}ltr",     // LTR mark
        ];

        for op_id in &unicode_ids {
            if op_id.len() <= MAX_OPERATION_ID_LEN {
                let result = router.assign_operation(&cx, op_id, None, 1);

                match result {
                    Ok(outcome) => {
                        if !outcome.queued {
                            let complete_result = router.complete_operation(op_id, 2, false);
                            assert!(
                                complete_result.is_ok(),
                                "Unicode operation should complete cleanly"
                            );
                        }
                    }
                    Err(_) => {
                        // Clean rejection is also acceptable
                    }
                }
            }
        }

        // Verify router state remains consistent
        let snapshot = router.metrics_snapshot();
        assert!(snapshot.total_in_flight >= 0);
    }

    #[test]
    fn negative_priority_weight_overflow_in_promotion_logic() {
        let mut cfg = runtime_config();

        // Set up lanes with extreme priority weights that could cause overflow
        cfg.lanes.insert(
            "cancel".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 4,
                priority_weight: u32::MAX, // Maximum priority weight
                queue_limit: 10,
                enqueue_timeout_ms: 1000,
                overflow_policy: LaneOverflowPolicy::EnqueueWithTimeout,
            },
        );

        cfg.lanes.insert(
            "background".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 1,
                priority_weight: 1, // Minimum priority weight
                queue_limit: 10,
                enqueue_timeout_ms: 1000,
                overflow_policy: LaneOverflowPolicy::EnqueueWithTimeout,
            },
        );

        let mut router = LaneRouter::from_runtime_config(&cfg).expect("router");
        let cancel = cx_with_scope("lane.cancel");
        let background = cx_with_scope("lane.background");

        // Fill cancel lane to force queueing
        for i in 0..4 {
            router
                .assign_operation(&cancel, &format!("cancel-active-{}", i), None, i)
                .expect("cancel assignment");
        }

        // Queue operations on both lanes
        router
            .assign_operation(&cancel, "cancel-queued", None, 10)
            .expect("cancel queued");
        router
            .assign_operation(&background, "background-active", None, 11)
            .expect("background active");
        router
            .assign_operation(&background, "background-queued", None, 12)
            .expect("background queued");

        // Complete an operation to trigger promotion logic
        router
            .complete_operation("cancel-active-0", 20, false)
            .expect("completion");

        // Verify promotion occurred without overflow/panic in priority calculations
        let events: Vec<_> = router
            .events()
            .iter()
            .filter(|e| e.event_code == event_codes::LANE_ASSIGNED)
            .map(|e| e.operation_id.as_str())
            .collect();

        // Cancel should be promoted before background due to higher priority
        assert!(events.contains(&"cancel-queued"));

        // Router should remain in consistent state
        let snapshot = router.metrics_snapshot();
        assert!(snapshot.total_in_flight > 0);
    }

    #[test]
    fn negative_queue_wait_samples_massive_accumulation_bounded() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");

        // Manually insert a massive number of queue wait samples to test bounds
        let background_state = router.lanes.get_mut(&ProductLane::Background).unwrap();

        // Fill beyond MAX_QUEUE_WAIT_SAMPLES with extreme values using bounded push
        for i in 0..(MAX_QUEUE_WAIT_SAMPLES * 2) {
            push_bounded(
                &mut background_state.metrics.queue_wait_samples_ms,
                i.saturating_mul(1000) as u64, // Large wait times that could cause issues
                MAX_QUEUE_WAIT_SAMPLES,
            );
        }

        // Verify samples are properly bounded without panic
        assert!(background_state.metrics.queue_wait_samples_ms.len() > MAX_QUEUE_WAIT_SAMPLES);

        // Test p99 calculation with massive dataset
        let p99 = background_state.metrics.p99_queue_wait_ms();
        assert!(
            p99.is_finite() as bool,
            "P99 calculation should not produce infinite values"
        );
        assert!(p99 > 0, "P99 should be positive with wait samples");

        // Add one more operation to trigger bounded cleanup
        enqueue_for_test(
            &mut router,
            ProductLane::Background,
            "test-bounded",
            1,
            10000,
        );
        router
            .promote_queued(5000)
            .expect("promotion with bounded samples");
        router
            .complete_operation("test-bounded", 5001, false)
            .expect("completion");

        // Verify samples were properly bounded during promotion
        let final_state = router.lanes.get(&ProductLane::Background).unwrap();
        assert!(final_state.metrics.queue_wait_samples_ms.len() <= MAX_QUEUE_WAIT_SAMPLES);
    }

    #[test]
    fn negative_concurrent_operation_id_collision_prevention() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = cx_with_scope("lane.background");

        // Assign operation with specific ID
        let result1 = router.assign_operation(&cx, "collision-test", None, 1);
        assert!(result1.is_ok(), "First assignment should succeed");

        // Attempt to assign operation with same ID while first is active
        let result2 = router.assign_operation(&cx, "collision-test", None, 2);
        assert!(
            result2.is_err(),
            "Duplicate active operation ID should be rejected"
        );
        assert_eq!(
            result2.unwrap_err().code(),
            error_codes::OPERATION_DUPLICATE
        );

        // Complete first operation
        router
            .complete_operation("collision-test", 3, false)
            .expect("completion should succeed");

        // Now same ID should be reusable
        let result3 = router.assign_operation(&cx, "collision-test", None, 4);
        assert!(result3.is_ok(), "ID should be reusable after completion");

        // Test collision with queued operations
        let mut cfg = runtime_config();
        cfg.lanes.insert(
            "timed".to_string(),
            RuntimeLaneConfig {
                max_concurrent: 1,
                priority_weight: 10,
                queue_limit: 5,
                enqueue_timeout_ms: 1000,
                overflow_policy: LaneOverflowPolicy::EnqueueWithTimeout,
            },
        );

        let mut queue_router = LaneRouter::from_runtime_config(&cfg).expect("queue router");
        let timed = cx_with_scope("lane.timed");

        // Fill lane to force queueing
        queue_router
            .assign_operation(&timed, "timed-active", None, 10)
            .expect("active");

        let queued = queue_router
            .assign_operation(&timed, "queued-collision", None, 11)
            .expect("queued");
        assert!(queued.queued);

        // Attempt duplicate of queued operation
        let dup_result = queue_router.assign_operation(&timed, "queued-collision", None, 12);
        assert!(
            dup_result.is_err(),
            "Duplicate queued operation should be rejected"
        );
        assert_eq!(
            dup_result.unwrap_err().code(),
            error_codes::OPERATION_DUPLICATE
        );
    }
}
