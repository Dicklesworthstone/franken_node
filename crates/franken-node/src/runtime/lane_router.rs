//! bd-lus: Product lane router integrating lane policy and global bulkhead.
//!
//! Defines the product lane taxonomy and deterministic routing behavior for
//! runtime operations. Lane assignment uses capability metadata first, with a
//! fail-safe default to background for unknown or missing lane hints.

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
}

pub mod error_codes {
    pub const LANE_SATURATED: &str = "LANE_SATURATED";
    pub const BULKHEAD_OVERLOAD: &str = "BULKHEAD_OVERLOAD";
    pub const OPERATION_UNKNOWN: &str = "OPERATION_UNKNOWN";
    pub const OPERATION_DUPLICATE: &str = "OPERATION_DUPLICATE";
    pub const CONFIG_INVALID: &str = "CONFIG_INVALID";
}

const MAX_OPERATION_ID_LEN: usize = 256;
const MAX_QUEUE_WAIT_SAMPLES: usize = 1024;

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
        let target_idx = idx.min(values.len() - 1);
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
    OperationUnknown {
        operation_id: String,
    },
    OperationDuplicate {
        operation_id: String,
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
            Self::OperationUnknown { .. } => error_codes::OPERATION_UNKNOWN,
            Self::OperationDuplicate { .. } => error_codes::OPERATION_DUPLICATE,
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
            Self::OperationUnknown { operation_id } => {
                write!(f, "{}: operation_id={operation_id}", self.code())
            }
            Self::OperationDuplicate { operation_id } => {
                write!(f, "{}: operation_id={operation_id}", self.code())
            }
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
        if self.active.contains_key(operation_id)
            || self.queued_operation_ids.contains(operation_id)
        {
            return Err(LaneRouterError::OperationDuplicate {
                operation_id: operation_id.to_string(),
            });
        }

        let lane = self.resolve_lane(cx, lane_hint, operation_id, now_ms);
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
            self.events.push(LaneEvent {
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

        self.events.push(LaneEvent {
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
        let Some(active) = self.active.remove(operation_id) else {
            return Err(LaneRouterError::OperationUnknown {
                operation_id: operation_id.to_string(),
            });
        };

        self.bulkhead
            .release(&active.permit_id, operation_id, now_ms)
            .map_err(map_bulkhead_err)?;

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

        self.events.push(LaneEvent {
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
    ) -> ProductLane {
        if let Some(raw) = lane_hint {
            if let Some(lane) = ProductLane::parse_label(raw) {
                if Self::context_allows_lane(cx, lane) {
                    return lane;
                }
                self.unknown_lane_default_count = self.unknown_lane_default_count.saturating_add(1);
                self.events.push(LaneEvent {
                    event_code: event_codes::LANE_DEFAULTED_BACKGROUND.to_string(),
                    operation_id: operation_id.to_string(),
                    lane_name: ProductLane::Background.as_str().to_string(),
                    now_ms,
                    lane_in_flight: self.background_in_flight(),
                    total_in_flight: self.bulkhead.in_flight(),
                    detail: format!("lane_hint_scope_mismatch={raw}"),
                });
                return ProductLane::Background;
            }
            self.unknown_lane_default_count = self.unknown_lane_default_count.saturating_add(1);
            self.events.push(LaneEvent {
                event_code: event_codes::LANE_DEFAULTED_BACKGROUND.to_string(),
                operation_id: operation_id.to_string(),
                lane_name: ProductLane::Background.as_str().to_string(),
                now_ms,
                lane_in_flight: self.background_in_flight(),
                total_in_flight: self.bulkhead.in_flight(),
                detail: format!("unknown_lane_hint={raw}"),
            });
            return ProductLane::Background;
        }

        if cx.has_scope("lane.cancel") {
            return ProductLane::Cancel;
        }
        if cx.has_scope("lane.timed") {
            return ProductLane::Timed;
        }
        if cx.has_scope("lane.realtime") || cx.has_scope("lane.ready") {
            return ProductLane::Realtime;
        }
        if cx.has_scope("lane.background") {
            return ProductLane::Background;
        }

        self.unknown_lane_default_count = self.unknown_lane_default_count.saturating_add(1);
        self.events.push(LaneEvent {
            event_code: event_codes::LANE_DEFAULTED_BACKGROUND.to_string(),
            operation_id: operation_id.to_string(),
            lane_name: ProductLane::Background.as_str().to_string(),
            now_ms,
            lane_in_flight: self.background_in_flight(),
            total_in_flight: self.bulkhead.in_flight(),
            detail: "missing_lane_annotation".to_string(),
        });
        ProductLane::Background
    }

    fn context_allows_lane(cx: &CapabilityContext, lane: ProductLane) -> bool {
        match lane {
            ProductLane::Cancel => cx.has_scope("lane.cancel"),
            ProductLane::Timed => cx.has_scope("lane.timed"),
            ProductLane::Realtime => cx.has_scope("lane.realtime") || cx.has_scope("lane.ready"),
            ProductLane::Background => cx.has_scope("lane.background"),
        }
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
                self.events.push(LaneEvent {
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
        let mut lanes = ProductLane::all().to_vec();
        lanes.sort_by_key(ProductLane::priority_rank);

        for lane in lanes {
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
                        .metrics
                        .queue_wait_samples_ms
                        .push(now_ms.saturating_sub(queued.enqueued_at_ms));
                    if lane_state.metrics.queue_wait_samples_ms.len() > MAX_QUEUE_WAIT_SAMPLES {
                        let overflow =
                            lane_state.metrics.queue_wait_samples_ms.len() - MAX_QUEUE_WAIT_SAMPLES;
                        lane_state.metrics.queue_wait_samples_ms.drain(0..overflow);
                    }
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

                self.events.push(LaneEvent {
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
        BulkheadError::UnknownPermit { permit_id } => LaneRouterError::OperationUnknown {
            operation_id: permit_id,
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

#[cfg(test)]
mod tests {
    use super::*;

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
            remote_max_in_flight: 50,
            bulkhead_retry_after_ms: 20,
            lanes,
        }
    }

    fn cx_with_scope(scope: &str) -> CapabilityContext {
        CapabilityContext::with_scopes("cx-1", "operator-a", vec![scope.to_string()])
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
    fn unknown_lane_hint_defaults_to_background_with_warning() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = CapabilityContext::new("cx-2", "operator-b");

        let assigned = router
            .assign_operation(&cx, "op-1", Some("not-a-lane"), 1)
            .expect("assigned");
        assert_eq!(assigned.lane, ProductLane::Background);
        assert_eq!(router.unknown_lane_default_count(), 1);
        assert!(
            router
                .events()
                .iter()
                .any(|e| e.event_code == event_codes::LANE_DEFAULTED_BACKGROUND)
        );
    }

    #[test]
    fn lane_hint_scope_mismatch_defaults_to_background() {
        let mut router = LaneRouter::from_runtime_config(&runtime_config()).expect("router");
        let cx = cx_with_scope("lane.background");

        let assigned = router
            .assign_operation(&cx, "op-hint-mismatch", Some("cancel"), 1)
            .expect("assigned");
        assert_eq!(assigned.lane, ProductLane::Background);
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
}
