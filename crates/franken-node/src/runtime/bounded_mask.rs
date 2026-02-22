//! bd-24k: bounded masking helper for tiny atomic operations.
//!
//! This module implements a capability-context-first masking primitive for
//! synchronous critical sections. Cancellation is deferred while the mask is
//! active and delivered immediately after the mask exits.

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Compile-time budget threshold for mask duration warnings (1 microsecond).
pub const MAX_MASK_DURATION_NS: u64 = 1_000;

/// Default timeout budget for `bounded_mask` (1 millisecond).
pub const DEFAULT_TIMEOUT_NS: u64 = 1_000_000;

/// Structured event name for completed invocations.
pub const MASK_INVOCATION_EVENT: &str = "bounded_mask.invocation";

/// Event code: mask entered.
pub const FN_BM_001_MASK_ENTER: &str = "FN-BM-001";
/// Event code: mask exited.
pub const FN_BM_002_MASK_EXIT: &str = "FN-BM-002";
/// Event code: budget warning triggered.
pub const FN_BM_003_MASK_BUDGET_EXCEEDED: &str = "FN-BM-003";
/// Event code: non-nestable guard violation.
pub const FN_BM_004_MASK_NESTING_VIOLATION: &str = "FN-BM-004";
/// Event code: timeout exceeded.
pub const FN_BM_005_MASK_TIMEOUT_EXCEEDED: &str = "FN-BM-005";
/// Event code: deferred cancellation delivered after unmask.
pub const FN_BM_006_MASK_CANCEL_DEFERRED: &str = "FN-BM-006";

/// Event type: mask entered.
pub const MASK_ENTER: &str = "MASK_ENTER";
/// Event type: mask exited.
pub const MASK_EXIT: &str = "MASK_EXIT";
/// Event type: budget warning.
pub const MASK_BUDGET_EXCEEDED: &str = "MASK_BUDGET_EXCEEDED";
/// Event type: nesting violation.
pub const MASK_NESTING_VIOLATION: &str = "MASK_NESTING_VIOLATION";
/// Event type: timeout exceeded.
pub const MASK_TIMEOUT_EXCEEDED: &str = "MASK_TIMEOUT_EXCEEDED";
/// Event type: deferred cancellation delivered.
pub const MASK_CANCEL_DEFERRED: &str = "MASK_CANCEL_DEFERRED";

thread_local! {
    static MASK_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

/// Capability context required to invoke bounded masking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityContext {
    pub cx_id: String,
    pub principal: String,
    pub scopes: BTreeSet<String>,
}

impl CapabilityContext {
    /// Construct a capability context with no explicit scopes.
    #[must_use]
    pub fn new(cx_id: impl Into<String>, principal: impl Into<String>) -> Self {
        Self {
            cx_id: cx_id.into(),
            principal: principal.into(),
            scopes: BTreeSet::new(),
        }
    }

    /// Construct a capability context and normalize scopes deterministically.
    #[must_use]
    pub fn with_scopes(
        cx_id: impl Into<String>,
        principal: impl Into<String>,
        scopes: impl IntoIterator<Item = String>,
    ) -> Self {
        let normalized = scopes
            .into_iter()
            .map(|scope| scope.trim().to_string())
            .filter(|scope| !scope.is_empty())
            .collect::<BTreeSet<_>>();
        Self {
            cx_id: cx_id.into(),
            principal: principal.into(),
            scopes: normalized,
        }
    }

    /// Check whether this context contains the requested scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }
}

/// Mutable cancellation state used by bounded masks.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancellationState {
    cancel_requested: bool,
    masked: bool,
    deferred_signals: u64,
    delivered_after_mask: u64,
}

impl CancellationState {
    /// Create a fresh cancellation state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation.
    ///
    /// When called inside an active mask, cancellation is deferred.
    pub fn request_cancel(&mut self) {
        if self.masked {
            self.deferred_signals = self.deferred_signals.saturating_add(1);
            return;
        }
        self.cancel_requested = true;
    }

    /// Whether cancellation has been requested and delivered.
    #[must_use]
    pub fn is_cancel_requested(&self) -> bool {
        self.cancel_requested
    }

    /// Deferred cancellation signals waiting for mask exit.
    #[must_use]
    pub fn deferred_signals(&self) -> u64 {
        self.deferred_signals
    }

    /// Number of deferred signals delivered immediately after mask exit.
    #[must_use]
    pub fn delivered_after_mask(&self) -> u64 {
        self.delivered_after_mask
    }

    /// Clear delivered cancellation state (useful in tests).
    pub fn clear_cancellation(&mut self) {
        self.cancel_requested = false;
    }

    fn begin_mask(&mut self) {
        self.masked = true;
    }

    fn end_mask_and_deliver_deferred(&mut self) -> bool {
        self.masked = false;
        let had_deferred = self.deferred_signals > 0;
        if had_deferred {
            self.cancel_requested = true;
            self.delivered_after_mask = self
                .delivered_after_mask
                .saturating_add(self.deferred_signals);
            self.deferred_signals = 0;
        }
        had_deferred
    }
}

/// Bounded-mask behavior policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskPolicy {
    pub max_duration_ns: u64,
    pub enforce_timeout: bool,
    pub test_mode: bool,
    pub trace_id: String,
}

impl Default for MaskPolicy {
    fn default() -> Self {
        Self {
            max_duration_ns: DEFAULT_TIMEOUT_NS,
            enforce_timeout: true,
            test_mode: false,
            trace_id: "trace-bounded-mask".to_string(),
        }
    }
}

impl MaskPolicy {
    /// Create a policy from a timeout duration and trace id.
    #[must_use]
    pub fn new(max_duration: Duration, trace_id: impl Into<String>) -> Self {
        let max_duration_ns = saturating_u64(max_duration.as_nanos());
        Self {
            max_duration_ns,
            trace_id: trace_id.into(),
            ..Self::default()
        }
    }

    /// Effective timeout budget as a `Duration`.
    #[must_use]
    pub fn max_duration(&self) -> Duration {
        Duration::from_nanos(self.max_duration_ns)
    }
}

/// Stable error modes for bounded masking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MaskError {
    MissingCapabilityContext,
    CancelledBeforeEntry,
    MaskTimeoutExceeded {
        operation_name: String,
        elapsed_ns: u64,
        max_duration_ns: u64,
    },
}

impl MaskError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingCapabilityContext => "MASK_MISSING_CAPABILITY_CONTEXT",
            Self::CancelledBeforeEntry => "MASK_CANCELLED_BEFORE_ENTRY",
            Self::MaskTimeoutExceeded { .. } => "MASK_TIMEOUT_EXCEEDED",
        }
    }
}

impl fmt::Display for MaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCapabilityContext => write!(
                f,
                "{}: missing capability context for bounded mask",
                self.code()
            ),
            Self::CancelledBeforeEntry => write!(
                f,
                "{}: cancellation requested before entering mask",
                self.code()
            ),
            Self::MaskTimeoutExceeded {
                operation_name,
                elapsed_ns,
                max_duration_ns,
            } => write!(
                f,
                "{}: operation `{operation_name}` exceeded mask timeout (elapsed={elapsed_ns}ns, max={max_duration_ns}ns)",
                self.code()
            ),
        }
    }
}

impl std::error::Error for MaskError {}

/// Structured event emitted by bounded-mask operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskEvent {
    pub event_code: String,
    pub event_name: String,
    pub operation_name: String,
    pub trace_id: String,
    pub cx_id: String,
    pub elapsed_ns: u64,
    pub completed_within_bound: bool,
    pub deferred_cancel_pending: bool,
}

/// Summary record for a completed invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaskInvocationReport {
    pub event_name: String,
    pub operation_name: String,
    pub trace_id: String,
    pub cx_id: String,
    pub mask_duration_us: u64,
    pub mask_duration_ns: u64,
    pub completed_within_bound: bool,
    pub deferred_cancel_pending: bool,
}

/// Output wrapper with operation value and mask telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedMask<T> {
    value: T,
    pub report: MaskInvocationReport,
    pub events: Vec<MaskEvent>,
}

impl<T> BoundedMask<T> {
    /// Borrow the wrapped value.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Consume the wrapper and return the value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.value
    }
}

/// Execute a bounded mask and return only the operation value.
pub fn bounded_mask<T, F>(
    cx: &CapabilityContext,
    cancellation: &mut CancellationState,
    operation_name: &str,
    op: F,
) -> Result<T, MaskError>
where
    F: FnOnce(&CapabilityContext, &mut CancellationState) -> T,
{
    let wrapped = bounded_mask_with_policy(
        Some(cx),
        cancellation,
        operation_name,
        &MaskPolicy::default(),
        op,
    )?;
    Ok(wrapped.into_inner())
}

/// Execute a bounded mask and return value plus telemetry report.
pub fn bounded_mask_with_report<T, F>(
    cx: &CapabilityContext,
    cancellation: &mut CancellationState,
    operation_name: &str,
    policy: &MaskPolicy,
    op: F,
) -> Result<BoundedMask<T>, MaskError>
where
    F: FnOnce(&CapabilityContext, &mut CancellationState) -> T,
{
    bounded_mask_with_policy(Some(cx), cancellation, operation_name, policy, op)
}

/// Internal entry point that supports runtime validation for absent contexts.
pub fn bounded_mask_with_policy<T, F>(
    cx: Option<&CapabilityContext>,
    cancellation: &mut CancellationState,
    operation_name: &str,
    policy: &MaskPolicy,
    op: F,
) -> Result<BoundedMask<T>, MaskError>
where
    F: FnOnce(&CapabilityContext, &mut CancellationState) -> T,
{
    let cx = cx.ok_or(MaskError::MissingCapabilityContext)?;
    if cancellation.is_cancel_requested() {
        return Err(MaskError::CancelledBeforeEntry);
    }

    let mut events = Vec::with_capacity(6);
    let _scope = enter_mask_scope(operation_name, &policy.trace_id, &cx.cx_id, &mut events);
    let event_ctx = MaskEventContext {
        operation_name,
        trace_id: &policy.trace_id,
        cx_id: &cx.cx_id,
    };
    cancellation.begin_mask();
    emit_event(
        &mut events,
        MaskEventKind {
            event_code: FN_BM_001_MASK_ENTER,
            event_name: MASK_ENTER,
        },
        event_ctx,
        MaskEventOutcome {
            elapsed_ns: 0,
            completed_within_bound: true,
            deferred_cancel_pending: cancellation.deferred_signals() > 0,
        },
    );

    let started = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| op(cx, cancellation)));
    let elapsed_ns = saturating_u64(started.elapsed().as_nanos());

    let deferred_cancel_pending = cancellation.end_mask_and_deliver_deferred();
    if deferred_cancel_pending {
        emit_event(
            &mut events,
            MaskEventKind {
                event_code: FN_BM_006_MASK_CANCEL_DEFERRED,
                event_name: MASK_CANCEL_DEFERRED,
            },
            event_ctx,
            MaskEventOutcome {
                elapsed_ns,
                completed_within_bound: true,
                deferred_cancel_pending: true,
            },
        );
    }

    match result {
        Ok(value) => {
            let completed_within_bound = elapsed_ns <= policy.max_duration_ns;
            emit_event(
                &mut events,
                MaskEventKind {
                    event_code: FN_BM_002_MASK_EXIT,
                    event_name: MASK_EXIT,
                },
                event_ctx,
                MaskEventOutcome {
                    elapsed_ns,
                    completed_within_bound,
                    deferred_cancel_pending,
                },
            );

            if policy.test_mode && elapsed_ns > MAX_MASK_DURATION_NS {
                emit_event(
                    &mut events,
                    MaskEventKind {
                        event_code: FN_BM_003_MASK_BUDGET_EXCEEDED,
                        event_name: MASK_BUDGET_EXCEEDED,
                    },
                    event_ctx,
                    MaskEventOutcome {
                        elapsed_ns,
                        completed_within_bound,
                        deferred_cancel_pending,
                    },
                );
            }

            if !completed_within_bound && policy.enforce_timeout {
                emit_event(
                    &mut events,
                    MaskEventKind {
                        event_code: FN_BM_005_MASK_TIMEOUT_EXCEEDED,
                        event_name: MASK_TIMEOUT_EXCEEDED,
                    },
                    event_ctx,
                    MaskEventOutcome {
                        elapsed_ns,
                        completed_within_bound: false,
                        deferred_cancel_pending,
                    },
                );
                return Err(MaskError::MaskTimeoutExceeded {
                    operation_name: operation_name.to_string(),
                    elapsed_ns,
                    max_duration_ns: policy.max_duration_ns,
                });
            }

            let report = MaskInvocationReport {
                event_name: MASK_INVOCATION_EVENT.to_string(),
                operation_name: operation_name.to_string(),
                trace_id: policy.trace_id.clone(),
                cx_id: cx.cx_id.clone(),
                mask_duration_us: elapsed_ns / 1_000,
                mask_duration_ns: elapsed_ns,
                completed_within_bound,
                deferred_cancel_pending,
            };

            Ok(BoundedMask {
                value,
                report,
                events,
            })
        }
        Err(panic_payload) => {
            emit_event(
                &mut events,
                MaskEventKind {
                    event_code: FN_BM_002_MASK_EXIT,
                    event_name: MASK_EXIT,
                },
                event_ctx,
                MaskEventOutcome {
                    elapsed_ns,
                    completed_within_bound: elapsed_ns <= policy.max_duration_ns,
                    deferred_cancel_pending,
                },
            );
            resume_unwind(panic_payload);
        }
    }
}

fn enter_mask_scope<'a>(
    operation_name: &'a str,
    trace_id: &'a str,
    cx_id: &'a str,
    events: &mut Vec<MaskEvent>,
) -> MaskScopeGuard {
    MASK_ACTIVE.with(|active| {
        if active.get() {
            emit_event(
                events,
                MaskEventKind {
                    event_code: FN_BM_004_MASK_NESTING_VIOLATION,
                    event_name: MASK_NESTING_VIOLATION,
                },
                MaskEventContext {
                    operation_name,
                    trace_id,
                    cx_id,
                },
                MaskEventOutcome {
                    elapsed_ns: 0,
                    completed_within_bound: false,
                    deferred_cancel_pending: false,
                },
            );
            panic!(
                "{MASK_NESTING_VIOLATION}: nested bounded mask for operation `{operation_name}`"
            );
        }
        active.set(true);
    });
    MaskScopeGuard
}

fn emit_event(
    events: &mut Vec<MaskEvent>,
    event: MaskEventKind<'_>,
    ctx: MaskEventContext<'_>,
    outcome: MaskEventOutcome,
) {
    events.push(MaskEvent {
        event_code: event.event_code.to_string(),
        event_name: event.event_name.to_string(),
        operation_name: ctx.operation_name.to_string(),
        trace_id: ctx.trace_id.to_string(),
        cx_id: ctx.cx_id.to_string(),
        elapsed_ns: outcome.elapsed_ns,
        completed_within_bound: outcome.completed_within_bound,
        deferred_cancel_pending: outcome.deferred_cancel_pending,
    });
}

fn saturating_u64(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

struct MaskScopeGuard;

#[derive(Copy, Clone)]
struct MaskEventKind<'a> {
    event_code: &'a str,
    event_name: &'a str,
}

#[derive(Copy, Clone)]
struct MaskEventContext<'a> {
    operation_name: &'a str,
    trace_id: &'a str,
    cx_id: &'a str,
}

#[derive(Copy, Clone)]
struct MaskEventOutcome {
    elapsed_ns: u64,
    completed_within_bound: bool,
    deferred_cancel_pending: bool,
}

impl Drop for MaskScopeGuard {
    fn drop(&mut self) {
        MASK_ACTIVE.with(|active| active.set(false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::catch_unwind;
    use std::thread;

    fn spin_for(duration: Duration) {
        let started = Instant::now();
        while started.elapsed() < duration {
            std::hint::spin_loop();
        }
    }

    #[test]
    fn operation_within_budget_succeeds() {
        let cx =
            CapabilityContext::with_scopes("cx-1", "operator-a", vec!["runtime.mask".to_string()]);
        let mut cancellation = CancellationState::new();
        let mut policy = MaskPolicy::new(Duration::from_millis(5), "trace-001");
        policy.test_mode = true;

        let result = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "counter_increment",
            &policy,
            |_cx, _cancel| 41_u64 + 1,
        )
        .expect("mask should succeed");

        assert_eq!(result.into_inner(), 42);
    }

    #[test]
    fn timeout_exceeded_returns_error() {
        let cx = CapabilityContext::new("cx-timeout", "operator-timeout");
        let mut cancellation = CancellationState::new();
        let mut policy = MaskPolicy::new(Duration::from_micros(500), "trace-timeout");
        policy.enforce_timeout = true;
        policy.test_mode = true;

        let started = Instant::now();
        let err = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "slow_path",
            &policy,
            |_cx, _cancel| {
                spin_for(Duration::from_micros(700));
                7_u8
            },
        )
        .expect_err("mask should fail on timeout");

        let elapsed = started.elapsed();
        match err {
            MaskError::MaskTimeoutExceeded {
                elapsed_ns,
                max_duration_ns,
                ..
            } => {
                assert!(elapsed_ns > max_duration_ns);
                assert!(elapsed <= Duration::from_micros(1_000));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn cancellation_before_entry_aborts_immediately() {
        let cx = CapabilityContext::new("cx-cancel", "operator-cancel");
        let mut cancellation = CancellationState::new();
        cancellation.request_cancel();

        let result = bounded_mask(&cx, &mut cancellation, "op", |_cx, _cancel| 1_u8);
        assert!(matches!(result, Err(MaskError::CancelledBeforeEntry)));
    }

    #[test]
    fn cancellation_during_mask_is_deferred_then_delivered() {
        let cx = CapabilityContext::new("cx-defer", "operator-defer");
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-defer");

        let wrapped = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "defer_cancel",
            &policy,
            |_cx, cancel| {
                cancel.request_cancel();
                assert!(!cancel.is_cancel_requested());
                11_u8
            },
        )
        .expect("mask should succeed");

        assert_eq!(wrapped.into_inner(), 11);
        assert!(cancellation.is_cancel_requested());
        assert_eq!(cancellation.delivered_after_mask(), 1);
    }

    #[test]
    fn nested_mask_panics_with_violation_code() {
        let cx = CapabilityContext::new("cx-nested", "operator-nested");
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-nested");

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = bounded_mask_with_report(
                &cx,
                &mut cancellation,
                "outer",
                &policy,
                |inner_cx, inner_cancel| {
                    let _ = bounded_mask(inner_cx, inner_cancel, "inner", |_cx, _cancel| 9_u8);
                    1_u8
                },
            );
        }));

        assert!(result.is_err());
        // catch_unwind captures the panic payload; verify it contains the violation code.
        let payload = result.unwrap_err();
        let panic_text = payload
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(
            panic_text.contains(MASK_NESTING_VIOLATION),
            "expected MASK_NESTING_VIOLATION in panic message, got: {panic_text}"
        );
    }

    #[test]
    fn test_mode_emits_budget_warning_without_timeout_when_not_enforced() {
        let cx = CapabilityContext::new("cx-budget", "operator-budget");
        let mut cancellation = CancellationState::new();
        let mut policy = MaskPolicy::new(Duration::from_millis(5), "trace-budget");
        policy.enforce_timeout = false;
        policy.test_mode = true;

        let wrapped = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "budget_warn",
            &policy,
            |_cx, _cancel| {
                thread::sleep(Duration::from_micros(50));
                99_u16
            },
        )
        .expect("mask should succeed when timeout enforcement disabled");

        assert_eq!(wrapped.value(), &99_u16);
        assert!(
            wrapped
                .events
                .iter()
                .any(|event| event.event_name == MASK_BUDGET_EXCEEDED)
        );
    }

    #[test]
    fn panic_inside_mask_lifts_scope_and_delivers_deferred_cancel() {
        let cx = CapabilityContext::new("cx-panic", "operator-panic");
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-panic");

        let panic_result = catch_unwind(AssertUnwindSafe(|| {
            let _ = bounded_mask_with_report(
                &cx,
                &mut cancellation,
                "panic_op",
                &policy,
                |_cx, cancel| {
                    cancel.request_cancel();
                    panic!("boom");
                },
            );
        }));
        assert!(panic_result.is_err());
        assert!(cancellation.is_cancel_requested());

        cancellation.clear_cancellation();
        let ok = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "follow_up",
            &policy,
            |_cx, _cancel| 5_u8,
        )
        .expect("mask scope should be lifted after panic");
        assert_eq!(ok.into_inner(), 5);
    }

    #[test]
    fn missing_capability_context_returns_error() {
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-missing");

        let err = bounded_mask_with_policy::<u8, _>(
            None,
            &mut cancellation,
            "missing_context",
            &policy,
            |_cx, _cancel| 1_u8,
        )
        .expect_err("missing context must fail");

        assert!(matches!(err, MaskError::MissingCapabilityContext));
    }

    #[test]
    fn report_contains_required_invocation_fields() {
        let cx = CapabilityContext::new("cx-report", "operator-report");
        let mut cancellation = CancellationState::new();
        let policy = MaskPolicy::new(Duration::from_millis(5), "trace-report");

        let wrapped = bounded_mask_with_report(
            &cx,
            &mut cancellation,
            "report_op",
            &policy,
            |_cx, _cancel| 64_u8,
        )
        .expect("report op should succeed");

        assert_eq!(wrapped.report.event_name, MASK_INVOCATION_EVENT);
        assert_eq!(wrapped.report.operation_name, "report_op");
        assert_eq!(wrapped.report.trace_id, "trace-report");
        assert_eq!(wrapped.report.cx_id, "cx-report");
    }
}
