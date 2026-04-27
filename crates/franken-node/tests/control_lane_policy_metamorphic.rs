//! Metamorphic proptest harness for control_lane_policy `tick` and
//! `tick_deadline_aware` (bd-1dqo8).
//!
//! Properties tested:
//!
//! 1. **Slot conservation** — for any `(cancel_pending, timed_pending,
//!    ready_pending, total_slots)`, the per-lane `*_tasks_run` values from
//!    `tick` sum to ≤ `total_slots`.
//! 2. **No phantom work** — each lane's `*_tasks_run` is ≤ that lane's
//!    `*_pending` count (the scheduler never schedules work that wasn't queued).
//! 3. **Cancel-priority floor** — when `cancel_pending > 0 && total_slots > 0`,
//!    `cancel_lane_tasks_run >= 1`. This is the load-bearing safety property
//!    for INV-CLP-CANCEL-PRIORITY: cancellation work must always get capacity
//!    when slots exist, regardless of how saturated the other lanes are.
//! 4. **Starvation flag correctness** — for each lane,
//!    `*_lane_starved == (*_pending > 0 && *_tasks_run == 0)`.
//! 5. **Cancel never starves with capacity** — combining (3) and (4): when
//!    `total_slots > 0 && cancel_pending > 0`, `cancel_lane_starved == false`.
//! 6. **Lane-mapping totality** — `canonical_lane` and `lookup` are total
//!    functions over every variant of `ControlTaskClass`, and the lane returned
//!    matches `lookup(...).lane`.
//! 7. **Cancel/Timed/Ready classification consistency** — every variant maps
//!    consistently to its declared lane class.
//! 8. **Deadline timeout fail-closed** — when a deadline-bound (`Cancel` or
//!    `Timed`) task is enqueued at `t0` and `tick_deadline_aware` runs at
//!    `t0 + canonical_timeout + extra` with `extra >= 0`, the task is in
//!    `timed_out_task_ids`, never in `scheduled_task_ids`.
//! 9. **Deadline run-count match** — `len(tick.scheduled_task_ids)` equals
//!    `cancel_lane_tasks_run + timed_lane_tasks_run + ready_lane_tasks_run`
//!    from the same tick's metrics.
//! 10. **Fresh-policy invariants** — `verify_all_assigned()` and
//!     `verify_budget_sum()` always return `true` on a freshly constructed
//!     policy.

use frankenengine_node::control_plane::control_lane_policy::{
    CANCEL_LANE_BUDGET_PCT, ControlLane, ControlLanePolicy, ControlTaskClass,
    READY_LANE_BUDGET_PCT, TIMED_LANE_BUDGET_PCT,
};
use proptest::prelude::*;

fn task_class_strategy() -> impl Strategy<Value = ControlTaskClass> {
    let variants = ControlTaskClass::all();
    (0_usize..variants.len()).prop_map(move |i| variants[i])
}

fn cancel_tier_classes() -> &'static [ControlTaskClass] {
    &[
        ControlTaskClass::CancellationHandler,
        ControlTaskClass::DrainOperation,
        ControlTaskClass::RegionClose,
        ControlTaskClass::GracefulShutdown,
        ControlTaskClass::AbortCompensation,
    ]
}

fn timed_tier_classes() -> &'static [ControlTaskClass] {
    &[
        ControlTaskClass::HealthCheck,
        ControlTaskClass::LeaseRenewal,
        ControlTaskClass::EpochTransition,
        ControlTaskClass::EpochSeal,
        ControlTaskClass::TransitionBarrier,
        ControlTaskClass::DeadlineEnforcement,
        ControlTaskClass::ForkDetection,
    ]
}

fn ready_tier_classes() -> &'static [ControlTaskClass] {
    &[
        ControlTaskClass::BackgroundMaintenance,
        ControlTaskClass::TelemetryFlush,
        ControlTaskClass::EvidenceArchival,
        ControlTaskClass::MarkerCompaction,
        ControlTaskClass::AuditLogRotation,
        ControlTaskClass::MetricsExport,
        ControlTaskClass::StaleEntryCleanup,
    ]
}

#[test]
fn fresh_policy_invariants_hold() {
    let policy = ControlLanePolicy::new();
    assert!(policy.verify_all_assigned(), "verify_all_assigned must hold on fresh policy");
    assert!(policy.verify_budget_sum(), "verify_budget_sum must hold on fresh policy");
    assert_eq!(
        u16::from(CANCEL_LANE_BUDGET_PCT)
            + u16::from(TIMED_LANE_BUDGET_PCT)
            + u16::from(READY_LANE_BUDGET_PCT),
        100,
        "documented lane budgets must total exactly 100%"
    );
}

#[test]
fn canonical_lane_and_lookup_are_total_and_agree() {
    let policy = ControlLanePolicy::new();
    for &tc in ControlTaskClass::all() {
        let canonical = ControlLanePolicy::canonical_lane(tc);
        let assignment = policy
            .lookup(tc)
            .unwrap_or_else(|| panic!("lookup returned None for {tc:?}"));
        assert_eq!(
            assignment.lane, canonical,
            "lookup lane disagrees with canonical_lane for {tc:?}"
        );
        assert_eq!(
            assignment.task_class, tc,
            "lookup returned wrong task_class for {tc:?}"
        );
    }
}

#[test]
fn tier_classification_is_consistent() {
    for &tc in cancel_tier_classes() {
        assert_eq!(
            ControlLanePolicy::canonical_lane(tc),
            ControlLane::Cancel,
            "cancel-tier class {tc:?} must map to Cancel"
        );
    }
    for &tc in timed_tier_classes() {
        assert_eq!(
            ControlLanePolicy::canonical_lane(tc),
            ControlLane::Timed,
            "timed-tier class {tc:?} must map to Timed"
        );
    }
    for &tc in ready_tier_classes() {
        assert_eq!(
            ControlLanePolicy::canonical_lane(tc),
            ControlLane::Ready,
            "ready-tier class {tc:?} must map to Ready"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 64,
        ..ProptestConfig::default()
    })]

    /// Properties 1, 2, 3, 4, 5: tick semantics under arbitrary pending/slot
    /// inputs. Bounds are deliberately modest to stress the budget allocation
    /// math (small slot counts force the cancel-priority floor branch).
    #[test]
    fn tick_invariants_hold_for_arbitrary_inputs(
        cancel_pending in 0_u32..=64,
        timed_pending in 0_u32..=64,
        ready_pending in 0_u32..=64,
        total_slots in 0_u32..=32,
    ) {
        let mut policy = ControlLanePolicy::new();
        let metrics = policy.tick(
            cancel_pending,
            timed_pending,
            ready_pending,
            total_slots,
            "trace-prop",
        );

        // Property 1: slot conservation
        let used = metrics
            .cancel_lane_tasks_run
            .saturating_add(metrics.timed_lane_tasks_run)
            .saturating_add(metrics.ready_lane_tasks_run);
        prop_assert!(
            used <= total_slots,
            "lanes ran {} > total_slots {}",
            used,
            total_slots
        );

        // Property 2: no phantom work
        prop_assert!(
            metrics.cancel_lane_tasks_run <= cancel_pending,
            "cancel ran {} > pending {}",
            metrics.cancel_lane_tasks_run,
            cancel_pending
        );
        prop_assert!(
            metrics.timed_lane_tasks_run <= timed_pending,
            "timed ran {} > pending {}",
            metrics.timed_lane_tasks_run,
            timed_pending
        );
        prop_assert!(
            metrics.ready_lane_tasks_run <= ready_pending,
            "ready ran {} > pending {}",
            metrics.ready_lane_tasks_run,
            ready_pending
        );

        // Property 3: cancel-priority floor
        if cancel_pending > 0 && total_slots > 0 {
            prop_assert!(
                metrics.cancel_lane_tasks_run >= 1,
                "cancel-priority floor violated: cancel_pending={}, total_slots={}, cancel_run={}",
                cancel_pending,
                total_slots,
                metrics.cancel_lane_tasks_run
            );
        }

        // Property 4: starvation flag correctness
        prop_assert_eq!(
            metrics.cancel_lane_starved,
            cancel_pending > 0 && metrics.cancel_lane_tasks_run == 0,
            "cancel_lane_starved flag inconsistent with run/pending"
        );
        prop_assert_eq!(
            metrics.timed_lane_starved,
            timed_pending > 0 && metrics.timed_lane_tasks_run == 0,
            "timed_lane_starved flag inconsistent with run/pending"
        );
        prop_assert_eq!(
            metrics.ready_lane_starved,
            ready_pending > 0 && metrics.ready_lane_tasks_run == 0,
            "ready_lane_starved flag inconsistent with run/pending"
        );

        // Property 5: cancel never starves when there is capacity
        if total_slots > 0 && cancel_pending > 0 {
            prop_assert!(
                !metrics.cancel_lane_starved,
                "cancel starved despite total_slots={} and cancel_pending={}",
                total_slots,
                cancel_pending
            );
        }

        // tick_history must record exactly one entry for this tick.
        prop_assert_eq!(policy.tick_history().len(), 1);
    }

    /// Properties 8, 9: deadline fail-closed and scheduled-count consistency.
    /// Enqueue exactly one task and run the tick at a `now_ms` that is past the
    /// deadline (when the class is deadline-bound).
    #[test]
    fn deadline_aware_tick_respects_deadline_and_run_counts(
        tc in task_class_strategy(),
        enqueued_at_ms in 0_u64..=1_000_000,
        // `extra` keeps `now_ms` from underflowing and lets us land both
        // before and after the deadline depending on the class.
        extra_ms in 0_u64..=200_000,
        total_slots in 1_u32..=8,
    ) {
        let mut policy = ControlLanePolicy::new();
        let task_id = "task-prop-1";
        policy
            .enqueue_deadline_task(tc, task_id, enqueued_at_ms, "trace-prop")
            .expect("enqueue must succeed");

        let canonical_timeout = ControlLanePolicy::canonical_timeout(tc);
        // Run the tick well past any deadline: enqueued + (timeout or 0) + extra.
        let now_ms = enqueued_at_ms
            .saturating_add(canonical_timeout.unwrap_or(0))
            .saturating_add(extra_ms);

        let result = policy.tick_deadline_aware(now_ms, total_slots, "trace-prop");

        // Property 9: scheduled_task_ids count matches the metrics' run sum.
        let run_sum = result
            .metrics
            .cancel_lane_tasks_run
            .saturating_add(result.metrics.timed_lane_tasks_run)
            .saturating_add(result.metrics.ready_lane_tasks_run);
        prop_assert_eq!(
            u32::try_from(result.scheduled_task_ids.len()).unwrap_or(u32::MAX),
            run_sum,
            "scheduled_task_ids.len() must equal run-count sum"
        );
        prop_assert!(
            result.scheduled_task_ids.len() as u32 <= total_slots,
            "scheduled count must not exceed total_slots"
        );

        match canonical_timeout {
            Some(timeout_ms) => {
                // Deadline-bound classes (Cancel, Timed). The deadline is
                // `enqueued + timeout`; we ran at `enqueued + timeout + extra`,
                // i.e. now_ms >= deadline_at_ms. The scheduler uses fail-closed
                // semantics (`now >= deadline`), so the task must time out.
                let _ = timeout_ms;
                prop_assert!(
                    result.timed_out_task_ids.iter().any(|t| t == task_id),
                    "deadline-bound task {task_id} must be in timed_out_task_ids \
                     (class={tc:?}, enqueued={enqueued_at_ms}, now={now_ms})"
                );
                prop_assert!(
                    !result.scheduled_task_ids.iter().any(|t| t == task_id),
                    "timed-out task must not also be scheduled (class={tc:?})"
                );
            }
            None => {
                // Ready-tier tasks have no deadline — they must be scheduled
                // (we have at least 1 slot and they are the only queued task).
                prop_assert!(
                    result.timed_out_task_ids.is_empty(),
                    "ready-tier task must never time out (class={tc:?})"
                );
                prop_assert!(
                    result.scheduled_task_ids.iter().any(|t| t == task_id),
                    "ready-tier task must be scheduled given >=1 slot (class={tc:?})"
                );
            }
        }
    }
}
