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
//! 11. **Priority monotonicity under lower-priority padding** — adding extra
//!     Ready-lane work MUST NOT reduce Cancel or Timed run counts for the same
//!     tick, and SHOULD NOT reduce the Ready-lane run count.

use frankenengine_node::control_plane::control_lane_policy::{
    CANCEL_LANE_BUDGET_PCT, ControlLane, ControlLanePolicy, ControlTaskClass,
    READY_LANE_BUDGET_PCT, TIMED_LANE_BUDGET_PCT, error_codes,
};
use proptest::prelude::*;

fn task_class_strategy() -> impl Strategy<Value = ControlTaskClass> {
    proptest::sample::select(ControlTaskClass::all().to_vec())
}

fn invalid_task_id_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        ".*".prop_map(|suffix| format!(" {suffix}")),
        ".*".prop_map(|prefix| format!("{prefix} ")),
        (0_u8..=31, ".*")
            .prop_map(|(control, suffix)| { format!("task{}{}", char::from(control), suffix) }),
        (257_usize..=320).prop_map(|len| "x".repeat(len)),
    ]
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
    assert!(
        policy.verify_all_assigned(),
        "verify_all_assigned must hold on fresh policy"
    );
    assert!(
        policy.verify_budget_sum(),
        "verify_budget_sum must hold on fresh policy"
    );
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
        let assignment = policy.lookup(tc);
        assert!(assignment.is_some(), "lookup returned None for {tc:?}");
        if let Some(assignment) = assignment {
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

    /// Property 11: adding lower-priority Ready work is an inclusive
    /// transformation. MUST: higher-priority Cancel/Timed scheduling is
    /// unchanged. SHOULD: Ready scheduling is monotonic because the available
    /// Ready capacity is unchanged and only Ready demand increased.
    #[test]
    fn ready_padding_preserves_higher_priority_lane_counts(
        cancel_pending in 0_u32..=64,
        timed_pending in 0_u32..=64,
        ready_pending in 0_u32..=64,
        ready_padding in 0_u32..=64,
        total_slots in 0_u32..=32,
    ) {
        let mut base_policy = ControlLanePolicy::new();
        let base = base_policy.tick(
            cancel_pending,
            timed_pending,
            ready_pending,
            total_slots,
            "trace-mr-base",
        );

        let mut padded_policy = ControlLanePolicy::new();
        let padded = padded_policy.tick(
            cancel_pending,
            timed_pending,
            ready_pending.saturating_add(ready_padding),
            total_slots,
            "trace-mr-ready-padding",
        );

        prop_assert_eq!(
            padded.cancel_lane_tasks_run,
            base.cancel_lane_tasks_run,
            "MUST: Ready padding changed Cancel scheduling"
        );
        prop_assert_eq!(
            padded.timed_lane_tasks_run,
            base.timed_lane_tasks_run,
            "MUST: Ready padding changed Timed scheduling"
        );
        prop_assert!(
            padded.ready_lane_tasks_run >= base.ready_lane_tasks_run,
            "SHOULD: Ready padding reduced Ready scheduling"
        );
        prop_assert_eq!(base_policy.tick_history().len(), 1);
        prop_assert_eq!(padded_policy.tick_history().len(), 1);
    }

    /// Invalid task IDs are an untrusted-input boundary for the lane policy's
    /// mutating APIs. Rejection must happen before any state mutation.
    #[test]
    fn invalid_task_ids_fail_closed_before_state_mutation(
        tc in task_class_strategy(),
        invalid_task_id in invalid_task_id_strategy(),
        timestamp_ms in any::<u64>(),
        budget_remaining_ms in any::<u64>(),
    ) {
        let mut policy = ControlLanePolicy::new();

        let assign_error = policy
            .assign_task(tc, &invalid_task_id, "trace-invalid-assign", timestamp_ms)
            .expect_err("invalid task id must reject assignment");
        prop_assert!(
            assign_error.contains(error_codes::ERR_CLP_INVALID_TASK_ID),
            "assign_task returned wrong error: {assign_error}"
        );
        prop_assert!(policy.audit_log().is_empty());
        prop_assert!(policy.deadline_queue().is_empty());
        prop_assert!(policy.preemption_events().is_empty());

        let enqueue_error = policy
            .enqueue_deadline_task(
                tc,
                &invalid_task_id,
                timestamp_ms,
                "trace-invalid-enqueue",
            )
            .expect_err("invalid task id must reject deadline enqueue");
        prop_assert!(
            enqueue_error.contains(error_codes::ERR_CLP_INVALID_TASK_ID),
            "enqueue_deadline_task returned wrong error: {enqueue_error}"
        );
        prop_assert!(policy.audit_log().is_empty());
        prop_assert!(policy.deadline_queue().is_empty());
        prop_assert!(policy.preemption_events().is_empty());

        let preempt_error = policy
            .preempt_task(
                &invalid_task_id,
                ControlLanePolicy::canonical_lane(tc),
                budget_remaining_ms,
                "trace-invalid-preempt",
            )
            .expect_err("invalid task id must reject preemption");
        prop_assert!(
            preempt_error.contains(error_codes::ERR_CLP_INVALID_TASK_ID),
            "preempt_task returned wrong error: {preempt_error}"
        );
        prop_assert!(policy.audit_log().is_empty());
        prop_assert!(policy.deadline_queue().is_empty());
        prop_assert!(policy.preemption_events().is_empty());
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

    /// Saturation conformance test: system behavior under extreme load conditions
    /// where demand vastly exceeds capacity. Tests priority ordering, budget
    /// minimums, cascade allocation, and starvation detection under sustained
    /// saturation pressure.
    #[test]
    fn control_lane_policy_metamorphic_saturation_conformance(
        // Extreme saturation: demand >> capacity in all lanes
        cancel_pending in 100_u32..=2000,
        timed_pending in 200_u32..=3000,
        ready_pending in 500_u32..=5000,
        // Severely constrained capacity to force saturation
        total_slots in 1_u32..=20,
        // Test timestamp reordering metamorphism
        timestamp_shift_ms in 0_u64..=86400000, // up to 24 hours
    ) {
        let mut policy_base = ControlLanePolicy::new();
        let mut policy_shifted = ControlLanePolicy::new();
        let mut policy_reordered = ControlLanePolicy::new();

        // Base saturation scenario
        let metrics_base = policy_base.tick(
            cancel_pending,
            timed_pending,
            ready_pending,
            total_slots,
            "saturation-base",
        );

        // Timestamp-shifted scenario (metamorphic transformation)
        let base_timestamp = 1000000_u64;
        let shifted_timestamp = base_timestamp.saturating_add(timestamp_shift_ms);

        // Enqueue tasks with shifted timestamps to test ordering preservation
        for i in 0..cancel_pending.min(50) {
            let task_id = format!("cancel-task-{i}");
            let _ = policy_shifted.enqueue_deadline_task(
                ControlTaskClass::CancellationHandler,
                &task_id,
                shifted_timestamp.saturating_add(i as u64 * 100),
                "saturation-shifted",
            );
        }
        for i in 0..timed_pending.min(50) {
            let task_id = format!("timed-task-{i}");
            let _ = policy_shifted.enqueue_deadline_task(
                ControlTaskClass::HealthCheck,
                &task_id,
                shifted_timestamp.saturating_add(i as u64 * 200),
                "saturation-shifted",
            );
        }

        let metrics_shifted = policy_shifted.tick(
            cancel_pending,
            timed_pending,
            ready_pending,
            total_slots,
            "saturation-shifted",
        );

        // Reordered scenario (metamorphic transformation)
        // Enqueue in reverse order to test ordering independence
        for i in (0..cancel_pending.min(50)).rev() {
            let task_id = format!("cancel-rev-{i}");
            let _ = policy_reordered.enqueue_deadline_task(
                ControlTaskClass::DrainOperation,
                &task_id,
                base_timestamp.saturating_add(i as u64 * 100),
                "saturation-reordered",
            );
        }
        for i in (0..timed_pending.min(50)).rev() {
            let task_id = format!("timed-rev-{i}");
            let _ = policy_reordered.enqueue_deadline_task(
                ControlTaskClass::LeaseRenewal,
                &task_id,
                base_timestamp.saturating_add(i as u64 * 200),
                "saturation-reordered",
            );
        }

        let metrics_reordered = policy_reordered.tick(
            cancel_pending,
            timed_pending,
            ready_pending,
            total_slots,
            "saturation-reordered",
        );

        // SATURATION CONFORMANCE PROPERTIES

        // Property S1: Budget minimums respected under extreme saturation
        let cancel_min_slots = u32::try_from(
            u64::from(total_slots) * CANCEL_LANE_BUDGET_PCT as u64 / 100
        ).unwrap_or(u32::MAX);
        if cancel_pending > 0 && total_slots > 0 {
            prop_assert!(
                metrics_base.cancel_lane_tasks_run >= cancel_min_slots.max(1).min(total_slots),
                "Cancel lane minimum budget violated under saturation: \
                 expected >= {}, got {} (total_slots={}, cancel_pending={})",
                cancel_min_slots.max(1).min(total_slots),
                metrics_base.cancel_lane_tasks_run,
                total_slots,
                cancel_pending
            );
        }

        let timed_min_slots = u32::try_from(
            u64::from(total_slots) * TIMED_LANE_BUDGET_PCT as u64 / 100
        ).unwrap_or(u32::MAX);
        let cancel_leftover = cancel_min_slots.saturating_sub(metrics_base.cancel_lane_tasks_run);
        let timed_expected_min = if timed_pending > 0 && total_slots > metrics_base.cancel_lane_tasks_run {
            timed_min_slots.saturating_add(cancel_leftover).max(1)
                .min(total_slots.saturating_sub(metrics_base.cancel_lane_tasks_run))
        } else {
            timed_min_slots.saturating_add(cancel_leftover)
                .min(total_slots.saturating_sub(metrics_base.cancel_lane_tasks_run))
        };

        if timed_pending > 0 && total_slots > metrics_base.cancel_lane_tasks_run {
            prop_assert!(
                metrics_base.timed_lane_tasks_run >= timed_expected_min,
                "Timed lane minimum budget violated under saturation: \
                 expected >= {}, got {} (remaining_slots={})",
                timed_expected_min,
                metrics_base.timed_lane_tasks_run,
                total_slots.saturating_sub(metrics_base.cancel_lane_tasks_run)
            );
        }

        // Property S2: Priority ordering preserved under extreme saturation
        // Cancel must run before ready when both are pending and slots available
        if cancel_pending > 0 && ready_pending > 0 && total_slots > 0 {
            prop_assert!(
                metrics_base.cancel_lane_tasks_run > 0,
                "Cancel priority violated: cancel tasks starved while ready pending \
                 (cancel_pending={}, ready_pending={}, total_slots={})",
                cancel_pending, ready_pending, total_slots
            );
        }

        // When cancel is saturated and timed pending, timed runs before ready
        if cancel_pending >= total_slots && timed_pending > 0 && ready_pending > 0 {
            let remaining_after_cancel = total_slots.saturating_sub(metrics_base.cancel_lane_tasks_run);
            if remaining_after_cancel > 0 {
                prop_assert!(
                    metrics_base.timed_lane_tasks_run > 0,
                    "Timed priority violated: timed tasks starved while ready pending \
                     and slots available after cancel (remaining={})",
                    remaining_after_cancel
                );
            }
        }

        // Property S3: Slot conservation under saturation
        let total_run = metrics_base.cancel_lane_tasks_run
            .saturating_add(metrics_base.timed_lane_tasks_run)
            .saturating_add(metrics_base.ready_lane_tasks_run);
        prop_assert!(
            total_run <= total_slots,
            "Slot conservation violated under saturation: ran {} > total_slots {}",
            total_run, total_slots
        );

        // Property S4: No phantom work under saturation
        prop_assert!(
            metrics_base.cancel_lane_tasks_run <= cancel_pending,
            "Cancel phantom work under saturation: ran {} > pending {}",
            metrics_base.cancel_lane_tasks_run, cancel_pending
        );
        prop_assert!(
            metrics_base.timed_lane_tasks_run <= timed_pending,
            "Timed phantom work under saturation: ran {} > pending {}",
            metrics_base.timed_lane_tasks_run, timed_pending
        );
        prop_assert!(
            metrics_base.ready_lane_tasks_run <= ready_pending,
            "Ready phantom work under saturation: ran {} > pending {}",
            metrics_base.ready_lane_tasks_run, ready_pending
        );

        // Property S5: Starvation detection accuracy under saturation
        let expected_cancel_starved = cancel_pending > 0 && metrics_base.cancel_lane_tasks_run == 0;
        let expected_timed_starved = timed_pending > 0 && metrics_base.timed_lane_tasks_run == 0;
        let expected_ready_starved = ready_pending > 0 && metrics_base.ready_lane_tasks_run == 0;

        prop_assert_eq!(
            metrics_base.cancel_lane_starved, expected_cancel_starved,
            "Cancel starvation flag incorrect under saturation"
        );
        prop_assert_eq!(
            metrics_base.timed_lane_starved, expected_timed_starved,
            "Timed starvation flag incorrect under saturation"
        );
        prop_assert_eq!(
            metrics_base.ready_lane_starved, expected_ready_starved,
            "Ready starvation flag incorrect under saturation"
        );

        // Property S6: Cancel never starves with any capacity (critical safety)
        if total_slots > 0 && cancel_pending > 0 {
            prop_assert!(
                !metrics_base.cancel_lane_starved,
                "CRITICAL: Cancel lane starved despite available capacity \
                 (total_slots={}, cancel_pending={})",
                total_slots, cancel_pending
            );
            prop_assert!(
                metrics_base.cancel_lane_tasks_run > 0,
                "CRITICAL: Cancel lane got zero tasks despite available capacity"
            );
        }

        // Property S7: Metamorphic timestamp shift invariance
        // Timestamp shifts should not affect scheduling decisions for current tick
        prop_assert_eq!(
            metrics_base.cancel_lane_tasks_run,
            metrics_shifted.cancel_lane_tasks_run,
            "Timestamp shift affected cancel scheduling under saturation"
        );
        prop_assert_eq!(
            metrics_base.timed_lane_tasks_run,
            metrics_shifted.timed_lane_tasks_run,
            "Timestamp shift affected timed scheduling under saturation"
        );
        prop_assert_eq!(
            metrics_base.ready_lane_tasks_run,
            metrics_shifted.ready_lane_tasks_run,
            "Timestamp shift affected ready scheduling under saturation"
        );

        // Property S8: Metamorphic task reordering invariance
        // Task enqueueing order should not affect current tick scheduling totals
        prop_assert_eq!(
            metrics_base.cancel_lane_tasks_run,
            metrics_reordered.cancel_lane_tasks_run,
            "Task reordering affected cancel scheduling under saturation"
        );
        prop_assert_eq!(
            metrics_base.timed_lane_tasks_run,
            metrics_reordered.timed_lane_tasks_run,
            "Task reordering affected timed scheduling under saturation"
        );
        prop_assert_eq!(
            metrics_base.ready_lane_tasks_run,
            metrics_reordered.ready_lane_tasks_run,
            "Task reordering affected ready scheduling under saturation"
        );

        // Property S9: Cascade allocation efficiency under saturation
        // Verify leftover capacity cascades to lower priority lanes
        let cancel_theoretical_max = cancel_pending.min(total_slots);

        if metrics_base.cancel_lane_tasks_run < cancel_theoretical_max {
            // If cancel didn't consume all slots, check timed got cascade
            let remaining = total_slots.saturating_sub(metrics_base.cancel_lane_tasks_run);
            let timed_theoretical_max = timed_pending.min(remaining);

            if timed_theoretical_max > 0 {
                prop_assert!(
                    metrics_base.timed_lane_tasks_run > timed_min_slots.min(remaining),
                    "Cascade allocation failed: timed should benefit from cancel leftover \
                     under saturation (remaining={}, timed_run={})",
                    remaining, metrics_base.timed_lane_tasks_run
                );
            }
        }

        // Property S10: Saturation sustains across multiple ticks
        // Run additional ticks to verify sustained saturation behavior
        let metrics_tick2 = policy_base.tick(
            cancel_pending,
            timed_pending,
            ready_pending,
            total_slots,
            "saturation-sustain",
        );

        // Scheduling behavior should be consistent across saturated ticks
        prop_assert_eq!(
            metrics_base.cancel_lane_tasks_run,
            metrics_tick2.cancel_lane_tasks_run,
            "Cancel scheduling inconsistent across saturated ticks"
        );
        prop_assert_eq!(
            metrics_base.timed_lane_tasks_run,
            metrics_tick2.timed_lane_tasks_run,
            "Timed scheduling inconsistent across saturated ticks"
        );
        prop_assert_eq!(
            metrics_base.ready_lane_tasks_run,
            metrics_tick2.ready_lane_tasks_run,
            "Ready scheduling inconsistent across saturated ticks"
        );

        // Verify tick history grows correctly
        prop_assert_eq!(policy_base.tick_history().len(), 2);
        prop_assert_eq!(policy_shifted.tick_history().len(), 1);
        prop_assert_eq!(policy_reordered.tick_history().len(), 1);
    }
}
