# bd-1fp4: Integrity Sweep Escalation/De-Escalation Policy

## Overview

Dynamically adjusts integrity sweep cadence based on evidence trajectories.
Escalation is immediate; de-escalation requires hysteresis to prevent
oscillation.

## Module

`crates/franken-node/src/policy/integrity_sweep_scheduler.rs`

## Types

| Type | Purpose |
|------|---------|
| `Trend` | Evidence direction: Improving, Stable, Degrading |
| `EvidenceTrajectory` | Recent rejections, escalations, repairability, trend |
| `PolicyBand` | Green (stable), Yellow (concern), Red (active threat) |
| `SweepDepth` | Quick, Standard, Deep, Full |
| `SweepScheduleDecision` | Scheduling decision recorded in evidence ledger |
| `SweepSchedulerConfig` | Configurable thresholds, intervals, hysteresis |
| `IntegritySweepScheduler` | Adaptive scheduler with hysteresis |

## Band Classification

| Band | Condition (any trigger) |
|------|----------------------|
| Red | rejections >= red_threshold OR (Degrading + low repairability) |
| Yellow | rejections >= yellow_threshold OR escalations > 0 OR Degrading trend |
| Green | none of the above |

## Default Sweep Parameters

| Band | Interval | Depth |
|------|----------|-------|
| Green | 5 min (300s) | Quick |
| Yellow | 1 min (60s) | Standard |
| Red | 10s | Deep |

## Invariants

| ID | Rule |
|----|------|
| INV-SWEEP-ADAPTIVE | Cadence scales with actual risk, not fixed timer |
| INV-SWEEP-HYSTERESIS | De-escalation requires N consecutive lower-band readings |
| INV-SWEEP-BOUNDED | Sweep overhead within configured resource budget |
| INV-SWEEP-DETERMINISTIC | Identical trajectory sequences produce identical schedules |

## Event Codes

| Code | Trigger |
|------|---------|
| EVD-SWEEP-001 | Sweep scheduled (interval, depth, band) |
| EVD-SWEEP-002 | Band transition (from/to) |
| EVD-SWEEP-003 | Hysteresis preventing de-escalation |
| EVD-SWEEP-004 | Trajectory updated |

## Acceptance Criteria

1. Cadence increases immediately on evidence degradation.
2. Cadence decreases only after N consecutive stable updates (default N=3).
3. De-escalation proceeds one step at a time (Red -> Yellow -> Green).
4. Oscillation test: alternating evidence doesn't cause cadence flickering.
5. All scheduling decisions recorded with trajectory context.
6. NaN/Inf repairability values safely clamped.
7. Trajectory CSV artifact is valid and parseable.
8. Scheduler state is serializable for persistence.
