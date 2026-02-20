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
| `BandThresholds` | Configurable thresholds for band classification |
| `SweepIntervals` | Configurable intervals per band |
| `IntegritySweepScheduler` | Adaptive scheduler with hysteresis |

## Band Classification

| Band | Condition (any trigger) |
|------|----------------------|
| Red | rejections >= 20, repairability <= 0.4, escalations >= 5, degrading trend |
| Yellow | rejections >= 5, repairability <= 0.7, escalations >= 2 |
| Green | none of the above |

## Sweep Parameters per Band

| Band | Interval | Depth |
|------|----------|-------|
| Green | 1 hour | Quick |
| Yellow | 10 min | Standard |
| Red | 1 min | Deep |

## Invariants

| ID | Rule |
|----|------|
| INV-SWEEP-ESCALATE-IMMEDIATE | One evidence update in higher band → immediate escalation |
| INV-SWEEP-DEESCALATE-HYSTERESIS | De-escalation requires N consecutive stable updates |
| INV-SWEEP-DETERMINISTIC | Identical trajectory → identical decisions |
| INV-SWEEP-BOUNDED | Sweep overhead within configured budget |

## Event Codes

| Code | Trigger |
|------|---------|
| EVD-SWEEP-001 | Sweep scheduled (interval, depth, band) |
| EVD-SWEEP-002 | Band transition (from/to) |
| EVD-SWEEP-003 | Hysteresis preventing de-escalation |
| EVD-SWEEP-004 | Trajectory updated |

## Acceptance Criteria

1. Cadence increases immediately on evidence degradation.
2. Cadence decreases only after N consecutive stable updates.
3. Oscillation test: alternating evidence doesn't cause cadence flickering.
4. All scheduling decisions recorded with trajectory context.
5. Decision history bounded (max 1000 entries).
