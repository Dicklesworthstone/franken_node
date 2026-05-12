# bd-145n: Deterministic Lab Runtime Scenarios

**Section:** 10.15 | **Type:** task | **Priority:** P1

## Overview

Integrates deterministic lab runtime for all high-impact control protocols.
Seed-controlled scheduling, 5 scenarios, 5 boundary seeds, reproducible traces.

## Scenarios (5)

- lab_lifecycle_start_stop, lab_rollout_go_abort, lab_epoch_commit_abort
- lab_saga_forward_compensate, lab_evidence_capture_replay

## Seed Matrix

10 entries across 5 seeds (0, 42, 12345, u64::MAX, 0xDEADBEEF) x 5 scenarios.

## Artifacts

- `docs/testing/control_lab_scenarios.md`
- `tests/lab/control_protocol_scenarios.rs`
- `artifacts/10.15/control_lab_seed_matrix.json`
- `scripts/check_control_lab_scenarios.py`
- `tests/test_check_control_lab_scenarios.py`
