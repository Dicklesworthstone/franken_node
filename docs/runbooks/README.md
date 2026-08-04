# Operator Runbooks Index

This index tracks high-severity trust-incident runbooks for Section 10.8 (`bd-nr4`).

## Table of Contents

| Runbook ID | Incident | Markdown | JSON Fixture | Severity | Privilege | ETR | Last Reviewed | Cadence | Coverage Tags |
|---|---|---|---|---|---|---|---|---|---|
| RB-001 | Trust State Corruption | `docs/runbooks/trust_state_corruption.md` | `fixtures/runbooks/rb_001_trust_state_corruption.json` | critical | P1 | 30m | 2026-02-21 | per_release_cycle | `trust-anchor-compromise`, `malicious-extension-detection` |
| RB-002 | Mass Revocation Event | `docs/runbooks/mass_revocation_event.md` | `fixtures/runbooks/rb_002_mass_revocation_event.json` | critical | P1 | 1h | 2026-05-01 | per_release_cycle | `key-rotation-emergency`, `malicious-extension-detection` |
| RB-003 | Fleet Quarantine Activation | `docs/runbooks/fleet_quarantine_activation.md` | `fixtures/runbooks/rb_003_fleet_quarantine_activation.json` | high | P2 | 45m | 2026-02-21 | per_release_cycle | `fleet-wide-quarantine-escalation`, `malicious-extension-detection` |
| RB-004 | Epoch Transition Failure | `docs/runbooks/epoch_transition_failure.md` | `fixtures/runbooks/rb_004_epoch_transition_failure.json` | critical | P1 | 1h | 2026-02-21 | per_release_cycle | `control-plane-split-brain` |
| RB-005 | Evidence Ledger Divergence | `docs/runbooks/evidence_ledger_divergence.md` | `fixtures/runbooks/rb_005_evidence_ledger_divergence.json` | high | P2 | 45m | 2026-02-21 | per_release_cycle | `control-plane-split-brain` |
| RB-006 | Proof Pipeline Outage | `docs/runbooks/proof_pipeline_outage.md` | `fixtures/runbooks/rb_006_proof_pipeline_outage.json` | high | P2 | 30m | 2026-02-21 | per_release_cycle | `malicious-extension-detection` |

## Validation Source-Only Runbooks

These runbooks handle validation-proof preflight blockers. They do not replace
the Section 10.8 incident fixtures above, and they do not count source-only
readiness records as green cargo proof.

| Runbook ID | Scenario | Markdown | Related Spec | Last Reviewed | Cadence |
|---|---|---|---|---|---|
| VAL-001 | Proof-lane readiness blockers | `docs/runbooks/proof_lane_readiness_blockers.md` | `docs/specs/proof_lane_readiness.md` | 2026-05-07 | per_release_cycle |
| VAL-002 | No-ready swarm recovery | `docs/runbooks/no_ready_swarm_recovery.md` | `docs/specs/validation_autopilot.md` | 2026-06-18 | per_release_cycle |

VAL-002 uses `scripts/check_validation_autopilot.py` as a dry-run planner and
keeps fixture-backed transcript coverage in
`tests/fixtures/validation_autopilot/transcript_cases.json`,
`tests/golden/validation_autopilot/transcript_golden.json`, and
`artifacts/validation_autopilot/bd-dy7vu/provenance.json`.

## Required Category Coverage

The following high-severity categories must be covered at minimum:

- `trust-anchor-compromise`
- `fleet-wide-quarantine-escalation`
- `control-plane-split-brain`
- `key-rotation-emergency`
- `malicious-extension-detection`

Coverage is validated by `scripts/check_operator_runbooks.py` against JSON fixture `coverage_tags`.
