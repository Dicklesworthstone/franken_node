# bd-kwwg - BPET with DGIS integration

## Verdict: PASS

The remediation replaces the stale `crates/franken-node/src/bpet/` claim with the real implementation path: `crates/franken-node/src/security/bpet/dgis_fusion.rs`.

## Implementation

- `crates/franken-node/src/security/bpet/dgis_fusion.rs` fuses BPET trajectory risk with DGIS `TopologyRiskMetrics`.
- `tests/integration/bpet_dgis_priority_escalation.rs` proves high-centrality trajectory anomalies escalate with expected-loss context while the same BPET score on a leaf node remains lower priority.
- `artifacts/10.21/bpet_dgis_escalation_report.json` records a deterministic sample escalation report.

## Verification

- 18/18 evidence checks pass.
- Focused validation commands are listed in `verification_evidence.json`.
