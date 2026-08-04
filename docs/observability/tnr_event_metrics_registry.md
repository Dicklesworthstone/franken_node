# TNR Event-Code and Metrics Registry

This registry defines the structured logging and Prometheus metric namespace for
the trust-native runtime program. Concrete `FN-*` event/error codes must be
registered before they appear in source or scripts.

## TNR Subsystems

| Subsystem | Event codes | Error code | Metrics |
|---|---|---|---|
| `FN-COMPAT` | `FN-COMPAT-001` compat contract loaded; `FN-COMPAT-002` compat oracle green; `FN-COMPAT-003` compat oracle red; `FN-COMPAT-004` compat divergence fixture emitted; `FN-COMPAT-005` compat leg unavailable; `FN-COMPAT-006` compat leg error | `FN-COMPAT-ERR-001` compat oracle divergence | `franken_node_compat_operations_total{operation,verdict}` |
| `FN-EFFECT` | `FN-EFFECT-001` effect receipt started; `FN-EFFECT-002` effect receipt chained | `FN-EFFECT-ERR-001` effect receipt invalid | `franken_node_effect_receipts_total{effect_kind,verdict}` |
| `FN-CAS` | `FN-CAS-001` CAS put started; `FN-CAS-002` CAS integrity verified | `FN-CAS-ERR-001` CAS integrity mismatch | `franken_node_cas_blobs_total{operation,verdict}` |
| `FN-TTR` | `FN-TTR-001` replay bundle loaded; `FN-TTR-002` replay verdict emitted | `FN-TTR-ERR-001` replay divergence | `franken_node_ttr_replays_total{verdict}` |
| `FN-FLOW` | `FN-FLOW-001` flow source registered; `FN-FLOW-002` flow transform propagated; `FN-FLOW-003` flow sink blocked; `FN-FLOW-004` flow declassification accepted; `FN-FLOW-005` flow non-exfiltration proof ready | `FN-FLOW-ERR-001` flow sink refused | `franken_node_flow_blocks_total{sink,label_class}` |
| `FN-SENTINEL` | `FN-SENTINEL-001` sentinel observation ingested; `FN-SENTINEL-002` sentinel action selected; `FN-SENTINEL-003` sentinel guardrail precedence; `FN-SENTINEL-004` sentinel ledger receipt appended; `FN-SENTINEL-005` sentinel hardening monotonic; `FN-SENTINEL-006` sentinel replay verified; `FN-SENTINEL-007` sentinel expected loss selected; `FN-SENTINEL-008` sentinel escalation receipt signed; `FN-SENTINEL-009` sentinel escalation enforced | `FN-SENTINEL-ERR-001` guardrail override | `franken_node_sentinel_escalations_total{action}` |
| `FN-CONFORMAL` | `FN-CONFORMAL-001` conformal set emitted; `FN-CONFORMAL-002` ACI quantile updated | `FN-CONFORMAL-ERR-001` coverage under target | `franken_node_conformal_coverage_observations_total{risk_class,covered}` |
| `FN-CAP` | `FN-CAP-001` capability proof issued; `FN-CAP-002` capability proof verified | `FN-CAP-ERR-001` capability proof rejected | `franken_node_capability_proofs_total{scope,verdict}` |
| `FN-MIGCERT` | `FN-MIGCERT-001` migration certificate started; `FN-MIGCERT-002` migration certificate verified; `FN-MIGCERT-003` migration differential witness verified; `FN-MIGCERT-004` migration sdk certified | `FN-MIGCERT-ERR-001` migration witness diverged | `franken_node_migration_certificates_total{rule_id,verdict}` |
| `FN-MCP` | `FN-MCP-001` MCP tool invoked; `FN-MCP-002` MCP mutation receipted; `FN-MCP-003` MCP tool rejected; `FN-MCP-004` MCP mutation dispatched; `FN-MCP-005` MCP session replay built | `FN-MCP-ERR-001` MCP scope denied | `franken_node_mcp_tool_invocations_total{tool,verdict}` |
| `FN-LTV` | `FN-LTV-001` LTV anchor dual signed; `FN-LTV-002` LTV root re-attested; `FN-LTV-003` LTV verify-as-of completed | `FN-LTV-ERR-001` anteriority unproven | `franken_node_ltv_reattestations_total{suite,verdict}` |
| `FN-FLEETLOG` | `FN-FLEETLOG-001` fleet-log action appended; `FN-FLEETLOG-002` fleet-log quorum certified | `FN-FLEETLOG-ERR-001` fleet-log equivocation proven | `franken_node_fleetlog_quorum_certificates_total{action,verdict}` |
| `FN-RESOLVE` | `FN-RESOLVE-001` resolver candidate scored; `FN-RESOLVE-002` resolver admission decided | `FN-RESOLVE-ERR-001` resolver candidate quarantined | `franken_node_resolver_admission_decisions_total{decision,reason}` |
| `FN-CORPUS` | `FN-CORPUS-001` corpus record loaded; `FN-CORPUS-002` corpus hash verified | `FN-CORPUS-ERR-001` corpus hash mismatch | `franken_node_corpus_records_total{profile,verdict}` |
| `FN-CALIB` | `FN-CALIB-001` calibration run started; `FN-CALIB-002` calibration artifact signed | `FN-CALIB-ERR-001` calibration recompute mismatch | `franken_node_calibration_runs_total{profile,verdict}` |
| `FN-ACCEPT` | `FN-ACCEPT-001` acceptance gate evaluated; `FN-ACCEPT-002` acceptance gate pass; `FN-ACCEPT-003` acceptance gate fail closed; `FN-ACCEPT-004` acceptance gate blocking finding | `FN-ACCEPT-ERR-001` acceptance gate input invalid | `franken_node_acceptance_gate_evaluations_total{verdict}` |

## Legacy Namespaces

These namespaces predate the TNR program-level registry but are intentionally
covered so the source scanner can fail only on newly unregistered concrete
codes.

| Namespace | Covered codes |
|---|---|
| `FN-AA` | `FN-AA-001` through `FN-AA-008` |
| `FN-AE` | `FN-AE-001` through `FN-AE-008` |
| `FN-BM` | `FN-BM-001` through `FN-BM-006` |
| `FN-CK` | `FN-CK-001` through `FN-CK-008` |
| `FN-CX` | `FN-CX-001` through `FN-CX-010` |
| `FN-IFL` | `FN-IFL-001` through `FN-IFL-018` |
| `FN-LB` | `FN-LB-001` through `FN-LB-011` |
| `FN-NV` | `FN-NV-001` through `FN-NV-012` |
| `FN-OB` | `FN-OB-001` through `FN-OB-013` |
| `FN-SG` | `FN-SG-001` through `FN-SG-012` |
| `FN-ZK` | `FN-ZK-001` through `FN-ZK-012` |

## Gate

Run the registry checker with:

```bash
python3 scripts/check_tnr_observability_contract.py --json
```

The gate fails if a required subsystem is missing, a metric name is not a valid
Prometheus identifier under `franken_node_*`, the Markdown omits a registered
TNR code or metric, or source/scripts contain a concrete `FN-*` code outside
the registry and legacy namespace ranges.
