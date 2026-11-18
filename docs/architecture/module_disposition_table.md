# Module Disposition Table (`bd-reality-20260923-26n9r.14`)

This document records the authoritative product disposition (`WIRE`, `GATE`, or `RETAIN-NON-AUTHORITY`) for trust, control-plane, runtime, replay, migration, and frontier modules under `crates/franken-node/src/`, enforced on every push by `scripts/check_reachability.py` and `scripts/reachability_ceiling.json` (`island_line_ceiling = 14084`).

Per `AGENTS.md` Rule 1, zero files are deleted without explicit written owner authorization.

## 1. `WIRE` — Connected to Live Default-Binary CLI Surfaces with E2E Coverage

| Subsystem / Module | Live CLI Command(s) | Verification Target |
|---|---|---|
| `replay::time_travel_engine` + `storage::cas` | `franken-node incident replay --inspect-steps` / `--step <SEQ>` | `incident_replay_counterfactual_cli_e2e` |
| `migration::product_minimizer`, `native_minimizer`, `source_fix::inspect` | `franken-node migrate kit-plan --capsule --capsule-sha256 [--minimize]` | `vef_and_ops_cli_e2e` |
| `connector::migration_pipeline`, `connector::migration_artifact` | `franken-node migrate kit-plan` (`singularity_pipeline`, `migration_artifact_contract`) | `vef_and_ops_cli_e2e` |
| `vef::{constraint_compiler, receipt_chain, proof_scheduler, proof_service (Ed25519MerkleTransparencyV1), proof_generator, evidence_capsule, proof_verifier, control_integration, verification_state, sdk_integration}` | `franken-node trust vef-prove`, `franken-node verify vef-proof`, `franken-node debug evidence` | `vef_and_ops_cli_e2e` |
| `dgis::*`, `security::dgis` | `franken-node trust scan --deep`, `franken-node ops dgis-fixture-suite` | `vef_and_ops_cli_e2e`, `trust_observe_cli_e2e` |
| `security::bpet::calibration_benchmark`, `security::conformal` | `franken-node trust calibrate-conformal [--include-bpet-benchmark]`, `franken-node trust observe` | `run_language_semantics_e2e`, `vef_and_ops_cli_e2e` |
| `security::copilot_engine` (IBD-8) + `VilleMartingaleMonitor` | `franken-node doctor expected-loss-actions` | `vef_and_ops_cli_e2e` |
| `tools::reputation_graph_apis` (IBD-9), `supply_chain::trust_graph` | `franken-node trust-card reputation`, `franken-node trust graph` | `trust_cli_e2e` |
| `security::zk_attestation` (`zka-ristretto255-v3.0`) | `franken-node trust zk-attest`, `franken-node verify zk-attestation` | `zk_attestation_e2e` |
| `security::staking_governance`, `security::intent_firewall`, `supply_chain::artifact_Pipeline` | `franken-node trust governance-audit` | `vef_and_ops_cli_e2e` |
| `runtime::optimization_governor` (`VilleMartingaleMonitor`), `runtime::speculation::proof_executor`, `security::blake3_adapter` | `franken-node runtime supervision-audit` | `vef_and_ops_cli_e2e` |
| `runtime::region_tree`, `connector::cancel_injection_gate`, `connector::saga` | `franken-node runtime region-quiescence-audit` | `vef_and_ops_cli_e2e` |
| `runtime::anti_entropy`, `control_plane::fork_detection`, `security::revocation_freshness_gate`, `security::sybil_defense` | `franken-node trust fabric-convergence-audit` | `vef_and_ops_cli_e2e` |
| `extensions::artifact_contract` (`MacaroonCapabilityEnvelope`) | `franken-node registry publish`, `franken-node run --registry-artifact`, `franken-node deploy` | `extension_admission_execution_e2e` |

## 2. `GATE` — Opt-In Experimental / Feature-Scoped Surfaces (Excluded from Default Release Binary)

| Module Namespace | Cargo Feature Gate in `lib.rs` / `mod.rs` | Rationale |
|---|---|---|
| `federation::atc_*`, `atc` | `feature = "advanced-features"` | Cross-deployment federated ATC aggregation; kept opt-in until multi-org transport authentication is deployed |
| `repair::proof_carrying_decode` | `feature = "advanced-features"` | Erasure-coded fragment repair; opt-in storage extension |
| `conformance::{connector_method_validator, fsqlite_inspired_suite, protocol_harness}` | `feature = "advanced-features"` | Conformance harnesses for external connector certification |
| `encoding::deterministic_seed` | `feature = "advanced-features"` | Auxiliary deterministic schedule seeder |
| `perf::optimization_governor` | `feature = "advanced-features"` | Extended `GovernorGate` wrapper over live `runtime::optimization_governor` |
| `api::*` (`compat_gate`, `mcp`, `operator_routes`, etc.) | `feature = "control-plane"` | Library-level control-plane route catalog (distinct from `fleet serve` `fastapi_rust` coordinator) |
| `policy::{compat_gates, compatibility_gate, approval_workflow, ...}` | `feature = "policy-engine"` | Extended policy-engine surfaces outside the default-compiled Bayesian Runtime Sentinel |
| `registry::*` | `feature = "admin-tools"` | Extended enterprise governance helpers |
| `verifier_economy`, `sdk` | `feature = "verifier-tools"` | Verifier-economy staking/settlement models |
| `testing::{lab_runtime, scenario_builder, virtual_transport}` | `any(test, feature = "test-support")` | Deterministic simulation harnesses for integration/Loom/chaos suites |

## 3. `RETAIN-NON-AUTHORITY` — Explicitly Retained Outside Execution Authority

| Module | Disposition & Security Boundary |
|---|---|
| `connector/capability_artifact.rs` | Retained for artifact-schema conformance tests only; **never** wired as an execution-authority gate (`extensions::artifact_contract` + `supply_chain::extension_registry` own live signed capability enforcement). |
| `migration/rewrite_tree_transaction.rs` | Active inherent `impl RewriteTransaction` methods (`apply_with_trees_receipt`, `apply_with_trees_for_request`) compiled into `migration::rewrite_transaction` on Linux. |
| `test_strategies/mod.rs`, `tools/replay_bundle_adversarial_fuzz.rs` | Shared `proptest` / fuzz generators consumed by crate integration and metamorphic suites. |
