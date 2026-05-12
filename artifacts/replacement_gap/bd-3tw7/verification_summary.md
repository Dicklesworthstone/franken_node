# bd-3tw7 Static Truthfulness Gate Seed

- Parent bead: `bd-3tw7`
- Support beads: `bd-3tw7.1, bd-3tw7.2, bd-3tw7.4, bd-3tw7.5, bd-3tw7.6, bd-3tw7.8, bd-3tw7.9`
- Verdict: `PASS`
- Scope: Static cross-surface surrogate scanner, operator E2E seed, migration evidence binding, and telemetry contract for currently unreserved replacement-critical surfaces.
- Static-seed disclaimer: this pack does not claim the full parent dynamic/e2e truthfulness gate is complete.

## Guarded Witnesses

- `migration_placeholder_prefix_shortcuts` (migration): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `compatibility_placeholder_signature_shortcuts` (policy): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `safe_mode_stale_frontier_fail_closed` (runtime_safe_mode): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `anti_entropy_canonical_proof_verification` (runtime_anti_entropy): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `extension_registry_shape_only_signature_shortcuts` (supply_chain_extension_registry): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `control_channel_non_empty_token_shortcut` (control_channel): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `session_auth_opaque_signature_regression` (api_session_auth): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `trust_card_evidence_binding` (supply_chain_trust_card): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `certification_evidence_binding` (supply_chain_certification): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `workspace_verifier_sdk_cryptographic_bundle_posture` (workspace_verifier_sdk): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `workspace_verifier_sdk_package_metadata_truthfulness` (workspace_verifier_sdk_metadata): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `incrate_sdk_verifier_structural_only_posture` (incrate_sdk_verifier): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `incrate_sdk_replay_capsule_structural_only_posture` (incrate_sdk_replay_capsule): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `supervision_time_budget_real_clock` (supervision): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`
- `migration_artifact_real_signature_verification` (migration_artifact): `PASS` via `TRUTHFULNESS_GATE_STATIC_PASS`

## Completion-Debt Coverage

- `tests.e2e.primary` (e2e): `covered` via deterministic operator E2E suite runs the truthfulness gate twice in isolated fixture workspaces and compares normalized artifacts
- `migrations.primary` (migrations): `covered` via migration placeholder-prefix and signed-artifact witnesses are first-class truthfulness-gate cases
- `telemetry.primary` (telemetry): `covered` via every witness result and JSON log event carries stable TRUTHFULNESS_GATE_* fields

## Telemetry Contract

- Event family: `TRUTHFULNESS_GATE_WITNESS`
- Trace ID: `trace-bd-3tw7-static`
- Evidence bundle: `replacement-gap/bd-3tw7/static-truthfulness-gate-v1`
- Required fields: `trace_id, witness_id, surface, offending_path, decision, reason_code, remediation_bead, evidence_bundle_id`

## Excluded Reserved Surfaces

- `crates/franken-node/src/verifier_economy/mod.rs` excluded because Reserved under bd-1z5a.8 (`RoseRidge`).
- `crates/franken-node/src/connector/verifier_sdk.rs` excluded because Reserved under bd-1z5a.8 (`RoseRidge`).

## Guard Checkers

- Primary seed checker: `scripts/check_replacement_truthfulness_gate.py`
- Primary seed tests: `tests/test_check_replacement_truthfulness_gate.py`
- Evidence-pack coherence checker: `scripts/check_bd_3tw7_evidence_pack.py`
- Evidence-pack coherence tests: `tests/test_check_bd_3tw7_evidence_pack.py`

## Artifact Paths

- `artifacts/replacement_gap/bd-3tw7/verification_evidence.json`
- `artifacts/replacement_gap/bd-3tw7/verification_summary.md`
- `artifacts/replacement_gap/bd-3tw7/witness_matrix.json`
