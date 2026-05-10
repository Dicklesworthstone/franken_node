# bd-1d7n: Deterministic Activation Pipeline

## Bead: bd-1d7n | Section: 10.13

## Purpose

Implements a deterministic activation pipeline with fixed stage ordering:
sandbox creation -> ephemeral secret mount -> capability issuance ->
health-ready transition. The pipeline enforces that stages execute in
order, partial activation cannot leak persistent secrets, and restart
replay reproduces an identical transcript.

## Invariants

| ID | Statement |
|----|-----------|
| INV-ACT-STAGE-ORDER | Stages execute in fixed order; skipping or reordering is forbidden. |
| INV-ACT-NO-SECRET-LEAK | Partial activation failure cleans up ephemeral secrets before returning. |
| INV-ACT-DETERMINISTIC | Same inputs produce the same activation transcript on replay. |
| INV-ACT-HEALTH-LAST | Health-ready transition is always the final stage; it cannot precede capability issuance. |

## Stages

| Order | Stage | Description |
|-------|-------|-------------|
| 1 | `SandboxCreate` | Create and configure the isolation sandbox. |
| 2 | `SecretMount` | Mount ephemeral secrets into the sandbox. |
| 3 | `CapabilityIssue` | Issue capabilities to the connector within the sandbox. |
| 4 | `HealthReady` | Transition connector to health-ready state. |

## Types

### ActivationStage
- Enum: `SandboxCreate`, `SecretMount`, `CapabilityIssue`, `HealthReady`
- Ordered by activation sequence.

### StageResult
- `stage: ActivationStage`
- `success: bool`
- `error: Option<StageError>`
- `timestamp: String`

### ActivationTranscript
- `connector_id: String`
- `stages: Vec<StageResult>`
- `completed: bool`
- `trace_id: String`

### StageError
- `SandboxFailed { reason: String }`
- `SecretMountFailed { reason: String }`
- `CapabilityFailed { reason: String }`
- `HealthCheckFailed { reason: String }`

## Error Codes

| Code | Trigger |
|------|---------|
| `ACT_SANDBOX_FAILED` | Sandbox creation failed. |
| `ACT_SECRET_MOUNT_FAILED` | Ephemeral secret mount failed. |
| `ACT_CAPABILITY_FAILED` | Capability issuance failed. |
| `ACT_HEALTH_FAILED` | Health-ready transition failed. |

## Executor Boundary

`DefaultExecutor` is fail-closed. It returns
`ACTIVATION_EXECUTOR_REQUIRED` instead of creating a completed transcript so
operator-facing activation cannot look successful without real sandbox,
secret, capability, and health hooks.

`FixtureActivationExecutor` is a deterministic test baseline only. It validates
inputs and preserves transcript/order semantics, but it does not create a
sandbox, mount real secrets, issue real capabilities, or perform a live health
probe. It must not be cited as production activation evidence.

## Expected Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_10_13/bd-1d7n_contract.md` |
| Implementation | `crates/franken-node/src/connector/activation_pipeline.rs` |
| Integration tests | `tests/integration/activation_pipeline_determinism.rs` |
| Stage transcript | `artifacts/section_10_13/bd-1d7n/activation_stage_transcript.jsonl` |
| Verification evidence | `artifacts/section_10_13/bd-1d7n/verification_evidence.json` |
| Verification summary | `artifacts/section_10_13/bd-1d7n/verification_summary.md` |
