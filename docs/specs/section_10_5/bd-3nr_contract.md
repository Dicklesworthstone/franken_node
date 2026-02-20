# bd-3nr Contract: Degraded-Mode Policy Behavior

## Scope

Implement deterministic degraded-mode semantics for stale trust inputs, with mandatory audit emission and bounded recovery behavior.

## Required Policy Surface

`DegradedModePolicy` includes:
- `mode_name`
- `trigger_conditions: Vec<TriggerCondition>`
- `permitted_actions: HashSet<String>`
- `denied_actions: HashSet<String>`
- `mandatory_audit_events: Vec<AuditEventSpec>`
- `auto_recovery_criteria: Vec<RecoveryCriterion>`

## Trigger Conditions

`TriggerCondition` variants:
- `HealthGateFailed(String)`
- `CapabilityUnavailable(String)`
- `ErrorRateExceeded { threshold: f64, window_secs: u64 }`
- `ManualActivation(String)`

## State Machine

`DegradedModeState`:
- `Normal`
- `Degraded`
- `Suspended`

Transition highlights:
- activation emits `TRUST_INPUT_STALE` then `DEGRADED_MODE_ENTERED`
- prolonged degradation escalates to `DEGRADED_MODE_SUSPENDED`
- recovery requires all criteria satisfied for stabilization window before `DEGRADED_MODE_EXITED`

## Action Policy

During degraded/suspended operation:
- high-risk actions in `denied_actions` are blocked
- non-blocked actions are annotated as degraded
- every degraded/suspended action attempt emits `DegradedModeActionAudit`

Stable action/audit codes:
- `DEGRADED_ACTION_BLOCKED`
- `DEGRADED_ACTION_ANNOTATED`

## Mandatory Audit Ticks

Mandatory audit events are described by `AuditEventSpec { event_code, interval_secs }`.

While degraded/suspended:
- periodic `MandatoryAuditTick` events fire by interval
- missing intervals emit `AUDIT_EVENT_MISSED`

## Recovery Contract

`RecoveryCriterion` controls exit:
- `HealthGateRestored(String)`
- `CapabilityAvailable(String)`
- `ErrorRateBelow { threshold: f64, window_secs: u64 }`
- `OperatorAcknowledged(String)`

Exit requires:
- all criteria true
- held continuously for stabilization window (default 300s)

## Verification Artifacts

- Implementation: `crates/franken-node/src/security/degraded_mode_policy.rs`
- Module export: `crates/franken-node/src/security/mod.rs`
- Verifier: `scripts/check_degraded_mode.py`
- Unit tests: `tests/test_check_degraded_mode.py`
- Evidence:
  - `artifacts/section_10_5/bd-3nr/verification_evidence.json`
  - `artifacts/section_10_5/bd-3nr/verification_summary.md`
