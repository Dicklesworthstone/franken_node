# Bootstrap Doctor Contract (`bd-1pk`)

## Goal

Define deterministic diagnostics output for `franken-node doctor` so operators and CI can detect readiness blockers with stable pass/warn/fail codes and actionable remediation.

## Command Surface

- `franken-node doctor [--config <path>] [--profile <profile>] [--policy-activation-input <path>] [--json] [--trace-id <id>] [--verbose]`
- `--json` emits machine-readable report.
- default output is human-readable text.
- `--trace-id` binds all check log events to a stable correlation identifier.
- `--policy-activation-input` activates live policy pipeline diagnostics (guardrails, decision engine, explainer wording) from JSON input.

## Determinism Contract

For equivalent config/environment state, report semantics are deterministic:

- check list is emitted in a fixed order
- each check has stable `code`, `event_code`, and `scope`
- status mapping is stable (`pass|warn|fail`)
- remediation text is deterministic by status condition

Runtime metadata (`generated_at_utc`, per-check `duration_ms`) may vary, but does not alter check ordering, status, or code identity.

## Check Matrix

| Code | Event Code | Scope | Pass Condition | Warn/Fail Condition | Remediation |
|---|---|---|---|---|---|
| `DR-CONFIG-001` | `DOC-001` | `config.resolve` | Resolver completed | N/A | N/A |
| `DR-CONFIG-002` | `DOC-002` | `config.source` | Config file discovered | Warn when defaults-only | create `franken_node.toml` or pass `--config` |
| `DR-PROFILE-003` | `DOC-003` | `profile.safety` | `strict` or `balanced` | Warn on `legacy-risky` | use `--profile balanced|strict` |
| `DR-TRUST-004` | `DOC-004` | `registry.assurance` | `minimum_assurance_level >= 3` | Warn below target | raise assurance level to `3+` |
| `DR-MIGRATE-005` | `DOC-005` | `migration.lockstep` | lockstep validation enabled | Warn when disabled | set `migration.require_lockstep_validation=true` |
| `DR-OBS-006` | `DOC-006` | `observability.audit_events` | structured audit events enabled | Warn when disabled | set `observability.emit_structured_audit_events=true` |
| `DR-ENV-007` | `DOC-007` | `environment.cwd` | working directory accessible | Fail when cwd unavailable | restore directory access / permissions |
| `DR-CONFIG-008` | `DOC-008` | `config.provenance` | merge decisions present | Warn when missing | repair resolver provenance instrumentation |
| `DR-POLICY-009` | `DOC-009` | `policy.guardrails` | dominant guardrail verdict is `allow` | Warn on dominant `warn`; Fail on dominant `block` or invalid input | resolve blocked budgets and telemetry anomalies before policy activation |
| `DR-POLICY-010` | `DOC-010` | `policy.decision_engine` | top candidate accepted | Warn when fallback candidate used; Fail when all candidates blocked/no candidates/invalid input | provide safer candidates or reduce risk exposure |
| `DR-POLICY-011` | `DOC-011` | `policy.explainer_wording` | wording validator passes | Fail when wording separation fails or policy pipeline cannot execute | fix diagnostic-vs-guarantee wording and input integrity |

`DR-POLICY-009..011` are emitted only when `--policy-activation-input` is supplied.

## Status Aggregation

- `overall_status = fail` if any check is fail
- else `overall_status = warn` if any check is warn
- else `overall_status = pass`

## Machine-Readable Report Schema (CI)

Top-level fields:

- `command`
- `trace_id`
- `generated_at_utc`
- `selected_profile`
- `source_path`
- `overall_status`
- `status_counts.{pass,warn,fail}`
- `checks[]` with:
  - `code`
  - `event_code`
  - `scope`
  - `status`
  - `message`
  - `remediation`
  - `duration_ms`
- `structured_logs[]` with:
  - `trace_id`
  - `event_code`
  - `check_code`
  - `scope`
  - `status`
  - `duration_ms`
- `merge_decision_count`
- `merge_decisions[]`
- optional `policy_activation` object (present when policy activation input parses and executes):
  - `input_path`
  - `candidate_count`
  - `observation_count`
  - `prefiltered_candidate_count`
  - `top_ranked_candidate`
  - `guardrail_certificate.{epoch_id,dominant_verdict,findings[],blocking_budget_ids[]}`
  - `decision_outcome`
  - `explanation`
  - `wording_validation`

## CI Artifacts

`bd-1pk` verification emits:

- `artifacts/section_bootstrap/bd-1pk/doctor_contract_checks.json`
- `artifacts/section_bootstrap/bd-1pk/doctor_checks_matrix.json`
- `artifacts/section_bootstrap/bd-1pk/doctor_report_healthy.json`
- `artifacts/section_bootstrap/bd-1pk/doctor_report_degraded.json`
- `artifacts/section_bootstrap/bd-1pk/doctor_report_failure.json`
- `artifacts/section_bootstrap/bd-1pk/doctor_report_invalid_input.json`
- `artifacts/section_bootstrap/bd-1pk/verification_evidence.json`
- `artifacts/section_bootstrap/bd-1pk/verification_summary.md`
