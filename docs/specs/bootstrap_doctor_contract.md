# Bootstrap Doctor Contract (`bd-1pk`)

## Goal

Define deterministic diagnostics output for `franken-node doctor` so operators and CI can detect readiness blockers with stable pass/warn/fail codes and actionable remediation.

## Command Surface

- `franken-node doctor [--config <path>] [--profile <profile>] [--policy-activation-input <path>] [--json] [--structured-logs-jsonl] [--trace-id <id>] [--verbose]`
- `franken-node doctor [--trace-id <id>] evidence-readiness --input <path> [--json]`
- `--json` emits machine-readable report.
- `--structured-logs-jsonl` emits one structured diagnostic log event per line to stderr without changing stdout.
- default output is human-readable text.
- `--trace-id` binds all check log events to a stable correlation identifier.
- `--policy-activation-input` activates live policy pipeline diagnostics (guardrails, decision engine, explainer wording) from JSON input.
- `evidence-readiness` aggregates an operator-exported readiness snapshot so generated evidence is not trusted while sentinel hashes, default trust roots, producer-owned verdicts, or stale telemetry are present.

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
| `DR-STORAGE-012` | `DOC-012` | `storage.state_dir` | configured fleet state directory exists and is writable | Warn when missing; Fail when unwritable | create the directory or fix permissions |
| `DR-SECURITY-013` | `DOC-013` | `security.signing_key` | configured receipt signing key path is a readable regular file | Fail when missing, unreadable, or not a regular file | create the signing key or update `security.decision_receipt_signing_key_path` |
| `DR-ENGINE-014` | `DOC-014` | `engine.binary` | configured engine binary path is a regular executable file | Warn when missing or non-executable; Fail when not a regular file or metadata cannot be read | install `franken_engine`, update `engine.binary_path`, or fix permissions |
| `DR-BENCH-015` | `DOC-015` | `benchmark.validation` | benchmark threshold artifact exists and thresholds pass | Warn when validation cannot run; Fail when thresholds fail | run category shift validation and fix benchmark regressions |

`DR-POLICY-009..011` are emitted only when `--policy-activation-input` is supplied.
`DR-STORAGE-012`, `DR-SECURITY-013`, and `DR-ENGINE-014` are emitted only when their corresponding config paths are set.

## Evidence-Readiness Subcommand

`doctor evidence-readiness` consumes a JSON snapshot with schema
`franken-node/evidence-readiness-input/v1` and emits
`franken-node/evidence-readiness-report/v1`. The input is expected to be an
operator-side aggregation of existing verification surfaces such as signed
decision receipts, trust-root inventory, `debug evidence` verifier verdicts,
and telemetry exporter state.

Readiness checks:

| Code | Event Code | Scope | Pass Condition | Fail Condition | Recovery Hint |
|---|---|---|---|---|---|
| `DR-EVIDENCE-016` | `DOC-016` | `evidence.snapshot_schema` | snapshot schema is `franken-node/evidence-readiness-input/v1` | unsupported or missing schema | export a supported readiness snapshot |
| `DR-EVIDENCE-017` | `DOC-017` | `evidence.signed_decisions` | each decision has a verified trusted signature and non-sentinel sha256 evidence hash | unsigned decision, untrusted signer, missing signer key, sentinel hash, or malformed hash | re-sign with trusted operator keys and bind to real evidence hashes |
| `DR-EVIDENCE-018` | `DOC-018` | `evidence.trust_roots` | active roots are operator-managed and not demo/default/public-registry material | missing roots, duplicate roots, or default/non-operator roots | replace demo/default roots with operator-managed verifier keys |
| `DR-EVIDENCE-019` | `DOC-019` | `evidence.verification_basis` | evidence artifacts have verifier-owned pass verdicts, verified signatures, and real content digests | producer-trusted verdict, missing signature proof, failing verifier verdict, sentinel digest, or malformed digest | run `franken-node debug evidence --json` and trust only verifier-owned pass verdicts |
| `DR-EVIDENCE-020` | `DOC-020` | `observability.telemetry_exporter` | telemetry exporter is active and latest export age is within `max_staleness_secs` | inactive exporter, missing export timestamp, clock regression, or stale export | restart/fix telemetry export before trusting generated evidence |

Machine-readable evidence-readiness reports use the same status aggregation
rule as bootstrap doctor. Each check includes `code`, `event_code`, `scope`,
`status`, `message`, `recovery_hint`, and `duration_ms`.

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

When `--structured-logs-jsonl` is present, stderr contains newline-delimited JSON log entries derived from the same doctor checks. Each line includes:

- `timestamp`
- `level`
- `message`
- `trace_id`
- `span_id`
- `error_code` for warn/fail events
- `surface`
- `metric_refs[]`
- `recovery_hint`
- `event_code`
- `check_code`
- `scope`
- `status`
- `duration_ms`

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
