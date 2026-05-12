# bd-34d5: Friction-Minimized Install-to-Production Pathway

## Section
13 -- Friction-Minimized Install-to-Production Pathway

## Status
Reality-Checked Target Contract

## Summary
This document now distinguishes between the **current shipped surface** and the
**future friction-minimized target contract**. Today the repository ships the
raw GitHub `install.sh` installer, `franken-node init --profile balanced`
state/bootstrap reporting, and `franken-node run ./my-app --policy balanced`
with an explicit application path. It does **not** currently ship a
`get.frankennode.dev` installer alias, archetype-aware init onboarding, or
FMP-001..004 pathway telemetry. Those remain the target contract for bd-34d5.

## Archetypes

| ID  | Archetype         | Description                                      | Expected Compat Score |
|-----|-------------------|--------------------------------------------------|-----------------------|
| A-1 | Express API       | Node.js Express HTTP service (REST/GraphQL)      | >= 0.90               |
| A-2 | React SPA         | Create-React-App or Vite-based single-page app   | >= 0.85               |
| A-3 | CLI Tool          | Node.js CLI packaged with npm bin stubs          | >= 0.92               |
| A-4 | Monorepo          | Turborepo / Nx workspace with 3+ packages        | >= 0.80               |
| A-5 | Serverless        | AWS Lambda / Vercel serverless function project   | >= 0.88               |

## Current Shipped Surface

1. **Install** -- `curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/franken_node/main/install.sh | bash`
2. **Init** -- `franken-node init --profile balanced` prints resolved config to stdout by default, bootstraps `.franken-node/` state, and can persist generated files when `--out-dir` is supplied.
3. **Run** -- `franken-node run ./my-app --policy balanced` requires an explicit application entrypoint.

The current shipped CLI does **not** auto-detect archetypes during `init`, and
it does **not** emit FMP-001 through FMP-004 telemetry events.
Current command-local reporting surfaces are `franken-node init --json`,
`franken-node init --structured-logs-jsonl`, `franken-node run --json`, and
`franken-node run --structured-logs-jsonl`.

The named completion-debt artifacts for the original target now exist as
current-reality boundary evidence:

- `tests/e2e/install_to_production_pathway.sh` checks the section-13 verifier
  and timing report boundary. It must not be cited as full end-to-end success.
- `artifacts/13/onboarding_timing_report.json` records the five setup cohorts
  with `target_pathway_shipped=false` and no claimed target timings.

## Planned Target Pathway

1. **Install** -- `curl -fsSL https://get.frankennode.dev | sh`
2. **Init** -- `franken-node init --profile balanced` with future archetype-aware onboarding and generated defaults
3. **Run** -- `franken-node run ./my-app --policy balanced` as the first policy-governed operation

## Time Budget

| Step      | Max Duration | Cumulative Max |
|-----------|-------------|----------------|
| Install   | 60 s        | 60 s           |
| Init      | 60 s        | 120 s          |
| Run       | 180 s       | 300 s (5 min)  |

Total wall-clock budget: **300 seconds (5 minutes)** for the future target
pathway. This is a design-time contract, not a claim that the current shipped
bootstrap flow is already proven end-to-end.

## Event Codes

| Code    | Name              | Emitted When                                    |
|---------|-------------------|-------------------------------------------------|
| FMP-001 | pathway_started   | Install command begins execution                |
| FMP-002 | step_completed    | Any pathway step finishes (includes step name)  |
| FMP-003 | pathway_succeeded | Final run step completes with policy active     |
| FMP-004 | pathway_failed    | Any step fails or time budget exceeded          |

All events are structured JSON objects with fields: `code`, `step`,
`archetype`, `elapsed_ms`, `timestamp_utc`, and `metadata` (arbitrary
key-value pairs).

Current reality: these event codes are reserved target semantics. They are not
emitted by the current `init`/`run` implementation or covered by a live CLI
telemetry harness today.

## Invariants

| ID                   | Statement                                                                 |
|----------------------|---------------------------------------------------------------------------|
| INV-FMP-TIME         | Total pathway wall-clock time MUST be < 300 seconds for every archetype   |
| INV-FMP-ZERO-EDIT    | Balanced-profile onboarding MUST require zero manual file edits           |
| INV-FMP-TELEMETRY    | Every pathway step MUST emit a structured telemetry event (FMP-001..004)  |
| INV-FMP-ARCHETYPES   | All 5 archetypes MUST be tested in CI on every merge to main             |

These remain target invariants for bd-34d5. The current repository only ships
the narrower bootstrap surface documented above.

## Acceptance Criteria

1. Spec document exists at `docs/specs/section_13/bd-34d5_contract.md` and
   covers all 5 archetypes, time budget, event codes, invariants, and current
   shipped pathway notes.
2. Policy document exists at `docs/policy/friction_minimized_pathway.md` with
   step definitions, archetype compatibility scores, telemetry requirements,
   error-handling rules, and explicit reality notes for the current CLI.
3. Verification script `scripts/check_friction_pathway.py` passes with
   `--json` output and includes a `self_test()` function that checks both the
   current shipped surface and the future target contract notes.
4. Unit tests in `tests/test_check_friction_pathway.py` cover all checks.
5. Evidence artifact at `artifacts/section_13/bd-34d5/verification_evidence.json`
   records pass/fail for each check.
6. Summary artifact at `artifacts/section_13/bd-34d5/verification_summary.md`
   provides a human-readable roll-up.
7. Completion-debt artifacts at `tests/e2e/install_to_production_pathway.sh`
   and `artifacts/13/onboarding_timing_report.json` cite the original expected
   shell/report paths while preserving the reality boundary:
   `target_pathway_shipped=false` and these artifacts must not be cited as full
   end-to-end success.

## Dependencies
- bd-1ta (Section 10.13 Epic -- connector infrastructure)
- Section 10.2 compatibility core (archetype detection)

## Error Handling
- Every failure MUST produce a clear, actionable error message.
- Every failure MUST include a recovery suggestion.
- Silent failures are prohibited; any non-zero exit MUST emit FMP-004.

Current `init` and `run` behavior already emit human-readable and JSON reports,
but they do not yet implement the FMP-004 event envelope above.
