# bd-34d5: Friction-Minimized Install-to-Production Pathway

## Section
13 -- Friction-Minimized Install-to-Production Pathway

## Status
In Progress

## Summary
Define and enforce a friction-minimized pathway from initial `curl` install of
franken_node through to the first policy-governed production operation.  The
pathway must complete in under 5 minutes wall-clock time with zero manual file
edits when using the balanced onboarding profile.  Five representative project
archetypes are tested end-to-end in CI to guarantee the time and zero-edit
invariants hold across the ecosystem.

## Archetypes

| ID  | Archetype         | Description                                      | Expected Compat Score |
|-----|-------------------|--------------------------------------------------|-----------------------|
| A-1 | Express API       | Node.js Express HTTP service (REST/GraphQL)      | >= 0.90               |
| A-2 | React SPA         | Create-React-App or Vite-based single-page app   | >= 0.85               |
| A-3 | CLI Tool          | Node.js CLI packaged with npm bin stubs          | >= 0.92               |
| A-4 | Monorepo          | Turborepo / Nx workspace with 3+ packages        | >= 0.80               |
| A-5 | Serverless        | AWS Lambda / Vercel serverless function project   | >= 0.88               |

## Pathway Steps

1. **Install** -- `curl -fsSL https://get.frankennode.dev | sh`
2. **Init** -- `franken-node init` (auto-detects archetype)
3. **Configure** -- `franken-node configure --profile balanced` (zero manual edits)
4. **Run** -- `franken-node run --policy balanced` (first policy-governed operation)

## Time Budget

| Step      | Max Duration | Cumulative Max |
|-----------|-------------|----------------|
| Install   | 60 s        | 60 s           |
| Init      | 30 s        | 90 s           |
| Configure | 30 s        | 120 s          |
| Run       | 180 s       | 300 s (5 min)  |

Total wall-clock budget: **300 seconds (5 minutes)**.

## Event Codes

| Code    | Name              | Emitted When                                    |
|---------|-------------------|-------------------------------------------------|
| FMP-001 | pathway_started   | Install command begins execution                |
| FMP-002 | step_completed    | Any pathway step finishes (includes step name)  |
| FMP-003 | pathway_succeeded | Final run step completes with policy active     |
| FMP-004 | pathway_failed    | Any step fails or time budget exceeded          |

All events are structured JSON objects with fields: `code`, `step`, `archetype`,
`elapsed_ms`, `timestamp_utc`, and `metadata` (arbitrary key-value pairs).

## Invariants

| ID                   | Statement                                                                 |
|----------------------|---------------------------------------------------------------------------|
| INV-FMP-TIME         | Total pathway wall-clock time MUST be < 300 seconds for every archetype   |
| INV-FMP-ZERO-EDIT    | Balanced-profile onboarding MUST require zero manual file edits           |
| INV-FMP-TELEMETRY    | Every pathway step MUST emit a structured telemetry event (FMP-001..004)  |
| INV-FMP-ARCHETYPES   | All 5 archetypes MUST be tested in CI on every merge to main             |

## Acceptance Criteria

1. Spec document exists at `docs/specs/section_13/bd-34d5_contract.md` and
   covers all 5 archetypes, time budget, event codes, and invariants.
2. Policy document exists at `docs/policy/friction_minimized_pathway.md` with
   step definitions, archetype compatibility scores, telemetry requirements,
   and error-handling rules.
3. Verification script `scripts/check_friction_pathway.py` passes with
   `--json` output and includes a `self_test()` function.
4. Unit tests in `tests/test_check_friction_pathway.py` cover all checks.
5. Evidence artifact at `artifacts/section_13/bd-34d5/verification_evidence.json`
   records pass/fail for each check.
6. Summary artifact at `artifacts/section_13/bd-34d5/verification_summary.md`
   provides a human-readable roll-up.

## Dependencies
- bd-1ta (Section 10.13 Epic -- connector infrastructure)
- Section 10.2 compatibility core (archetype detection)

## Error Handling
- Every failure MUST produce a clear, actionable error message.
- Every failure MUST include a recovery suggestion.
- Silent failures are prohibited; any non-zero exit MUST emit FMP-004.
