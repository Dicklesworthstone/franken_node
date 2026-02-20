# bd-28wj: Non-Negotiable Constraints

**Section:** 4 — Hard Guardrails
**Type:** Governance
**Status:** In Progress

## 13 Non-Negotiable Constraints

### Substrate Rules (MUST)

| # | Constraint | Enforcement |
|---|-----------|-------------|
| 1 | **Engine dependency**: depends on /dp/franken_engine, no fork | CI: crate-reintroduction gate (10.1) |
| 2 | **Asupersync dependency**: high-impact async paths MUST be Cx-first, region-owned, cancel-correct, obligation-tracked | CI: Cx-first signature policy (10.15 bd-2g6r) |
| 3 | **FrankenTUI substrate**: Console/TUI surfaces MUST use /dp/frankentui | CI: substrate compliance gate (10.16) |
| 4 | **FrankenSQLite substrate**: SQLite persistence MUST use /dp/frankensqlite | CI: substrate compliance gate (10.16) |

### Substrate Preferences (SHOULD)

| # | Constraint | Enforcement |
|---|-----------|-------------|
| 5 | **SQLModel Rust**: SHOULD use /dp/sqlmodel_rust for typed schema/query | Review: PR review gate |
| 6 | **FastAPI Rust**: SHOULD use /dp/fastapi_rust for service/API surfaces | Review: PR review gate |

### Process Rules

| # | Constraint | Enforcement |
|---|-----------|-------------|
| 7 | **Waiver discipline**: deviations require signed waiver with rationale, risk, expiry | Registry: waiver_registry.json |
| 8 | **Compatibility shim visibility**: shims must be explicit, typed, policy-visible | CI: shim audit gate (10.2) |
| 9 | **No line-by-line translation**: legacy runtimes for spec extraction only | Review: PR gate |
| 10 | **Policy-gated dangerous behavior**: gated by policy + auditable receipts | CI: policy gate (10.5) |
| 11 | **Evidence-backed claims**: every major claim has reproducible artifacts | CI: evidence gate (10.14/10.15) |
| 12 | **Deterministic migration**: tooling must be deterministic and replayable | CI: migration gate (10.3) |
| 13 | **Safe defaults**: defaults prioritize safe operation | Review: default audit |

## Event Codes

- `NNC-001`: Constraint check passed
- `NNC-002`: Constraint violation detected
- `NNC-003`: Waiver applied (constraint bypassed with approval)
- `NNC-004`: Waiver expired (constraint re-enforced)

## Invariants

- `INV-NNC-COMPLETE`: All 13 constraints have enforcement mechanisms
- `INV-NNC-ACTIONABLE`: Violation messages specify which constraint and how to fix
- `INV-NNC-AUDITABLE`: All violations and waivers are logged with trace IDs
- `INV-NNC-NO-SILENT-EROSION`: Quarterly audit confirms no untracked deviations

## Artifacts

- Constraint doc: `docs/governance/non_negotiable_constraints.md`
- Waiver registry: `docs/governance/waiver_registry.json`
- Verification: `scripts/check_non_negotiable_constraints.py`
- Tests: `tests/test_check_non_negotiable_constraints.py`
