# Placeholder Surface Inventory

**Program:** `bd-2fqyv`  
**Beads:** `bd-2fqyv.1.1` inventory, `bd-2fqyv.1.2` scanner  
**Status:** Active inventory for placeholder/demo/simulated production-surface remediation.

## Purpose

This document is the authoritative inventory of placeholder, demo, sample,
synthetic, skeleton, and simulated surfaces that matter to the current
remediation program.

It exists to answer three questions precisely:

1. Which surfaces are actually reachable from live operator-facing entrypoints?
2. Which simulations are acceptable because they are explicit test/modeling
   helpers rather than deceptive live behavior?
3. Which follow-on remediation bead owns each dangerous surface?

## Classification Rules

### `disallowed_live_shortcut`

The surface is reachable from a live CLI, script, exported operator flow, or
other production-facing path and currently manufactures attractive-but-fake
behavior. These paths must be removed or made fail-closed.

### `truthful_partial_surface`

The surface performs real work, but its real scope is materially narrower than
its product framing. The scope must be documented honestly and must not be
marketed or wired as a complete implementation until the missing behavior
exists.

### `deferred_skeleton`

The surface is intentionally not a live runtime yet. It may remain only if the
code and docs clearly describe it as a skeleton/deferred boundary and no live
operator path treats it as finished.

### `allowlisted_simulation`

The surface is an explicit test fixture, modeling helper, or self-test utility.
It is allowed only if it stays out of live operator/release paths and remains
clearly labeled as synthetic.

## Inventory

| ID | Classification | Surface | Entry points / files | Reachability | Current behavior | Remediation owner |
|---|---|---|---|---|---|---|
| `PSI-001` | `disallowed_live_shortcut` | Trust CLI demo registry | `crates/franken-node/src/main.rs` via `trust_card_cli_registry()`, `handle_trust_card_command(...)`; historical fixture source lived at `crates/franken-node/src/supply_chain/trust_card.rs::fixture_registry(...)` | Live CLI | `trust list`, `trust revoke`, `trust quarantine`, `trust sync`, and `trust-card *` commands previously operated on canned in-memory trust-card state rather than authoritative persisted state. Persistence/bootstrap contract is defined in `docs/specs/section_10_4/bd-2fqyv_2_1_contract.md`. | `bd-2fqyv.2` |
| `PSI-002` | `disallowed_live_shortcut` | Demo receipt signing in live CLI flows | Legacy shortcut previously lived in `crates/franken-node/src/main.rs::maybe_export_demo_receipts(...)`; live path is being replaced by `maybe_export_signed_receipts(...)`. Deterministic fixture key remains in `crates/franken-node/src/security/decision_receipt.rs::demo_signing_key(...)` for tests/artifacts only. | Live CLI + fixture boundary | Live trust and incident paths now target explicit signing-material discovery (`--receipt-signing-key` -> env -> config) and emit deterministic `signer_key_id` provenance. This inventory item remains until validation closes the loop and the regression scanner is updated to ensure the fixture key cannot leak back into operator-facing code. | `bd-2fqyv.3` |
| `PSI-003` | `allowlisted_simulation` | Fixture incident timeline helper | `crates/franken-node/src/tools/replay_bundle.rs::fixture_incident_events(...)`; fixture consumers in `crates/franken-node/src/main.rs::incident_list_tests` | Test-only | Live `franken-node incident bundle` now reads authoritative incident evidence from `--evidence-path` or `<project-root>/.franken-node/state/incidents/<incident-id-slug>/evidence.v1.json`. Deterministic fixture timelines remain allowlisted only for tests and must never re-enter operator-facing incident evidence export. | `bd-2fqyv.4` |
| `PSI-004` | `deferred_skeleton` | Control-plane catalog boundary with explicitly unavailable perf baselines | `crates/franken-node/src/api/service.rs`, `crates/franken-node/src/api/middleware.rs`; supporting docs in `docs/architecture/blueprint.md` and `docs/architecture/tri_kernel_ownership_contract.md` | Not a live server boundary | Route catalog, middleware, and endpoint reports exist, but the module explicitly declares `TransportBoundaryKind::InProcessCatalog`, leaves request lifecycle/cancellation transport-unowned, and marks perf baselines as unavailable pending a real transport boundary instead of emitting fake `0.0` measurements. This is allowed only as a documented deferred boundary. | Validation ratchet under `bd-2fqyv.5.4`; scanner policy under `bd-2fqyv.1.2` must keep it allowlisted until a real transport boundary exists. |
| `PSI-005` | `truthful_partial_surface` | Migration live surface is audit/manifest-rewrite only | `crates/franken-node/src/main.rs` `MigrateCommand::{Audit,Rewrite,Validate}`; implementation in `crates/franken-node/src/migration/mod.rs::{run_audit, run_rewrite, run_validate}`; future connector executor contract in `docs/specs/section_10_13/bd-2fqyv_6_1_contract.md` | Live CLI | Current migration behavior is real but narrow: audit, lockfile/script checks, `package.json` engine pinning, manual-review reporting, and validation gates. It is not a general state/data migration executor and must not be represented as one. `bd-2fqyv.6.1` now defines the executable step semantics, rollback rules, idempotency contract, and receipt fields that `bd-2fqyv.6.2` must implement before this surface can be promoted. | `bd-2fqyv.6`; scanner policy under `bd-2fqyv.1.2` should flag overclaims about full migration execution. |
| `PSI-006` | `allowlisted_simulation` | Fuzz gate simulation helper | `crates/franken-node/src/connector/fuzz_corpus.rs::run_gate(...)`; verified by `scripts/check_fuzz_corpus.py` | Library / verification only | Crashes are inferred from seed text containing `crash`, and coverage is hard-coded to `0.0`. This is acceptable only as an internal modeling helper until a live empirical fuzz runner exists. | Keep allowlisted for now; `bd-2fqyv.1.2` must fail if any live gate or operator path starts consuming it as real fuzz evidence. |
| `PSI-008` | `truthful_partial_surface` | Ecosystem health export requires explicit upstream provenance for derived metrics | `crates/franken-node/src/supply_chain/ecosystem_telemetry.rs::export_health(...)` | Library / export helper | `compromise_reduction_factor` is now derived from the verified Section 13 compromise-reduction report and `certification_distribution` is computed from the active signed-extension set joined against canonical certification records. When those upstream inputs are missing, stale, or produce an undefined ratio, the export emits explicit `DerivedMetricAvailability` metadata instead of substituting `1.0` or an ambiguous empty map. This surface remains classified as truthful-partial because operator-facing callers must still provide authoritative upstream inputs for the same reporting window. | Validation ratchet under `bd-2fqyv.9.3`; scanner policy under `bd-2fqyv.1.2` should keep the explicit availability/provenance markers enforced. |
| `PSI-009` | `truthful_partial_surface` | DGIS barrier receipts must distinguish authoritative passes from missing-barrier cases | `crates/franken-node/src/security/dgis/barrier_primitives.rs::check_sandbox_escalation(...)`, `check_composition_firewall(...)`, `check_fork_pin(...)`, and `make_not_applicable_receipt(...)` | Library / internal security primitive | The live DGIS checks now emit authoritative pass receipts only when a matching barrier exists, and explicit `not_applicable` receipts (`DGIS-BARRIER-007`) when no barrier matches. The validation ratchet now covers both the no-barrier receipt matrix and audit-log/JSONL export so downstream operator flows cannot silently collapse back into synthetic pass-through outcomes. | Validation ratchet under `bd-2fqyv.11.3`; scanner policy under `bd-2fqyv.1.2` should flag any regression to synthetic pass-through receipts. |
| `PSI-010` | `disallowed_live_shortcut` | External reproduction script simulates claim verification | `scripts/reproduce.py::{verify_claim, run_reproduction}`; docs point to it from `docs/reproduction_playbook.md` and `docs/policy/external_reproduction.md` | Live operator script | The script currently emits `pass: true` with `verification simulated (full execution requires test harness)` instead of performing the referenced verification commands. Design bead `bd-2fqyv.10.1` now defines the required non-deceptive contract: explicit `procedure_ref` / `harness_kind` / `measurement_key` mapping plus `plan` vs `executed` result states. Follow-on implementation bead `bd-2fqyv.10.2` must make the script comply. | Follow-on remediation bead required under `bd-2fqyv`; scanner policy under `bd-2fqyv.1.2` should fail on simulated verification in live reproduction entrypoints. |

## Allowed Simulations

The following simulations are currently allowed because they are explicit
test/modeling helpers rather than deceptive live surfaces:

| Surface | Why it is allowed |
|---|---|
| `fixture_registry(...)` inside unit tests in `crates/franken-node/src/supply_chain/trust_card.rs`, `crates/franken-node/src/api/trust_card_routes.rs`, `crates/franken-node/src/main.rs`, and trust CLI e2e workspace seeding | Explicit deterministic fixture state used to exercise registry behavior; not acceptable in live CLI wiring. |
| `fixture_incident_events(...)` when used by tests in `crates/franken-node/src/tools/replay_bundle.rs` or `crates/franken-node/src/main.rs` | Deterministic fixture generation for replay-bundle tests and incident-list test coverage; not acceptable in live incident evidence export. |
| `decision_receipt::demo_signing_key(...)` in `crates/franken-node/src/security/decision_receipt.rs` fixture helpers/tests, `crates/franken-node/tests/verify_release_cli_e2e.rs`, `tests/integration/decision_receipt_export.rs`, and symbol-checker scripts such as `scripts/check_artifact_signing.py` | Deterministic fixture signing material remains acceptable only for tests, artifacts, and checker assertions. Operator-facing receipt export must use explicit operator-managed signing material. |
| `synthetic_bearer_admin_route()` in `crates/franken-node/src/api/service.rs` tests | Explicit negative test helper proving bearer auth cannot reach mTLS-only admin routes. |
| Python script self-tests that generate synthetic data (`scripts/check_*`, `scripts/project_scanner.py`, `scripts/e2e_test_server.py`) | Internal test harness behavior is acceptable when the script/docstring makes the synthetic nature explicit and no live operator contract treats the output as real evidence. |

## Inventory Notes

- Reachability matters more than keywords. A `demo_*` helper used only inside
  unit tests is not a program-level risk by itself.
- Skeletons are not automatically bugs. They become bugs when operator-facing
  flows, reports, or docs imply they are live, complete, or evidence-bearing.
- Truthful partial surfaces are allowed to exist temporarily, but only if their
  narrow real scope is documented explicitly and downstream consumers do not
  mistake them for completed product capabilities.
- `bd-2fqyv.8` remediated the former `PSI-007` shortcut: `ObligationGuard::drop`
  now performs real tracker-backed rollback and emits structured cleanup
  diagnostics. The scanner keeps regression pressure on the old placeholder
  wording and logging-only behavior instead of treating it as open debt.

## Regression Scanner Contract

`bd-2fqyv.1.2` implements the first repo-wide regression scanner at:

- `scripts/check_placeholder_surface_inventory.py`
- `tests/test_check_placeholder_surface_inventory.py`
- `.github/workflows/placeholder-remediation-gate.yml`

The scanner uses a two-stage policy:

1. Lexical stage: find suspicious helper names and placeholder markers such as
   `fixture_registry(...)`, `fixture_incident_events(...)`,
   `demo_signing_key(...)`, `verification simulated`, and other explicit
   truth-anchor tokens listed in the scanner rule set.
2. Reachability stage: classify each hit as one of:
   - explicit allowlisted fixture/test usage
   - documented open debt at a declared live anchor
   - failure due to allowlist escape, undocumented occurrence, missing truth
     anchor, or inventory drift

Current exit semantics are intentionally narrow: the scanner passes on
documented open debt that still matches this inventory, and fails only when the
documented boundary drifts or expands deceptively.

Run it with:

```bash
python3 scripts/check_placeholder_surface_inventory.py --json
python3 scripts/check_placeholder_surface_inventory.py --write-artifacts --json
python3 -m unittest tests.test_check_placeholder_surface_inventory
```

When `--write-artifacts` is used, the scanner emits:

- `artifacts/program/bd-2fqyv.1.3/verification_evidence.json`
- `artifacts/program/bd-2fqyv.1.3/verification_summary.md`

## Temporary Allowlist Strategy

The temporary allowlist is explicit and shrinking:

- `explicit_test_fixture`: helper is allowed only in the listed fixture/test
  paths or on the explicitly allowlisted helper-definition line.
- `documented_open_debt`: the marker may remain only at the live source anchor
  already documented in this inventory while the owning remediation bead is
  still open.
- `truth_anchor`: truthful partial and deferred skeleton surfaces must keep the
  honesty markers that prevent them from masquerading as complete live
  behavior.

No marker earns a permanent carve-out. When the owning remediation bead closes,
its documented live anchor must either disappear entirely or collapse into a
strictly test-only allowlist entry.

## Reproduction Procedure

The current inventory can be refreshed with focused searches like:

```bash
rg -n "demo_registry\\(|fixture_incident_events\\(|demo_signing_key\\(|maybe_export_(demo_)?signed_receipts|trust_card_cli_registry" crates/franken-node/src
rg -n "in-process catalog|UnavailablePendingTransport|synthetic_bearer_admin_route" crates/franken-node/src/api
rg -n "run_rewrite|run_validate|engines.node|manual review" crates/franken-node/src/migration
rg -n "simulated crash|coverage_pct: 0.0" crates/franken-node/src/connector/fuzz_corpus.rs
rg -n "In a real implementation this would call tracker.rollback|obligation rolled back by guard drop|OBL_DROP_SKIPPED" crates/franken-node/src/connector/obligation_tracker.rs
rg -n "Placeholder|Populated from live data" crates/franken-node/src/supply_chain/ecosystem_telemetry.rs
rg -n "placeholder" crates/franken-node/src/security/dgis/barrier_primitives.rs
rg -n "verification simulated" scripts/reproduce.py
```

Downstream beads must update this inventory when they remove a shortcut or when
a currently allowlisted simulation becomes live-reachable.
