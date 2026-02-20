# Non-Negotiable Constraints — Enforcement Reference

**Bead:** bd-28wj | Section: 4

## Purpose

This document codifies the 13 hard guardrails from Section 4 of the master plan.
Violating any constraint is a program-level failure. Each constraint has an automated
enforcement mechanism (CI gate or review gate) and a structured violation event code.

## Constraint Registry

### C-01: Engine Dependency Rule

- **Rule:** franken_node depends on /dp/franken_engine. No fork of engine internals. No local reintroduction of engine core crates.
- **Severity:** HARD (blocks merge)
- **Enforcement:** CI gate scans `Cargo.toml` and `crates/` for engine crate reintroduction. Implemented in 10.1.
- **Violation code:** `NNC-002:C-01`
- **Fix:** Remove the reintroduced crate and use the engine dependency directly.

### C-02: Asupersync Dependency Rule

- **Rule:** High-impact async control paths MUST be Cx-first, region-owned, cancel-correct, and obligation-tracked.
- **Severity:** HARD (blocks merge)
- **Enforcement:** Cx-first signature policy gate (bd-2g6r, section 10.15). Ambient authority audit gate (bd-721z).
- **Violation code:** `NNC-002:C-02`
- **Fix:** Add `Cx` parameter to the async entrypoint and register with the obligation tracker.

### C-03: FrankenTUI Substrate Rule

- **Rule:** Console/TUI surfaces MUST use /dp/frankentui as the canonical presentation substrate.
- **Severity:** HARD (blocks merge)
- **Enforcement:** Substrate compliance gate (section 10.16, bd-1xtf).
- **Violation code:** `NNC-002:C-03`
- **Fix:** Migrate the TUI code to use frankentui primitives.

### C-04: FrankenSQLite Substrate Rule

- **Rule:** Any feature needing SQLite persistence MUST use /dp/frankensqlite as the storage substrate.
- **Severity:** HARD (blocks merge)
- **Enforcement:** Substrate compliance gate (section 10.16, bd-2tua).
- **Violation code:** `NNC-002:C-04`
- **Fix:** Replace direct rusqlite/sqlite3 usage with frankensqlite adapter.

### C-05: SQLModel Rust Preference

- **Rule:** /dp/sqlmodel_rust SHOULD be used for typed schema/model/query integration.
- **Severity:** SOFT (reviewer discretion)
- **Enforcement:** PR review checklist. Waiver required if alternative chosen.
- **Violation code:** `NNC-002:C-05`
- **Fix:** Adopt sqlmodel_rust or file a waiver with justification.

### C-06: FastAPI Rust Preference

- **Rule:** /dp/fastapi_rust SHOULD be used for service/API control surfaces.
- **Severity:** SOFT (reviewer discretion)
- **Enforcement:** PR review checklist. Waiver required if alternative chosen.
- **Violation code:** `NNC-002:C-06`
- **Fix:** Adopt fastapi_rust or file a waiver with justification.

### C-07: Waiver Discipline

- **Rule:** Any deviation from substrate rules requires an explicit, signed waiver artifact with rationale, risk analysis, and expiry.
- **Severity:** HARD (blocks merge for MUST constraints)
- **Enforcement:** Waiver registry (`docs/governance/waiver_registry.json`). CI checks waiver expiry on every build.
- **Violation code:** `NNC-002:C-07`
- **Fix:** File a waiver in the registry with required fields.

### C-08: Compatibility Shim Visibility

- **Rule:** Compatibility shims must be explicit, typed, and policy-visible.
- **Severity:** HARD (blocks merge)
- **Enforcement:** Shim audit gate (section 10.2). All shims registered in shim manifest.
- **Violation code:** `NNC-002:C-08`
- **Fix:** Register the shim in the compatibility manifest with type annotation.

### C-09: No Line-by-Line Translation

- **Rule:** Legacy runtimes may be used for spec extraction and conformance fixture capture ONLY. Line-by-line Bun/Node translation is off-charter.
- **Severity:** HARD (blocks merge)
- **Enforcement:** PR review gate. Automated pattern detection for `// Translated from` comments.
- **Violation code:** `NNC-002:C-09`
- **Fix:** Remove the translated code. Use spec extraction for behavior, not source translation.

### C-10: Policy-Gated Dangerous Behavior

- **Rule:** Dangerous compatibility behavior must be gated by policy and auditable receipts.
- **Severity:** HARD (blocks merge)
- **Enforcement:** Policy gate (section 10.5). Hardening state machine (bd-25nl).
- **Violation code:** `NNC-002:C-10`
- **Fix:** Wrap the dangerous behavior in a policy gate with receipt emission.

### C-11: Evidence-Backed Claims

- **Rule:** Every major claim ships with reproducible benchmark/security artifacts.
- **Severity:** HARD (blocks release)
- **Enforcement:** Evidence gate (sections 10.14/10.15). Verification scripts produce machine-readable evidence.
- **Violation code:** `NNC-002:C-11`
- **Fix:** Add a verification script and evidence artifact for the claim.

### C-12: Deterministic Migration

- **Rule:** Migration tooling must be deterministic and replayable for high-severity failures.
- **Severity:** HARD (blocks release)
- **Enforcement:** Migration gate (section 10.3). Replay infrastructure (bd-145n).
- **Violation code:** `NNC-002:C-12`
- **Fix:** Add deterministic replay support to the migration path.

### C-13: Safe Defaults

- **Rule:** Product defaults prioritize safe operation while preserving practical adoption velocity.
- **Severity:** HARD (blocks release)
- **Enforcement:** Default audit in PR review. Configuration system (bd-n9r) enforces safe defaults.
- **Violation code:** `NNC-002:C-13`
- **Fix:** Change the default to the safe option. Document the rationale.

## Waiver Process

1. File a waiver in `docs/governance/waiver_registry.json` with fields:
   - `constraint_id`: Which constraint (C-01 through C-13)
   - `waiver_id`: Unique identifier
   - `rationale`: Why the deviation is necessary
   - `risk_analysis`: What risks the deviation introduces
   - `mitigations`: What mitigations are in place
   - `approved_by`: Who approved (agent name or human)
   - `expires_at`: When the waiver expires (ISO 8601)
   - `status`: `active` or `expired`
2. CI checks waiver expiry on every build.
3. Expired waivers re-enforce the constraint.

## Quarterly Audit

Every quarter, scan for:
- Active waivers approaching expiry
- Constraints without enforcement mechanisms
- Silent constraint erosion (violations without event codes)
