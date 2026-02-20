# bd-38ri: Risk Control — Scope Explosion

**Bead:** bd-38ri
**Section:** 12 — Risk Control
**Status:** Active
**Last reviewed:** 2026-02-20

---

## Scope

The Scope Explosion risk arises when unchecked feature growth overwhelms
delivery capacity. Enhancement maps, capability proposals, and bead creation
can generate unbounded work that exceeds a track's ability to deliver quality
artifacts within its time budget.

This contract defines the countermeasures, invariants, and event codes that
govern scope explosion detection and enforcement across all franken_node
tracks.

## Risk Description

Scope creep occurs when:
- Enhancement maps generate beads faster than they can be closed.
- New capabilities are added to tracks without formal approval.
- Artifact-gated delivery is bypassed or deferred.
- Per-track bead budgets are exceeded without escalation.

Left unchecked, scope explosion leads to incomplete deliverables, abandoned
beads, quality degradation, and loss of project velocity.

## Countermeasures

### 1. Capability Gates

Each track has a maximum capability count. New capabilities require explicit
approval from the track owner and engineering lead before implementation
begins. The gate prevents silent feature creep.

- Maximum capabilities per track: configurable, default 16.
- Adding a capability beyond the limit emits **RSE-003** and blocks until
  approved.
- All capability additions are logged in the bead system.

### 2. Artifact-Gated Delivery

No bead may be closed without its full artifact chain:
1. Spec contract document.
2. Implementation (Rust or Python).
3. Verification script with `--json` and `self_test()`.
4. Unit tests.
5. Verification evidence JSON.
6. Verification summary.

Attempting to close a bead without artifacts emits **RSE-004** (validation)
and is rejected.

### 3. Scope Budgets per Track

Each track has a per-epoch bead count budget. When the budget is exceeded:
- **RSE-002** is emitted.
- New bead creation for the track is gated behind escalation approval.
- The track health dashboard reflects the over-budget state.

Default budget: 50 beads per track per epoch (configurable).

## Event Codes

| Code | Trigger |
|------|---------|
| RSE-001 | Scope check passed — track within budget and capability limits |
| RSE-002 | Scope budget exceeded — bead count for track exceeds configured limit |
| RSE-003 | Capability gate enforced — new capability blocked pending approval |
| RSE-004 | Artifact-gated delivery validated — bead closure confirmed artifact chain |

## Invariants

| ID | Statement |
|----|-----------|
| INV-RSE-GATE | Every new capability addition is gated by explicit track-owner approval |
| INV-RSE-BUDGET | Per-track bead count does not exceed configured budget without escalation |
| INV-RSE-ARTIFACT | No bead closes without a complete artifact chain (spec, impl, verification, tests, evidence, summary) |
| INV-RSE-TRACK | Track health dashboards reflect current scope state including budget utilization and capability count |

## Threshold Enforcement

| Level | Condition | Action |
|-------|-----------|--------|
| Green | Budget utilization < 80% | No action required |
| Warning | Budget utilization 80%--95% | Alert track owner; review scope |
| Critical | Budget utilization > 95% or exceeded | Block new beads; escalation required |

The **hard threshold** is **95%** budget utilization. Tracks exceeding this
value cannot create new beads without explicit engineering-lead approval.

## Alert Pipeline

```
Scope Check
  |
  v
Compute budget utilization
  |
  +-- < 80% --> log RSE-001, continue
  |
  +-- 80%-95% --> log RSE-001, fire WARNING alert
  |
  +-- > 95% --> log RSE-001 + RSE-002, fire CRITICAL alert
                 block new bead creation
```

## Escalation Procedures

| Trigger | Escalation |
|---------|------------|
| Budget utilization > 95% | Track owner notified; new beads blocked |
| Budget exceeded for > 48h | Engineering lead escalation; scope review meeting |
| Capability gate override requested | Requires track owner + engineering lead approval |
| Artifact chain incomplete at bead close | Bead closure rejected; author notified |

## Evidence Requirements for Risk Mitigation Review

A risk mitigation review requires:
1. **Track budget report** — Current bead count vs. budget for all tracks.
2. **Capability gate log** — All capability additions and gate decisions.
3. **Artifact completeness audit** — Percentage of closed beads with full artifact chains.
4. **Scope trend** — 30-day trend of bead creation vs. closure rates.
5. **Invariant status** — Confirmation that INV-RSE-GATE, INV-RSE-BUDGET,
   INV-RSE-ARTIFACT, and INV-RSE-TRACK are satisfied.
6. **Escalation log** — Record of any escalations since last review.

Reviews are conducted monthly or after any critical-severity budget breach,
whichever comes first.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec contract | `docs/specs/section_12/bd-38ri_contract.md` |
| Risk policy | `docs/policy/risk_scope_explosion.md` |
| Verification script | `scripts/check_scope_explosion.py` |
| Python unit tests | `tests/test_check_scope_explosion.py` |
| Verification evidence | `artifacts/section_12/bd-38ri/verification_evidence.json` |
| Verification summary | `artifacts/section_12/bd-38ri/verification_summary.md` |
