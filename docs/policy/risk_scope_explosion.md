# Risk Policy: Scope Explosion

**Bead:** bd-38ri
**Section:** 12 — Risk Control
**Status:** Active
**Last reviewed:** 2026-02-20

---

## 1. Risk Description

The **Scope Explosion** risk arises when unchecked feature growth overwhelms
delivery capacity. In the franken_node project, enhancement maps can generate
unbounded work across tracks. Each capability proposal, bead creation, and
feature request increases scope. Without explicit gates, the project accumulates
more work than it can deliver at quality, leading to abandoned beads, incomplete
artifact chains, and degraded engineering velocity.

Root causes of scope explosion:
- Enhancement maps generating beads faster than tracks can close them.
- New capabilities added to tracks without formal approval workflows.
- Artifact-gated delivery bypassed under schedule pressure.
- Absence of per-track budgets allowing unbounded bead accumulation.
- Scope creep from adjacent substrate integrations and cross-track dependencies.

## 2. Impact

| Dimension        | Rating   | Detail                                                           |
|------------------|----------|------------------------------------------------------------------|
| Delivery         | Critical | Tracks stall when open bead count exceeds capacity.              |
| Quality          | High     | Rushed deliverables when too many beads compete for attention.    |
| Trust            | High     | Stakeholders lose confidence when beads remain open indefinitely. |
| Remediation      | Medium   | Scope can be reduced once identified, but detection lag is costly.|

## 3. Likelihood

| Factor              | Assessment                                                      |
|---------------------|-----------------------------------------------------------------|
| Code surface area   | Large — franken_node spans 16+ capability tracks.               |
| Enhancement velocity| High — new capabilities proposed regularly across tracks.       |
| Historical evidence | Multiple tracks have exceeded informal capacity limits.         |
| Overall likelihood  | **High**                                                         |

## 4. Countermeasure Details

### 4.1 Capability Gates

Each track has a maximum capability count (default: 16 capabilities per track).
New capability additions are gated:

1. The proposer creates a capability proposal bead.
2. The track owner reviews the proposal against current track scope.
3. If the track is at or above its capability limit, event code **RSE-003**
   is emitted and the addition is blocked.
4. An explicit approval from both the track owner and engineering lead is
   required to override the gate.
5. All gate decisions are logged with timestamp, approver, and rationale.

### 4.2 Artifact-Gated Delivery

No bead may be merged or closed without its complete artifact chain:

| Artifact | Required |
|----------|----------|
| Spec contract (`docs/specs/section_*/bd-*_contract.md`) | Yes |
| Implementation (Rust in `crates/` or Python in `scripts/`) | Yes |
| Verification script (`scripts/check_*.py` with `--json` and `self_test()`) | Yes |
| Unit tests (`tests/test_check_*.py`) | Yes |
| Verification evidence (`artifacts/section_*/bd-*/verification_evidence.json`) | Yes |
| Verification summary (`artifacts/section_*/bd-*/verification_summary.md`) | Yes |

Attempting to close a bead without all six artifacts emits **RSE-004** and the
closure is rejected. This ensures every deliverable meets the project's evidence
standard.

### 4.3 Scope Budgets

Per-track bead count limits with escalation:

| Parameter | Default | Configurable |
|-----------|---------|-------------|
| Max beads per track per epoch | 50 | Yes |
| Warning threshold | 80% of budget | Yes |
| Critical threshold | 95% of budget | Yes |
| Hard block threshold | 100% of budget | Yes |

When a track's bead count reaches:
- **80%**: Warning alert to track owner. Event **RSE-001** logged.
- **95%**: Critical alert. Event **RSE-002** emitted. New bead creation
  requires engineering-lead approval.
- **100%**: Hard block. No new beads until existing beads are closed or budget
  is explicitly expanded.

### 4.4 Monitoring

Track health is monitored via:

- **Track health dashboards**: Real-time display of bead count, budget
  utilization, capability count, and closure velocity per track.
- **Bead velocity metrics**: Rolling 7-day and 30-day averages of bead
  creation rate vs. closure rate.
- **Scope trend analysis**: Automated detection of tracks where creation
  rate consistently exceeds closure rate.
- **Budget utilization alerts**: Automated alerts at warning and critical
  thresholds.

## 5. Escalation Procedures

When scope budget is exceeded:

1. **Immediate** (within 1 hour):
   - Track owner notified via dashboard alert and direct message.
   - New bead creation for the track is blocked.
   - Event **RSE-002** emitted.

2. **24-hour escalation**:
   - If budget remains exceeded, engineering lead is notified.
   - Scope review meeting scheduled within 48 hours.

3. **48-hour escalation**:
   - If no resolution, project-level scope review is triggered.
   - Track may be placed in "scope freeze" — only bug fixes and critical
     security beads permitted.

4. **Capability gate override**:
   - Requires written approval from both track owner and engineering lead.
   - Override rationale is recorded in the bead system.
   - Override expires after one epoch; must be re-approved if still needed.

## 6. Evidence Requirements for Risk Mitigation Review

A risk mitigation review requires:
1. **Track budget report** — Current bead count vs. budget for all tracks.
2. **Capability gate log** — All capability additions and gate decisions.
3. **Artifact completeness audit** — Percentage of closed beads with full
   artifact chains.
4. **Scope trend** — 30-day trend of bead creation vs. closure rates.
5. **Invariant status** — Confirmation that all four invariants
   (INV-RSE-GATE, INV-RSE-BUDGET, INV-RSE-ARTIFACT, INV-RSE-TRACK)
   are satisfied.
6. **Escalation log** — Record of any escalations since last review.

Reviews are conducted monthly or after any critical-severity budget breach,
whichever comes first.
