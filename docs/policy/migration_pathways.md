# Migration Pathways Policy

**Bead:** bd-2f43
**Section:** 13 — Success Criteria
**Last updated:** 2026-02-20

## 1. Migration Pathway Definition and Lifecycle

A **migration pathway** is a fully-specified, machine-verifiable plan for moving
a workload from one runtime cohort (e.g., Node.js 18) to another (e.g., Bun 1.x
or Node.js 22). Each pathway progresses through a fixed lifecycle:

```
DRAFT -> ANALYZED -> SCORED -> APPROVED -> CANARY -> PROGRESSIVE -> FULL -> CLOSED
                                  |                                          ^
                                  +--- ROLLBACK --->-------------------------+
```

**State descriptions:**

| State        | Description                                                   |
|--------------|---------------------------------------------------------------|
| DRAFT        | Pathway created, cohort and target identified                 |
| ANALYZED     | Automated compatibility analysis complete (MIG-001)           |
| SCORED       | Composite risk score computed (MIG-002)                       |
| APPROVED     | Risk score <= 0.30 or explicit waiver granted                 |
| CANARY       | Rollout stage 1: 1-5% traffic (MIG-003)                      |
| PROGRESSIVE  | Rollout stage 2: 5-50% traffic in 10% increments (MIG-003)   |
| FULL         | Rollout stage 3: 100% traffic (MIG-003)                      |
| ROLLBACK     | Rollback triggered, restoring previous state (MIG-004)        |
| CLOSED       | Pathway completed successfully or after confirmed rollback    |

A pathway may transition to ROLLBACK from any stage (CANARY, PROGRESSIVE, FULL).
Rollback transitions the pathway to CLOSED once recovery is confirmed.

## 2. Risk Scoring Framework

### 2.1 Compatibility Risk (weight: 0.40)

Measures the degree of API surface and behavioral divergence between source and
target runtimes.

| Factor                        | Score Range | Example                          |
|-------------------------------|-------------|----------------------------------|
| No breaking API changes       | 0.00-0.10   | Pure additive API additions      |
| Minor behavioral differences  | 0.10-0.30   | Timer resolution differences     |
| Moderate API removals         | 0.30-0.60   | Deprecated APIs removed          |
| Major semantic changes        | 0.60-1.00   | Event loop model differences     |

### 2.2 Dependency Risk (weight: 0.35)

Measures the probability of transitive dependency breakage.

| Factor                          | Score Range | Example                        |
|---------------------------------|-------------|--------------------------------|
| All deps support target         | 0.00-0.10   | Verified compatibility matrix  |
| < 5% deps need updates          | 0.10-0.30   | Minor version bumps required   |
| 5-15% deps need major updates   | 0.30-0.60   | Breaking changes in deps       |
| > 15% deps incompatible         | 0.60-1.00   | Native addon rebuild required  |

### 2.3 Operational Risk (weight: 0.25)

Measures deployment and rollback complexity.

| Factor                          | Score Range | Example                        |
|---------------------------------|-------------|--------------------------------|
| Simple blue-green deploy        | 0.00-0.10   | Stateless service swap         |
| Moderate coordination needed    | 0.10-0.30   | Database migration required    |
| Multi-service orchestration     | 0.30-0.60   | Cross-team deployment window   |
| Infrastructure changes needed   | 0.60-1.00   | New cluster provisioning       |

### 2.4 Composite Score Calculation

```
composite = (compatibility * 0.40) + (dependency * 0.35) + (operational * 0.25)
```

Classification:
- **Low risk:** composite <= 0.30
- **Medium risk:** 0.30 < composite <= 0.60
- **High risk:** composite > 0.60

Only low-risk pathways proceed without a waiver. Medium- and high-risk pathways
require an explicit waiver recorded in the waiver registry with justification.

## 3. Staged Rollout Process

### 3.1 Canary Stage (1-5% traffic)

- Duration: minimum 15 minutes observation
- Entry criteria: pathway in APPROVED state, rollback mechanism verified
- Exit criteria: error rate delta < 0.5%, latency p99 delta < 50 ms
- Automatic rollback on: error rate delta >= 0.5% OR latency p99 delta >= 50 ms

### 3.2 Progressive Stage (5-50% traffic)

- Increments: 10% steps (5% -> 15% -> 25% -> 35% -> 50%)
- Duration per step: minimum 10 minutes observation
- Exit criteria per step: same as canary stage
- Automatic rollback on: same thresholds as canary

### 3.3 Full Stage (100% traffic)

- Duration: 30-minute validation window
- Entry criteria: progressive stage completed, all steps green
- Exit criteria: migration success rate >= 90%, zero data loss confirmed
- Final validation: byte-level checksum comparison

### 3.4 Stage Gate Evidence

Each stage transition produces a structured evidence record:

```json
{
  "event_code": "MIG-003",
  "stage": "canary",
  "direction": "enter|exit",
  "timestamp": "2026-02-20T12:00:00Z",
  "cohort_id": "node18-to-bun1",
  "correlation_id": "uuid-v4",
  "metrics": {
    "error_rate_delta": 0.001,
    "latency_p99_delta_ms": 12,
    "traffic_percentage": 5
  },
  "gate_passed": true
}
```

## 4. Rollback Safety Requirements

### 4.1 Time Constraint

Rollback must complete in under 5 minutes from the moment the rollback trigger
fires to the moment the previous runtime state is confirmed restored. This is
measured as:

```
rollback_duration = timestamp(restore_confirmed) - timestamp(rollback_triggered)
assert rollback_duration < timedelta(minutes=5)
```

### 4.2 Automatic Triggers

Rollback fires automatically when:
1. Any stage gate health check fails (error rate or latency threshold exceeded)
2. Data integrity check detects a checksum mismatch
3. Circuit breaker trips on the target runtime
4. Manual operator override (emergency stop)

### 4.3 Zero-Data-Loss Guarantee

- All writes committed before the rollback trigger are preserved
- Write-ahead log (WAL) is flushed before runtime swap
- Byte-level checksum comparison confirms data integrity post-rollback
- Evidence record includes pre-rollback and post-rollback checksums

### 4.4 Rollback Evidence

```json
{
  "event_code": "MIG-004",
  "timestamp": "2026-02-20T12:05:00Z",
  "cohort_id": "node18-to-bun1",
  "correlation_id": "uuid-v4",
  "trigger_reason": "error_rate_threshold_exceeded",
  "rollback_duration_seconds": 127,
  "affected_cohort_size": 1500,
  "data_integrity": {
    "pre_checksum": "sha256:abc123",
    "post_checksum": "sha256:abc123",
    "zero_loss_confirmed": true
  }
}
```

## 5. Evidence Requirements per Pathway

Every pathway must accumulate the following evidence artifacts before it can
transition to CLOSED:

| Artifact                        | Required At        | Format        |
|---------------------------------|--------------------|---------------|
| Compatibility analysis report   | ANALYZED           | JSON          |
| Risk score breakdown            | SCORED             | JSON          |
| Waiver (if risk > 0.30)        | APPROVED           | JSON + sig    |
| Stage gate records (per stage)  | CANARY+            | JSON          |
| Rollback drill result           | Before CANARY      | JSON          |
| Final validation report         | FULL exit          | JSON          |
| Data integrity checksums        | Every stage exit   | JSON          |

Missing evidence blocks the lifecycle transition. The verification script
(`scripts/check_migration_pathways.py`) validates evidence completeness.

## 6. Node/Bun Cohort Targeting Strategy

### 6.1 Cohort Definition

A **cohort** is a group of workloads sharing:
- Source runtime (e.g., Node.js 18.x)
- Target runtime (e.g., Bun 1.x or Node.js 22.x)
- Deployment topology (e.g., single-region, multi-region)
- Dependency profile (e.g., native addons, pure JS)

### 6.2 Prioritization

Cohorts are prioritized for migration by:
1. **Lowest composite risk score first** — easiest wins build confidence
2. **Highest business value second** — maximize impact of early migrations
3. **Smallest blast radius third** — reduce risk exposure during learning phase

### 6.3 Supported Migration Paths

| Source         | Target         | Status       | Typical Risk |
|----------------|----------------|--------------|--------------|
| Node.js 18.x   | Node.js 22.x   | Supported    | Low          |
| Node.js 18.x   | Bun 1.x        | Supported    | Medium       |
| Node.js 20.x   | Node.js 22.x   | Supported    | Low          |
| Node.js 20.x   | Bun 1.x        | Supported    | Medium       |
| Bun 1.x        | Node.js 22.x   | Supported    | Low-Medium   |

### 6.4 Unsupported Paths

Migrations that skip more than one major Node.js version (e.g., Node 16 -> 22)
are not supported as a single pathway. They must be decomposed into sequential
pathways, each validated independently.

## 7. CI Gate for Migration Pathway Validation

### 7.1 Gate Definition

The CI pipeline includes a `migration-pathway-gate` job that:

1. Runs `scripts/check_migration_pathways.py --json`
2. Asserts `overall_passed == true` in the output
3. Fails the pipeline if any check returns `passed: false`

### 7.2 Gate Triggers

The gate runs on:
- Any change to `crates/franken-node/src/connector/`
- Any change to `docs/specs/section_13/`
- Any change to `docs/policy/migration_pathways.md`
- Any change to `scripts/check_migration_pathways.py`

### 7.3 Gate Output

The gate produces:
- `artifacts/section_13/bd-2f43/verification_evidence.json` — machine-readable
- `artifacts/section_13/bd-2f43/verification_summary.md` — human-readable
- Exit code 0 on success, 1 on failure

### 7.4 Integration with Existing Gates

This gate is additive to existing gates (compatibility gate, migration system
gate). It does not replace them. The migration pathway gate specifically
validates the success criterion layer above the mechanical migration
infrastructure.
