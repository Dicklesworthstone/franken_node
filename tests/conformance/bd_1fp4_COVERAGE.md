# bd-1fp4 Coverage Report

## Conformance Test Coverage Matrix

| Spec Section | MUST Clauses | SHOULD Clauses | MAY Clauses | Tested | Passing | Divergent | Score |
|--------------|:------------:|:--------------:|:-----------:|:------:|:-------:|:---------:|:-----:|
| **INV-SWEEP-ADAPTIVE** | 4 | 0 | 0 | 4 | 4 | 0 | 100% |
| **INV-SWEEP-HYSTERESIS** | 4 | 0 | 0 | 4 | 4 | 0 | 100% |
| **INV-SWEEP-BOUNDED** | 2 | 0 | 0 | 2 | 2 | 0 | 100% |
| **INV-SWEEP-DETERMINISTIC** | 2 | 0 | 0 | 2 | 2 | 0 | 100% |
| **Band Classification** | 3 | 0 | 0 | 3 | 3 | 0 | 100% |
| **Evidence Validation** | 2 | 0 | 0 | 2 | 2 | 0 | 100% |
| **Configuration** | 0 | 2 | 0 | 2 | 2 | 0 | 100% |
| **TOTAL** | **17** | **2** | **0** | **19** | **19** | **0** | **100%** |

## Integrity Sweep Scheduler Specification

The bd-1fp4 specification defines an adaptive integrity sweep scheduler that adjusts cadence based on evidence trajectories:

### Policy Bands (Risk-Based Scheduling)
- **Green**: Stable, long intervals (5min), quick sweeps
- **Yellow**: Concern, medium intervals (1min), standard sweeps  
- **Red**: Active threat, short intervals (10s), deep sweeps

### Evidence Metrics
- **Rejection Count**: Number of guardrail rejections in recent window
- **Escalation Count**: Number of hardening escalations in recent window
- **Repairability Score**: Average repairability across monitored objects [0.0, 1.0]
- **Trend**: Direction of evidence (Improving, Stable, Degrading)

## Test Case Summary

### Core Invariants (MUST Requirements)

#### INV-SWEEP-ADAPTIVE: Cadence scales with risk
- `bd-1fp4-adaptive-1`: Red band has shortest intervals (highest risk)
- `bd-1fp4-adaptive-2`: Green band has longest intervals (lowest risk)
- `bd-1fp4-adaptive-3`: Band escalation triggers immediate interval adjustment
- `bd-1fp4-adaptive-4`: Sweep depth correlates with band severity

#### INV-SWEEP-HYSTERESIS: De-escalation requires N consecutive readings
- `bd-1fp4-hysteresis-1`: De-escalation requires hysteresis_threshold consecutive readings
- `bd-1fp4-hysteresis-2`: Escalation is immediate (no hysteresis)
- `bd-1fp4-hysteresis-3`: Hysteresis counter resets on escalation or same-band
- `bd-1fp4-hysteresis-4`: De-escalation only steps down one band at a time

#### INV-SWEEP-BOUNDED: Overhead stays within budget
- `bd-1fp4-bounded-1`: Decision log respects MAX_DECISIONS capacity (4096)
- `bd-1fp4-bounded-2`: Update count tracks all trajectory updates

#### INV-SWEEP-DETERMINISTIC: Same inputs → same outputs
- `bd-1fp4-deterministic-1`: Identical trajectory sequences produce identical schedules
- `bd-1fp4-deterministic-2`: Band classification is deterministic for same evidence

### Band Classification Logic (MUST)
- `bd-1fp4-classification-1`: High rejection count triggers Red band
- `bd-1fp4-classification-2`: Medium rejection count triggers Yellow band
- `bd-1fp4-classification-3`: Low repairability can escalate band

### Evidence Validation (MUST)
- `bd-1fp4-evidence-1`: Repairability score clamped to [0.0, 1.0]
- `bd-1fp4-evidence-2`: Non-finite repairability defaults to 0.0

### Configuration Consistency (SHOULD)
- `bd-1fp4-config-1`: PolicyBand ordering matches severity levels
- `bd-1fp4-config-2`: Default configuration has reasonable values

## Key Design Principles

1. **Risk-Adaptive Scheduling**: Higher risk bands get more frequent, thorough sweeps
2. **Escalation Asymmetry**: Immediate escalation vs. hysteresis-gated de-escalation
3. **Bounded Resource Usage**: Decision log and counters prevent unbounded growth
4. **Deterministic Behavior**: Same evidence sequences always produce same schedules
5. **Graceful Degradation**: Invalid inputs are handled safely (clamping, defaults)

## Components Tested

### EvidenceTrajectory
- Input validation and sanitization
- Repairability clamping [0.0, 1.0]
- Non-finite value handling

### IntegritySweepScheduler  
- Band classification logic
- Escalation/de-escalation state machine
- Hysteresis counter management
- Decision logging with bounded capacity
- Deterministic scheduling behavior

### SweepSchedulerConfig
- Threshold validation
- Interval ordering constraints
- Default value reasonableness

## Event Code Coverage
The specification defines these event codes:
- **EVD-SWEEP-001**: Sweep scheduled
- **EVD-SWEEP-002**: Band transition  
- **EVD-SWEEP-003**: Hysteresis preventing de-escalation
- **EVD-SWEEP-004**: Trajectory updated

## Test Architecture

- **Pattern**: Spec-Derived Test Matrix (Pattern 4)
- **Framework**: Custom conformance case runner with structured JSON output
- **Coverage**: 100% of MUST clauses, 100% of SHOULD clauses
- **Compliance**: Zero divergences from specification
- **State Machine**: Comprehensive validation of band transitions and hysteresis