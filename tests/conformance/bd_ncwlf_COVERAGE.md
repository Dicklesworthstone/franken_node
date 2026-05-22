# bd-ncwlf Coverage Report

## Conformance Test Coverage Matrix

| Spec Section | MUST Clauses | SHOULD Clauses | MAY Clauses | Tested | Passing | Divergent | Score |
|--------------|:------------:|:--------------:|:-----------:|:------:|:-------:|:---------:|:-----:|
| **INV-HOT-PATH-DETERMINISTIC** | 3 | 0 | 0 | 3 | 3 | 0 | 100% |
| **INV-BUDGET-ENFORCEMENT** | 3 | 0 | 0 | 3 | 3 | 0 | 100% |
| **INV-CORRECTNESS-VALIDATION** | 2 | 0 | 0 | 2 | 2 | 0 | 100% |
| **INV-REGRESSION-PROTECTION** | 3 | 0 | 0 | 3 | 3 | 0 | 100% |
| **INV-SKIP-MODE-HONESTY** | 3 | 0 | 0 | 3 | 3 | 0 | 100% |
| **Schema Consistency** | 2 | 2 | 0 | 4 | 4 | 0 | 100% |
| **Hot Path Coverage** | 0 | 2 | 0 | 2 | 2 | 0 | 100% |
| **TOTAL** | **16** | **4** | **0** | **20** | **20** | **0** | **100%** |

## Test Case Summary

### Core Invariants (MUST Requirements)

#### INV-HOT-PATH-DETERMINISTIC
- `bd-ncwlf-deterministic-1`: Default cases generate identical measurements on repeated calls
- `bd-ncwlf-deterministic-2`: measurement() method produces consistent BenchmarkMeasurement
- `bd-ncwlf-deterministic-3`: p50 calculation follows fixed 0.70 multiplier rule

#### INV-BUDGET-ENFORCEMENT  
- `bd-ncwlf-budget-1`: PathBudget correctly identifies overhead violations
- `bd-ncwlf-budget-2`: Cold start violations are properly flagged
- `bd-ncwlf-budget-3`: Budget policy applies correct budgets to hot paths

#### INV-CORRECTNESS-VALIDATION
- `bd-ncwlf-correctness-1`: All hot paths have non-empty correctness assertions
- `bd-ncwlf-correctness-2`: Correctness assertions are specific and actionable

#### INV-REGRESSION-PROTECTION
- `bd-ncwlf-regression-1`: All hot paths have regression guards defined
- `bd-ncwlf-regression-2`: Post-fix performance must be better than pre-fix
- `bd-ncwlf-regression-3`: Regression guards include specific thresholds

#### INV-SKIP-MODE-HONESTY
- `bd-ncwlf-skip-1`: Skip mode generates proper skip report with blocker
- `bd-ncwlf-skip-2`: Skip mode sets overall_pass=false and verdict=SKIP
- `bd-ncwlf-skip-3`: Skip policy documented for each hot path

### Schema Requirements (MUST/SHOULD)
- `bd-ncwlf-schema-1`: Report schema version matches constant (MUST)
- `bd-ncwlf-schema-2`: Bead ID matches specification constant (MUST)
- `bd-ncwlf-schema-3`: JSON serialization is round-trip safe (SHOULD)
- `bd-ncwlf-schema-4`: Evidence path follows naming convention (SHOULD)

### Coverage Requirements (SHOULD)
- `bd-ncwlf-coverage-1`: Covers critical system hot paths
- `bd-ncwlf-coverage-2`: Source beads properly reference originating work

## Covered Hot Paths

The test suite validates these critical system hot paths:

1. **ops.telemetry_bridge.persistence_batch** - Telemetry batch processing
2. **control_plane.fleet_transport.read_snapshot** - Control plane snapshots  
3. **observability.evidence_ledger.len_snapshot** - Evidence ledger operations
4. **storage.frankensqlite_adapter.write_event** - Storage layer writes
5. **crypto.ed25519_scheme.sign_raw** - Cryptographic signing

## Invariant Validation

Each hot path case includes:
- **Performance measurements**: before_fix vs post_fix p95/p99 timings
- **Budget enforcement**: max overhead percentages and cold start limits
- **Correctness assertions**: specific behavioral requirements (3 per path)
- **Regression guards**: specific thresholds to prevent degradation
- **Skip policies**: conditions under which testing should be skipped

## Test Architecture

- **Pattern**: Spec-Derived Test Matrix (Pattern 4)
- **Framework**: Custom conformance case runner with structured JSON output
- **Coverage**: 100% of MUST clauses, 100% of SHOULD clauses
- **Compliance**: Zero divergences from specification
- **CI Integration**: JSON-line output for automated parsing

## Maintainability

- Test cases are data-driven and easily extendable
- Each case tests exactly one requirement 
- Structured reporting enables compliance tracking
- Self-validating coverage ensures no test gaps