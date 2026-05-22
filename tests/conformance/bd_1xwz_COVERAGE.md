# bd-1xwz Performance Budget Guard Conformance Test Coverage

This document tracks what aspects of the bd-1xwz specification are covered by our conformance test suite vs. what remains untested.

## Coverage Matrix

| Specification Section | MUST Clauses | SHOULD Clauses | Tested | Passing | Coverage |
|----------------------|:------------:|:--------------:|:------:|:-------:|:--------:|
| Core Invariants      |      4       |       0        |   4    |    4    |  100%    |
| Event Codes          |      4       |       0        |   4    |    4    |  100%    |
| Error Handling       |      2       |       0        |   2    |    2    |  100%    |
| Budget Policy        |      2       |       0        |   2    |    2    |  100%    |
| Timing Collection    |      2       |       0        |   2    |    2    |  100%    |
| Edge Cases           |      0       |       3        |   3    |    3    |  100%    |
| **TOTAL**            |     14       |       3        |  17    |   17    |  100%    |

**Compliance Score: 100% (17/17 requirements tested and passing)**

## Detailed Coverage

### ✅ Fully Tested

#### Core Invariants (4/4 MUST)
- **INV-PBG-BUDGET-ENFORCED**: Every hot path overhead check compares against policy budget
- **INV-PBG-REGRESSION-BLOCKED**: Measurements exceeding any budget threshold blocks gate
- **INV-PBG-FLAMEGRAPH-ON-FAIL**: Flamegraph evidence captured on every gate failure
- **INV-PBG-REPORT-ALWAYS**: Structured CSV report emitted on every gate run

#### Event Codes (4/4 MUST)
- **PRF_001_BENCHMARK_STARTED**: Emitted for every measurement evaluation
- **PRF_002_WITHIN_BUDGET**: Emitted for measurements passing budget checks
- **PRF_003_OVER_BUDGET**: Emitted for measurements failing budget checks
- **PRF_005_COLD_START**: Emitted for every measurement cold-start timing

#### Error Handling (2/2 MUST)
- **ERR_NO_MEASUREMENTS**: Error when empty measurement list provided
- **Fail-Closed Behavior**: Invalid floating point values cause gate failures

#### Budget Policy (2/2 MUST)
- **Canonical Path Budgets**: budget_for() returns correct budgets for all canonical hot paths
- **Default Budget Fallback**: Unknown hot paths use default budget configuration

#### Timing Collection (2/2 MUST)
- **PRF_006_TIMING_SAMPLE**: Events emitted for valid timing sample recordings
- **Measurement Synthesis**: Only paths with both baseline and integrated samples included

#### Edge Cases (3/3 SHOULD)
- **Exact Boundary Fail-Closed**: Values exactly at budget boundary correctly fail
- **Flamegraph Path Traversal**: Protection against path traversal attacks in flamegraph paths
- **CSV Report Format**: Correctly structured CSV output with proper schema

## Test Categories

| Category | Count | Description |
|----------|:-----:|-------------|
| Unit | 8 | Individual component behavior testing |
| Integration | 6 | Cross-component interaction testing |
| EdgeCase | 3 | Boundary conditions and security testing |

## What Is NOT Tested

### Intentionally Excluded
- **Actual flamegraph generation**: bd-1xwz specifies capture attempt, not successful generation
- **Performance characteristics**: bd-1xwz specifies correctness, not performance of the guard itself
- **Concurrency**: bd-1xwz doesn't specify thread safety requirements for the guard
- **Persistence**: Budget policies and results are ephemeral by design

### Out of Scope
- **asupersync integration details**: bd-1xwz measures overhead, not integration mechanics
- **Hot path instrumentation**: bd-1xwz consumes measurements, doesn't specify how to generate them
- **Policy configuration UI**: bd-1xwz specifies enforcement, not configuration management
- **Historical trend analysis**: bd-1xwz focuses on single evaluation, not time series

## Test Methodology

Our conformance suite uses **Pattern 4: Spec-Derived Test Matrix** from the conformance harnesses framework:

1. **Requirement Extraction**: Every MUST/SHOULD clause mapped to test cases
2. **Direct Testing**: One test per specification requirement
3. **Structured Organization**: Tests categorized by requirement level and type
4. **Comprehensive Reporting**: Machine-readable results with compliance scoring

## Invariant Testing Matrix

| Invariant | Test Coverage | Verification Method |
|-----------|:-------------:|---------------------|
| INV-PBG-BUDGET-ENFORCED | 1XWZ-INV-1 | Policy enforcement verification with mixed results |
| INV-PBG-REGRESSION-BLOCKED | 1XWZ-INV-2 | Gate blocking verification for over-budget measurements |
| INV-PBG-FLAMEGRAPH-ON-FAIL | 1XWZ-INV-3 | Flamegraph capture and event emission verification |
| INV-PBG-REPORT-ALWAYS | 1XWZ-INV-4 | Report generation for both passing and failing cases |

## Event Code Testing Matrix

| Event Code | Test Coverage | Verification Method |
|------------|:-------------:|---------------------|
| PRF_001_BENCHMARK_STARTED | 1XWZ-EVT-1 | Count verification for all measurements |
| PRF_002_WITHIN_BUDGET | 1XWZ-EVT-2 | Event emission for passing measurements |
| PRF_003_OVER_BUDGET | 1XWZ-EVT-3 | Event emission for failing measurements |
| PRF_005_COLD_START | 1XWZ-EVT-4 | Event emission for cold-start timings |

## Maintenance Notes

- **Specification Version**: bd-1xwz (no version indicated - assumed stable)
- **Last Updated**: 2026-05-22
- **Next Review**: When bd-1xwz specification updates are published
- **Test Count**: 17 conformance tests covering 17 requirements (100% coverage)

## Regression Protection

All tests are deterministic and provide strong regression protection for:
- Budget enforcement logic changes
- Event emission workflow modifications
- Error handling and reporting changes
- Flamegraph capture behavior updates
- CSV report format preservation

Any changes to the performance budget guard implementation must pass this full conformance suite to ensure continued bd-1xwz compliance.

## Hot Path Coverage

Our conformance tests exercise all canonical hot paths defined in the specification:
- lifecycle_transition
- health_gate_evaluation  
- rollout_state_change
- fencing_token_acquire
- fencing_token_release

Plus verification of custom hot path handling through the default budget mechanism.