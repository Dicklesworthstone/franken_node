# bd-3a3q Guardrail Monitor Conformance Test Coverage

This document tracks what aspects of the bd-3a3q specification are covered by our conformance test suite vs. what remains untested.

## Coverage Matrix

| Specification Section | MUST Clauses | SHOULD Clauses | Tested | Passing | Coverage |
|----------------------|:------------:|:--------------:|:------:|:-------:|:--------:|
| Core Invariants      |      4       |       0        |   4    |    4    |  100%    |
| Event Codes          |      3       |       0        |   3    |    3    |  100%    |
| Budget Management     |      1       |       0        |   1    |    1    |  100%    |
| Hardening Integration |      0       |       1        |   1    |    1    |  100%    |
| **TOTAL**            |     8        |       1        |   9    |    9    |  100%    |

**Compliance Score: 100% (9/9 requirements tested and passing)**

## Detailed Coverage

### ✅ Fully Tested

#### Core Invariants (4/4 MUST)
- **INV-GUARD-ANYTIME**: Every monitor is valid at any stopping point
- **INV-GUARD-PRECEDENCE**: Guardrail verdicts override Bayesian recommendations
- **INV-GUARD-RESTRICTIVE**: The set returns the most restrictive verdict
- **INV-GUARD-CONFIGURABLE**: Thresholds are configurable above envelope minimums

#### Event Codes (3/3 MUST)
- **EVD-GUARD-001**: Emitted for Allow verdicts with GUARD_PASS event code
- **EVD-GUARD-002**: Emitted for Block verdicts with GUARD_BLOCK event code
- **EVD-GUARD-003**: Emitted for Warn verdicts with GUARD_WARN event code

#### Budget Management (1/1 MUST)
- **Budget ID Preservation**: Budget IDs properly managed and preserved through verdicts

#### Hardening Integration (1/1 SHOULD)
- **Hardening Level Awareness**: Monitors consider hardening level in their evaluations

## Test Categories

| Category | Count | Description |
|----------|:-----:|-------------|
| Unit | 4 | Individual component behavior testing |
| Integration | 5 | Cross-component interaction testing |
| EdgeCase | 0 | Boundary conditions and security testing |

## What Is NOT Tested

### Intentionally Excluded
- **Performance characteristics**: bd-3a3q specifies correctness, not performance of monitors
- **Monitor implementation details**: bd-3a3q focuses on interface behavior, not internal algorithms
- **Concurrency**: bd-3a3q doesn't specify thread safety requirements for monitor sets
- **Persistence**: Monitor state and verdicts are ephemeral by design in bd-3a3q

### Out of Scope
- **Bayesian engine integration**: bd-3a3q specifies guardrail precedence, not Bayesian mechanics
- **Specific budget types**: bd-3a3q provides framework, not domain-specific budget definitions
- **Threshold calculation algorithms**: bd-3a3q specifies configurability, not calculation methods
- **Alert/notification systems**: bd-3a3q focuses on verdict generation, not downstream actions

## Test Methodology

Our conformance suite uses **Pattern 4: Spec-Derived Test Matrix** from the conformance harnesses framework:

1. **Requirement Extraction**: Every MUST/SHOULD clause mapped to test cases
2. **Direct Testing**: One test per specification requirement
3. **Structured Organization**: Tests categorized by requirement level and type
4. **Comprehensive Reporting**: Machine-readable results with compliance scoring

## Invariant Testing Matrix

| Invariant | Test Coverage | Verification Method |
|-----------|:-------------:|---------------------|
| INV-GUARD-ANYTIME | 3A3Q-INV-1 | Validity verification at multiple stopping points |
| INV-GUARD-PRECEDENCE | 3A3Q-INV-2 | Override verification with simulated Bayesian input |
| INV-GUARD-RESTRICTIVE | 3A3Q-INV-3 | Multi-monitor set with mixed verdicts |
| INV-GUARD-CONFIGURABLE | 3A3Q-INV-4 | Threshold reconfiguration and validation |

## Event Code Testing Matrix

| Event Code | Test Coverage | Verification Method |
|------------|:-------------:|---------------------|
| EVD-GUARD-001 (GUARD_PASS) | 3A3Q-EVT-1 | Event emission verification for Allow verdicts |
| EVD-GUARD-002 (GUARD_BLOCK) | 3A3Q-EVT-2 | Event emission verification for Block verdicts |
| EVD-GUARD-003 (GUARD_WARN) | 3A3Q-EVT-3 | Event emission verification for Warn verdicts |

## Verdict Testing Matrix

| Verdict Type | Test Coverage | Verification Method |
|--------------|:-------------:|---------------------|
| Allow | 3A3Q-EVT-1, 3A3Q-INV-1 | Low value acceptance and event emission |
| Warn | 3A3Q-EVT-3, 3A3Q-INV-1 | Threshold approach detection and warning |
| Block | 3A3Q-EVT-2, 3A3Q-INV-2, 3A3Q-INV-3 | Threshold violation blocking and precedence |

## Maintenance Notes

- **Specification Version**: bd-3a3q (no version indicated - assumed stable)
- **Last Updated**: 2026-05-22
- **Next Review**: When bd-3a3q specification updates are published
- **Test Count**: 9 conformance tests covering 9 requirements (100% coverage)

## Regression Protection

All tests are deterministic and provide strong regression protection for:
- Monitor interface contract changes
- Verdict generation logic modifications
- Event emission workflow updates
- Budget ID management preservation
- Threshold configuration behavior changes
- Hardening level integration compatibility

Any changes to the guardrail monitor implementation must pass this full conformance suite to ensure continued bd-3a3q compliance.

## Monitor Interface Coverage

Our conformance tests exercise all core monitor interface methods defined in the specification:
- Monitor creation with budget ID and threshold
- Verdict generation for various input values and hardening levels
- Event code emission consistency across verdict types
- Threshold reconfiguration with validation
- Budget ID preservation through all operations
- Severity-based verdict comparison for monitor set aggregation

Plus verification of error handling for invalid configurations and edge cases.