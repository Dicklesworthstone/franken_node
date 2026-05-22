# bd-20uo Conformance Test Coverage

This document tracks what aspects of the bd-20uo specification are covered by our conformance test suite vs. what remains untested.

## Coverage Matrix

| Specification Section | MUST Clauses | SHOULD Clauses | Tested | Passing | Coverage |
|----------------------|:------------:|:--------------:|:------:|:-------:|:--------:|
| Core Invariants      |      3       |       0        |   3    |    3    |  100%    |
| Operational Modes    |      2       |       0        |   2    |    2    |  100%    |
| Event Codes          |      4       |       0        |   4    |    4    |  100%    |
| Error Handling       |      4       |       0        |   4    |    4    |  100%    |
| API Requirements     |      3       |       2        |   5    |    5    |  100%    |
| Edge Cases           |      0       |       4        |   4    |    4    |  100%    |
| **TOTAL**            |     16       |       6        |  22    |   22    |  100%    |

**Compliance Score: 100% (22/22 requirements tested and passing)**

## Detailed Coverage

### ✅ Fully Tested

#### Core Invariants (3/3 MUST)
- **INV-REPAIR-PROOF-COMPLETE**: Proof contains all required components
- **INV-REPAIR-PROOF-BINDING**: Cryptographic binding between fragments and attestations
- **INV-REPAIR-PROOF-DETERMINISTIC**: Consistent proof generation for identical inputs

#### Operational Modes (2/2 MUST)
- **Mandatory Mode**: Hard errors on missing/invalid proofs
- **Advisory Mode**: Warnings without blocking operations

#### Event Codes (4/4 MUST)
- **REPAIR_PROOF_EMITTED**: Generated when proof is created
- **REPAIR_PROOF_VERIFIED**: Generated when proof validates successfully
- **REPAIR_PROOF_MISSING**: Generated when required proof is absent
- **REPAIR_PROOF_INVALID**: Generated when proof fails validation

#### Error Handling (4/4 MUST)
- **PROOF_MISSING_MANDATORY**: Error when mandatory proof absent
- **PROOF_INVALID**: Error when proof fails cryptographic verification
- **RECONSTRUCTION_FAILED**: Error when proof cannot reconstruct repair
- **CAPACITY_EXCEEDED**: Error when proof size exceeds limits

#### API Requirements (5/5 total: 3 MUST + 2 SHOULD)
- **decode() method**: MUST be present and functional
- **register_algorithm() method**: MUST accept algorithm registration
- **audit() method**: MUST return verification results
- **Event callback support**: SHOULD provide event notifications (tested)
- **Batch processing**: SHOULD support multiple repairs (tested)

#### Edge Cases (4/4 SHOULD)
- **Unicode handling**: Proper processing of non-ASCII content
- **Capacity management**: Graceful handling of size limits
- **Cryptographic consistency**: Stable hashing across invocations
- **Empty input handling**: Correct behavior with minimal inputs

## Test Categories

| Category | Count | Description |
|----------|:-----:|-------------|
| Unit | 8 | Individual component behavior |
| Integration | 10 | Component interaction testing |
| EdgeCase | 4 | Boundary and error conditions |

## What Is NOT Tested

### Intentionally Excluded
- **Performance characteristics**: bd-20uo specifies correctness, not performance
- **Implementation internals**: Testing observable behavior only, not internal state
- **Platform-specific behavior**: Specification is platform-agnostic
- **Concurrency**: bd-20uo doesn't specify thread safety requirements

### Out of Scope
- **Network protocols**: bd-20uo focuses on local proof generation/verification
- **Persistence formats**: Specification doesn't mandate storage format
- **Key management**: Assumes cryptographic keys are available, doesn't specify source

## Test Methodology

Our conformance suite uses **Pattern 4: Spec-Derived Test Matrix** from the conformance harnesses framework:

1. **Requirement Extraction**: Every MUST/SHOULD clause mapped to test cases
2. **Direct Testing**: One test per specification requirement
3. **Structured Organization**: Tests categorized by requirement level and type
4. **Comprehensive Reporting**: Machine-readable results with compliance scoring

## Maintenance Notes

- **Specification Version**: bd-20uo (no version indicated - assumed stable)
- **Last Updated**: 2026-05-22
- **Next Review**: When bd-20uo specification updates are published
- **Test Count**: 22 conformance tests covering 22 requirements (100% coverage)

## Regression Protection

All tests are deterministic and provide strong regression protection for:
- Cryptographic algorithm changes
- API behavior modifications  
- Error handling updates
- Mode switching logic
- Event emission patterns

Any changes to the proof-carrying decode implementation must pass this full conformance suite to ensure continued bd-20uo compliance.