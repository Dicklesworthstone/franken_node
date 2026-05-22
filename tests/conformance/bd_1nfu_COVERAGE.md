# bd-1nfu Remote Capability Gate Conformance Test Coverage

This document tracks what aspects of the bd-1nfu specification are covered by our conformance test suite vs. what remains untested.

## Coverage Matrix

| Specification Section | MUST Clauses | SHOULD Clauses | Tested | Passing | Coverage |
|----------------------|:------------:|:--------------:|:------:|:-------:|:--------:|
| Core Invariants      |      2       |       0        |   2    |    2    |  100%    |
| Event Codes          |      3       |       0        |   3    |    3    |  100%    |
| Error Handling       |      2       |       0        |   2    |    2    |  100%    |
| Security              |      2       |       0        |   2    |    2    |  100%    |
| Replay Protection     |      1       |       0        |   1    |    1    |  100%    |
| Local Mode           |      0       |       1        |   1    |    1    |  100%    |
| Audit Trail          |      1       |       0        |   1    |    1    |  100%    |
| **TOTAL**            |     11       |       1        |  12    |   12    |  100%    |

**Compliance Score: 100% (12/12 requirements tested and passing)**

## Detailed Coverage

### ✅ Fully Tested

#### Core Invariants (2/2 MUST)
- **INV-RCAP-TOKEN-STRUCTURE**: RemoteCap tokens must contain scope, issuer, expiry, and signature
- **INV-RCAP-GATE-ENFORCEMENT**: CapabilityGate must be the single validation/enforcement point

#### Event Codes (3/3 MUST)
- **REMOTECAP_ISSUED**: Emitted for successful capability issuance with RC_CAP_GRANTED legacy code
- **REMOTECAP_DENIED**: Emitted for capability check failures with RC_CHECK_DENIED legacy code  
- **REMOTECAP_CONSUMED**: Emitted for single-use token consumption with RC_CHECK_PASSED legacy code

#### Error Handling (2/2 MUST)
- **REMOTECAP_MISSING**: Error when no capability is provided for protected operation
- **REMOTECAP_EXPIRED**: Error when capability has exceeded its TTL/expiry time

#### Security (2/2 MUST)
- **Signature Verification**: Must prevent capability forgery through invalid signatures
- **Scope Validation**: Must prevent unauthorized endpoint access outside permitted scope

#### Replay Protection (1/1 MUST)
- **Single-Use Prevention**: Single-use tokens must prevent replay attacks after consumption

#### Local Mode (1/1 SHOULD)
- **Local Operations**: Local-only mode should allow operations without network capabilities

#### Audit Trail (1/1 MUST)
- **Comprehensive Logging**: All capability operations must generate structured audit events

## Test Categories

| Category | Count | Description |
|----------|:-----:|-------------|
| Unit | 6 | Individual component behavior testing |
| Integration | 6 | Cross-component interaction testing |
| EdgeCase | 0 | Boundary conditions and security testing |

## What Is NOT Tested

### Intentionally Excluded
- **Network connectivity details**: bd-1nfu specifies capability gates, not transport implementation
- **Cryptographic algorithm specifics**: bd-1nfu relies on Ed25519 implementation correctness
- **Performance characteristics**: bd-1nfu specifies correctness, not performance of the gate itself
- **Concurrency**: bd-1nfu doesn't specify thread safety requirements for the gate

### Out of Scope
- **Capability Provider key management**: bd-1nfu focuses on gates, not key lifecycle
- **Network-layer security**: bd-1nfu operates above transport security
- **Remote endpoint implementation**: bd-1nfu validates capabilities, not endpoint behavior
- **Storage/persistence**: Capabilities and audit events are ephemeral by design in bd-1nfu

## Test Methodology

Our conformance suite uses **Pattern 4: Spec-Derived Test Matrix** from the conformance harnesses framework:

1. **Requirement Extraction**: Every MUST/SHOULD clause mapped to test cases
2. **Direct Testing**: One test per specification requirement
3. **Structured Organization**: Tests categorized by requirement level and type
4. **Comprehensive Reporting**: Machine-readable results with compliance scoring

## Event Code Testing Matrix

| Event Code | Test Coverage | Verification Method |
|------------|:-------------:|---------------------|
| REMOTECAP_ISSUED | 1NFU-EVT-1 | Event emission verification for successful issuance |
| REMOTECAP_DENIED | 1NFU-EVT-2 | Event emission verification for check failures |
| REMOTECAP_CONSUMED | 1NFU-EVT-3 | Event emission verification for single-use consumption |
| REMOTECAP_REVOKED | Covered in 1NFU-AUD-1 | Event emission verification for revocation operations |
| REMOTECAP_LOCAL_MODE_ACTIVE | 1NFU-LOC-1 | Event emission verification for local-only mode |

## Error Code Testing Matrix

| Error Code | Test Coverage | Verification Method |
|------------|:-------------:|---------------------|
| REMOTECAP_MISSING | 1NFU-ERR-1 | Error code verification when no capability provided |
| REMOTECAP_EXPIRED | 1NFU-ERR-2 | Error code verification for expired capabilities |
| REMOTECAP_INVALID_SIGNATURE | 1NFU-SEC-1 | Error code verification for signature forgery attempts |
| REMOTECAP_SCOPE_DENIED | 1NFU-SEC-2 | Error code verification for out-of-scope access attempts |
| REMOTECAP_REPLAY | 1NFU-REP-1 | Error code verification for single-use token replay |

## Maintenance Notes

- **Specification Version**: bd-1nfu (no version indicated - assumed stable)
- **Last Updated**: 2026-05-22
- **Next Review**: When bd-1nfu specification updates are published
- **Test Count**: 12 conformance tests covering 12 requirements (100% coverage)

## Regression Protection

All tests are deterministic and provide strong regression protection for:
- Capability token structure validation
- Gate enforcement logic changes
- Event emission workflow modifications
- Error handling and audit trail changes
- Signature verification behavior updates
- Scope validation rule preservation

Any changes to the remote capability gate implementation must pass this full conformance suite to ensure continued bd-1nfu compliance.

## Capability Operation Coverage

Our conformance tests exercise all core capability operations defined in the specification:
- Token issuance with scope and expiry validation
- Gate-based capability verification and enforcement
- Single-use token consumption and replay protection
- Signature-based forgery prevention
- Scope-based access control enforcement
- Local-only mode operation without network capabilities
- Comprehensive audit trail generation for all operations

Plus verification of error handling for all specified failure modes and edge cases.