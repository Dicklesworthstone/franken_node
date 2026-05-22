# bd-tg2 Fleet Quarantine/Revocation API Conformance Test Coverage

This document tracks what aspects of the bd-tg2 specification are covered by our conformance test suite vs. what remains untested.

## Coverage Matrix

| Specification Section | MUST Clauses | SHOULD Clauses | Tested | Passing | Coverage |
|----------------------|:------------:|:--------------:|:------:|:-------:|:--------:|
| Core Invariants      |      4       |       0        |   4    |    4    |  100%    |
| Event Codes          |      2       |       0        |   2    |    2    |  100%    |
| Error Handling       |      1       |       0        |   1    |    1    |  100%    |
| Rollback Operations   |      1       |       0        |   1    |    1    |  100%    |
| Reconciliation        |      0       |       1        |   1    |    1    |  100%    |
| **TOTAL**            |     8        |       1        |   9    |    9    |  100%    |

**Compliance Score: 100% (9/9 requirements tested and passing)**

## Detailed Coverage

### ✅ Fully Tested

#### Core Invariants (4/4 MUST)
- **INV-FLEET-ZONE-SCOPE**: Every operation is scoped to a zone/tenant
- **INV-FLEET-RECEIPT**: All operations produce signed decision receipts
- **INV-FLEET-BOUNDED**: All collections are bounded with capacity eviction
- **INV-FLEET-SAFE-START**: API starts in read-only mode, requires activation

#### Event Codes (2/2 MUST)
- **FLEET-001**: FLEET_QUARANTINE_INITIATED emitted on quarantine initiation
- **FLEET-002**: FLEET_REVOCATION_ISSUED emitted on revocation issuance

#### Error Handling (1/1 MUST)
- **FLEET_SCOPE_INVALID**: Error returned for invalid zone scoping

#### Rollback Operations (1/1 MUST)
- **INV-FLEET-ROLLBACK**: Release deterministically rolls back quarantine state

#### Reconciliation (1/1 SHOULD)
- **Convergence Tracking**: Fleet reconciliation tracks convergence with progress and ETA

## Test Categories

| Category | Count | Description |
|----------|:-----:|-------------|
| Unit | 3 | Individual component behavior testing |
| Integration | 6 | Cross-component interaction testing |
| EdgeCase | 0 | Boundary conditions and security testing |

## What Is NOT Tested

### Intentionally Excluded
- **Network transport details**: bd-tg2 specifies API contracts, not HTTP/gRPC implementation
- **Persistence mechanisms**: bd-tg2 focuses on API behavior, not storage implementation
- **Performance characteristics**: bd-tg2 specifies correctness, not performance of operations
- **Concurrent access**: bd-tg2 doesn't specify thread safety requirements for API endpoints

### Out of Scope
- **Fleet transport layer**: bd-tg2 operates above transport implementation details
- **Zone management**: bd-tg2 consumes zone IDs, doesn't define zone lifecycle
- **Extension lifecycle**: bd-tg2 quarantines extensions, doesn't manage extension deployment
- **Incident management**: bd-tg2 references incidents, doesn't define incident workflows

## Test Methodology

Our conformance suite uses **Pattern 4: Spec-Derived Test Matrix** from the conformance harnesses framework:

1. **Requirement Extraction**: Every MUST/SHOULD clause mapped to test cases
2. **Direct Testing**: One test per specification requirement
3. **Structured Organization**: Tests categorized by requirement level and type
4. **Comprehensive Reporting**: Machine-readable results with compliance scoring

## Invariant Testing Matrix

| Invariant | Test Coverage | Verification Method |
|-----------|:-------------:|---------------------|
| INV-FLEET-ZONE-SCOPE | TG2-INV-1 | Zone ID preservation across all operation types |
| INV-FLEET-RECEIPT | TG2-INV-2 | Signed receipt generation for operations |
| INV-FLEET-BOUNDED | TG2-INV-3 | Capacity limits with oldest-first eviction |
| INV-FLEET-SAFE-START | TG2-INV-4 | Read-only mode before activation |
| INV-FLEET-ROLLBACK | TG2-ROLLBACK-1 | Deterministic quarantine state rollback |

## Event Code Testing Matrix

| Event Code | Test Coverage | Verification Method |
|------------|:-------------:|---------------------|
| FLEET-001 (FLEET_QUARANTINE_INITIATED) | TG2-EVT-1 | Event emission verification for quarantine operations |
| FLEET-002 (FLEET_REVOCATION_ISSUED) | TG2-EVT-2 | Event emission verification for revocation operations |
| FLEET-004 (FLEET_RELEASED) | TG2-ROLLBACK-1 | Event emission verification for release operations |
| FLEET-005 (FLEET_RECONCILE_COMPLETED) | TG2-RECONCILE-1 | Event emission verification for reconciliation |

## API Route Coverage

| Route | Test Coverage | Verification Method |
|-------|:-------------:|---------------------|
| POST /v1/fleet/quarantine | TG2-INV-1, TG2-EVT-1 | Zone scoping and event emission |
| POST /v1/fleet/revoke | TG2-EVT-2 | Revocation operation and events |
| POST /v1/fleet/release | TG2-ROLLBACK-1 | Rollback functionality |
| GET /v1/fleet/status | TG2-INV-4, TG2-ROLLBACK-1 | Status queries and state verification |
| POST /v1/fleet/reconcile | TG2-RECONCILE-1 | Convergence tracking |

## Error Code Testing Matrix

| Error Code | Test Coverage | Verification Method |
|------------|:-------------:|---------------------|
| FLEET_SCOPE_INVALID | TG2-ERR-1 | Invalid zone ID validation |
| FLEET_NOT_ACTIVATED | TG2-INV-4 | Pre-activation write operation blocking |

## Maintenance Notes

- **Specification Version**: bd-tg2 (no version indicated - assumed stable)
- **Last Updated**: 2026-05-22
- **Next Review**: When bd-tg2 specification updates are published
- **Test Count**: 9 conformance tests covering 9 requirements (100% coverage)

## Regression Protection

All tests are deterministic and provide strong regression protection for:
- Zone scoping enforcement across all operations
- Decision receipt generation and signing
- Collection capacity management with proper eviction
- Safe-start activation flow
- Event emission consistency
- Error handling for invalid inputs
- Rollback operation correctness
- Reconciliation convergence tracking

Any changes to the fleet quarantine/revocation API must pass this full conformance suite to ensure continued bd-tg2 compliance.

## Fleet Operation Coverage

Our conformance tests exercise all core fleet operations defined in the specification:
- Quarantine operations with zone scoping and receipt generation
- Revocation operations with proper event emission
- Release operations with deterministic rollback
- Status queries for fleet state verification
- Reconciliation with convergence progress tracking
- Error handling for invalid zone scoping and pre-activation attempts

Plus verification of bounded collections, safe-start mode, and comprehensive audit trail generation.