# bd-2wz Coverage Report

## Conformance Test Coverage Matrix

| Spec Section | MUST Clauses | SHOULD Clauses | MAY Clauses | Tested | Passing | Divergent | Score |
|--------------|:------------:|:--------------:|:-----------:|:------:|:-------:|:---------:|:-----:|
| **INV-MATRIX-COMPLETENESS** | 2 | 0 | 0 | 2 | 2 | 0 | 100% |
| **INV-CORE-BAND-PRIORITY** | 1 | 0 | 0 | 1 | 1 | 0 | 100% |
| **INV-MODE-ORDERING** | 3 | 0 | 0 | 3 | 3 | 0 | 100% |
| **INV-BAND-ORDERING** | 2 | 0 | 0 | 2 | 2 | 0 | 100% |
| **INV-DETERMINISTIC** | 1 | 0 | 0 | 1 | 1 | 0 | 100% |
| **Matrix Behavior** | 3 | 0 | 0 | 3 | 3 | 0 | 100% |
| **Enum Properties** | 0 | 1 | 0 | 1 | 1 | 0 | 100% |
| **TOTAL** | **12** | **1** | **0** | **13** | **13** | **0** | **100%** |

## Mode-Band Matrix Specification

The bd-2wz specification defines a deterministic mapping from `(CompatibilityBand, CompatibilityMode)` → `DivergenceAction`:

| Band \\ Mode | Strict | Balanced | LegacyRisky |
|--------------|:------:|:--------:|:-----------:|
| **Core** | Error | Error | Error |
| **HighValue** | Error | Warn | Warn |
| **Edge** | Warn | Log | Log |
| **Unsafe** | Blocked | Blocked | Warn |

## Test Case Summary

### Core Invariants (MUST Requirements)

#### INV-MATRIX-COMPLETENESS
- `bd-2wz-completeness-1`: divergence_action defined for all band+mode combinations
- `bd-2wz-completeness-2`: no panic or invalid states in matrix lookup

#### INV-CORE-BAND-PRIORITY  
- `bd-2wz-core-priority-1`: Core band always returns Error regardless of mode

#### INV-MODE-ORDERING
- `bd-2wz-mode-ordering-1`: Strict mode is most restrictive for non-Core bands
- `bd-2wz-mode-ordering-2`: LegacyRisky mode is most permissive  
- `bd-2wz-mode-ordering-3`: Balanced mode provides middle ground

#### INV-BAND-ORDERING
- `bd-2wz-band-ordering-1`: Core band is most protected (strictest actions)
- `bd-2wz-band-ordering-2`: band priority ordering: Core > HighValue > Edge > Unsafe

#### INV-DETERMINISTIC
- `bd-2wz-deterministic-1`: divergence_action returns consistent results

### Matrix Behavior Verification (MUST)
- `bd-2wz-matrix-1`: HighValue band behavior matches specification
- `bd-2wz-matrix-2`: Edge band behavior matches specification  
- `bd-2wz-matrix-3`: Unsafe band behavior matches specification

### Enum Properties (SHOULD)
- `bd-2wz-enums-1`: enum orderings support priority comparisons

## Component Definitions

### CompatibilityBand (Priority-Ordered)
- **Core**: Foundation APIs (fs, path, process, Buffer) — highest priority
- **HighValue**: Frequently-used patterns (http, crypto, timers, url)
- **Edge**: Corner cases, undocumented behaviors, platform quirks
- **Unsafe**: Dangerous behaviors (eval variants, unchecked native access) — lowest priority

### CompatibilityMode (Risk-Tolerance Ordered)
- **Strict**: Only verified-compatible behaviors allowed, no shims activated
- **Balanced**: Tested shims activated with monitoring, divergences produce warnings
- **LegacyRisky**: All available shims activated, divergences tolerated with receipts

### DivergenceAction (Response Types)
- **Error**: Divergence blocks execution (most restrictive)
- **Blocked**: Shim/divergence is blocked entirely
- **Warn**: Warning emitted, receipt generated, execution continues
- **Log**: Logged with receipt, no warning surfaced (least restrictive)

## Key Design Principles

1. **Core Band Supremacy**: Core band always errors regardless of mode (highest protection)
2. **Mode Restrictiveness**: Strict > Balanced > LegacyRisky in terms of restriction level
3. **Band Protection**: Core > HighValue > Edge > Unsafe in terms of protection level
4. **Deterministic Mapping**: Same inputs always produce same outputs
5. **Complete Coverage**: Every valid (band, mode) combination has a defined action

## Test Architecture

- **Pattern**: Spec-Derived Test Matrix (Pattern 4)
- **Framework**: Custom conformance case runner with structured JSON output
- **Coverage**: 100% of MUST clauses, 100% of SHOULD clauses
- **Compliance**: Zero divergences from specification
- **Matrix Validation**: Comprehensive verification of all 12 (band, mode) combinations

## Usage Implications

The mode-band matrix enables:
- **Risk-based compatibility decisions**: Higher-risk bands get stricter treatment
- **Operator control**: Mode selection allows balancing compatibility vs. safety
- **Predictable behavior**: Deterministic matrix lookup ensures consistent decisions
- **Audit trail**: Every decision maps to a specific matrix cell for traceability