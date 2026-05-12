# bd-2wz: Compatibility Bands with Policy Defaults

## Decision Rationale

The canonical plan (Section 10.2) requires defining four compatibility bands that classify all Node/Bun API surface areas by priority and risk, with policy defaults governing how divergences are handled in each band. This is the foundation for the compatibility oracle, divergence ledger, and release gating system.

## Band Definitions

| Band | Priority | Description | Policy Default |
|------|----------|-------------|---------------|
| `core` | Highest | Foundation APIs (fs, path, process, Buffer, EventEmitter, streams) | Strict parity required; divergence blocks release |
| `high-value` | High | Frequently-used patterns (http, crypto, child_process, timers, url) | >= 95% pass target; divergences logged with receipts |
| `edge` | Medium | Corner cases, undocumented behaviors, platform-specific quirks | Best-effort; divergences logged, no release block |
| `unsafe` | Lowest | Dangerous behaviors (eval variants, unchecked native access) | Disabled by default; requires explicit policy opt-in |

## Compatibility Modes

| Mode | `core` | `high-value` | `edge` | `unsafe` |
|------|--------|-------------|--------|----------|
| `strict` | Error on divergence | Error on divergence | Warn on divergence | Blocked |
| `balanced` | Error on divergence | Warn + receipt | Log + receipt | Blocked |
| `legacy-risky` | Error on divergence | Warn + receipt | Log + receipt | Warn + policy gate |

## Primary Implementation Surface

- `crates/franken-node/src/policy/compat_gates.rs` encodes the `CompatibilityBand`, `CompatibilityMode`, and `DivergenceAction` types, the bd-2wz mode-band matrix, and runtime shim activation by band.
- `crates/franken-node/src/config.rs` parses and resolves compatibility modes for strict, balanced, and legacy-risky runtime profiles before policy evaluation.

## Invariants

1. `docs/COMPATIBILITY_BANDS.md` exists with all 4 bands defined.
2. Each band has: name, priority level, description, policy default, example APIs.
3. Three compatibility modes defined: strict, balanced, legacy-risky.
4. Mode-band matrix is complete (3 modes x 4 bands = 12 cells).
5. Document references the canonical plan Section 10.2.

## Interface Boundaries

- **Input**: `docs/COMPATIBILITY_BANDS.md` (band definitions)
- **Output**: PASS/FAIL verdict on completeness and correctness

## Failure Semantics

- Missing document: FAIL
- Missing band definition: FAIL per band
- Incomplete mode matrix: FAIL
- Missing plan reference: FAIL
