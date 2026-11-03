# Verifier SDK Test Suite

> **Status**: ✅ Complete conformance testing infrastructure  
> **Coverage**: 100% of vsdk-v1.0 specification validated

## Overview

This directory contains comprehensive tests for the frankenengine-verifier-sdk, including functional tests, conformance validation, and compliance reporting.

## Test Structure

```
tests/
├── conformance_harness.rs    # Full vsdk-v1.0 spec conformance tests
├── compliance_report.rs      # Automated compliance reporting tools
├── COVERAGE.md              # Detailed conformance coverage matrix
├── DISCREPANCIES.md         # Known specification divergences (currently: none)
├── facade.rs                # SDK facade integration tests
├── bundle_roundtrip.rs      # Bundle serialization/integrity tests
├── signed_bundle.rs         # Ed25519 signature validation tests
├── chain_verify_registry.rs # Chain verification tests
└── counterfactual_verify.rs # Counterfactual verification tests
```

## Running Tests

### All Tests
```bash
# Run complete test suite
cargo test -p frankenengine-verifier-sdk

# With verbose output
cargo test -p frankenengine-verifier-sdk -- --nocapture
```

### Conformance Tests Only
```bash
# Run conformance harness
cargo test -p frankenengine-verifier-sdk conformance_harness

# Generate detailed conformance report
cargo test -p frankenengine-verifier-sdk conformance_harness -- --nocapture
```

### Individual Test Files
```bash
# SDK facade tests
cargo test -p frankenengine-verifier-sdk facade

# Bundle roundtrip tests
cargo test -p frankenengine-verifier-sdk bundle_roundtrip

# Signed bundle tests
cargo test -p frankenengine-verifier-sdk signed_bundle
```

### Embedded Native Module Sources

`verify_incident_bundle` independently checks any embedded FNSGCAP1 source
capsule after authenticating the enclosing bundle against the caller's Ed25519
anchor. It verifies canonical base64 and header encoding, the domain-separated
capsule digest, the captured graph identity, bounded project-relative
observations, recorded parent directories, each file/link digest, and exact
payload consumption. No captured pathname is opened and no file is extracted.

The producer vectors in `fixtures/module_source_capsules.json` contain nested
CommonJS/ESM package selection, additive conditions and contained workspace
symlinks. They were emitted by the real production graph builder through
`tools/module-graph`, then reconstructed with the original projects moved. Each
vector records its original test fixture, input files, command and source
hashes. Tests also recompute capsule, native payload, timeline and bundle hashes
and sign corrupted candidates with the trusted test key, so a valid outer
signature cannot hide missing inner integrity checks.

```bash
cargo test -p frankenengine-verifier-sdk module_capsule
cargo test -p frankenengine-verifier-sdk valid_outer_signatures_cannot_authorize_corrupted_embedded_source_capsules
```

These tests establish source-byte integrity, not native execution equivalence.
The SDK binds the declared graph hash but does not recompute resolution, prove
that all loads were captured, check engine IR, or verify replay consumption.
Those properties still require production graph reconstruction and native
`incident replay --execute` under the intended policy.

## Conformance Testing

### What is Tested

The conformance harness (`conformance_harness.rs`) validates **56 requirements** from the vsdk-v1.0 specification:

- **Schema Version Requirements** (5 tests): SDK version constants and validation
- **Event Code Requirements** (5 tests): Event code definitions and usage  
- **Error Code Requirements** (6 tests): Error code format and mapping
- **Invariant Requirements** (4 tests): Core SDK invariants validation
- **Capsule Format Requirements** (10 tests): Replay capsule structure and behavior
- **Bundle Format Requirements** (15 tests): Bundle serialization and integrity
- **SDK Interface Requirements** (11 tests): Public API contract validation

### Test Output

Conformance tests produce structured JSON output for CI integration:

```json
{"id":"VSDK-SCHEMA-1.1","verdict":"PASS","level":"Must","section":"schema"}
{"id":"VSDK-EVENT-2.1","verdict":"PASS","level":"Must","section":"events"}
```

### Coverage Matrix

See [COVERAGE.md](COVERAGE.md) for the complete conformance coverage matrix showing:

- Requirements tested vs. total requirements by section
- Pass/fail status for each test case
- Overall conformance score (currently: 100%)

## Compliance Reporting

### Generate Reports

```rust
use frankenengine_verifier_sdk::tests::compliance_report::*;

// Run tests and collect results
let results = run_conformance_tests();
let report = ComplianceReport::from_test_results(results);

// Generate markdown report
println!("{}", report.to_markdown());

// Generate JSON for CI
println!("{}", report.to_json()?);
```

### CI Integration

The conformance tests are designed for CI/CD pipeline integration:

- **Exit Code**: Non-zero if conformance score < 95%
- **Structured Output**: JSON-formatted test results for parsing
- **Coverage Metrics**: Tracks specification coverage over time
- **Divergence Tracking**: Documents any intentional spec deviations

## Specification Source

All tests validate against the **frozen vsdk-v1.0 specification** defined in:

- `src/lib.rs` - Core SDK constants, types, and interfaces
- `src/bundle.rs` - Bundle format and serialization specification  
- `src/capsule.rs` - Capsule format and replay specification

## Test Philosophy

### Conformance vs Functional Testing

- **Functional Tests** (`facade.rs`, `bundle_roundtrip.rs`, etc.): Verify the SDK works correctly
- **Conformance Tests** (`conformance_harness.rs`): Verify the SDK matches the specification exactly

### Coverage Goals

- **100% MUST clause coverage**: All mandatory requirements tested
- **100% SHOULD clause coverage**: All recommended requirements tested  
- **Deterministic outcomes**: Same inputs always produce same test results
- **No false positives**: Failed tests always indicate real conformance issues

## Contributing

### Adding New Tests

1. **Functional tests**: Add to existing test files or create new ones
2. **Conformance tests**: Only add when the vsdk specification changes
3. **Follow naming**: Use `test_` prefix and descriptive names
4. **Document coverage**: Update COVERAGE.md for new conformance tests

### Updating Conformance Tests

⚠️  **Warning**: Conformance tests should only change when the vsdk specification changes. Random test modifications can mask real conformance issues.

1. **Specification Change**: Update specification first
2. **Test Update**: Modify conformance tests to match new spec
3. **Documentation**: Update COVERAGE.md and DISCREPANCIES.md
4. **Review**: Get approval for any breaking changes

## Architecture

### Pattern: Spec-Derived Testing

This test suite implements **Pattern 4: Spec-Derived Tests** from the conformance testing methodology:

- One test per MUST/SHOULD clause from the specification
- Test IDs map directly to specification requirements
- Requirement level tracking (MUST/SHOULD/MAY)
- Structured pass/fail verdicts with detailed failure reasons

### Design Principles

1. **Traceability**: Each test maps to specific spec requirement
2. **Stability**: Tests change only when specification changes
3. **Clarity**: Test names and descriptions explain what's being validated
4. **Automation**: Designed for automated CI/CD integration
5. **Completeness**: All testable requirements have corresponding tests

---

**Conformance Status**: 🎯 **100%** (56/56 requirements validated)
