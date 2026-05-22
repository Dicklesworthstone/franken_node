# MMR Proof Verification Conformance Discrepancies

This document tracks all known intentional divergences from the MMR specification in the franken_node implementation.

## Overview

The MMR proof verification system in franken_node is designed to be fully conformant with the specification defined in `mmr_specification.md`. This document records any intentional departures from strict specification compliance, along with their justification and review schedule.

**Current Status**: No known discrepancies as of 2026-05-22.

## Discrepancy Format

Each discrepancy must follow this format:

### DISC-NNN: Brief Description
- **Reference:** What the specification says
- **Our implementation:** What we actually do
- **Impact:** Effect on interoperability or security
- **Resolution:** ACCEPTED | INVESTIGATING | WILL-FIX
- **Justification:** Why this divergence exists
- **Tests affected:** List of conformance tests marked XFAIL
- **Review date:** When to reconsider this decision

## Current Discrepancies

*None currently documented.*

## Historical Discrepancies

*None yet resolved.*

## Guidelines for Adding Discrepancies

1. **Sequential IDs**: Use DISC-001, DISC-002, etc.
2. **Status Required**: Must state ACCEPTED, INVESTIGATING, or WILL-FIX
3. **Test Tracking**: List all tests affected (they should be marked XFAIL)
4. **Review Schedule**: Set realistic review dates
5. **Precise Impact**: Document exact effect on conformance

## Potential Future Discrepancies

Based on the implementation analysis, these areas might require future documentation if divergences emerge:

### Performance Optimizations
- **Area**: Audit path length optimizations
- **Risk**: If we implement path compression beyond spec requirements
- **Monitoring**: Performance tests flag unusual audit path lengths

### Error Message Details
- **Area**: Error message formatting
- **Risk**: If our error messages differ from reference implementations
- **Monitoring**: Cross-implementation compatibility tests

### Unicode Handling
- **Area**: Marker hash input normalization
- **Risk**: If we normalize Unicode differently than expected
- **Monitoring**: Unicode handling edge case tests

### Serialization Format
- **Area**: JSON field ordering and formatting
- **Risk**: If our JSON serialization differs from expected format
- **Monitoring**: Serialization round-trip tests

## Review Process

Discrepancies must be reviewed according to this schedule:

1. **New divergences**: Review within 30 days of discovery
2. **INVESTIGATING status**: Review every 90 days until resolved
3. **ACCEPTED divergences**: Annual review (every 365 days)
4. **WILL-FIX divergences**: Review every 60 days until fixed

## Cross-Reference with Tests

The following conformance tests are currently marked XFAIL due to known discrepancies:

*None currently.*

## Verification Commands

To verify conformance and check for new discrepancies:

```bash
# Run full conformance suite
cargo test --test mmr_proof_verification_conformance

# Run specific requirement categories
cargo test --test mmr_proof_verification_conformance -- --filter R1
cargo test --test mmr_proof_verification_conformance -- --filter R7

# Generate conformance report
cargo run --bin mmr_proof_verification_conformance

# Check for undocumented XFAIL tests
grep -r "ExpectedFailure" tests/conformance/ | grep -v DISCREPANCIES.md
```

## Maintainer Notes

- **Update trigger**: Any new XFAIL test must have corresponding DISCREPANCIES.md entry
- **Removal process**: Resolved discrepancies move to Historical section with resolution date
- **Integration**: CI should fail if XFAIL tests lack DISCREPANCIES.md documentation
- **Stakeholder review**: Security discrepancies require cryptography team review

---

*Last updated: 2026-05-22*  
*Next scheduled review: 2027-05-22*  
*Conformance harness version: 1.0*