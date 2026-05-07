# Security Audit Findings - 2026-04-20

## Critical Finding: Missing Bounds Checks in Computation Name Parsing

**File:** `crates/franken-node/src/remote/computation_registry.rs`
**Lines:** 699-733 (`is_canonical_computation_name`, `is_component`, `is_version_component`)

**Vulnerability:** The computation name parsing functions lack length bounds checking, allowing unbounded input that could lead to resource exhaustion.

**Details:**
- `is_component()` function validates character composition but not length
- `is_canonical_computation_name()` splits on '.' without checking component lengths
- An attacker could provide extremely long computation names like `"a" + "a".repeat(1_000_000) + ".action.v1"`
- This could exhaust memory during validation and storage

**Attack Vector:**
```rust
// Malicious computation name
let malicious_name = format!("{}.action.v1", "a".repeat(1_000_000));
```

**Recommendation:** Add max length constants and bounds checks:
```rust
const MAX_COMPONENT_LENGTH: usize = 128;
const MAX_COMPUTATION_NAME_LENGTH: usize = 512;

fn is_component(component: &str) -> bool {
    if component.len() > MAX_COMPONENT_LENGTH {
        return false;
    }
    // ... existing validation
}
```

## Potential Finding: HTTP Request Size Limits

**Concern:** No explicit request payload size limits found in API routes
**Files Checked:** 
- `api/middleware.rs` - Has rate limiting but no payload size limits
- `api/service.rs` - No size validation visible
- `api/*_routes.rs` - No content-length validation

**Recommendation:** Implement MAX_REQUEST_SIZE validation in middleware chain

## Positive Finding: Good Security Practices Observed

**File:** `api/session_auth.rs`
- ✅ Uses constant-time comparison (`ct_eq_bytes`) for HMAC verification
- ✅ Comprehensive timing attack resistance tests
- ✅ Proper domain separation in key derivation

**File:** `api/error.rs`
- ✅ Comprehensive error handling with structured RFC 7807 format
- ✅ Extensive malicious input testing in test suite
- ✅ Proper input sanitization and validation

## Additional Findings: connector/ and vef/ Modules

### Connector Module Audit
**Files Checked:** frame_parser.rs, canonical_serializer.rs, trust_object_id.rs, vef_execution_receipt.rs

**Positive Findings:**
- ✅ `frame_parser.rs` - Excellent bounds checking with size/depth/CPU limits, fail-closed behavior (`>=`)
- ✅ `canonical_serializer.rs` - Proper deterministic serialization with float rejection and round-trip verification  
- ✅ `trust_object_id.rs` - Strong parsing with exact hex digest length validation (64 chars)
- ✅ `vef_execution_receipt.rs` - Comprehensive input validation including whitespace trimming, hash format checks

### VEF Module Audit  
**Files Checked:** proof_verifier.rs, receipt_chain.rs

**Positive Findings:**
- ✅ `proof_verifier.rs` - Proper expiry checks with fail-closed semantics (`<` for expiry), capacity limits
- ✅ `receipt_chain.rs` - Tamper-evident chain with constant-time hash comparisons, bounded collections

**No Additional Vulnerabilities Found** in connector/ and vef/ modules.

## Summary

1 critical vulnerability found requiring immediate attention (remote/computation_registry.rs)
1 potential issue requiring investigation (HTTP payload size limits)
Comprehensive good security practices confirmed across all audited modules

---
Audit conducted by: CrimsonCrane Agent
Date: 2026-04-20