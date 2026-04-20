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

## Summary

1 critical vulnerability found requiring immediate attention
1 potential issue requiring investigation 
Multiple good security practices confirmed

---
Audit conducted by: CrimsonCrane Agent
Date: 2026-04-20