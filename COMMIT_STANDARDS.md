# Commit Message Standards

## Security Commit Requirements

### CRITICAL: Security claims MUST match file changes

Commits claiming security fixes MUST actually modify security-relevant code. 

**❌ WRONG:**
```
SECURITY: Fix authentication bypass
- Changed: fuzz/test_fuzzing.rs
```

**✅ CORRECT:**
```  
SECURITY: Fix authentication bypass
- Changed: crates/franken-node/src/api/middleware.rs
```

### Security-relevant file paths:
- `crates/franken-node/src/api/middleware.rs` - Auth, authz, rate limiting
- `crates/franken-node/src/security/` - Security modules
- `crates/franken-node/src/supply_chain/` - Supply chain security  
- `crates/franken-node/Cargo.toml` - Feature flags affecting security
- `crates/franken-node/src/storage/` - Data access security
- `crates/franken-node/src/runtime/` - Runtime security

### Keywords that trigger security validation:
- `SECURITY`, `security`, `Security`
- `fix.*security`, `Security.*fix`
- `auth.*fix`  
- `rate.*limit.*fix`

### Process:
1. Pre-commit hook validates security claims against file changes
2. Post-commit audit script checks commit history for false claims
3. False security claims are flagged as P0 workflow violations

## Validation Tools

### Pre-commit Hook
```bash
# Install validation hook
cp scripts/pre-commit-security-validation .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

### Audit Script  
```bash
# Check last 20 commits for false security claims
./scripts/validate-security-commits.sh HEAD~20..HEAD

# Check specific range
./scripts/validate-security-commits.sh abc123..def456
```

## Bead Closure Standards

### ❌ WRONG:
```
Update beads: close bd-15mhr, bd-1xque (rate limiter security fixes)
# Only changes: .beads/issues.jsonl
```

**Problem:** Claims security fixes but only updates bead tracking.

### ✅ CORRECT:
```
fix(security): implement rate limiter fail-closed behavior

Resolves: bd-15mhr
# Changes: crates/franken-node/src/api/middleware.rs
```

Then separately:
```
chore(beads): close bd-15mhr following rate limiter fix
# Changes: .beads/issues.jsonl
```

## Examples

### Legitimate Security Commits:
- **Auth fixes:** Modify `middleware.rs` authentication logic
- **Rate limiting:** Change rate limiter configuration/behavior
- **Feature flags:** Enable/disable security features in `Cargo.toml`
- **Input validation:** Add security checks in relevant modules
- **Crypto fixes:** Modify cryptographic verification logic

### NOT Security Commits:
- **Test updates:** Changing test files, fuzz targets
- **Bead tracking:** Only updating `.beads/issues.jsonl` 
- **Documentation:** README, comments (unless documenting security)
- **Refactoring:** Code moves without security implications
- **Build fixes:** Dependency updates without security impact

## Incident Response

If false security claim is committed:
1. Create corrective commit explaining the discrepancy
2. File P0 bead for the false claim incident  
3. Audit related commits for systematic issues
4. Review/improve validation processes

## Example Corrective Commit:
```
fix(docs): Correct commit 241aa3ba - actual changes were SDK fuzzing, not rate limiters

Commit 241aa3ba incorrectly claimed "rate limiter security fixes" but 
only modified fuzz targets and SDK dependencies. No rate limiter code
was changed. The claimed security vulnerabilities remain unaddressed.

This corrects the commit history to prevent confusion during security
audits and ensures accurate tracking of actual security implementations.

Refs: 241aa3ba
```