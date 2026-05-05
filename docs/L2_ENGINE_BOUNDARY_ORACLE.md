# L2 Engine-Boundary Semantic Oracle

> Validates that franken_engine trust boundaries, capability gates, and policy
> enforcement remain intact across all compatibility work.

**Authority**: [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
**Related**: [ENGINE_SPLIT_CONTRACT.md](ENGINE_SPLIT_CONTRACT.md), [L1_LOCKSTEP_RUNNER.md](L1_LOCKSTEP_RUNNER.md)

---

## 1. Purpose

The L2 oracle complements the L1 product oracle. While L1 validates external behavioral compatibility, L2 validates that the franken_engine trust boundary remains semantically intact. Any compatibility shim that weakens trust gates, bypasses capability checks, or violates the engine split contract is a L2 failure.

## 2. Boundary Definition

The franken_engine trust boundary is defined by:

### 2.1 Capability Gates
- Extension loading requires cryptographic attestation
- Resource access requires explicit capability grants
- Network access requires policy approval
- File system access is scoped to declared paths

### 2.2 Execution Boundaries
- Sandboxed execution contexts cannot escape to host
- Deterministic replay requires identical outputs for identical inputs
- Policy decisions are auditable and reversible

### 2.3 Trust Transitions
- Every trust level transition is logged
- Escalation requires explicit approval chain
- Revocation is immediate and atomic

## 3. Semantic Checks

### 3.1 Split Contract Compliance
- No local engine crate reintroduction (validated by `check_split_contract.py`)
- Engine dependencies point to correct external paths
- No engine-internal imports in node crate

### 3.2 Trust Gate Integrity
- Compatibility shims do not bypass capability checks
- Polyfills cannot escalate trust level
- Bridge implementations preserve policy visibility

### 3.3 Policy Enforcement
- Divergence receipts are generated for all policy-relevant behaviors
- Unsafe behaviors are blocked unless explicitly gated
- Audit trail is complete for all trust-relevant operations

### 3.4 Boundary Crossing Validation
- All calls from franken_node into franken_engine go through defined interfaces
- No raw pointer passing across boundary
- Serialization/deserialization at boundary uses validated types

## 4. Release Gate Linkage

### 4.1 L2 Always Blocks
Unlike L1, which has mode-dependent behavior for different bands, **L2 failures always block release**. Trust boundary integrity is non-negotiable regardless of compatibility mode.

### 4.2 Gate Integration
- L2 oracle runs as part of the release pipeline
- L2 must PASS before L1 results are considered
- L2 verdict is included in the release gate aggregate
- Both L1 and L2 must pass — neither replaces the other

### 4.3 Failure Escalation
- L2 failure → immediate release block
- L2 failure → notification to repository maintainer
- L2 failure requires explicit resolution before retry
- No workarounds or temporary exceptions for L2 failures

## 5. Integration with Existing Infrastructure

| Component | Integration |
|-----------|------------|
| `check_split_contract.py` | Reused for split contract checks |
| `guard_dependency_direction.py` | Reused for dependency direction checks |
| L1 lockstep runner | L2 runs before L1; both required |
| Release pipeline | L2 verdict feeds into aggregate gate |
| Divergence ledger | L2 violations recorded as critical entries |

## 6. References

- [ENGINE_SPLIT_CONTRACT.md](ENGINE_SPLIT_CONTRACT.md) — Split boundary definition
- [L1_LOCKSTEP_RUNNER.md](L1_LOCKSTEP_RUNNER.md) — L1 product oracle
- [COMPATIBILITY_MODE_POLICY.md](COMPATIBILITY_MODE_POLICY.md) — Mode enforcement (L2 is mode-independent)
- [PLAN_TO_CREATE_FRANKEN_NODE.md](plans/PLAN_TO_CREATE_FRANKEN_NODE.md) Section 10.2
