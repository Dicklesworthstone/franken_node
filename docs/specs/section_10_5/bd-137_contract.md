# bd-137: Policy-Visible Compatibility Gate APIs

## Bead: bd-137 | Section: 10.5

## Purpose

Implements policy-visible compatibility gate APIs that expose compatibility mode
transitions, divergence receipts, and policy gates as programmatic APIs. This is
one of the 10 Impossible-by-Default capabilities (Section 3.2 #5): operators must
control which compatibility behaviors are active, at what risk level, with full
traceability. Without this, compatibility shims operate as hidden magic -- the
exact opposite of trust-native operations.

## API Surfaces

### 1. Gate Check Endpoint

Evaluates whether a given package/extension may operate under a specific
compatibility mode. Returns structured allow/deny/audit decisions with
machine-readable rationale.

```
POST /api/v1/compatibility/gate-check
Input:  { package_id, requested_mode, scope, policy_context }
Output: { decision: allow|deny|audit, rationale, trace_id, receipt_id }
```

### 2. Mode Query API

Queries the currently active compatibility mode for a given scope (project,
tenant, or extension). Returns the mode along with activation metadata and
the signed configuration receipt.

```
GET /api/v1/compatibility/mode?scope={scope_id}
Output: { mode: strict|balanced|legacy_risky, activated_at, receipt_id, policy_predicate }
```

### 3. Mode Transition Request API

Requests a mode transition for a given scope. Mode transitions are policy-gated
and produce signed configuration receipts. Transitions require approval workflow
when escalating risk level.

```
POST /api/v1/compatibility/mode/transition
Input:  { scope_id, from_mode, to_mode, justification, requestor }
Output: { transition_id, approved, receipt, rationale }
```

### 4. Receipt Query API

Queries issued divergence receipts. Receipts are cryptographically signed and
can be independently verified. Supports filtering by scope, time range, and
severity.

```
GET /api/v1/compatibility/receipts?scope={scope_id}&severity={level}
Output: { receipts: [...], total, page, signature }
```

### 5. Shim Registry Query API

Exposes all registered compatibility shims with full typed metadata: shim ID,
behavior description, risk category, activation policy, and divergence rationale.

```
GET /api/v1/compatibility/shims?scope={scope_id}
Output: { shims: [{ shim_id, description, risk_category, activation_policy, divergence_rationale }] }
```

## Invariants

| ID | Statement |
|----|-----------|
| INV-PCG-VISIBLE | All compatibility gate decisions are visible to operators via structured API responses with machine-readable rationale. No opaque gates. |
| INV-PCG-AUDITABLE | Every gate decision, mode transition, and receipt issuance produces a structured audit event with trace correlation ID. |
| INV-PCG-RECEIPT | Every divergence and mode transition produces a cryptographically signed receipt that can be independently verified. |
| INV-PCG-TRANSITION | Mode transitions are policy-gated: escalating risk requires approval workflow; de-escalating risk is auto-approved but still audited. |

## Event Codes

| Code | When Emitted |
|------|--------------|
| PCG-001 | Gate check passed: package/extension allowed under requested compatibility mode. |
| PCG-002 | Gate check failed: package/extension denied under requested compatibility mode with rationale. |
| PCG-003 | Mode transition approved: compatibility mode changed for scope with signed receipt. |
| PCG-004 | Divergence receipt issued: new divergence detected and receipt signed and stored. |

## Compatibility Modes

| Mode | Risk Level | Description |
|------|------------|-------------|
| strict | Low | Only verified-compatible behaviors allowed. No shims activated. |
| balanced | Medium | Tested shims activated with monitoring. Divergences produce warnings. |
| legacy_risky | High | All available shims activated. Divergences tolerated with receipts. |

## Policy-as-Data Contracts

Shim activation constraints are expressed as machine-verifiable policy predicates
(per 9B.5). Each policy predicate includes:

- `predicate_id`: Unique identifier for the policy constraint.
- `signature`: Cryptographic signature over the predicate body.
- `attenuation`: Scope-limiting constraints that narrow the predicate's applicability.
- `activation_condition`: Boolean expression over scope, risk level, and shim metadata.

## Non-Interference and Monotonicity

Per 9C.5, the API enforces:

1. **Non-interference:** Shim activation in scope A has no observable effect in
   scope B. Scopes are isolated by tenant/project boundary.
2. **Monotonicity:** Adding shims never weakens existing security guarantees.
   Formally: if policy P allows operation O, then policy P + shim S also allows O.

## Performance Requirements

Per 9D.5, gate evaluation must meet interactive budget:
- Cached policy evaluation: < 1ms p99 latency.
- Precompiled decision DAGs for hot-path evaluation.
- Deterministic rule ordering preserved across cache invalidations.

## Acceptance Criteria

1. API surface exposes all registered compatibility shims with full typed metadata.
2. Mode selection (strict/balanced/legacy_risky) is per-scope and produces signed receipts.
3. Gate evaluation returns structured allow/deny/audit decisions with machine-readable rationale.
4. Policy-as-data contracts are cryptographically verifiable.
5. Non-interference property: shim activation in scope A has no observable effect in scope B.
6. Monotonicity property: adding shims never weakens existing security guarantees (formally testable).
7. Gate evaluation latency meets interactive budget (< 1ms p99 for cached policy).
8. All gate decisions emit structured audit events with trace correlation IDs.

## Dependencies

- Upstream: bd-3il (compatibility core), bd-1xg (extension ecosystem), bd-1ta (FCP deep-mined)
- Downstream: bd-1koz (section gate), bd-20a (section rollup), bd-mwf (policy-visible compat shim system)
