# Policy: Compatibility Gate API

**Bead:** bd-137
**Section:** 10.5 -- Security + Policy Product Surfaces
**Status:** Active
**Last reviewed:** 2026-02-20

---

## 1. Overview

The compatibility gate API is the programmatic surface through which operators
inspect, control, and audit compatibility behavior in franken_node. Every
compatibility decision -- shim activation, mode selection, divergence detection --
flows through this API and produces structured evidence. There are no opaque gates.

This policy defines the API design, integration patterns, and governance rules
for the compatibility gate system.

## 2. API Design

### 2.1 Compatibility Gate Check

The gate check is the primary decision point. Before any compatibility-shimmed
behavior executes, the gate evaluates the current policy state and returns a
structured decision.

**Input:**
- `package_id` (string): The package or extension requesting compatibility behavior.
- `requested_mode` (enum): One of `strict`, `balanced`, `legacy_risky`.
- `scope` (string): The tenant/project scope for the evaluation.
- `policy_context` (object): Additional context for policy evaluation (risk metadata, caller identity).

**Output:**
- `decision` (enum): `allow`, `deny`, or `audit`.
- `rationale` (object): Machine-readable explanation of the decision, including which policy predicates matched.
- `trace_id` (string): Correlation ID for audit trail linkage.
- `receipt_id` (string): If a divergence receipt was issued, its ID.

**Event emission:**
- `PCG-001` on allow.
- `PCG-002` on deny.

### 2.2 Mode Transition API

Operators request mode changes through the transition API. Transitions that
escalate risk (e.g., strict -> balanced, balanced -> legacy_risky) require
the approval workflow (bd-sh3). De-escalating transitions are auto-approved
but still produce audit events.

**Request mode change:**
- `scope_id` (string): Target scope for the mode change.
- `from_mode` (enum): Current mode (validated server-side).
- `to_mode` (enum): Requested new mode.
- `justification` (string): Human-readable justification (minimum 20 characters).
- `requestor` (string): Identity of the requesting operator.

**Response:**
- `transition_id` (string): Unique ID for the transition.
- `approved` (bool): Whether the transition was immediately approved.
- `receipt` (object): Signed configuration receipt.
- `rationale` (string): Explanation if denied or pending approval.

**Event emission:**
- `PCG-003` on approved transition.

### 2.3 Divergence Receipt API

When the system detects a divergence between franken_node behavior and upstream
Node.js behavior, it issues a signed receipt. The receipt API allows operators
to query, filter, and verify these receipts.

**Query receipts:**
- Filter by scope, severity, time range, resolution status.
- Pagination support for large result sets.
- Each receipt includes a cryptographic signature that can be independently verified.

**Receipt schema:**
```json
{
  "receipt_id": "string (UUID)",
  "timestamp": "ISO-8601",
  "scope_id": "string",
  "shim_id": "string",
  "divergence_description": "string",
  "severity": "critical | major | minor | cosmetic",
  "signature": "string (hex-encoded HMAC-SHA256)",
  "trace_id": "string",
  "resolved": false
}
```

**Event emission:**
- `PCG-004` on receipt issuance.

### 2.4 Shim Registry Query

The shim registry query exposes all registered compatibility shims. This is the
transparency surface: operators can see exactly which shims exist, what they do,
and under what policy constraints they activate.

Each shim entry includes:
- `shim_id`: Unique identifier.
- `description`: Human-readable behavior description.
- `risk_category`: low, medium, high.
- `activation_policy`: The policy predicate that governs activation.
- `divergence_rationale`: Why this shim exists and what divergence it addresses.

## 3. Policy Visibility Principles

All decisions produce structured evidence. The following principles govern the
API's behavior:

1. **No opaque gates:** Every allow/deny/audit decision includes a rationale
   field that references the specific policy predicates that produced the decision.

2. **Structured audit events:** Every API call emits a structured event with a
   trace correlation ID. Events are recorded in the append-only audit ledger.

3. **Signed receipts:** Mode transitions and divergence detections produce
   cryptographically signed receipts. Receipt signatures use HMAC-SHA256 with
   a registry key that is rotated on a configurable schedule.

4. **Deterministic evaluation:** Given the same inputs and policy state, the gate
   always produces the same decision. This is verified by the determinism
   conformance tests.

## 4. Integration Patterns

### 4.1 CLI Usage

```bash
# Verify a runtime profile target
franken-node verify compatibility strict

# Verify a concrete runtime and emit machine-readable output
franken-node verify compatibility node --json

# Request a previous major contract version when needed by older tooling
franken-node verify compatibility bun --json --compat-version 0
```

The current shipped CLI surface is `franken-node verify compatibility <target>`,
where `<target>` is either a runtime profile (`strict`, `balanced`,
`legacy-risky`) or a concrete runtime (`node`, `bun`, `franken-node`). The
mode-transition, receipts, and shim-registry operations described in this
policy are library/API surfaces; there is not currently a top-level
`franken-node compat ...` command family.

### 4.2 Programmatic SDK

```rust
use franken_node::api::compat_gate::{CompatGateService, GateCheckRequest, CompatMode, GateDecision};

let mut service = CompatGateService::new();
let request = GateCheckRequest {
    package_id: "npm:@acme/auth".into(),
    requested_mode: CompatMode::Balanced,
    scope: "tenant-1".into(),
    policy_context: Some(ctx.into()),
};
let response = service.gate_check(&request)?;

match response.decision {
    GateDecision::Allow => { /* proceed with shimmed behavior */ },
    GateDecision::Deny => { /* reject with rationale */ },
    GateDecision::Audit => { /* proceed but record for review */ },
}
```

### 4.3 CI Pipeline Integration

The gate API can be called from CI pipelines to enforce compatibility policy
before deployment:

```yaml
- name: Check compatibility gate
  run: |
    franken-node verify compatibility "${{ env.RUNTIME_TARGET }}" \
      --json | jq -e '.status == "pass" and .verdict == "PASS"'
```

## 5. Security Considerations

- **Policy-as-data:** Shim activation constraints are cryptographically signed
  policy predicates. Unsigned or expired predicates are rejected.
- **Non-interference:** Scope isolation ensures that shim activation in one
  tenant cannot affect another tenant's behavior.
- **Monotonicity:** The system formally verifies that adding shims does not
  weaken security guarantees in any scope.
- **Audit completeness:** The audit trail is append-only and hash-chained.
  Gap detection alerts fire if expected events are missing.

## 6. Governance

- Mode transitions to `legacy_risky` require at least 2-of-3 approver signatures.
- Receipt signatures are rotated every 90 days.
- Quarterly review of shim registry completeness and divergence trends.
- Compatibility gate latency budget: < 1ms p99 for cached policy evaluation.
