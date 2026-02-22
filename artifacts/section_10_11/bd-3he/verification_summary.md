# bd-3he: Verification Summary

## Supervision Tree with Restart Budgets and Escalation Policies

### Section

10.11

### Implementation

The `connector::supervision` module (`crates/franken-node/src/connector/supervision.rs`)
implements an Erlang-inspired supervision tree with three restart strategies,
sliding-window restart budgets, bounded escalation policies, graceful shutdown
in reverse start order, and structured health reporting.

### Key Design Decisions

1. **Three supervision strategies.** `OneForOne` restarts only the failed
   child, `OneForAll` restarts all children, and `RestForOne` restarts the
   failed child and all children started after it. Strategy application is
   deterministic (`INV-SUP-STRATEGY-DETERMINISTIC`).

2. **Sliding-window restart budget.** Restart timestamps are tracked and
   pruned against a configurable time window. When the restart count within
   the window reaches `max_restarts`, the failure is escalated rather than
   restarted (`INV-SUP-BUDGET-BOUND`).

3. **Bounded escalation.** Escalation depth is tracked and bounded by
   `max_escalation_depth`. Exceeding this depth triggers a full shutdown
   (`INV-SUP-ESCALATION-BOUNDED`).

4. **Reverse-order shutdown.** Children are stopped in reverse insertion
   (start) order, respecting per-child shutdown timeouts
   (`INV-SUP-SHUTDOWN-ORDER`, `INV-SUP-TIMEOUT-ENFORCED`).

5. **BTreeMap for deterministic ordering.** Children are stored in a
   `BTreeMap` keyed by name for stable iteration. Insertion order is
   tracked via a monotonic counter for shutdown sequencing.

### Event Codes

- `SUP-001` / `supervisor.child_started`
- `SUP-002` / `supervisor.child_failed`
- `SUP-003` / `supervisor.child_restarted`
- `SUP-004` / `supervisor.budget_exhausted`
- `SUP-005` / `supervisor.escalation`
- `SUP-006` / `supervisor.shutdown_started`
- `SUP-007` / `supervisor.shutdown_complete`
- `SUP-008` / `supervisor.health_report`

### Error Codes

- `ERR_SUP_CHILD_NOT_FOUND`
- `ERR_SUP_BUDGET_EXHAUSTED`
- `ERR_SUP_MAX_ESCALATION`
- `ERR_SUP_SHUTDOWN_TIMEOUT`
- `ERR_SUP_DUPLICATE_CHILD`

### Invariants

| ID | Status |
|----|--------|
| `INV-SUP-BUDGET-BOUND` | Verified (restart count bounded by sliding window budget) |
| `INV-SUP-ESCALATION-BOUNDED` | Verified (escalation chain terminates at max depth) |
| `INV-SUP-SHUTDOWN-ORDER` | Verified (children stopped in reverse start order) |
| `INV-SUP-TIMEOUT-ENFORCED` | Verified (shutdown timeout respected per child) |
| `INV-SUP-STRATEGY-DETERMINISTIC` | Verified (strategy match is exhaustive and deterministic) |

### Evidence Artifacts

- Evidence JSON: `artifacts/section_10_11/bd-3he/verification_evidence.json`
- Spec contract: `docs/specs/section_10_11/bd-3he_contract.md`

### Verification Surfaces

- Gate script: `scripts/check_supervision_tree.py`
- Unit tests: 20
- Strategies: 3 (OneForOne, OneForAll, RestForOne)
- Restart types: 3 (Permanent, Transient, Temporary)
- Event codes: 8
- Error codes: 5
- Invariant constants: 5

### Result

**PASS**
