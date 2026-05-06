# Validation Proof Coalescer Contract

**Bead:** `bd-ov7ca`
**Schema catalog:** `franken-node/validation-proof-coalescer/schema-catalog/v1`
**Status:** Draft contract for follow-on implementation beads

## Purpose

The validation proof coalescer is the in-flight coordination layer in front of
the validation proof cache and validation broker receipts. It prevents agent
swarms from launching duplicate RCH validation jobs for identical proof work,
while still failing closed when the requested work differs, capacity is
exhausted, a lease is stale, a fencing token changes, or the worktree policy is
not acceptable.

This contract is cargo-free. The schema catalog, fixtures, and
`scripts/check_validation_proof_coalescer_contract.py` must be enough to validate
the coalescer contract on a busy machine without running Rust builds.

## ValidationProofWorkKey

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-proof-coalescer/work-key/v1` |
| `work_key_id` | String | Yes | Stable key ID, preferably `vpcowork-<sha256-prefix>` |
| `algorithm` | String | Yes | Digest algorithm, currently `sha256` |
| `hex` | SHA-256 hex | Yes | Digest of `canonical_material` |
| `canonical_material` | String | Yes | Canonical byte-string material used to compute `hex` |
| `proof_cache_key` | DigestRef | Yes | Cache-compatible digest for completed receipt handoff |
| `command_digest` | DigestRef | Yes | Digest of the validation command |
| `input_digests` | Array | Yes | Non-empty input path and digest set |
| `git_commit` | String | Yes | Git commit that scoped the proof work |
| `dirty_worktree` | Boolean | Yes | Whether the proof request includes uncommitted changes |
| `dirty_state_policy` | Enum | Yes | `clean_required`, `dirty_allowed_with_digest`, or `source_only_documented` |
| `feature_flags` | Array | Yes | Sorted feature flags that shape the validation command |
| `cargo_toolchain` | String | Yes | Toolchain selector such as `nightly-2026-02-19` |
| `package` | String | Yes | Cargo package validated by the proof |
| `test_target` | String | Yes | Test target or suite validated by the proof |
| `environment_policy_id` | String | Yes | Environment policy included in the proof scope |
| `target_dir_policy_id` | String | Yes | Target-directory policy included in the proof scope |

`hex`, `proof_cache_key.hex`, `command_digest.hex`, and `input_digests[*].hex`
are all SHA-256 checks. A work key is malformed if any digest is missing,
malformed, or inconsistent with its canonical material. Completed leases hand
off to the existing proof cache only when `proof_cache_key.hex` matches the
coalescer work key digest and the receipt reference verifies.

## ValidationProofCoalescerLease

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-proof-coalescer/lease/v1` |
| `lease_id` | String | Yes | Stable in-flight lease ID |
| `proof_work_key` | ValidationProofWorkKey | Yes | Exact proof work being coordinated |
| `state` | Enum | Yes | Lease lifecycle state |
| `owner_agent` | String | Yes | Agent allowed to produce the receipt for the active fence |
| `owner_bead_id` | String | Yes | Bead that owns the producer validation run |
| `fencing_token` | String | Yes | Monotonic or content-derived token for stale owner exclusion |
| `created_at` | RFC3339 String | Yes | UTC creation timestamp |
| `updated_at` | RFC3339 String | Yes | UTC last update timestamp |
| `expires_at` | RFC3339 String | Yes | UTC stale boundary for this lease |
| `waiter_agents` | Array | Yes | Agents joined to this lease instead of launching duplicate work |
| `admission_policy_id` | String | Yes | Policy used for producer or waiter admission |
| `rch_command` | Object | Yes | Command and command digest used by the producer |
| `target_dir_policy_id` | String | Yes | Off-repo target-directory policy used by the producer |
| `receipt_ref` | Object or null | Yes | Completed validation broker receipt, if available |
| `proof_cache_key` | DigestRef | Yes | Cache-compatible digest for receipt reuse |
| `diagnostics` | Object | Yes | Event code, reason code, trace ID, and fail-closed flags |

Lease states:

- `proposed`
- `running`
- `joined`
- `completed`
- `stale`
- `fenced`
- `rejected`
- `failed_closed`

Stale and fenced leases cannot satisfy readiness or closeout. A waiter may join
only when its work key is byte-for-byte identical to the lease work key, the
lease has not expired, the fence is current, the owner agent and bead ID are
present, and the admission policy allows more waiters.

## ValidationProofCoalescerDecision

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-proof-coalescer/decision/v1` |
| `decision_id` | String | Yes | Stable decision ID |
| `proof_work_key` | ValidationProofWorkKey | Yes | Exact work requested by the caller |
| `lease_ref` | Object or null | Yes | Lease reference considered by the decision |
| `bead_id` | String | Yes | Beads issue requesting proof work |
| `agent_name` | String | Yes | Agent receiving the decision |
| `trace_id` | String | Yes | Stable trace ID for logs and Agent Mail closeout |
| `decided_at` | RFC3339 String | Yes | UTC decision timestamp |
| `decision` | Enum | Yes | Admission or coalescing decision |
| `reason_code` | Enum | Yes | Stable reason code |
| `required_action` | Enum | Yes | Action the caller must take next |
| `diagnostics` | Object | Yes | Human-readable reason and machine flags |

Decision kinds:

- `run_locally_via_rch`
- `join_existing_proof`
- `wait_for_receipt`
- `queued_by_policy`
- `retry_after_stale_lease`
- `reject_dirty_policy`
- `reject_capacity`
- `repair_state`

Reason codes:

- `VPCO_RUN_NO_LEASE`
- `VPCO_JOIN_RUNNING`
- `VPCO_WAIT_COMPLETION`
- `VPCO_QUEUE_CAPACITY`
- `VPCO_RETRY_STALE`
- `VPCO_REJECT_DIRTY_POLICY`
- `VPCO_REJECT_CAPACITY`
- `VPCO_REPAIR_CORRUPTED`

Required actions:

- `start_rch_validation`
- `join_existing_lease`
- `wait_for_receipt`
- `queue_validation`
- `retry_with_new_fence`
- `fail_closed`
- `repair_state`

## ValidationProofCoalescerAdmissionPolicy

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-proof-coalescer/admission-policy/v1` |
| `policy_id` | String | Yes | Stable admission policy ID |
| `max_running_proofs` | Integer | Yes | Maximum concurrent producer proofs admitted |
| `max_waiters_per_lease` | Integer | Yes | Maximum waiter agents per in-flight lease |
| `stale_after_seconds` | Integer | Yes | Lease freshness window |
| `queue_high_watermark` | Integer | Yes | Queue depth where producers are queued or rejected |
| `min_available_worker_slots` | Integer | Yes | Minimum RCH worker slots required for a new producer |
| `dirty_state_policy` | Enum | Yes | Dirty worktree policy for admission |
| `capacity_mode` | Enum | Yes | `observe_only`, `queue_when_busy`, or `reject_when_busy` |

The admission policy is deterministic input to every decision. Capacity
observations are advisory only when `capacity_mode` is `observe_only`; they
become fail-closed when the policy is `reject_when_busy`.

## Event Codes

| Code | Event |
|------|-------|
| `VPCO-001` | Work-key lookup started |
| `VPCO-002` | Producer admitted |
| `VPCO-003` | Waiter joined a running proof |
| `VPCO-004` | Waiter must wait for receipt handoff |
| `VPCO-005` | Proof queued by capacity policy |
| `VPCO-006` | Stale lease fenced and retried |
| `VPCO-007` | Dirty-state policy rejected the proof request |
| `VPCO-008` | Capacity policy rejected the proof request |
| `VPCO-009` | Corrupted coalescer state requires repair |
| `VPCO-010` | Completed lease handed off to proof cache and broker receipt |

## Structured Log Fields

Every decision and lease transition must include these structured fields:

- `trace_id`
- `proof_work_key`
- `proof_cache_key`
- `lease_id`
- `decision`
- `reason_code`
- `event_code`
- `producer_agent`
- `waiter_agent`
- `bead_id`
- `receipt_path`
- `cache_key`
- `fencing_token`
- `target_dir_policy_id`
- `dirty_state_policy`

## Invariants

- **INV-VPCO-WORK-KEY-DETERMINISTIC** - Work keys are SHA-256 digests over
  command, input, worktree, feature, toolchain, package, test-target,
  environment-policy, and target-dir-policy material.
- **INV-VPCO-CACHE-COMPATIBLE** - Completed leases hand off to the proof cache
  only when `proof_cache_key.hex` equals the work key digest.
- **INV-VPCO-EXACT-JOIN** - Waiters join an existing proof only when their work
  key exactly matches the active lease work key.
- **INV-VPCO-FRESHNESS** - Expired leases are stale and cannot satisfy
  readiness, closeout, or proof reuse.
- **INV-VPCO-FENCING** - A stale owner cannot publish a receipt after a newer
  fencing token is issued.
- **INV-VPCO-OWNER-AUDIT** - Every producer lease records owner agent, bead ID,
  trace ID, and RCH command digest.
- **INV-VPCO-DIRTY-STATE** - Dirty worktree requests are admitted only when the
  policy explicitly allows and digests the dirty state.
- **INV-VPCO-CAPACITY-BOUNDED** - Admission policy caps producer count, waiters,
  and capacity behavior before launching RCH work.
- **INV-VPCO-FAIL-CLOSED** - Stale leases, fenced owners, dirty-policy
  rejections, capacity rejections, corrupted state, malformed keys, and digest
  mismatches cannot satisfy Beads closeout.
- **INV-VPCO-AUDITABLE-DECISION** - Every caller receives a stable decision,
  reason code, required action, event code, and trace ID.

## Error Codes

| Code | Meaning |
|------|---------|
| `ERR_VPCO_INVALID_SCHEMA_VERSION` | Unknown coalescer schema version |
| `ERR_VPCO_MALFORMED_WORK_KEY` | Work key is not an object or required key fields are missing |
| `ERR_VPCO_BAD_WORK_KEY` | Work key digest or canonical material does not verify |
| `ERR_VPCO_COMMAND_DIGEST_MISMATCH` | Command digest is missing, malformed, or inconsistent |
| `ERR_VPCO_INPUT_DIGEST_MISMATCH` | Input digests are missing, malformed, or inconsistent |
| `ERR_VPCO_MALFORMED_LEASE` | Lease is not an object or required lease fields are missing |
| `ERR_VPCO_STALE_LEASE` | Lease freshness has expired |
| `ERR_VPCO_FENCED_OWNER` | Lease owner or fence is no longer allowed to publish |
| `ERR_VPCO_DIRTY_POLICY` | Dirty-state policy rejected the request |
| `ERR_VPCO_CAPACITY_REJECTED` | Admission capacity policy rejected the request |
| `ERR_VPCO_CORRUPTED_STATE` | Coalescer state is explicitly corrupted or inconsistent |
| `ERR_VPCO_MALFORMED_DECISION` | Decision is missing required fields or has invalid enums |
| `ERR_VPCO_MALFORMED_POLICY` | Admission policy is missing required fields or has invalid bounds |

## Acceptance Scenarios

The fixture set must cover:

- `happy_path_join` - a waiter joins an identical running proof.
- `divergent_key_miss` - a different work key launches or queues separate work.
- `stale_lease_recovery` - a stale lease is fenced and retried with a new token.
- `fenced_owner_rejection` - an old owner is rejected after fencing.
- `dirty_policy_rejection` - dirty-state policy fails closed.
- `capacity_rejection` - capacity policy fails closed.
- `completed_receipt_handoff` - a completed lease hands off to a proof-cache key
  and validation broker receipt reference.

## Closeout Rules

Beads closeout may rely on a coalesced proof only when the decision is
`join_existing_proof`, `wait_for_receipt`, or `run_locally_via_rch` followed by
a completed lease with a fresh receipt reference and matching proof-cache key.
All rejection decisions require fresh validation, retry with a new fence, repair,
or explicit blocker reporting. No stale, fenced, rejected, corrupted, malformed,
or dirty-policy-disallowed lease may satisfy readiness or closeout.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec | `docs/specs/validation_proof_coalescer.md` |
| Schema catalog | `artifacts/validation_broker/proof_coalescer/validation_proof_coalescer_contract.schema.json` |
| Fixtures | `artifacts/validation_broker/proof_coalescer/validation_proof_coalescer_fixtures.v1.json` |
| Gate script | `scripts/check_validation_proof_coalescer_contract.py` |
| Gate tests | `tests/test_check_validation_proof_coalescer_contract.py` |
