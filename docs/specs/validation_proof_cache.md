# Validation Proof Cache Contract

**Bead:** `bd-jbkiq`
**Schema catalog:** `franken-node/validation-proof-cache/schema-catalog/v1`
**Status:** Draft contract for follow-on implementation beads

## Purpose

The validation proof cache is the content-addressed reuse layer for validation
broker receipts. It lets agents reuse a previous proof only when the command,
inputs, worktree state, policies, toolchain, package, and test target are
identical to the cache key and the source receipt is still fresh.

This contract is intentionally cargo-free. The schema catalog and fixtures under
`artifacts/validation_broker/proof_cache/` plus
`scripts/check_validation_proof_cache_contract.py` must be enough to validate
the proof-cache receipt format on a busy machine.

## ValidationProofCacheKey

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-proof-cache/key/v1` |
| `key_id` | String | Yes | Stable key ID, preferably `vpckey-<sha256-prefix>` |
| `algorithm` | String | Yes | Digest algorithm, currently `sha256` |
| `hex` | SHA-256 hex | Yes | Digest of `canonical_material` |
| `canonical_material` | String | Yes | Canonical byte-string material used to compute `hex` |
| `command_digest` | DigestRef | Yes | Digest of the validation command |
| `input_digests` | Array | Yes | Non-empty input path and digest set |
| `git_commit` | String | Yes | Git commit that scoped the proof |
| `dirty_worktree` | Boolean | Yes | Whether the proof was produced with uncommitted changes |
| `dirty_state_policy` | Enum | Yes | `clean_required`, `dirty_allowed_with_digest`, or `source_only_documented` |
| `feature_flags` | Array | Yes | Sorted feature flags that shaped the validation command |
| `cargo_toolchain` | String | Yes | Toolchain selector such as `nightly-2026-02-19` |
| `package` | String | Yes | Cargo package validated by the source receipt |
| `test_target` | String | Yes | Test target or suite validated by the source receipt |
| `environment_policy_id` | String | Yes | Environment policy included in the proof scope |
| `target_dir_policy_id` | String | Yes | Target-directory policy included in the proof scope |

`command_digest`, `input_digests[*]`, and `hex` are all SHA-256 checks. A cache
key is malformed if any digest is missing, malformed, or inconsistent with its
canonical material.

## ValidationProofCacheEntry

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-proof-cache/entry/v1` |
| `entry_id` | String | Yes | Stable cache entry ID |
| `cache_key` | ValidationProofCacheKey | Yes | Exact key for this entry |
| `bead_id` | String | Yes | Beads issue proven by the source receipt |
| `receipt_ref` | Object | Yes | Receipt ID, path, bead ID, command digest, input digests, and policies |
| `receipt_digest` | DigestRef | Yes | Digest over receipt canonical material |
| `producer_agent` | String | Yes | Agent that wrote the proof |
| `created_at` | RFC3339 String | Yes | UTC creation timestamp |
| `freshness_expires_at` | RFC3339 String | Yes | UTC time after which reuse is invalid |
| `trust` | Object | Yes | Trust state, git commit, signature status, and dirty-state policy |
| `reuse` | Object | Yes | Reuse count and last reuse timestamp |
| `storage` | Object | Yes | Cache path, byte size, quota class, and retention policy |
| `invalidation` | Object | Yes | Active invalidation state, reason, and corruption marker |

Entries are never authoritative without their source validation broker receipt.
The cache stores enough digest material to reject a mismatched receipt before any
consumer can reuse it.

## ValidationProofCacheDecision

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-proof-cache/decision/v1` |
| `decision_id` | String | Yes | Stable decision ID |
| `cache_key` | ValidationProofCacheKey | Yes | Key requested by the consumer |
| `bead_id` | String | Yes | Beads issue requesting reuse |
| `trace_id` | String | Yes | Stable trace ID for logs and Agent Mail closeout |
| `decided_at` | RFC3339 String | Yes | UTC decision timestamp |
| `decision` | Enum | Yes | Cache lookup result |
| `reason_code` | Enum | Yes | Stable reason code |
| `entry_ref` | Object or null | Yes | Entry reference when one was considered |
| `receipt_ref` | Object or null | Yes | Receipt reference when one was considered |
| `required_action` | Enum | Yes | Action the caller must take next |
| `diagnostics` | Object | Yes | Human-readable reason and machine flags |

Decision kinds:

- `hit`
- `miss`
- `stale`
- `digest_mismatch`
- `policy_mismatch`
- `dirty_state_mismatch`
- `quota_blocked`
- `corrupted_entry`

Reason codes:

- `VPC_HIT_FRESH`
- `VPC_MISS_NO_ENTRY`
- `VPC_REJECT_STALE`
- `VPC_REJECT_RECEIPT_DIGEST`
- `VPC_REJECT_COMMAND_DIGEST`
- `VPC_REJECT_INPUT_DIGEST`
- `VPC_REJECT_POLICY`
- `VPC_REJECT_DIRTY_STATE`
- `VPC_REJECT_QUOTA`
- `VPC_REJECT_CORRUPTED`

Required actions:

- `reuse_receipt`
- `run_validation`
- `refresh_validation`
- `repair_cache`
- `free_space`
- `source_only_not_allowed`

## ValidationProofCacheGcReport

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema_version` | String | Yes | `franken-node/validation-proof-cache/gc-report/v1` |
| `report_id` | String | Yes | Stable report ID |
| `generated_at` | RFC3339 String | Yes | UTC timestamp |
| `policy` | Object | Yes | Quota and retention policy |
| `kept_entries` | Array | Yes | Entries retained by the pass |
| `removed_entries` | Array | Yes | Entries removed by the pass |
| `rejected_entries` | Array | Yes | Entries rejected as invalid but not removed |
| `disk_pressure` | Object | Yes | Disk-pressure observation used by the pass |

The GC report is included in this spec so the implementation can be bounded from
the start. The `bd-zvxqb` implementation bead owns the runtime behavior.

## Invariants

- **INV-VPC-KEY-DETERMINISTIC** - Cache keys are SHA-256 digests over canonical
  command, input, worktree, feature, toolchain, package, test-target,
  environment-policy, and target-dir-policy material.
- **INV-VPC-RECEIPT-DIGEST** - Entries are invalid if `receipt_digest.hex` is
  missing, malformed, or does not match `receipt_digest.canonical_material`.
- **INV-VPC-COMMAND-DIGEST** - Entries are invalid if the cache key command
  digest differs from the referenced receipt command digest.
- **INV-VPC-INPUT-DIGESTS** - Entries are invalid if the cache key input digest
  set differs from the referenced receipt input digest set.
- **INV-VPC-FRESHNESS** - Stale entries cannot satisfy closeout, readiness, CI,
  or proof reuse.
- **INV-VPC-DIRTY-STATE** - Dirty worktree proofs are reusable only when the
  dirty-state policy and dirty-state digest material match exactly.
- **INV-VPC-POLICY-MATCH** - Environment policy and target-dir policy must match
  exactly between the cache key and source receipt.
- **INV-VPC-FAIL-CLOSED** - Cache entries are never trusted if receipt digest,
  command digest, input digest, freshness, dirty-state policy, environment
  policy, target-dir policy, quota, or corruption validation fails.
- **INV-VPC-AUDITABLE-DECISION** - Every lookup emits a
  ValidationProofCacheDecision with a stable decision, reason code, required
  action, and trace ID.
- **INV-VPC-BOUNDED-GROWTH** - Cache storage is quota-governed and stale or
  invalid entries are eligible for GC.

## Error Codes

| Code | Meaning |
|------|---------|
| `ERR_VPC_INVALID_SCHEMA_VERSION` | Unknown proof-cache schema version |
| `ERR_VPC_MALFORMED_KEY` | Key is not an object or required key fields are missing |
| `ERR_VPC_MALFORMED_ENTRY` | Entry is not an object or required entry fields are missing |
| `ERR_VPC_MALFORMED_DECISION` | Decision is not an object or required decision fields are missing |
| `ERR_VPC_BAD_CACHE_KEY` | Cache key digest or canonical material does not verify |
| `ERR_VPC_RECEIPT_DIGEST_MISMATCH` | Receipt digest does not verify |
| `ERR_VPC_COMMAND_DIGEST_MISMATCH` | Cache key command digest differs from receipt reference |
| `ERR_VPC_INPUT_DIGEST_MISMATCH` | Cache key input digests differ from receipt reference |
| `ERR_VPC_STALE_ENTRY` | Entry freshness has expired |
| `ERR_VPC_DIRTY_STATE_MISMATCH` | Dirty-worktree state or policy differs between key and receipt |
| `ERR_VPC_POLICY_MISMATCH` | Environment or target-dir policy differs between key and receipt |
| `ERR_VPC_QUOTA_BLOCKED` | Cache lookup or write is blocked by quota |
| `ERR_VPC_CORRUPTED_ENTRY` | Entry is explicitly marked corrupted or has a corrupted decision |

## Event Codes

| Code | Event |
|------|-------|
| `VPC-001` | Cache lookup started |
| `VPC-002` | Cache hit accepted |
| `VPC-003` | Cache miss recorded |
| `VPC-004` | Stale entry rejected |
| `VPC-005` | Receipt digest mismatch rejected |
| `VPC-006` | Command or input digest mismatch rejected |
| `VPC-007` | Dirty-state or policy mismatch rejected |
| `VPC-008` | Quota rejection recorded |
| `VPC-009` | Corrupted entry rejected |
| `VPC-010` | GC removal recorded |

## Closeout Rules

Beads closeout may reuse a cached proof only when the decision is `hit`, the
reason code is `VPC_HIT_FRESH`, `required_action` is `reuse_receipt`, the entry
is fresh, every digest verifies, and the referenced receipt path is present. All
other decisions require validation work, cache repair, or explicit blocker
reporting.

## Artifacts

| Artifact | Path |
|----------|------|
| Spec | `docs/specs/validation_proof_cache.md` |
| Schema catalog | `artifacts/validation_broker/proof_cache/validation_proof_cache_contract.schema.json` |
| Fixtures | `artifacts/validation_broker/proof_cache/validation_proof_cache_fixtures.v1.json` |
| Gate script | `scripts/check_validation_proof_cache_contract.py` |
| Gate tests | `tests/test_check_validation_proof_cache_contract.py` |
