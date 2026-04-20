# franken_node cod_3 review

Date: 2026-04-20
Reviewer: FoggyGlacier

## Scope

Reviewed pane 4 / `cod_3` changes in the observability, ops, and doctor surface, with emphasis on:

- `ce916c44` — `doctor --structured-logs-jsonl`
- `8dba9656` / `44aecaee` — doctor logs tests
- `b58ce5b3` — bench run determinism
- `6fa6ab6b` — oracle close-condition receipt
- `81619a07` — convergence wait loop
- `79e1b710` — signed convergence receipts

Requested path log command was run:

```console
git log 9707c9e1..HEAD --oneline --no-merges -- crates/franken-node/src/observability crates/franken-node/src/ops crates/franken-node/src/main.rs crates/franken-node/tests/doctor_*
```

No cargo commands were run. This was source review only.

## Summary

- Critical findings: 0
- High findings attributed to `cod_3`: 2
- High findings outside the target commit range but found in requested `fleet_transport` TOCTOU review: 1
- Style/nit findings: omitted by request

## High Findings

### H1 — Oracle close-condition receipt is hash-only, not authenticated

- Severity: High
- Commit: `6fa6ab6b`
- Bead: `bd-31ksq`
- Locations:
  - `crates/franken-node/src/ops/close_condition.rs:133`
  - `crates/franken-node/src/ops/close_condition.rs:134`
  - `crates/franken-node/src/ops/close_condition.rs:138`
  - `crates/franken-node/src/ops/close_condition.rs:144`
  - `crates/franken-node/tests/doctor_close_condition_e2e.rs:167`

`generate_close_condition_receipt` canonicalizes the receipt core, computes `SHA-256`, and stores that digest as `tamper_evidence` in the same JSON artifact. The test constructs an `unsigned_receipt` by removing `tamper_evidence` and verifies the digest over the remaining JSON, which confirms the receipt is hash-only.

That does not provide tamper evidence against any actor who can write the artifact. Such an actor can edit the receipt body, recompute the digest, and leave a self-consistent receipt with no trusted key, no signature, and no verifier rejection path. Because this receipt represents the oracle close condition for release policy linkage, the artifact can be forged after generation.

Recommended fix:

- Sign the canonical close-condition receipt core with configured/trusted signing material.
- Include key id, signature, algorithm, canonicalization, and payload hash in the receipt.
- Add a verification path/gate that rejects unsigned, hash-only, untrusted-key, mismatched-key-id, and payload-tampered receipts.
- Fail closed when release/oracle receipt signing material is unavailable.

### H2 — Fleet convergence receipts self-attest with a mutable local fallback key

- Severity: High
- Commit: `79e1b710`
- Bead: `bd-2nm23`
- Locations:
  - `crates/franken-node/src/main.rs:4750`
  - `crates/franken-node/src/main.rs:4752`
  - `crates/franken-node/src/main.rs:4790`
  - `crates/franken-node/src/main.rs:4795`
  - `crates/franken-node/src/main.rs:18183`
  - `crates/franken-node/src/control_plane/fleet_transport.rs:43`
  - `crates/franken-node/src/control_plane/fleet_transport.rs:76`
  - `crates/franken-node/src/control_plane/fleet_transport.rs:86`

`fleet reconcile` now signs convergence receipts, but `load_fleet_signing_material` silently falls back to creating and using `fleet-signing.ed25519` under the fleet state directory when configured receipt signing material is absent. The receipt then includes its own public key and key id in `FleetConvergenceReceiptSignature`.

This makes the production-looking signed receipt self-attesting. A writer who controls `.franken-node/state/fleet` or the configured fleet state directory can replace the fallback key and emit a tampered convergence receipt signed by an attacker-controlled key. There is no trust anchor or verifier path that pins the public key/key id to operator-configured signing material.

Recommended fix:

- Require configured or keyring-pinned signing material for trusted convergence receipts.
- Treat state-directory fallback keys as local-dev only, or fail closed when trusted material is absent.
- Add verifier coverage that rejects replaced local keys, untrusted keys, mismatched key ids, payload tampering, and self-attested receipts.
- Keep the key source explicit in receipt metadata without letting mutable state-dir material become a trust anchor.

## Out-of-range High Observation

### H3 — `FileFleetTransport` action-log compaction can lose concurrent writes

- Severity: High
- Scope note: pre-existing/out-of-range for `cod_3`; included because the review request explicitly called out TOCTOU gaps around the `fleet_transport` file.
- Bead: `bd-c830o`
- Locations:
  - `crates/franken-node/src/control_plane/fleet_transport.rs:652`
  - `crates/franken-node/src/control_plane/fleet_transport.rs:653`
  - `crates/franken-node/src/control_plane/fleet_transport.rs:707`
  - `crates/franken-node/src/control_plane/fleet_transport.rs:844`
  - `crates/franken-node/src/control_plane/fleet_transport.rs:845`

`compact_action_log_if_needed` opens `actions.jsonl`, locks that opened file handle, writes a compacted temp file, then renames the temp file over `actions.jsonl`. `publish_action` also opens `actions.jsonl` before locking the opened file handle.

Because the lock is on the opened data-file inode, compaction can replace the path with a new inode while a writer is still holding or waiting on a handle to the old inode. A writer that opened `actions.jsonl` before the rename and obtains the lock after compaction can append to the old unlinked inode, losing the action. Writers opening after the rename lock a different inode, so compaction and appends are not serialized by one stable lock.

Recommended fix:

- Use a stable sidecar lock file for all action-log reads used by compaction, appends, and rename promotion.
- Acquire the sidecar lock before opening `actions.jsonl`.
- Hold it through temp-file write, sync, rename, and parent-directory sync.
- Add a concurrency regression that proves a writer opened before compaction promotion cannot lose an action.

## Reviewed Without High/Critical Findings

- `ce916c44`: `doctor --structured-logs-jsonl` returns serialization errors before emitting partial output; no high-impact missing error path found.
- `8dba9656` / `44aecaee`: structured doctor log tests cover success, missing fixture, and strict-profile failure behavior; no high-impact gap found in the test additions.
- `b58ce5b3`: bench run determinism test addition did not introduce a reviewed high/critical issue in the targeted path.
- `81619a07`: convergence wait loop uses saturating/checked conversions for elapsed milliseconds and progress reporting; no truncation-unsafe cast found.
- Timing checks: no receipt signature verification path was added for convergence receipts, so the actionable issue is missing trust anchoring rather than a constant-time verifier comparison. The local keypair parse equality check in `parse_signing_key_from_blob` is not a receipt verification path and was not classified high/critical.
