# Dual-Oracle Completion Close Condition

## Purpose

This gate enforces the completion close condition for the franken_node platform: the program is only considered complete when all three oracle dimensions are green. No partial success is accepted.

## Oracle Dimensions

| Dimension | Owner Track | Description | Artifact |
|-----------|------------|-------------|----------|
| L1 Product Oracle | 10.2 | Spec-first compatibility oracle validates product-level semantics against Node/Bun behavior and requires proof-carrying host-effect evidence for first-tranche effects | `artifacts/oracle/l1_product_verdict.json` |
| L2 Engine-Boundary Oracle | 10.17 | Engine-boundary oracle validates that franken_engine integration points conform to spec | `artifacts/oracle/l2_engine_verdict.json` |
| Release Policy Linkage | 10.2 | Policy linkage validates that release gates consume both L1 and L2 verdicts and enforce pass-through | `artifacts/oracle/release_policy_verdict.json` |

## Gate Logic

```
PASS if and only if:
  L1.verdict == "GREEN"
  AND L2.verdict == "GREEN"
  AND release_policy.verdict == "GREEN"
  AND all three artifacts exist and are well-formed
  AND the L1 compatibility result contains verified proof-carrying
      EffectReceipt evidence for fs.read, fs.write, and http.request

FAIL if:
  any dimension is missing, malformed, RED, or YELLOW
```

## Acceptance Invariant

The L1 Product Oracle is **defined** by the acceptance invariant
(`INV-PCG-ACCEPTANCE`, bd-f5b04.2.4):

> No canonical operation is "done" until it is **both**
> lockstep/parity-GREEN **and** proof-carrying (a verifiable
> `EffectReceipt` for the operation's L1 subject).

The invariant rules out the two failure shapes by construction:

| Shape | Example | Outcome |
|---|---|---|
| Parity-GREEN-but-unproven | Compatibility corpus passes, but `proof_carrying_effects` evidence is missing, partial, invalid, or chain-unverified | L1 = RED (fail closed) |
| Proven-but-parity-RED | Effect receipts verify, but the corpus pass rate is below threshold or has errored cases | L1 = RED (fail closed) |

Both legs feed the same `blocking_findings` list in the L1 evaluator, so a
single failing condition on either leg makes the dimension RED and therefore
the composite verdict FAIL. There is no partial credit and no waiver.

### Canonical subject list

The per-operation acceptance subjects are owned by
`crates/franken-node/src/schema_versions.rs`
(`L1_PROOF_CARRYING_ACCEPTANCE_SUBJECTS`): `fs.read`, `fs.write`,
`http.request`. The list is bound at three points so it cannot drift:

- **Contract layer**: `api::compat_gate::l1_proof_carrying_acceptance_subjects()`
  derives the same list from `FIRST_TRANCHE_OPERATION_CONTRACTS`
  (`CompatOperationId::l1_proof_carrying_subject`); conformance tests fail if
  the derivation and the canonical constant diverge. Operations without a
  first-tranche host effect (`process.env`, `module.resolve`) carry no
  subject and are accepted on parity alone.
- **Gate**: `ops::close_condition` enforces the list fail-closed
  (`evaluate_l1_product_oracle` + `validate_l1_proof_carrying_effects`).
- **CI mirror**: `scripts/check_oracle_close_condition.py`
  (`REQUIRED_L1_PROOF_SUBJECTS`) applies the same list to the committed
  verdict artifacts in `.github/workflows/execution-normalization-gate.yml`.

### Enforcement and observability

`franken-node doctor close-condition` evaluates the invariant and emits the
stable `FN-ACCEPT-*` event stream under `--structured-logs-jsonl`:
`FN-ACCEPT-001` (evaluated), then exactly one of `FN-ACCEPT-002` (PASS) or
`FN-ACCEPT-003` (FAIL-CLOSED), plus one `FN-ACCEPT-004` line per blocking
finding. SIEM filters should pin on these codes, not message text.

### Current evidence contract and tracked hardening

Only the **v2** `proof_carrying_effects` schema is accepted:

- **v1** (`franken-node/l1-proof-carrying-effects/v1`) — RETIRED
  (bd-qr5i2.4). The legacy *declared* summary carried no receipts the gate
  could re-derive, so its acceptance is withdrawn in both the Rust doctor
  gate and the Python CI gate; a v1 block now fails closed with an
  unsupported-schema finding. The schema id stays registered in
  `schema_versions.rs` (the registry is append-only) for historical
  artifacts.
- **v2** (`franken-node/l1-proof-carrying-effects/v2`) — adds mandatory
  `receipt_chain_entries` (serialized `EffectReceiptChainEntry` array). The
  gate **re-derives** the evidence natively: chain integrity
  (`EffectReceiptChain::verify_entries_integrity`), per-receipt validity,
  subjects (via `EffectKind::l1_acceptance_subject`, counting only `allowed`
  receipts), and counts. Any mismatch between the declared summary fields
  and the re-derived values is a blocking finding, and the acceptance
  requirements are evaluated over the derived values only. Denied receipts
  are legitimate chain content but never evidence an executed subject.

v2 evidence is produced from a **real native-engine run** by
`franken-node ops proof-carrying-evidence`
(`ops::proof_carrying_evidence::produce_proof_carrying_effects_evidence`,
bd-qr5i2.2). The producer executes one guest program covering every
acceptance subject (`fs.write` + `fs.read` against the run sandbox,
`http.request` against a loopback sink allowlisted through the standard
`[security.network_policy]` mechanism), harvests the signed
`host_effect_ledger` from the dispatch report, re-verifies it natively with
the same primitives the gate uses, and emits the v2 block whose declared
summary equals the derived values by construction. `--merge-corpus
artifacts/13/compatibility_corpus_results.json` writes the block into the
artifact this gate reads (`--out` writes the block standalone). The producer
fails closed — dispatch failure, fallback runtime, missing ledger, chain or
receipt invalidity, a denied effect, a missing subject, or an egress that
never reached the loopback sink each abort production — and requires the
`engine` feature (no native run, no evidence).

The Python CI gate (`scripts/check_oracle_close_condition.py`) applies the
same v2 re-derivation independently (bd-qr5i2.3): it re-implements the
canonical receipt/chain hash preimages, re-derives chain integrity,
per-receipt validity, subjects, and counts from `receipt_chain_entries`, and
fail-closes on any declared↔derived mismatch — alongside the legacy v1
declared-summary path. A cross-language parity pin (the Rust
`effect_receipt_hash_cross_language_parity_pin_bd_qr5i2_3` test and the
Python `test_parity_pin_hashes` test assert identical deterministic hash
constants) makes preimage drift between the two implementations break CI
immediately. Reference fixtures: `tests/fixtures/oracle_gate/pass_v2/` and
`tests/fixtures/oracle_gate/fail_v2_tampered/`.

Regeneration of the committed artifacts (and v1 retirement) is tracked as
bd-qr5i2.4; unifying the Rust and Python gate inputs and wiring the real
lockstep-oracle verdict into the parity leg is tracked as bd-ry7d1.

## Verdict Artifact Schema

Each oracle dimension produces a verdict artifact:

```json
{
  "dimension": "l1_product | l2_engine_boundary | release_policy_linkage",
  "verdict": "GREEN | YELLOW | RED",
  "owner_track": "10.2 | 10.17",
  "timestamp": "<ISO-8601 UTC>",
  "evidence": {
    "tests_passed": "<int>",
    "tests_failed": "<int>",
    "tests_skipped": "<int>",
    "coverage_pct": "<float>",
    "details_ref": "<path to detailed report>",
    "proof_carrying_effects": {
      "schema_version": "franken-node/l1-proof-carrying-effects/v2",
      "required_subjects": ["fs.read", "fs.write", "http.request"],
      "verified_subjects": ["fs.read", "fs.write", "http.request"],
      "effect_receipts_verified": 3,
      "invalid_receipts": 0,
      "receipt_chain_verified": true,
      "receipt_chain_entries": ["… serialized EffectReceiptChainEntry array — see producer output …"]
    }
  },
  "blocking_findings": []
}
```

The `proof_carrying_effects` evidence object is mandatory for the
`l1_product` verdict artifact and is ignored for non-L1 dimensions.

The Rust `doctor close-condition` L1 evaluator also consumes
`artifacts/13/compatibility_corpus_results.json`. That artifact must include a
`proof_carrying_effects` object with:

```json
{
  "schema_version": "franken-node/l1-proof-carrying-effects/v2",
  "required_subjects": ["fs.read", "fs.write", "http.request"],
  "verified_subjects": ["fs.read", "fs.write", "http.request"],
  "effect_receipts_verified": 3,
  "invalid_receipts": 0,
  "receipt_chain_verified": true,
  "receipt_chain_entries": ["… serialized EffectReceiptChainEntry array — see producer output …"]
}
```

Generate/refresh this block from a real run with
`franken-node ops proof-carrying-evidence --merge-corpus
artifacts/13/compatibility_corpus_results.json`; the declared summary
fields must equal the values re-derived from the embedded entries, which
the producer guarantees by construction.

Parity-only evidence is not enough. A GREEN compatibility pass rate with missing,
partial, invalid, or chain-unverified `proof_carrying_effects` evidence makes the
L1 dimension RED and therefore makes the composite close-condition RED.

## Gate Verdict Schema

The close-condition gate produces:

```json
{
  "gate": "dual_oracle_close_condition",
  "verdict": "PASS | FAIL",
  "timestamp": "<ISO-8601 UTC>",
  "dimensions": {
    "l1_product": { "present": true, "verdict": "GREEN" },
    "l2_engine_boundary": { "present": true, "verdict": "GREEN" },
    "release_policy_linkage": { "present": true, "verdict": "GREEN" }
  },
  "failing_dimensions": []
}
```

## Waiver Policy

No waivers are supported for the dual-oracle close condition. All three dimensions must be GREEN for the program to be considered complete.

## Integration

The gate is invoked:
- Before any release candidate is promoted
- As part of the section-wide verification gate for 10.N
- During the final program completion check (PLAN 10.N → canonical graph)
