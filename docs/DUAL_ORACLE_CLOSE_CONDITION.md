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
      "schema_version": "franken-node/l1-proof-carrying-effects/v1",
      "required_subjects": ["fs.read", "fs.write", "http.request"],
      "verified_subjects": ["fs.read", "fs.write", "http.request"],
      "effect_receipts_verified": 3,
      "invalid_receipts": 0,
      "receipt_chain_verified": true
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
  "schema_version": "franken-node/l1-proof-carrying-effects/v1",
  "required_subjects": ["fs.read", "fs.write", "http.request"],
  "verified_subjects": ["fs.read", "fs.write", "http.request"],
  "effect_receipts_verified": 3,
  "invalid_receipts": 0,
  "receipt_chain_verified": true
}
```

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
