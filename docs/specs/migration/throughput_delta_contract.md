# Throughput Delta Contract: Live >=3x Migration Velocity Gate

Supersedes, for claim measurement, the constructed cohort contract in
`docs/specs/section_13/bd-3agp_contract.md` (its `artifacts/13/`
`cohort-*-001` archetype rows are fictional and must never be cited as
evidence). This contract is the CLAIM-002 evidence surface
(bd-reality-20260820-w0fc6.2).

## Goal

Enforce the charter's migration-velocity metric (PRODUCT_CHARTER §5,
">= 3x migration throughput/confidence vs. baseline patterns") as a LIVE
measurement: real `franken-node migrate audit/rewrite/validate` invocations
against a frozen cohort of checked-in app fixtures, compared wall-clock for
wall-clock against a documented manual-baseline reference procedure.

## Artifacts

- `artifacts/migration/throughput_delta.json` — signed summary (schema
  `franken-node/migration-throughput/v1`).
- `artifacts/migration/throughput_delta_evidence.json` — measurement census
  (schema `franken-node/migration-throughput-evidence/v1`).
- Producer: `scripts/emit_migration_throughput_delta.py`.
- Independent verifiers: `scripts/check_migration_velocity_gate.py` (Python)
  and `sdk/verifier/src/migration_throughput.rs` +
  `sdk/verifier/tests/migration_throughput_recompute.rs` (Rust SDK).

## Quantified Invariants

- `INV-MTP-RATIO`: The pooled velocity ratio is
  `velocity_ratio_bp >= required_velocity_ratio_bp = 30000`, where
  `velocity_ratio_bp = round(median(baseline_ms) * 10000 / median(tooled_ms))`
  over every recorded run of the cohort plus holdout.
- `INV-MTP-SIGNED`: The summary carries an Ed25519 signature over the
  canonical unsigned payload under the pinned throughput harness key; floats
  are forbidden anywhere in either artifact.
- `INV-MTP-CENSUS`: Every declared median/ratio — per fixture and pooled —
  is a faithful integer function of the recorded runs; the corpus digest
  commits to exactly the census presented.
- `INV-MTP-BOOTSTRAP`: A deterministic splitmix64-seeded percentile bootstrap
  (fixed resample count and seed in the signed payload) yields CI95 bounds;
  verifiers recompute them exactly from the census.
- `INV-MTP-FROZEN`: Every fixture input file's sha256 recorded at measurement
  time must still match the committed tree when the gate verifies; any drift
  fails closed until re-measured.
- `INV-MTP-HOLDOUT`: Exactly one fixture has role `holdout`; it has never
  been referenced by golden tests or rewrite-rule tuning, and its ratio is
  separately reported (`holdout_ratio_bp`).
- `INV-MTP-BASELINE-PROTOCOL`: Baseline minutes are never invented. The
  baseline is the checked-in reference procedure
  (`scripts/migration_baseline/baseline_{audit,rewrite,validate}.cjs`) doing
  the same three duties as the tooled pipeline on identical fresh fixture
  copies, timed identically (warmup excluded, N measured runs each).
- `INV-MTP-NO-CONSTRUCTED`: No constructed Feb 2026 archetype ID
  (`cohort-*-001`) may appear in the cohort.

## Fixture Cohort

Frozen checked-in apps under `crates/franken-node/tests/fixtures/migrate/`:
`rewrite-shell-commonjs`, `hardened`, `risky` (adversarial: the validator is
expected to reject it), and `holdout-worker-service` (holdout). Adding or
changing fixtures requires re-measurement and updating the SDK conformance
test's pinned fixture contract.

## Known Limits (disclosed, not hidden)

- The cohort exercises the static migration tier of small real apps; the
  ratio characterizes that tier, not large-repository migrations.
- The baseline is a scripted competent-operator codemod (regex/walk class),
  not a stopwatch study of human operators; it removes invented minute rows,
  not human variance.
