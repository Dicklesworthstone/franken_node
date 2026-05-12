# bd-15t: Category-Shift Reporting Pipeline with Reproducible Evidence Bundles

## Scope

Automated pipeline that generates category-shift evidence reports proving
franken_node changes what is possible in the runtime security space. Every claim
is backed by a reproducible artifact with integrity hash. The pipeline aggregates
data from benchmarks, adversarial campaigns, migration demos, trust economics,
and verifier attestation sources into structured reports in JSON and Markdown
formats.

## Report Dimensions

The report covers five mandatory dimensions:

| # | Dimension | Source System | Key Metrics |
|---|-----------|---------------|-------------|
| 1 | Benchmark Comparisons | bd-f5d benchmark infrastructure | Throughput delta, latency percentiles, unique capabilities (replay, containment) |
| 2 | Security Posture | bd-9is adversarial campaigns | Attack categories neutralized, defense coverage, attacker-cost amplification |
| 3 | Migration Velocity | bd-1e0 migration demos | Success rate, time-to-migrate, complexity reduction factor |
| 4 | Adoption Trends | bd-m8p verifier portal | Verifier registrations, attestation volume, community engagement |
| 5 | Economic Impact | bd-10c trust economics | Cost-benefit ratio, attacker-ROI delta, insurance-premium reduction |

## Category-Defining Thresholds (Section 3)

Per Section 3 of the charter, a valid category-shift report MUST score against
these three hard thresholds:

| Threshold | Target | Measurement Method |
|-----------|--------|-------------------|
| Compatibility | >= 95% Node.js API compatibility | Automated compatibility test suite pass rate |
| Migration velocity | >= 3x faster than manual migration | Median migration time vs. manual baseline |
| Compromise reduction | >= 10x reduction in compromise surface | Attack surface area ratio (before/after containment) |

## Moonshot Bet Status

Per Section 9F, each report includes a "bet status" section for every moonshot
initiative showing:

- **Progress**: percent complete with evidence references
- **Blockers**: enumerated, with projected resolution dates
- **Timeline**: projected vs. original timeline with variance

## Reproducibility Requirements

### Claim Verification (INV-CSR-CLAIM-VALID)

Before including a claim, the pipeline verifies:
1. The underlying artifact exists and passes integrity check (SHA-256).
2. The claim accurately represents the artifact data (no cherry-picking).
3. The artifact was produced within the configured freshness window (default: 30 days).

### Artifact Manifest (INV-CSR-MANIFEST)

Every report includes a manifest listing all referenced artifacts with:
- File path (relative to project root)
- SHA-256 hash
- Generation timestamp
- Freshness status (fresh / stale / missing)

### Reproduce-This-Claim Scripts (INV-CSR-REPRODUCE)

For each claim, a reproduce script is generated that:
- Fetches or regenerates the source artifact
- Validates the claim against the regenerated data
- Exits 0 on confirmation, non-zero on divergence

## Output Formats

| Format | File | Purpose |
|--------|------|---------|
| JSON | `category_shift_report.json` | Machine-readable, programmatic consumption |
| Markdown | `category_shift_report.md` | Human-readable publication |
| Dashboard | Summary view embedded in Markdown | Quick status overview |

All formats share consistent claim identifiers (CSR-CLAIM-NNN).

## Historical Trending

The pipeline maintains a history of reports and can show:
- Improving / declining metrics across report periods
- New capabilities demonstrated since last report
- Coverage gaps closed or opened
- Trend direction for each threshold metric

## Idempotency (INV-CSR-IDEMPOTENT)

Running the pipeline twice with identical input data produces byte-identical
reports. This is enforced by:
- Deterministic iteration order (BTreeMap)
- Canonical JSON serialization (sorted keys, no trailing whitespace)
- Fixed timestamp injection (not wall-clock dependent)

## Versioning and Diffing

Each pipeline run produces a versioned report. A diff tool highlights changes
from the previous version including:
- New/removed claims
- Metric value changes with direction indicators
- Threshold status changes (pass/fail transitions)

## Event Codes

| Code | Meaning |
|------|---------|
| CSR_PIPELINE_STARTED | Pipeline execution began |
| CSR_DIMENSION_COLLECTED | A report dimension was successfully aggregated |
| CSR_CLAIM_VERIFIED | A claim passed verification |
| CSR_REPORT_GENERATED | Final report was generated |

## Error Codes

| Code | Meaning |
|------|---------|
| ERR_CSR_SOURCE_UNAVAILABLE | A data source system could not be reached |
| ERR_CSR_CLAIM_STALE | Artifact exceeds freshness window |
| ERR_CSR_CLAIM_INVALID | Claim does not accurately represent artifact data |
| ERR_CSR_HASH_MISMATCH | Artifact integrity hash does not match |

## Invariants

| ID | Invariant |
|----|-----------|
| INV-CSR-CLAIM-VALID | Every claim references a verified, fresh artifact |
| INV-CSR-MANIFEST | Report manifest lists all artifacts with hashes |
| INV-CSR-REPRODUCE | Each claim has a reproducibility script |
| INV-CSR-IDEMPOTENT | Same inputs produce identical outputs |

## Acceptance Criteria

1. Pipeline aggregates data from at least four source systems (benchmarks,
   adversarial campaigns, migration demos, trust economics or verifier portal).
2. All five report dimensions are populated with measurement data.
3. Every claim references a specific artifact with integrity hash; verification
   confirms all references are valid.
4. Reproduce-this-claim scripts are generated and successfully reproduce data.
5. Claim verification rejects stale artifacts (older than freshness window) and
   inaccurate representations.
6. Reports are generated in at least two formats (JSON and Markdown) with
   consistent claim identifiers across formats.
7. Historical trending shows metric changes across at least two report periods.
8. The pipeline is idempotent: running it twice with same input produces
   identical reports.
9. Report scores against the three category-defining thresholds (>= 95% compat,
   >= 3x migration velocity, >= 10x compromise reduction).
10. Report includes a bet-status section for each moonshot initiative.

## Logging Requirements

- Pipeline execution logged at INFO with per-dimension timing.
- Claim verification failures logged at WARN with claim ID and reason.
- Data source unavailability logged at ERROR with source name and fallback status.
- All log entries include trace correlation IDs.

## Artifacts

- `docs/specs/section_10_9/bd-15t_contract.md` -- this specification
- `docs/policy/category_shift_reporting.md` -- reporting policy
- `crates/franken-node/src/supply_chain/category_shift.rs` -- Rust implementation
- `scripts/check_category_shift.py` -- verification script
- `scripts/check_category_shift_reports.py` -- report fixture verification entrypoint
- `tests/test_check_category_shift.py` -- unit tests
- `fixtures/category-shift/manifest.json` -- fixture inventory
- `fixtures/category-shift/category_shift_report.json` -- machine-readable report fixture
- `fixtures/category-shift/category_shift_report.md` -- human-readable report fixture
- `artifacts/section_10_9/bd-15t/report_fixture_check.json` -- report fixture verification output
- `artifacts/section_10_9/bd-15t/verification_evidence.json`
- `artifacts/section_10_9/bd-15t/verification_summary.md`

## Dependencies

- bd-f5d: Benchmark infrastructure (benchmark comparison data)
- bd-9is: Adversarial campaign runner (security posture data)
- bd-1e0: Migration demo pipeline (migration velocity data)
- bd-m8p: Verifier portal (adoption trend data)
- bd-10c: Trust economics dashboard (economic impact data)
