# bd-15t: Category-Shift Reporting Pipeline

**Section:** 10.9 | **Verdict:** PASS | **Date:** 2026-02-21

## Metrics

| Category | Pass | Total |
|----------|------|-------|
| Python verification checks | 105 | 105 |
| Rust unit tests | 34 | 34 |
| Simulation checks | 10 | 10 |
| Report fixture checks | 20 | 20 |

## Implementation

**File:** `crates/franken-node/src/supply_chain/category_shift.rs`

### Core Types (12 structs, 6 enums)
- `CategoryShiftReport` — top-level report with version, timestamp, claims, manifest
- `ReportClaim` / `ClaimInput` — individual claim with evidence reference and reproduce script
- `ShiftEvidence` / `EvidenceInput` — artifact reference with SHA-256 hash and freshness
- `ReportingPipeline` — stateful pipeline that ingests dimensions and generates reports
- `DimensionData` — per-dimension aggregated measurement data
- `ThresholdResult` / `ThresholdStatus` — threshold evaluation (met/exceeded/not_met)
- `MoonshotBetEntry` / `BetStatus` — initiative tracking (on_track/completed/blocked/cancelled)
- `ManifestEntry` — artifact manifest entry with hash and freshness
- `ReportDiffEntry` — historical trend comparison between report periods
- `PipelineEvent` — structured audit event
- `PipelineConfig` — configurable freshness window and schedule

### Key API Methods
- `start()` — initialize pipeline, emit CSR_PIPELINE_STARTED
- `ingest_dimension()` — collect data for a report dimension
- `register_bet()` — register moonshot initiative status
- `generate_report()` — produce full report with claim verification
- `render_markdown()` / `render_json()` — dual output formats
- `diff_reports()` — historical trending across report periods
- `sha256_hex()` — artifact integrity hashing
- `demo_pipeline()` — end-to-end demonstration
- `scripts/check_category_shift_reports.py` — fixture-level report verifier

### Category-Defining Thresholds
| Threshold | Target | Description |
|-----------|--------|-------------|
| THRESHOLD_COMPAT_PERCENT | >= 95% | Node.js API compatibility |
| THRESHOLD_MIGRATION_VELOCITY | >= 3x | Migration speed vs manual |
| THRESHOLD_COMPROMISE_REDUCTION | >= 10x | Attack surface reduction |

### Event Codes (4)
- CSR_PIPELINE_STARTED, CSR_DIMENSION_COLLECTED, CSR_CLAIM_VERIFIED, CSR_REPORT_GENERATED

### Invariants (4)
- **INV-CSR-CLAIM-VALID**: Every claim references a valid, fresh artifact
- **INV-CSR-MANIFEST**: Report includes manifest of all referenced artifacts
- **INV-CSR-REPRODUCE**: Reproduce scripts verify artifact integrity
- **INV-CSR-IDEMPOTENT**: Same input produces identical output

## Verification Commands

```bash
python3 scripts/check_category_shift.py --json    # 105/105 PASS
python3 scripts/check_category_shift_reports.py --json    # report fixture PASS
python3 -m pytest tests/test_check_category_shift.py  # Python unit tests
python3 -m pytest tests/test_check_category_shift_reports.py  # report checker unit tests
python3 -m json.tool artifacts/section_10_9/bd-15t/report_fixture_check.json
```

## Report Fixtures

- `fixtures/category-shift/manifest.json`
- `fixtures/category-shift/category_shift_report.json`
- `fixtures/category-shift/category_shift_report.md`
- `artifacts/section_10_9/bd-15t/report_fixture_check.json`

The fixture manifest records `scripts/check_category_shift_reports.py` as the expected report verifier entrypoint and lists both machine-readable and human-readable category-shift report fixtures.
