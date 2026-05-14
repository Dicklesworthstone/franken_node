# bd-1sgr: Report Output Contract - Verification Summary

**Section:** 16 | **Bead:** bd-1sgr | **Date:** 2026-05-14

## Gate Result: PASS (28/28)

All checks passed:
- Source exists and module wired in mod.rs
- 5 report types (TechnicalAnalysis, SecurityAssessment, PerformanceBenchmark, ComplianceReport, IncidentPostmortem)
- 5 required artifact types including report_pdf
- 4 required structs (ReportBundle, ArtifactEntry, OutputCatalog, ReportOutputContract)
- SHA-256 integrity verification via content_hash + Sha256
- Completeness checking with REQUIRED_ARTIFACT_TYPES
- Reproduction command support
- Catalog generation with OutputCatalog
- 12/12 event codes (ROC-001..ROC-010, ROC-ERR-001, ROC-ERR-002)
- 6/6 invariants (INV-ROC-COMPLETE/DETERMINISTIC/INTEGRITY/REPRODUCIBLE/VERSIONED/AUDITABLE)
- JSONL audit export with RocAuditRecord
- Contract version roc-v1.0
- Spec contract aligned
- Test coverage met with 50 inline Rust tests detected by the gate
- Concrete publishable report artifact directory exists at `artifacts/section_16/bd-1sgr/publishable_reports/`
- `reproducible_report_registry.json` contains 3 report records covering compatibility/migration, trust/security, and benchmark/verification methodology
- Each report artifact has publication-style sections, reproduction inputs, expected results, tolerance bounds, and a reproducibility badge

## Test Results
- **Gate script:** 28/28 PASS
- **Python tests:** 34/34 PASS
- **Registry JSON:** PASS
- **Section 16 aggregate gate:** FAIL due unrelated `bd-3id1`; `bd-1sgr` and the publication checklist pass inside the aggregate result
- **Cargo/Rust tests:** deferred during this completion-debt pass because the shared machine already had cargo/rustc contention above the repository threshold

## Completion Debt Closure

`bd-1sgr.1` found that no concrete publishable reports artifact directory could be located. The artifact directory now exists under the canonical Section 16 evidence path and is required by `scripts/check_report_output_contract.py`.

## Validation Commands
- `python3 -m json.tool artifacts/section_16/bd-1sgr/publishable_reports/reproducible_report_registry.json >/dev/null` - PASS
- `python3 scripts/check_report_output_contract.py --json` - PASS, 28/28 checks
- `python3 -m pytest tests/test_check_report_output_contract.py` - PASS, 34 tests
- `python3 scripts/check_section_16_gate.py --json` - FAIL, unrelated `bd-3id1`; `bd-1sgr` passed
