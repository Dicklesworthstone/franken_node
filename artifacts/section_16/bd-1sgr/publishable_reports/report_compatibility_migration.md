# Reproducible Compatibility and Migration Evidence for Franken Node

## Abstract

This report summarizes the compatibility and migration evidence used by the Section 16 publication gate. The claim under review is that Franken Node can publish reproducible technical evidence for migration and compatibility workflows using checked-in data and gate scripts.

## Introduction

Runtime migration claims are useful only when downstream operators can replay the evidence. This report packages the compatibility and migration portion of the Section 16 evidence into a publication-ready form with a fixed registry entry, source artifacts, and a reproduction command.

## Related Work

The report aligns with reproducible systems-paper practice: all evidence references are versioned in the repository, validation logic is executable, and the expected result is explicit. It also follows the local report output contract in `crates/franken-node/src/tools/report_output_contract.rs`.

## Methodology

Reproduction starts from the repository root. Run `python3 scripts/check_section_16_gate.py --json` and compare the publication checklist result with the registry entry `report-compat-migration-2026-05`. The source data are `artifacts/section_16/bd-2ad0/verification_evidence.json` and `artifacts/section_16/bd-unkm/verification_evidence.json`.

## Results

The expected result is a Section 16 `PASS` verdict with four publication checklist rows passing. The registry tolerance for publication checklist and dataset count drift is zero percent because these are discrete gate outcomes.

## Discussion

The report intentionally treats the gate output as the reproducibility boundary. Any future change to dataset counts, checklist targets, or migration evidence must update both the source evidence and this report registry.

## Conclusion

The compatibility and migration report is reproducible from checked-in scripts and artifacts, with explicit expected results and tolerance bounds.

## References

- `scripts/check_section_16_gate.py`
- `scripts/check_reproducible_datasets.py`
- `artifacts/section_16/bd-2ad0/verification_evidence.json`
- `artifacts/section_16/bd-unkm/verification_evidence.json`
