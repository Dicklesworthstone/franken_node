# bd-39ga — BehavioralGenome Schema and Version-Lineage Contract

## Verdict

PASS

## Concrete Implementation

The BehavioralGenome feature-vector schema and version-lineage extraction
contract are implemented in
`crates/franken-node/src/security/bpet/phenotype_extractor.rs` and exported by
`crates/franken-node/src/security/bpet/mod.rs:15`.

Key schema and extraction symbols are present at concrete source locations:

| Symbol | Evidence |
| --- | --- |
| `PHENOTYPE_EXTRACTOR_SCHEMA_VERSION` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:17` |
| `GENOME_DIMENSIONS` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:39` |
| `PhenotypeExtractionError` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:50` |
| `EvidenceSource` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:68` |
| `UncertaintyCode` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:77` |
| `ExtractedFeature` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:118` |
| `ProvenanceRecord` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:152` |
| `PhenotypeExtractionEvent` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:160` |
| `VersionEvidence` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:202` |
| `PhenotypeFeatureVector` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:212` |
| `PhenotypeExtractor` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:246` |
| `extract_version` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:276` |
| `extract_batch` | `crates/franken-node/src/security/bpet/phenotype_extractor.rs:403` |

## Invariants Covered

- Seven canonical genome dimensions are defined once in `GENOME_DIMENSIONS`.
- Every vector carries `PHENOTYPE_EXTRACTOR_SCHEMA_VERSION`.
- Missing evidence is represented as typed uncertainty, not silent zeroes.
- Per-feature provenance and extraction events provide the audit trail.
- Batch extraction is deterministic by package/version ordering and fails
  closed on empty, oversized, or duplicate version batches.
- The conformance harness is wired as the `bpet_feature_extraction` Cargo test
  target in `crates/franken-node/Cargo.toml:984`.

## Verification

- `python3 scripts/check_section_10_21_gate.py --json` reports section verdict
  PASS with 65/65 checks.
- `tests/conformance/bpet_feature_extraction.rs` exercises deterministic full
  extraction, typed uncertainty, version batch ordering/rejection, and JSONL
  sample replay at lines `127`, `191`, `265`, and `303`.
- The focused Cargo conformance test was not launched in this pass because
  `pgrep -af 'cargo|rustc' | wc -l` returned `9`, above the repo's contention
  threshold for starting heavy builds.
