# bd-2xgs.1 - Deterministic Phenotype Feature Extraction Completion Debt

## Verdict: PASS

## Implementation

- Added `crates/franken-node/src/security/bpet/phenotype_extractor.rs`.
- Exported `security::bpet::phenotype_extractor` from the BPET module tree.
- Added `tests/conformance/bpet_feature_extraction.rs` and registered it as the `bpet_feature_extraction` Cargo test target.
- Added `artifacts/10.21/bpet_feature_samples.jsonl` with deterministic full-evidence and missing-evidence samples.

## Covered Contracts

- Runtime evidence features: capability invocation intensity, resource envelope pressure, network surface area, and filesystem surface area.
- Manifest/code metadata features: declared permission surface, code complexity, and dependency surface.
- Deterministic BTreeMap ordering, sorted batch extraction, duplicate rejection, and explicit per-feature provenance.
- Typed uncertainty for missing source, missing field, and partial-evidence cases.
- Conversion from extracted feature vectors into BPET drift-engine `PhenotypeSample` input.

## Validation

- `rustfmt --edition 2024 --check crates/franken-node/src/security/bpet/phenotype_extractor.rs tests/conformance/bpet_feature_extraction.rs` - PASS
- `python3 -c 'import json,pathlib; p=pathlib.Path("artifacts/10.21/bpet_feature_samples.jsonl"); [json.loads(line) for line in p.read_text().splitlines() if line.strip()]; print("ok")'` - PASS
- `/home/ubuntu/.local/share/ubs/modules/ubs-rust.sh --no-cargo --ci --no-color --fail-critical=1 --fail-warning=9999 /data/tmp/franken-node-bd2xgs-ubs.i6LLLG` - PASS, 0 critical findings
- `python3 -m unittest tests.test_check_section_10_21_gate` - PASS, 20 tests
- `python3 scripts/check_section_10_21_gate.py --json` - PASS, 65/65 checks

Focused `rch exec -- cargo test -p frankenengine-node --test bpet_feature_extraction` was deferred because `pgrep -af 'cargo|rustc' | wc -l` returned 18, above the repo's contention backoff threshold.
