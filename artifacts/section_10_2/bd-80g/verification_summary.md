# bd-80g: Reference Capture Programs & Fixture Corpora — Verification Summary

## Bead
- **ID**: bd-80g
- **Section**: 10.2
- **Title**: Build prioritized Node/Bun reference capture programs and fixture corpora per API band

## Artifacts Created

### Reference Capture Programs
- `scripts/captures/capture_fs.js` — fs API family capture (readFile, writeFile)
- `scripts/captures/capture_path.js` — path API family capture (join, resolve, parse, dirname, basename, extname)
- `scripts/captures/capture_process.js` — process API family capture (env, argv, cwd, pid, version)

### Fixture Corpus (27 total fixtures)
- **Core band** (18 fixtures): fs (7), path (7), process (4)
- **High-value band** (6 fixtures): http (3), crypto (3)
- **Edge band** (3 fixtures): fs (1), path (1), process (1)

### Directory Structure
```
docs/fixtures/
├── core/fs/         (7 fixtures)
├── core/path/       (7 fixtures)
├── core/process/    (4 fixtures)
├── high_value/http/ (3 fixtures)
├── high_value/crypto/ (3 fixtures)
├── edge/            (3 fixtures)
└── minimized/       (reserved)
```

### Support Artifacts
- `docs/specs/section_10_2/bd-80g_contract.md`
- `scripts/check_fixture_corpus.py`
- `tests/test_check_fixture_corpus.py`
- `artifacts/section_10_2/bd-80g/check_report.json`
- `artifacts/section_10_2/bd-80g/unit_tests.txt`
- `artifacts/section_10_2/bd-80g/capture_program_matrix.json`
- `artifacts/section_10_2/bd-80g/artifact_inventory.json`

## Verification Results
- **CORPUS-STRUCTURE**: PASS — All band directories exist
- **CORPUS-CAPTURES**: PASS — 3 capture programs found
- **CORPUS-VALID**: PASS — 27/27 fixtures valid
- **CORPUS-UNIQUE**: PASS — No duplicate IDs
- **CORPUS-COVERAGE**: PASS — Core: 3 families, high-value: 2 families, edge: 3 families
- **CORPUS-REGISTRY**: PASS — All 5 registry entries covered

## Test Results
- 15 unit tests: all passed
- 6 verification checks: all passed
- Section 10.2 gate now requires the bd-80g check report, unit-test transcript,
  capture-program matrix, and artifact inventory so the capture-program evidence
  set cannot silently regress to four thin artifacts.

## Verdict: PASS
