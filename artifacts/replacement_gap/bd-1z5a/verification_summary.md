# bd-1z5a Replacement-Gap Evidence Pack

**Section:** 10.17  
**Support bead:** `bd-1z5a.14`  
**Completion-debt bead:** `bd-1z5a.27`
**Verdict:** PASS

## Scope Of This Support Slice

This artifact pack is the completion-debt refresh for the audit-missing
`bd-1z5a` obligations. It preserves the older `bd-1z5a.14` RCH tractability
proof metadata and adds explicit coverage for the four missing items from
`bd-1z5a.27`: unit tests, integration tests, E2E tests, and telemetry.

What this support slice adds:

- a refreshed evidence pack that now points at the passing operator E2E bundle
  and structured event log
- a deterministic replay fixture index that includes the operator shell harness,
  checker, machine-readable fraud-proof witness bundle, the evidence-pack
  coherence checker, and a first-class `rch_tractability_benchmarks.json`
  report
- explicit `rch` build IDs and durations for one representative external replay
  verification lane and one representative trust-score update lane
- a tighter evidence-pack checker that fails if the benchmark report, budget,
  fixture-index summary, human-readable references, or completion-debt coverage
  drift

## Completion-Debt Coverage

- `tests.unit.primary`: covered by checker/unit suites for the bd-1z5a evidence
  pack, verifier economy shortcut guard, connector verifier SDK shortcut guard,
  and operator E2E bundle checker.
- `tests.integration.primary`: covered by the verifier SDK capsule conformance
  fixture, claim-compiler scoreboard conformance fixture, section 10.17 capsule
  and scoreboard artifacts, and the recorded RCH tractability lanes.
- `tests.e2e.primary`: covered by
  `tests/e2e/verifier_replay_operator_suite.sh` and the normalized operator
  E2E bundle/log/fraud-proof artifacts.
- `telemetry.primary`: covered by the `CAPSULE_VERIFY_*` and
  `VERIFIER_SCORE_*` event families in
  `artifacts/replacement_gap/bd-1z5a/operator_e2e_log.jsonl`, including
  `trace_id`, `capsule_id`, `verifier_id`, `claim_id`,
  `commitment_digest`, `decision`, `reason_code`, and `fraud_proof_id`.

## Fresh Evidence Gathered

- `python3 scripts/check_verifier_economy.py --json` passed `171/171` checks.
  The replacement-critical guard windows for attestation signature verification,
  cached-key verification, and replay-capsule integrity all passed.
- `python3 scripts/check_verifier_sdk.py --json` passed `65/65` checks. The
  replacement-critical guard windows for canonical migration-signature
  verification and content-hash validation both passed.
- `python3 -m unittest tests/test_check_verifier_economy.py tests/test_check_verifier_sdk.py`
  passed `78` tests.
- `PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/check_verifier_replay_operator_e2e.py --json`
  passed `24/24` checks. The operator E2E bundle now reports a single trace id,
  five passing stages, all required `CAPSULE_VERIFY_*` / `VERIFIER_SCORE_*`
  events, per-stage provenance metadata, and valid stage artifact paths.
- `PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest tests/test_check_verifier_replay_operator_e2e.py`
  passed `13` tests.
- `python3 scripts/check_bd_1z5a_evidence_pack.py --json` now passes `30/30`
  checks. It verifies replacement-gap artifact paths, required fixture ids,
  current support-shard metadata, operator bundle/log linkage, fraud-proof
  witness references, canonical summary markdown, tractability benchmark build
  IDs/durations, stale-gap regression phrases, and bd-1z5a.27
  completion-debt coverage.
- `python3 scripts/check_bd_1z5a_evidence_pack.py --self-test --json` passed.
  Its internal mutation harness still forces a failure when stale-gap text is
  reintroduced.
- `python3 -m unittest tests/test_check_bd_1z5a_evidence_pack.py` now passes
  `16` tests, including tractability-benchmark fixture and budget regressions
  plus missing completion-debt item/path regressions.
- `python3 -m py_compile scripts/check_bd_1z5a_evidence_pack.py tests/test_check_bd_1z5a_evidence_pack.py`
  passed.
- `rch` build `29747325727408129` passed strict test-surface clippy for
  `frankenengine-node`.
- `rch` build `29747325727408132` passed the existing trust-state verification
  probe.
- `rch` build `29747325727408133` passed strict
  `cargo clippy -p frankenengine-node --all-targets -- -D warnings` on the
  current shared tree.
- `rch` build `29747594884285383` passed the representative external replay
  verification lane in `475466ms`.
- `rch` build `29747594884285343` passed the representative trust-score update
  lane in `465686ms`.

## Tractability Benchmark Snapshot

The dedicated machine-readable report lives at
`artifacts/replacement_gap/bd-1z5a/rch_tractability_benchmarks.json` and
declares a per-lane tractability budget of `900000ms`.

| Lane | Build ID | Duration (ms) | Result |
|---|---:|---:|---|
| `external_replay_verification` | `29747594884285383` | `475466` | `PASS` |
| `trust_score_update_publication` | `29747594884285343` | `465686` | `PASS` |

## Replay / Score / Witness Inventory

The indexed fixture set is currently anchored in the existing Section 10.17
reports, conformance tests, and replacement-gap operator artifacts:

- `artifacts/10.17/verifier_sdk_certification_report.json`
- `tests/conformance/verifier_sdk_capsule_replay.rs`
- `artifacts/10.17/public_trust_scoreboard_snapshot.json`
- `tests/conformance/claim_compiler_gate.rs`
- `tests/e2e/verifier_replay_operator_suite.sh`
- `scripts/check_verifier_replay_operator_e2e.py`
- `scripts/check_bd_1z5a_evidence_pack.py`
- `artifacts/replacement_gap/bd-1z5a/operator_e2e_summary.json`
- `artifacts/replacement_gap/bd-1z5a/operator_e2e_bundle.json`
- `artifacts/replacement_gap/bd-1z5a/operator_e2e_log.jsonl`
- `artifacts/replacement_gap/bd-1z5a/fraud_proof_bundle.json`
- `artifacts/replacement_gap/bd-1z5a/rch_tractability_benchmarks.json`
- the replacement-critical Python checker + unittest pairs for
  `verifier_economy`, `connector/verifier_sdk`, and the replacement-gap
  evidence pack itself

That now gives us deterministic capsule-report, scoreboard-report, operator E2E,
structured event-log, witness-reference, artifact-coherence, and
benchmark-budget inputs in the replacement-gap lane.

## Notes

- The older `bd-1z5a.2` evidence-pack gaps for operator shell coverage,
  acceptance-specific event-family artifacts, and a replacement-gap witness
  bundle are now closed by the passing operator E2E bundle and
  `fraud_proof_bundle.json`.
- This refresh makes both the older `bd-1z5a.9` coherence guard and the newer
  `bd-1z5a.14` tractability proof discoverable directly from the
  replacement-gap pack, then layers `bd-1z5a.27` completion-debt coverage on
  top of that evidence.
- The operator bundle is normalized to one coherent trace id:
  `trace-bd-1z5a-operator-e2e-final`.
- The witness bundle is intentionally truthful and minimal: it records the
  extracted fraud-proof id, trace binding, and source artifact references
  without inventing a counterexample payload that current stage outputs do not
  expose.
