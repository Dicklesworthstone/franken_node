# bd-3cvu Verification Summary

**Section:** 10.13
**Completion-debt bead:** bd-3cvu.1
**Verdict:** PASS for source, checker, and deterministic operator E2E evidence

bd-3cvu replaces non-empty-token control-channel authentication with
transcript-bound capability verification. The live implementation signs and
verifies a domain-separated HMAC over channel identity, subject, audience,
direction, sequence, payload hash, epoch, and nonce. It rejects forged MACs,
stale epochs, nonce reuse, direction swaps, audience swaps, payload swaps, and
same-sequence replay before accepting a frame.

bd-3cvu.1 records the audit-missing items in
`artifacts/replacement_gap/bd-3cvu/verification_evidence.json`:

- `tests.unit.primary`: inline unit/adversarial/property-style tests in
  `control_channel.rs` cover transcript binding and shortcut regressions.
- `tests.integration.primary`: `tests/integration/control_channel_replay.rs`
  covers authenticated rejection, monotonicity, replay-window rejection, and
  auditability through the public API.
- `tests.e2e.primary`: `tests/e2e/control_channel_operator_suite.sh` emits
  structured operator JSONL for valid traffic, guessed-token injection failure,
  replay failure, and attenuation/caveat mismatch failures.

The checker now fails closed if the source markers, unit/integration markers,
operator E2E artifacts, or completion-debt evidence pack disappear.

Recorded validation:

- `tests/e2e/control_channel_operator_suite.sh`: PASS, 4 scenarios
- `python3 scripts/check_control_channel.py --json`: PASS, 26 passing checks,
  0 failing checks, 1 skipped Rust-test check in structural mode
- `python3 -m unittest tests/test_check_control_channel.py`: PASS, 19 tests
