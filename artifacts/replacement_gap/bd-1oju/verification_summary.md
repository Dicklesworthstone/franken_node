# bd-1oju Verification Summary

**Section:** 10.4
**Completion-debt bead:** bd-1oju.1
**Verdict:** PASS for source, checker, and completion-debt evidence coverage

bd-1oju binds trust-card and certification outputs to verified upstream
evidence instead of trusting caller assertions. The implementation already
contains the critical gates: trust-card creation rejects empty evidence refs,
certification upgrades require new evidence, and both trust-card and
certification results carry derivation metadata that can be reconstructed by a
verifier.

bd-1oju.1 records the audit-missing items in
`artifacts/replacement_gap/bd-1oju/verification_evidence.json`:

- `tests.unit.primary`: inline trust-card and certification tests cover missing
  evidence, derivation metadata, and deterministic derivation hashing.
- `tests.integration.primary`: conformance coverage links artifact admission to
  trust-card creation and proves missing upstream evidence fails closed.
- `tests.e2e.primary`: mock-free lifecycle coverage drives create, upgrade,
  revoke, and snapshot paths with real verified evidence refs.

The trust-card checker now verifies those source markers, test markers, and
this completion-debt artifact. If any cited evidence path or required
completion-debt item disappears, `scripts/check_trust_card.py --json` fails.

Recorded validation:

- `python3 scripts/check_trust_card.py --json`: PASS, 131/131 checks.
- `python3 -m unittest tests/test_check_trust_card.py`: PASS, 12 tests.
- `python3 -m py_compile scripts/check_trust_card.py
  tests/test_check_trust_card.py`: PASS.
- `jq -e . artifacts/replacement_gap/bd-1oju/verification_evidence.json`: PASS.
- `git diff --check`: PASS.
- Focused cargo E2E was skipped because `pgrep -af 'cargo|rustc' | wc -l`
  returned 5 and `rch queue` reported 3 active builds.
