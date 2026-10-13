"""Deletion kernel regressions, including real dual-Node execution predicates.

Node/Node pairs test reduction/preservation, not Franken compatibility. The
production kernel performs no I/O; these tests own their explicit subprocesses.
The complete capsule workflow has its separate minimizer regression suite.
"""

from __future__ import annotations

import hashlib
import random
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from lib import migration_reduction as reduction


class Utf8ReductionTests(unittest.TestCase):
    def test_can_delete_inside_a_single_minified_line(self):
        original = b"const unused=123;console.log('required');const other=456;"
        result = reduction.reduce_utf8(original, lambda data: b"console.log('required')" in data)
        self.assertEqual(result, b"console.log('required')")

    def test_empty_is_checked_even_when_no_nonempty_deletion_is_accepted(self):
        seen = []
        result = reduction.reduce_utf8(b"irreducible", lambda data: seen.append(data) or data == b"")
        self.assertEqual(result, b"")
        self.assertEqual(seen, [b""])

    def test_empty_input_needs_no_new_oracle_call(self):
        def unexpected(_):
            self.fail("an unchanged empty input does not require a candidate")
        self.assertEqual(reduction.reduce_utf8(b"", unexpected), b"")

    def test_single_scalar_is_not_returned_as_removed_without_acceptance(self):
        seen = []
        result = reduction.reduce_utf8("雪".encode(), lambda data: seen.append(data) or False)
        self.assertEqual(result, "雪".encode())
        self.assertEqual(seen, [b""])

    def test_irreducible_source_is_byte_identical(self):
        original = b"a\r\nb\n\xef\xbb\xbfc"
        result = reduction.reduce_utf8(original, lambda data: data == original)
        self.assertEqual(result, original)

    def test_all_candidates_remain_valid_utf8(self):
        original = "😀junk雪keep雪junk🧪".encode()
        seen = []
        def oracle(data):
            text = data.decode("utf-8", errors="strict")
            seen.append(text)
            return "雪keep雪" in text
        self.assertEqual(reduction.reduce_utf8(original, oracle), "雪keep雪".encode())
        self.assertTrue(seen)

    def test_decomposed_unicode_is_not_normalized(self):
        required = "e\u0301".encode()
        result = reduction.reduce_utf8(b"prefix" + required + b"suffix", lambda data: required in data)
        self.assertEqual(result, required)
        self.assertNotEqual(result, "é".encode())

    def test_invalid_utf8_is_rejected_without_oracle_or_source_in_error(self):
        secret = b"private-source-must-not-be-printed"
        with self.assertRaises(ValueError) as error:
            reduction.reduce_utf8(secret + b"\xff", lambda _: self.fail("must not call oracle"))
        self.assertNotIn(secret.decode(), str(error.exception))
        self.assertIn("UTF-8", str(error.exception))

    def test_input_type_and_byte_limit_precede_oracle_calls(self):
        for value in (None, "source", bytearray(b"source"), b"x" * (reduction.MAX_REDUCTION_BYTES + 1)):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ValueError):
                reduction.reduce_utf8(value, lambda _: self.fail("invalid input reached oracle"))

    def test_exact_byte_limit_is_accepted_without_character_list_expansion(self):
        data = b"x" * reduction.MAX_REDUCTION_BYTES
        self.assertEqual(reduction.reduce_utf8(data, lambda _: True, max_candidates=1), b"")

    def test_candidate_budget_has_a_hard_bound(self):
        calls = []
        with self.assertRaisesRegex(reduction.CandidateBudgetExceeded, "candidate_partition_budget"):
            reduction.reduce_utf8(b"abcdef", lambda data: calls.append(data) or False, max_candidates=3)
        self.assertEqual(len(calls), 3)

    def test_invalid_budgets_fail_before_oracle(self):
        for count in (0, -1, True, None, 1.5, reduction.MAX_CANDIDATES + 1):
            with self.subTest(count=count), self.assertRaises(ValueError):
                reduction.reduce_utf8(b"abc", lambda _: self.fail("invalid budget reached oracle"), max_candidates=count)

    def test_budget_does_not_overwrite_callers_last_confirmed_candidate(self):
        best = b"abcKEEPxyz"
        accepted = []
        def oracle(data):
            nonlocal best
            if b"KEEP" not in data:
                return False
            best = data
            accepted.append(data)
            return True
        with self.assertRaises(reduction.CandidateBudgetExceeded):
            reduction.reduce_utf8(best, oracle, max_candidates=12)
        self.assertTrue(accepted)
        self.assertEqual(best, accepted[-1])
        self.assertIn(b"KEEP", best)

    def test_oracle_cancellation_is_not_a_rejection(self):
        stop = RuntimeError("operator cancellation")
        def cancelled(_):
            raise stop
        with self.assertRaises(RuntimeError) as error:
            reduction.reduce_utf8(b"abc", cancelled)
        self.assertIs(error.exception, stop)

    def test_keyboard_interrupt_is_not_swallowed(self):
        def interrupted(_):
            raise KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            reduction.reduce_utf8(b"abc", interrupted)

    def test_truthy_nonboolean_oracle_results_are_not_accepted(self):
        for response in (1, "accepted", [True], None):
            with self.subTest(kind=type(response).__name__), self.assertRaises(TypeError):
                reduction.reduce_utf8(b"abc", lambda _: response)

    def test_candidates_are_strict_deletions_and_never_reorder_text(self):
        randomizer = random.Random(0xF12A)
        for _ in range(24):
            prefix = "".join(randomizer.choices("a雪😀bc ", k=12))
            suffix = "".join(randomizer.choices("defé🧪 ", k=12))
            text = prefix + "KEEP" + suffix
            def oracle(data):
                decoded = data.decode()
                remaining = iter(text)
                self.assertTrue(all(any(item == wanted for item in remaining) for wanted in decoded))
                self.assertLess(len(data), len(text.encode()))
                return "KEEP" in decoded
            self.assertEqual(reduction.reduce_utf8(text.encode(), oracle), b"KEEP")

    def test_same_input_and_oracle_have_same_candidate_order(self):
        transcripts = []
        for _ in range(2):
            transcript = []
            def oracle(data):
                transcript.append(data)
                return b"keep" in data
            self.assertEqual(reduction.reduce_utf8(b"before keep after", oracle), b"keep")
            transcripts.append(transcript)
        self.assertEqual(transcripts[0], transcripts[1])


@unittest.skipUnless(shutil.which("node"), "real Node executable unavailable")
class ExecutedSourceReductionTests(unittest.TestCase):
    def test_minified_code_reduces_only_when_both_measured_outcomes_stay_exact(self):
        node = shutil.which("node")
        with tempfile.TemporaryDirectory(prefix="utf8-node-oracle-") as temporary:
            root = Path(temporary)
            baseline, migration = root / "baseline.cjs", root / "migration.cjs"
            original = b"const unused=123;console.log('original');const other=456;"
            baseline.write_bytes(original)
            migration.write_bytes(b"console.log('rewritten');")
            def observe(path):
                run = subprocess.run([node, str(path)], capture_output=True, timeout=3, check=False)
                return run.returncode, run.stdout, run.stderr
            expected = observe(baseline), observe(migration)
            self.assertEqual(expected, ((0, b"original\n", b""), (0, b"rewritten\n", b"")))
            rejected_syntax = 0
            accepted = []
            def oracle(data):
                nonlocal rejected_syntax
                baseline.write_bytes(data)
                # Acceptances need fresh confirmations, never just equal exits.
                for _ in range(2):
                    before, after = observe(baseline), observe(migration)
                    if before[0] != 0:
                        rejected_syntax += 1
                    if (before, after) != expected:
                        return False
                accepted.append(hashlib.sha256(data).hexdigest())
                return True
            reduced = reduction.reduce_utf8(original, oracle)
            self.assertLess(len(reduced), len(original))
            self.assertGreater(rejected_syntax, 0)
            self.assertTrue(accepted)
            baseline.write_bytes(reduced)
            for _ in range(2):
                self.assertEqual((observe(baseline), observe(migration)), expected)
            self.assertEqual(migration.read_bytes(), b"console.log('rewritten');")

    def test_unchanged_exit_with_different_console_bytes_is_rejected(self):
        node = shutil.which("node")
        with tempfile.TemporaryDirectory(prefix="utf8-node-output-") as temporary:
            script = Path(temporary) / "source.cjs"
            original = "console.log('雪😀');".encode()
            script.write_bytes(original)
            def run():
                result = subprocess.run([node, str(script)], capture_output=True, timeout=3, check=False)
                return result.returncode, result.stdout, result.stderr
            expected = run()
            different_successes = 0
            def oracle(data):
                nonlocal different_successes
                script.write_bytes(data)
                actual = run()
                if actual[0] == 0 and actual != expected:
                    different_successes += 1
                return actual == expected
            result = reduction.reduce_utf8(original, oracle)
            self.assertGreater(different_successes, 0)
            self.assertIn("雪😀".encode(), result)
            script.write_bytes(result)
            self.assertEqual(run(), expected)


if __name__ == "__main__":
    unittest.main()
