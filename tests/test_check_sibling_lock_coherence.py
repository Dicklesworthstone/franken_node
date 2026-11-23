"""Unit and adversarial tests for scripts/check_sibling_lock_coherence.py."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_sibling_lock_coherence.py"

spec = importlib.util.spec_from_file_location("check_sibling_lock_coherence", SCRIPT)
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class TestCheckSiblingLockCoherence(unittest.TestCase):
    def test_live_workspace_passes(self) -> None:
        report = mod.run_checks()
        self.assertTrue(report["overall_pass"], json.dumps(report, indent=2))
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["summary"]["failing"], 0)

    def test_node_fastapi_split_or_fourth_asupersync_generation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "Cargo.lock"
            lock_path.write_text(
                """
version = 4

[[package]]
name = "asupersync"
version = "0.2.9"

[[package]]
name = "asupersync"
version = "0.3.10"

[[package]]
name = "asupersync"
version = "0.6.2"

[[package]]
name = "asupersync"
version = "0.7.0"

[[package]]
name = "fastapi-core"
version = "0.6.0"

[[package]]
name = "fastapi-http"
version = "0.6.0"
dependencies = ["asupersync 0.7.0"]

[[package]]
name = "franken-kernel"
version = "0.2.9"

[[package]]
name = "franken-decision"
version = "0.2.9"

[[package]]
name = "franken-evidence"
version = "0.2.9"

[[package]]
name = "fsqlite-error"
version = "0.4.1"

[[package]]
name = "frankenengine-node"
version = "0.2.0"
dependencies = ["asupersync 0.6.2"]
""".lstrip(),
                encoding="utf-8",
            )
            report = mod.run_checks(cargo_lock=lock_path, check_local_git=False)
        self.assertFalse(report["overall_pass"])
        failed = {c["check"] for c in report["checks"] if not c["pass"]}
        self.assertIn("cargo_lock:frankenengine_node_asupersync_0_7", failed)
        self.assertIn("cargo_lock:node_and_fastapi_share_asupersync", failed)
        self.assertIn("cargo_lock:generation_bound:asupersync", failed)

    def test_coverage_exit_zero_masking_and_non_blocking_census_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wf_dir = Path(tmp) / "workflows"
            wf_dir.mkdir()
            for wf in mod.REQUIRED_MAIN_PUSH_WORKFLOWS:
                shutil.copy2(ROOT / ".github" / "workflows" / wf, wf_dir / wf)

            cov = (wf_dir / "coverage-report.yml").read_text(encoding="utf-8")
            (wf_dir / "coverage-report.yml").write_text(
                cov.replace(
                    '            exit "${status:-1}"\n          fi',
                    '            exit "${status:-1}"\n          fi\n          exit 0',
                ),
                encoding="utf-8",
            )
            vt = (wf_dir / "verification-target-compile-gate.yml").read_text(encoding="utf-8")
            (wf_dir / "verification-target-compile-gate.yml").write_text(
                vt.replace('BLOCKING: "1"', 'BLOCKING: "0"'),
                encoding="utf-8",
            )
            report = mod.run_checks(workflows_dir=wf_dir, check_local_git=False)
        self.assertFalse(report["overall_pass"])
        failed = {c["check"] for c in report["checks"] if not c["pass"]}
        self.assertIn("coverage_report:no_exit_zero_masking", failed)
        self.assertIn("verification_target_compile_gate:blocking_enabled", failed)

    def test_malformed_siblings_tsv_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tsv = Path(tmp) / "source-siblings.tsv"
            tsv.write_text("frankentui\tmain\nfastapi_rust\t" + "a" * 40 + "\n", encoding="utf-8")
            report = mod.run_checks(siblings_tsv=tsv, check_local_git=False)
        self.assertFalse(report["overall_pass"])
        failed = {c["check"] for c in report["checks"] if not c["pass"]}
        self.assertIn("siblings_tsv_well_formed", failed)
        self.assertIn("sibling_pinned:sqlmodel_rust", failed)

    def test_duplicate_fastapi_or_fsqlite_generation_and_engine_pin_drift_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock_path = Path(tmp) / "Cargo.lock"
            lock_path.write_text(
                """
version = 4

[[package]]
name = "asupersync"
version = "0.7.0"

[[package]]
name = "fastapi-core"
version = "0.5.0"

[[package]]
name = "fastapi-core"
version = "0.6.0"

[[package]]
name = "fastapi-http"
version = "0.6.0"
dependencies = ["asupersync 0.7.0"]

[[package]]
name = "franken-kernel"
version = "0.7.0"

[[package]]
name = "franken-decision"
version = "0.7.0"

[[package]]
name = "franken-evidence"
version = "0.7.0"

[[package]]
name = "fsqlite-error"
version = "0.1.19"

[[package]]
name = "fsqlite-error"
version = "0.4.1"

[[package]]
name = "frankenengine-node"
version = "0.2.0"
dependencies = ["asupersync 0.7.0"]
""".lstrip(),
                encoding="utf-8",
            )
            wf_dir = Path(tmp) / "workflows"
            wf_dir.mkdir()
            for wf in mod.REQUIRED_MAIN_PUSH_WORKFLOWS:
                shutil.copy2(ROOT / ".github" / "workflows" / wf, wf_dir / wf)
            mutants_path = wf_dir / "mutants-gate.yml"
            live_refs = mod._extract_engine_refs(mutants_path)
            self.assertTrue(live_refs, "mutants-gate.yml must contain an engine ref")
            mutants_path.write_text(
                mutants_path.read_text(encoding="utf-8").replace(
                    live_refs[0],
                    "1" * 40,
                ),
                encoding="utf-8",
            )
            report = mod.run_checks(
                cargo_lock=lock_path,
                workflows_dir=wf_dir,
                check_local_git=False,
            )
        self.assertFalse(report["overall_pass"])
        self.assertEqual(report["locked_metadata_status"], "drift_detected")
        self.assertIsNotNone(report["failure_code"])
        failed = {c["check"] for c in report["checks"] if not c["pass"]}
        self.assertIn("cargo_lock:generation_bound:fastapi-core", failed)
        self.assertIn("cargo_lock:generation_bound:fsqlite-error", failed)
        self.assertIn("engine_pin:workflow_matches_action:mutants-gate.yml", failed)

    def test_release_pin_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wf_dir = Path(tmp) / "workflows"
            shutil.copytree(ROOT / ".github" / "workflows", wf_dir)
            dist_path = wf_dir / "dist.yml"
            data = mod.yaml.safe_load(dist_path.read_text(encoding="utf-8"))
            data["env"]["FRANKEN_ENGINE_REVISION"] = "b" * 40
            dist_path.write_text(mod.yaml.safe_dump(data), encoding="utf-8")
            checks, _ = mod.check_engine_pin_coherence(
                wf_dir, check_local_git=False
            )
        failed = {c["check"] for c in checks if not c["pass"]}
        self.assertIn("engine_pin:workflow_matches_action:dist.yml", failed)

    def test_missing_required_pin_owner_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checks, _ = mod.check_engine_pin_coherence(
                Path(tmp), check_local_git=False
            )
        failed = {c["check"] for c in checks if not c["pass"]}
        for name in mod.ENGINE_PINNED_WORKFLOWS:
            self.assertIn(f"engine_pin:workflow_matches_action:{name}", failed)

    def test_new_workflow_pin_is_checked_without_an_allowlist_change(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wf_dir = Path(tmp) / "workflows"
            shutil.copytree(ROOT / ".github" / "workflows", wf_dir)
            extra = wf_dir / "new-engine-build.yaml"
            extra.write_text(
                "jobs:\n  check:\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "        with:\n"
                "          repository: Dicklesworthstone/franken_engine\n"
                "          ref: " + "b" * 40 + "\n",
                encoding="utf-8",
            )
            checks, _ = mod.check_engine_pin_coherence(
                wf_dir, check_local_git=False
            )
        failed = {c["check"] for c in checks if not c["pass"]}
        self.assertIn(
            "engine_pin:workflow_matches_action:new-engine-build.yaml", failed
        )

    def test_engine_ref_extraction_resolves_scoped_env_and_quoted_pins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "workflow.yml"
            path.write_text(
                "env:\n  PIN: " + "a" * 40 + "\n"
                "jobs:\n"
                "  inherited:\n"
                "    steps:\n"
                '      - run: bash bootstrap --engine-ref "$PIN"\n'
                "      - uses: actions/checkout@v4\n"
                "        with:\n"
                "          repository: Dicklesworthstone/franken_engine\n"
                "          ref: $" + "{{ env.PIN }}\n"
                "  overridden:\n"
                "    env:\n      PIN: " + "b" * 40 + "\n"
                "    steps:\n"
                '      - run: bash bootstrap --engine-ref="$' + '{PIN}"\n'
                "      - env:\n          PIN: " + "c" * 40 + "\n"
                '        run: bash bootstrap --engine-ref "$PIN"\n'
                '      - run: bash bootstrap --engine-ref "' + "d" * 40 + '"\n',
                encoding="utf-8",
            )
            self.assertEqual(
                mod._extract_engine_refs(path),
                ["a" * 40, "a" * 40, "b" * 40, "c" * 40, "d" * 40],
            )

    def test_unresolved_engine_variables_and_missing_checkout_refs_fail_closed(self) -> None:
        cases = (
            {"run": 'bash bootstrap --engine-ref "$MISSING"'},
            {"run": "bash bootstrap --engine-ref '$PIN'"},
            {"run": "bash bootstrap --engine-ref"},
            {"run": "bash bootstrap --engine-ref $" + "{{ inputs.pin }}"},
            {"run": 'bash bootstrap --engine-ref "' + "a" * 40 + '"suffix'},
            {"run": 'bash bootstrap --engine-ref "$PIN"suffix'},
            {"run": 'bash bootstrap --engine-ref "${PIN}"/suffix'},
            {
                "uses": "actions/checkout@v4",
                "with": {"repository": "Dicklesworthstone/franken_engine"},
            },
            {
                "uses": "actions/checkout@v4",
                "with": {
                    "repository": "Dicklesworthstone/franken_engine",
                    "ref": "$PIN",
                },
            },
        )
        cases += tuple(
            step
            for invalid_ref in (" " + "a" * 40, "a" * 40 + " ", "a" * 40 + "\n")
            for step in (
                {
                    "env": {"PIN": invalid_ref},
                    "run": 'bash bootstrap --engine-ref "$PIN"',
                },
                {"run": f'bash bootstrap --engine-ref "{invalid_ref}"'},
                {
                    "uses": "actions/checkout@v4",
                    "with": {
                        "repository": "Dicklesworthstone/franken_engine",
                        "ref": invalid_ref,
                    },
                },
            )
        )
        with tempfile.TemporaryDirectory() as tmp:
            wf_dir = Path(tmp) / "workflows"
            wf_dir.mkdir()
            action = Path(tmp) / "action.yml"
            action.write_text(
                "runs:\n  using: composite\n  steps:\n"
                "    - run: bash bootstrap --engine-ref " + "a" * 40 + "\n",
                encoding="utf-8",
            )
            path = wf_dir / "extra.yml"
            for step in cases:
                with self.subTest(step=step):
                    path.write_text(
                        mod.yaml.safe_dump(
                            {
                                "env": {"PIN": "a" * 40},
                                "jobs": {"check": {"steps": [step]}},
                            }
                        ),
                        encoding="utf-8",
                    )
                    refs = mod._extract_engine_refs(path)
                    self.assertTrue(refs, "an unresolved selection must not disappear")
                    checks, _ = mod.check_engine_pin_coherence(
                        wf_dir, action_yml=action, check_local_git=False
                    )
                    check = next(
                        c for c in checks
                        if c["check"] == "engine_pin:workflow_matches_action:extra.yml"
                    )
                    self.assertFalse(check["pass"], refs)

    def test_canonical_action_pin_rejects_whitespace_and_newlines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wf_dir = root / "workflows"
            wf_dir.mkdir()
            action = root / "action.yml"
            for invalid_ref in (" " + "a" * 40, "a" * 40 + " ", "a" * 40 + "\n"):
                with self.subTest(ref=invalid_ref):
                    action.write_text(
                        mod.yaml.safe_dump(
                            {
                                "runs": {
                                    "using": "composite",
                                    "steps": [
                                        {"run": f'bash bootstrap --engine-ref "{invalid_ref}"'}
                                    ],
                                }
                            }
                        ),
                        encoding="utf-8",
                    )
                    checks, canonical = mod.check_engine_pin_coherence(
                        wf_dir, action_yml=action, check_local_git=False
                    )
                    self.assertIsNone(canonical)
                    check = next(
                        c for c in checks
                        if c["check"] == "engine_pin:franken_siblings_action_sha40"
                    )
                    self.assertFalse(check["pass"])

    def test_step_env_override_cannot_hide_a_different_engine_pin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wf_dir = Path(tmp) / "workflows"
            shutil.copytree(ROOT / ".github" / "workflows", wf_dir)
            dist_path = wf_dir / "dist.yml"
            data = mod.yaml.safe_load(dist_path.read_text(encoding="utf-8"))
            step = next(
                step
                for step in data["jobs"]["release-certification"]["steps"]
                if "--engine-ref" in step.get("run", "")
            )
            step["env"] = {"FRANKEN_ENGINE_REVISION": "b" * 40}
            dist_path.write_text(mod.yaml.safe_dump(data), encoding="utf-8")
            checks, _ = mod.check_engine_pin_coherence(
                wf_dir, check_local_git=False
            )
        failed = {c["check"] for c in checks if not c["pass"]}
        self.assertIn("engine_pin:workflow_matches_action:dist.yml", failed)

    def test_pinned_commit_must_provide_clock_and_failure_replay_apis(self) -> None:
        # Use tiny real Git commits instead of requiring a historical upstream
        # object, so this regression always executes in a shallow CI checkout.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            product = root / "franken_node"
            engine = root / "franken_engine"
            engine.mkdir()

            def git(*args: str) -> str:
                proc = subprocess.run(
                    ["git", "-C", str(engine), *args],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                return proc.stdout.strip()

            git("init", "--quiet")
            git("config", "user.name", "Sibling gate fixture")
            git("config", "user.email", "sibling-gate@example.invalid")
            git("config", "commit.gpgsign", "false")
            hooks = root / "empty-hooks"
            hooks.mkdir()
            git("config", "core.hooksPath", str(hooks))
            engine_source = engine / "crates/franken-engine/src/execution_orchestrator.rs"
            engine_source.parent.mkdir(parents=True)
            revisions: list[str] = []
            for methods in (
                (),
                ("set_clock_epoch_ms",),
                ("set_clock_epoch_ms", "last_failed_execution_replay_context"),
            ):
                engine_source.write_text(
                    "\n".join(f"pub fn {name}() {{}}" for name in methods) + "\n",
                    encoding="utf-8",
                )
                git("add", ".")
                git("commit", "--quiet", "-m", f"APIs: {len(methods)}")
                revisions.append(git("rev-parse", "HEAD"))

            dispatcher = product / "crates/franken-node/src/ops/engine_dispatcher.rs"
            dispatcher.parent.mkdir(parents=True)
            dispatcher.write_text(
                "orchestrator.set_clock_epoch_ms(None);\n"
                "orchestrator.last_failed_execution_replay_context();\n",
                encoding="utf-8",
            )
            action = product / ".github/actions/franken-siblings/action.yml"
            action.parent.mkdir(parents=True)
            wf_dir = product / ".github/workflows"
            wf_dir.mkdir()
            # HEAD has both APIs throughout. A stale pin must still fail by
            # inspecting its committed tree, not the current working copy.
            for index, revision in enumerate(revisions):
                with self.subTest(revision=index):
                    action.write_text(
                        "runs:\n  using: composite\n  steps:\n"
                        "    - run: bash bootstrap --engine-ref " + revision + "\n",
                        encoding="utf-8",
                    )
                    for name in mod.ENGINE_PINNED_WORKFLOWS:
                        (wf_dir / name).write_text(
                            "jobs:\n  check:\n    steps:\n"
                            "      - run: bash bootstrap --engine-ref " + revision + "\n",
                            encoding="utf-8",
                        )
                    with mock.patch.object(mod, "ROOT", product):
                        checks, _ = mod.check_engine_pin_coherence(
                            wf_dir, action_yml=action, check_local_git=True
                        )
                    by_name = {check["check"]: check["pass"] for check in checks}
                    self.assertTrue(by_name["sibling_commit_resolvable:franken_engine"])
                    self.assertEqual(
                        by_name["engine_pin:provides_set_clock_epoch_ms"], index >= 1
                    )
                    self.assertEqual(
                        by_name["engine_pin:provides_last_failed_execution_replay_context"],
                        index == 2,
                    )
                    if index == 2:
                        self.assertTrue(all(check["pass"] for check in checks), checks)

    def test_cli_json_and_self_test(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["verdict"], "PASS")

        st = subprocess.run(
            [sys.executable, str(SCRIPT), "--self-test", "--json"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(st.returncode, 0, st.stderr)
        self.assertTrue(json.loads(st.stdout)["self_test_passed"])


if __name__ == "__main__":
    unittest.main()
