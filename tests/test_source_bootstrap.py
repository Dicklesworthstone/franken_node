"""Real Git checkout tests for source bootstrap; no compiler or network claims.

Only Git's URL transport is redirected to local repositories. Revision lookup,
fetch, checkout, filesystem guards, lock parsing and receipt publication are real.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/bootstrap_source.sh"
MANIFESTS = {
    "franken_engine": ["crates/franken-engine/Cargo.toml", "crates/franken-extension-host/Cargo.toml"],
    "frankentui": ["crates/ftui/Cargo.toml"],
    "fastapi_rust": ["crates/fastapi/Cargo.toml"],
    "sqlmodel_rust": ["crates/sqlmodel/Cargo.toml", "crates/sqlmodel-core/Cargo.toml", "crates/sqlmodel-schema/Cargo.toml"],
}


def git(directory: Path, *args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(["git", "-C", str(directory), *args], env=env,
                            text=True, capture_output=True, timeout=15, check=True)
    return result.stdout.strip()


class SourceBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="franken source bootstrap ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.remotes = self.root / "remotes"
        self.remotes.mkdir()
        self.parent = self.root / "build"
        self.parent.mkdir()
        self.workspace = self.parent / "franken_node"
        self.workspace.mkdir()
        self.env = os.environ.copy()
        # Keep tests independent of user Git configuration and identity.
        self.env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                         "GIT_AUTHOR_NAME": "Bootstrap test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
                         "GIT_COMMITTER_NAME": "Bootstrap test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
                         "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_COUNT": "2",
                         "GIT_CONFIG_KEY_0": f"url.{self.remotes.as_uri()}/.insteadOf",
                         "GIT_CONFIG_VALUE_0": "https://github.com/Dicklesworthstone/",
                         "GIT_CONFIG_KEY_1": "protocol.file.allow", "GIT_CONFIG_VALUE_1": "always"})
        self.pins = {}
        self.newer = {}
        for name, manifests in MANIFESTS.items():
            repository = self.remotes / (name + ".git")
            repository.mkdir()
            git(repository, "init", "--quiet", "--initial-branch=main", env=self.env)
            for relative in ["Cargo.toml", *manifests]:
                target = repository / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("# fixture manifest; not a compiled crate\n", encoding="utf-8")
            (repository / "selected.txt").write_text("pinned input\n")
            git(repository, "add", ".", env=self.env)
            git(repository, "commit", "--quiet", "-m", "recorded source", env=self.env)
            self.pins[name] = git(repository, "rev-parse", "HEAD", env=self.env)
            git(repository, "tag", "recorded", env=self.env)
            (repository / "selected.txt").write_text("later main input\n")
            git(repository, "commit", "--quiet", "-am", "advance branch", env=self.env)
            self.newer[name] = git(repository, "rev-parse", "HEAD", env=self.env)
        git(self.workspace, "init", "--quiet", "--initial-branch=main", env=self.env)
        (self.workspace / "Cargo.toml").write_text("[workspace]\n")
        (self.workspace / "packaging").mkdir()
        self.lock = self.workspace / "packaging/source-siblings.tsv"
        self.lock.write_text(self.lock_text())
        self.commit_workspace()
        self.receipt = self.root / "inputs.tsv"

    def lock_text(self):
        return "# pinned inputs\n" + "".join(
            f"{name}\t{self.pins[name]}\n" for name in MANIFESTS if name != "franken_engine")

    def commit_workspace(self):
        git(self.workspace, "add", ".", env=self.env)
        git(self.workspace, "commit", "--quiet", "--allow-empty", "-m", "workspace inputs", env=self.env)

    def run_bootstrap(self, *extra, engine=None, receipt=None, env=None):
        return subprocess.run(["bash", str(SCRIPT), "--workspace", str(self.workspace),
                               "--engine-ref", engine or self.pins["franken_engine"],
                               "--receipt", str(receipt or self.receipt), *extra],
                              text=True, capture_output=True, env=env or self.env, timeout=25)

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_failure(self, result, text):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(text, result.stderr)

    def test_materializes_every_required_sibling_at_pins_not_later_main(self):
        self.assert_success(self.run_bootstrap())
        for name, manifests in MANIFESTS.items():
            destination = self.parent / name
            self.assertEqual(git(destination, "rev-parse", "HEAD", env=self.env), self.pins[name])
            self.assertEqual((destination / "selected.txt").read_text(), "pinned input\n")
            for path in manifests:
                self.assertTrue((destination / path).is_file())
        rows = dict(line.split("\t") for line in self.receipt.read_text().splitlines() if not line.startswith("#"))
        self.assertEqual(rows, {"franken_node": git(self.workspace, "rev-parse", "HEAD", env=self.env), **self.pins})
        self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
        self.assertEqual(git(self.workspace, "status", "--porcelain", env=self.env), "")

    def test_verify_only_is_offline_and_does_not_change_existing_checkouts(self):
        self.assert_success(self.run_bootstrap())
        for name in MANIFESTS:
            git(self.parent / name, "remote", "set-url", "origin", "file:///does-not-exist", env=self.env)
        again = self.root / "verified.tsv"
        self.assert_success(self.run_bootstrap("--verify-only", receipt=again))
        self.assertEqual(again.read_bytes(), self.receipt.read_bytes())

    def test_existing_wrong_revision_is_refused_without_mutating_any_repository(self):
        self.assert_success(self.run_bootstrap())
        target = self.parent / "frankentui"
        git(target, "fetch", "origin", "main", env=self.env)
        git(target, "checkout", "--quiet", "--detach", "FETCH_HEAD", env=self.env)
        result = self.run_bootstrap(receipt=self.root / "refused.tsv")
        self.assert_failure(result, "revision mismatch")
        self.assertEqual(git(target, "rev-parse", "HEAD", env=self.env), self.newer["frankentui"])
        self.assertFalse((self.root / "refused.tsv").exists())

    def test_dirty_existing_repository_and_untracked_work_are_preserved(self):
        self.assert_success(self.run_bootstrap())
        target = self.parent / "fastapi_rust" / "local-work"
        target.write_text("do not discard\n")
        result = self.run_bootstrap(receipt=self.root / "refused.tsv")
        self.assert_failure(result, "local changes")
        self.assertEqual(target.read_text(), "do not discard\n")
        self.assertFalse((self.root / "refused.tsv").exists())

    def test_dirty_workspace_is_refused_before_creating_siblings(self):
        (self.workspace / "Cargo.toml").write_text("changed\n")
        self.assert_failure(self.run_bootstrap(), "local changes")
        self.assertFalse((self.parent / "franken_engine").exists())

    def test_symlinked_sibling_is_not_followed_or_replaced(self):
        outside = self.root / "outside"
        outside.mkdir()
        link = self.parent / "sqlmodel_rust"
        link.symlink_to(outside, target_is_directory=True)
        self.assert_failure(self.run_bootstrap(), "ordinary standalone checkout")
        self.assertTrue(link.is_symlink())
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.parent / "franken_engine").exists())

    def test_missing_verify_only_dependency_does_not_start_a_checkout(self):
        self.assert_failure(self.run_bootstrap("--verify-only"), "missing sibling")
        self.assertEqual(set(self.parent.iterdir()), {self.workspace})

    def test_malformed_lock_is_rejected_before_network_or_directory_creation(self):
        good = self.lock_text()
        for name, bad in {
            "duplicate": good + f"frankentui\t{self.pins['frankentui']}\n",
            "missing": good.replace(f"sqlmodel_rust\t{self.pins['sqlmodel_rust']}\n", ""),
            "floating": good.replace(self.pins["frankentui"], "main"),
            "uppercase": good.replace(self.pins["frankentui"], self.pins["frankentui"].upper()),
            "unknown": good.replace("frankentui\t", "untrusted\t"),
            "traversal": good.replace("frankentui\t", "../frankentui\t"),
            "extra": good.replace("frankentui\t", "frankentui\textra\t"),
            "crlf": good.replace("\n", "\r\n"),
            "large": "#" + "x" * 4096,
        }.items():
            with self.subTest(name=name):
                self.lock.write_text(bad)
                self.commit_workspace()
                result = self.run_bootstrap()
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertFalse((self.parent / "franken_engine").exists())
                self.assertFalse(self.receipt.exists())

    def test_linked_lock_is_rejected_without_reading_or_executing_its_content(self):
        original = self.lock.with_name("original.tsv")
        self.lock.rename(original)
        self.lock.symlink_to(original.name)
        self.commit_workspace()
        self.assert_failure(self.run_bootstrap(), "regular packaging/source-siblings.tsv")
        self.assertFalse((self.parent / "franken_engine").exists())

    def test_explicit_engine_branch_and_annotated_tag_resolve_and_record_exact_commits(self):
        git(self.remotes / "franken_engine.git", "tag", "-a", "annotated", self.pins["franken_engine"],
            "-m", "annotated source", env=self.env)
        self.assert_success(self.run_bootstrap(engine="annotated"))
        self.assertIn("franken_engine\t" + self.pins["franken_engine"], self.receipt.read_text())
        self.assert_failure(self.run_bootstrap(engine="main", receipt=self.root / "again.tsv"),
                            "existing engine checkout requires an exact commit")

    def test_invalid_or_option_like_engine_refs_fail_before_creating_siblings(self):
        for reference in ["--upload-pack=bad", "a:b", "main~1", "main\nother", "main other"]:
            with self.subTest(reference=reference):
                self.assert_failure(self.run_bootstrap(engine=reference), "invalid engine ref")
                self.assertFalse((self.parent / "franken_engine").exists())

    def test_fetch_failure_never_falls_back_to_main_or_publishes_a_receipt(self):
        self.assert_failure(self.run_bootstrap(engine="0" * 40), "cannot fetch requested")
        self.assertFalse(self.receipt.exists())
        self.assertFalse((self.parent / "frankentui").exists())
        self.assertTrue((self.parent / "franken_engine" / ".git").is_dir())
        self.assert_failure(self.run_bootstrap(), "checkout has no commit")

    def test_missing_required_cargo_manifests_prevent_success(self):
        target = self.remotes / "frankentui.git"
        manifest = target / "crates/ftui/Cargo.toml"
        manifest.rename(target / "misplaced.toml")
        git(target, "add", "-A", env=self.env)
        git(target, "commit", "--quiet", "-m", "missing package", env=self.env)
        self.pins["frankentui"] = git(target, "rev-parse", "HEAD", env=self.env)
        self.lock.write_text(self.lock_text())
        self.commit_workspace()
        self.assert_failure(self.run_bootstrap(), "missing Cargo manifest parent")
        self.assertFalse(self.receipt.exists())

    def test_receipt_is_create_only_and_cannot_be_written_inside_inputs(self):
        self.receipt.write_text("preserve")
        self.assert_failure(self.run_bootstrap(), "receipt already exists")
        self.assertEqual(self.receipt.read_text(), "preserve")
        self.assert_failure(self.run_bootstrap(receipt=self.workspace / "receipt.tsv"), "outside the workspace")
        self.assertFalse((self.parent / "franken_engine").exists())

    def test_linked_cargo_manifest_parent_cannot_use_another_checkout(self):
        target = self.remotes / "frankentui.git"
        package = target / "crates/ftui"
        package.rename(target / "saved-ftui")
        package.symlink_to("../saved-ftui", target_is_directory=True)
        git(target, "add", "-A", env=self.env)
        git(target, "commit", "--quiet", "-m", "linked package parent", env=self.env)
        self.pins["frankentui"] = git(target, "rev-parse", "HEAD", env=self.env)
        self.lock.write_text(self.lock_text())
        self.commit_workspace()
        self.assert_failure(self.run_bootstrap(), "linked or missing Cargo manifest parent")
        self.assertFalse(self.receipt.exists())

    def test_explicit_engine_main_resolves_once_and_can_then_be_verified_offline(self):
        self.assert_success(self.run_bootstrap(engine="main"))
        self.assertIn("franken_engine\t" + self.newer["franken_engine"], self.receipt.read_text())
        again = self.root / "verified.tsv"
        self.assert_success(self.run_bootstrap("--verify-only", engine=self.newer["franken_engine"], receipt=again))
        self.assertEqual(self.receipt.read_bytes(), again.read_bytes())

    def test_dangling_receipt_symlink_is_refused(self):
        missing = self.root / "missing"
        self.receipt.symlink_to(missing)
        self.assert_failure(self.run_bootstrap(), "receipt already exists")
        self.assertFalse(missing.exists())

    def test_verify_only_rejects_a_moving_ref(self):
        self.assert_failure(self.run_bootstrap("--verify-only", engine="main"), "resolved engine commit")

    def test_script_remains_bash32_safe(self):
        self.assertEqual(subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True).returncode, 0)
        special = {"BASH_SOURCE", "BASH_LINENO", "FUNCNAME", "PIPESTATUS", "BASH_REMATCH"}
        bare = [name for name in re.findall(r'(?<!\+)"\$\{([A-Za-z_][A-Za-z0-9_]*)\[@\]\}"', SCRIPT.read_text())
                if name not in special]
        self.assertEqual(bare, [])

    def installer_fixture(self, *, helper=True):
        """Real source checkouts; only the expensive compiler boundary is a fixture."""
        scripts = self.workspace / "scripts"
        scripts.mkdir()
        if helper:
            (scripts / "bootstrap_source.sh").write_bytes(SCRIPT.read_bytes())
        (self.workspace / ".gitignore").write_text("/target/\n")
        (self.workspace / "Cargo.lock").write_text("# committed fixture lock\n")
        self.commit_workspace()
        self.node_pin = git(self.workspace, "rev-parse", "HEAD", env=self.env)
        subprocess.run(["git", "clone", "--quiet", "--bare", str(self.workspace),
                        str(self.remotes / "franken_node.git")], env=self.env, check=True,
                       capture_output=True, timeout=15)
        self.tools = self.root / "compiler boundary"
        self.tools.mkdir()
        self.install_dir = self.root / "installed"
        self.install_dir.mkdir()
        self.old_binary = b"#!/usr/bin/env bash\necho old-working-binary\n"
        target = self.install_dir / "franken-node"
        target.write_bytes(self.old_binary)
        target.chmod(0o755)
        self.candidate = self.root / "candidate-executable"
        self.candidate.write_text("#!/usr/bin/env bash\necho franken-node-source-fixture\n")
        self.args_log = self.root / "cargo-arguments"
        self.env_log = self.root / "cargo-provenance"
        compiler = self.tools / "cargo"
        compiler.write_text('''#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$@" > "$TEST_CARGO_ARGS"
printf '%s\\n' "$FRANKEN_NODE_SOURCE_GIT_SHA" "$FRANKEN_ENGINE_SOURCE_GIT_SHA" "$CARGO_TARGET_DIR" > "$TEST_CARGO_ENV"
[ "${TEST_BUILD_FAIL:-0}" = 0 ] || exit 67
mkdir -p "$CARGO_TARGET_DIR/release"
cp "$TEST_CANDIDATE" "$CARGO_TARGET_DIR/release/franken-node"
chmod 0755 "$CARGO_TARGET_DIR/release/franken-node"
case "${TEST_MUTATE:-}" in
  engine) printf changed >> "$(dirname "$(dirname "$CARGO_TARGET_DIR")")/franken_engine/selected.txt" ;;
  lock) printf changed >> "$(dirname "$CARGO_TARGET_DIR")/Cargo.lock" ;;
esac
''')
        compiler.chmod(0o755)
        self.install_env = {**self.env, "PATH": str(self.tools) + os.pathsep + self.env["PATH"],
                            "TEST_CARGO_ARGS": str(self.args_log), "TEST_CARGO_ENV": str(self.env_log),
                            "TEST_CANDIDATE": str(self.candidate), "OWNER": "Dicklesworthstone",
                            "REPO": "franken_node"}

    def install_source(self, *, extra_env=None):
        work = self.root / "source install working directory"
        work.mkdir()
        self.saved_receipt = self.root / "installed-source-inputs.tsv"
        script = f"""source {shlex.quote(str(ROOT / 'install.sh'))}
WORK_DIR={shlex.quote(str(work))}
DEST_DIR={shlex.quote(str(self.install_dir))}
QUIET=1
NODE_REF={shlex.quote(self.node_pin)}
ENGINE_REF={shlex.quote(self.pins['franken_engine'])}
install_from_source
cp "$WORK_DIR/source-inputs.tsv" {shlex.quote(str(self.saved_receipt))}
"""
        # The work directory is owned by this fixture, not the installer's
        # normal TMPDIR pattern. Its refusal to auto-delete is intentional.
        return subprocess.run(["bash", "-c", script], env={**self.install_env, **(extra_env or {})},
                              capture_output=True, text=True, timeout=25)

    def test_source_installer_builds_locked_inputs_then_installs_checked_candidate(self):
        self.installer_fixture()
        self.assert_success(self.install_source())
        self.assertEqual((self.install_dir / "franken-node").read_bytes(), self.candidate.read_bytes())
        arguments = self.args_log.read_text().splitlines()
        self.assertIn("--locked", arguments)
        self.assertNotIn("--no-default-features", arguments)
        self.assertEqual(arguments[-4:], ["-p", "frankenengine-node", "--bin", "franken-node"])
        provenance = self.env_log.read_text().splitlines()
        self.assertEqual(provenance[:2], [self.node_pin, self.pins["franken_engine"]])
        self.assertIn("source/franken_node/target", provenance[2])
        self.assertIn("frankentui\t" + self.pins["frankentui"], self.saved_receipt.read_text())

    def test_source_installer_compile_failure_never_replaces_working_binary(self):
        self.installer_fixture()
        self.assert_failure(self.install_source(extra_env={"TEST_BUILD_FAIL": "1"}), "source build failed")
        self.assertEqual((self.install_dir / "franken-node").read_bytes(), self.old_binary)
        self.assertFalse(self.saved_receipt.exists())

    def test_source_installer_rejects_engine_changes_made_during_build(self):
        self.installer_fixture()
        self.assert_failure(self.install_source(extra_env={"TEST_MUTATE": "engine"}), "source inputs changed during build")
        self.assertEqual((self.install_dir / "franken-node").read_bytes(), self.old_binary)

    def test_source_installer_rejects_lock_changes_made_during_build(self):
        self.installer_fixture()
        self.assert_failure(self.install_source(extra_env={"TEST_MUTATE": "lock"}), "source inputs changed during build")
        self.assertEqual((self.install_dir / "franken-node").read_bytes(), self.old_binary)

    def test_source_installer_missing_bootstrap_does_not_invent_floating_dependencies(self):
        self.installer_fixture(helper=False)
        self.assert_failure(self.install_source(), "selected source lacks scripts/bootstrap_source.sh")
        self.assertFalse(self.args_log.exists())
        self.assertEqual((self.install_dir / "franken-node").read_bytes(), self.old_binary)

    def test_source_installer_rejects_unrunnable_compiler_output_before_replacement(self):
        self.installer_fixture()
        self.candidate.write_text("#!/usr/bin/env bash\nexit 7\n")
        self.assert_failure(self.install_source(), "candidate cannot run on this host")
        self.assertEqual((self.install_dir / "franken-node").read_bytes(), self.old_binary)

    def test_initial_clone_never_deletes_a_preexisting_checkout_even_in_conditional(self):
        result = subprocess.run(["bash", "-c",
            f"source {shlex.quote(str(ROOT / 'install.sh'))}; "
            f"if clone_ref franken_node {shlex.quote(str(self.workspace))} main; then exit 99; fi"],
            env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("source destination already exists", result.stderr)
        self.assertEqual(self.lock.read_text(), self.lock_text())
        self.assertEqual(git(self.workspace, "status", "--porcelain", env=self.env), "")

    def test_checkout_under_autocrlf_keeps_executable_bootstrap_and_lock_in_lf(self):
        scripts = self.workspace / "scripts"
        scripts.mkdir()
        (scripts / "bootstrap_source.sh").write_bytes(SCRIPT.read_bytes())
        (self.workspace / ".gitattributes").write_bytes((ROOT / ".gitattributes").read_bytes())
        self.commit_workspace()
        parent = self.root / "windows-style-checkout"
        parent.mkdir()
        checkout = parent / "franken_node"
        subprocess.run(["git", "-c", "core.autocrlf=true", "clone", "--quiet",
                        str(self.workspace), str(checkout)], env=self.env, check=True,
                       capture_output=True, timeout=15)
        git(checkout, "config", "core.autocrlf", "true", env=self.env)
        for path in ["scripts/bootstrap_source.sh", "packaging/source-siblings.tsv"]:
            self.assertNotIn(b"\r", (checkout / path).read_bytes())
        result = subprocess.run(["bash", str(checkout / "scripts/bootstrap_source.sh"),
            "--workspace", str(checkout), "--engine-ref", self.pins["franken_engine"],
            "--receipt", str(self.root / "autocrlf-inputs.tsv")], env=self.env,
            text=True, capture_output=True, timeout=25)
        self.assert_success(result)


if __name__ == "__main__":
    unittest.main()
