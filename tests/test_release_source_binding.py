"""Execute the actual pre-signing workflow guard on real receipt/checksum files.

Archive payloads are fixtures, not compiled products. This does not run GitHub
Actions, sign a release, or prove that the selected Rust inputs compile.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/dist.yml"
STEP = "Require the complete platform set and certified sources before signing"
TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
           "aarch64-apple-darwin", "x86_64-pc-windows-msvc")
REVISION = "a" * 40


def guard_script() -> str:
    # This is a deliberately narrow extractor for this workflow's literal
    # block, not a YAML interpreter. A moved/renamed/nonliteral step fails the
    # test instead of running a second copy of the implementation.
    lines = WORKFLOW.read_text().splitlines()
    marker = f"      - name: {STEP}"
    if lines.count(marker) != 1:
        raise AssertionError("release-source guard step must exist exactly once")
    start = lines.index(marker) + 1
    if lines[start:start + 2] != ["        shell: bash", "        run: |"]:
        raise AssertionError("release-source guard must be an explicit literal Bash block")
    result = []
    for line in lines[start + 2:]:
        if not line.startswith("          "):
            break
        result.append(line[10:])
    if not result:
        raise AssertionError("release-source guard must not be empty")
    return "\n".join(result) + "\n"


class ReleaseSourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="release source binding ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.certified = f"franken-node-source-inputs-{REVISION}.tsv"
        self.receipt = ("# franken-node/source-inputs/v1\n"
                        + "# source-siblings-sha256\t" + "c" * 64 + "\n"
                        + f"franken_node\t{REVISION}\n"
                        + "".join(f"{name}\t{'b' * 40}\n" for name in
                                  ("franken_engine", "frankentui", "fastapi_rust", "sqlmodel_rust"))).encode()
        self.write(self.certified, self.receipt)
        for target in TARGETS:
            extension = "zip" if "windows" in target else "tar.xz"
            self.write(f"franken-node-{target}.{extension}", b"archive fixture\n")
            self.write(f"franken-node-{target}.source-inputs.tsv", self.receipt)
        self.env = {**os.environ, "GITHUB_SHA": REVISION}

    def write(self, name: str, data: bytes):
        (self.dist / name).write_bytes(data)
        (self.dist / (name + ".sha256")).write_text(hashlib.sha256(data).hexdigest() + "  " + name + "\n")

    def run_guard(self):
        return subprocess.run(["bash", "-c", guard_script()], cwd=self.root, env=self.env,
                              capture_output=True, text=True, timeout=10)

    def assert_refused(self):
        result = self.run_guard()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_complete_matching_platforms_are_accepted_without_changing_files(self):
        before = {path.name: path.read_bytes() for path in self.dist.iterdir()}
        result = self.run_guard()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.dist.iterdir()})

    def test_valid_checksums_cannot_hide_a_different_platform_dependency_revision(self):
        name = "franken-node-aarch64-unknown-linux-gnu.source-inputs.tsv"
        # Recompute the sidecar too: this is an internally consistent artifact
        # whose dependency input differs from the certified one, not corruption.
        changed = self.receipt.replace(b"frankentui\t" + b"b" * 40, b"frankentui\t" + b"d" * 40)
        self.write(name, changed)
        self.assert_refused()

    def test_valid_checksums_cannot_hide_a_different_engine_or_node_revision(self):
        for repo in ("franken_engine", "franken_node"):
            with self.subTest(repo=repo):
                name = "franken-node-x86_64-pc-windows-msvc.source-inputs.tsv"
                old = REVISION if repo == "franken_node" else "b" * 40
                self.write(name, self.receipt.replace(f"{repo}\t{old}".encode(), f"{repo}\t{'f' * 40}".encode()))
                self.assert_refused()
                self.write(name, self.receipt)

    def test_missing_arm_archive_is_not_an_acceptable_three_platform_release(self):
        path = self.dist / "franken-node-aarch64-unknown-linux-gnu.tar.xz"
        path.rename(path.with_suffix(".unavailable"))
        self.assert_refused()

    def test_missing_source_receipt_is_refused_even_when_the_binary_exists(self):
        path = self.dist / "franken-node-aarch64-apple-darwin.source-inputs.tsv"
        path.rename(path.with_suffix(".unavailable"))
        self.assert_refused()

    def test_missing_certification_receipt_is_refused(self):
        path = self.dist / self.certified
        path.rename(path.with_suffix(".unavailable"))
        self.assert_refused()

    def test_corrupt_archive_or_receipt_is_refused(self):
        for name in ("franken-node-x86_64-unknown-linux-gnu.tar.xz", self.certified,
                     "franken-node-aarch64-unknown-linux-gnu.source-inputs.tsv"):
            with self.subTest(name=name):
                path = self.dist / name
                before = path.read_bytes()
                path.write_bytes(before + b"corrupted")
                self.assert_refused()
                path.write_bytes(before)

    def test_missing_or_malformed_checksum_cannot_be_ignored(self):
        for content in (b"", b"not-a-checksum\n", b"0" * 64 + b"  absent-artifact\n"):
            with self.subTest(content=content):
                sidecar = self.dist / (self.certified + ".sha256")
                before = sidecar.read_bytes()
                sidecar.write_bytes(content)
                self.assert_refused()
                sidecar.write_bytes(before)

    def test_certification_from_another_workflow_revision_is_not_used(self):
        self.env["GITHUB_SHA"] = "e" * 40
        self.assert_refused()


if __name__ == "__main__":
    unittest.main()
