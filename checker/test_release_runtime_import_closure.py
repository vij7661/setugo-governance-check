#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import verify_release_runtime_import_closure as gate


class ReleaseRuntimeImportClosureTests(unittest.TestCase):
    def _repo(self, files: dict[str, str]) -> tuple[tempfile.TemporaryDirectory, Path]:
        td = tempfile.TemporaryDirectory(prefix="setugo-runtime-closure-test-")
        repo = Path(td.name)
        runtime = repo / gate.RUNTIME_DIR
        runtime.mkdir(parents=True)
        for name, content in files.items():
            (runtime / name).write_text(content, encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
        return td, repo

    def test_unpinned_candidate_local_import_fails_closed(self):
        td, repo = self._repo({"entry.py": "import hidden\n", "hidden.py": "VALUE = 1\n"})
        try:
            with mock.patch.object(gate, "PINNED_RUNTIME_BLOBS", {"entry.py": gate._blob_sha(repo, "governance-runtime/entry.py")}), \
                 mock.patch.object(gate, "ENTRY_POINTS", frozenset({"entry.py"})):
                with self.assertRaisesRegex(AssertionError, "unpinned candidate-local import"):
                    gate.verify_repo(repo)
        finally:
            td.cleanup()

    def test_dynamic_import_construct_fails_closed(self):
        td, repo = self._repo({"entry.py": "import importlib\nimportlib.import_module('x')\n"})
        try:
            with mock.patch.object(gate, "PINNED_RUNTIME_BLOBS", {"entry.py": gate._blob_sha(repo, "governance-runtime/entry.py")}), \
                 mock.patch.object(gate, "ENTRY_POINTS", frozenset({"entry.py"})):
                with self.assertRaisesRegex(AssertionError, "dynamic import construct forbidden"):
                    gate.verify_repo(repo)
        finally:
            td.cleanup()

    def test_blob_substitution_fails_closed(self):
        td, repo = self._repo({"entry.py": "VALUE = 1\n"})
        try:
            with mock.patch.object(gate, "PINNED_RUNTIME_BLOBS", {"entry.py": "0" * 40}), \
                 mock.patch.object(gate, "ENTRY_POINTS", frozenset({"entry.py"})):
                with self.assertRaisesRegex(AssertionError, "runtime closure blob mismatch"):
                    gate.verify_repo(repo)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
