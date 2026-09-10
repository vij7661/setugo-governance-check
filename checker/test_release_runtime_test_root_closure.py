#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import verify_release_runtime_import_closure as gate


class ReleaseRuntimeTestRootClosureTests(unittest.TestCase):
    def _repo(self, files: dict[str, str]):
        td = tempfile.TemporaryDirectory(prefix="setugo-test-root-closure-")
        repo = Path(td.name)
        runtime = repo / gate.RUNTIME_DIR
        runtime.mkdir(parents=True)
        for relpath, content in files.items():
            path = runtime / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
        return td, repo

    def _blob(self, repo: Path, relpath: str) -> str:
        out = subprocess.check_output(
            ["git", "ls-tree", "HEAD", "--", f"governance-runtime/{relpath}"],
            cwd=repo, text=True,
        ).strip().split()
        return out[2]

    def test_unpinned_helper_imported_only_by_pinned_test_fails_closed(self):
        td, repo = self._repo({
            "core.py": "VALUE = 1\n",
            "helper.py": "VALUE = 2\n",
            "test_entry.py": "import helper\n",
        })
        try:
            pinned = {"core.py": self._blob(repo, "core.py")}
            with mock.patch.object(gate, "PINNED_RUNTIME_BLOBS", pinned), \
                 mock.patch.object(gate, "ENTRY_POINTS", frozenset(pinned)), \
                 mock.patch.object(gate, "QUALIFICATION_TEST_FILES", frozenset({"test_entry.py"})):
                with self.assertRaisesRegex(AssertionError, "TEST:test_entry.py -> helper.py"):
                    gate.verify_repo(repo)
        finally:
            td.cleanup()

    def test_exact_pinned_helper_imported_by_pinned_test_is_recorded(self):
        td, repo = self._repo({
            "core.py": "VALUE = 1\n",
            "helper.py": "VALUE = 2\n",
            "test_entry.py": "import helper\n",
        })
        try:
            pinned = {
                "core.py": self._blob(repo, "core.py"),
                "helper.py": self._blob(repo, "helper.py"),
            }
            with mock.patch.object(gate, "PINNED_RUNTIME_BLOBS", pinned), \
                 mock.patch.object(gate, "ENTRY_POINTS", frozenset(pinned)), \
                 mock.patch.object(gate, "QUALIFICATION_TEST_FILES", frozenset({"test_entry.py"})):
                graph = gate.verify_repo(repo)
                self.assertEqual(["helper.py"], graph["TEST:test_entry.py"])
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
