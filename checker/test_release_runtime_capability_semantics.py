#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import verify_release_runtime_import_closure as gate


class ReleaseRuntimeCapabilitySemanticsTests(unittest.TestCase):
    def _repo(self, source: str):
        td = tempfile.TemporaryDirectory(prefix="setugo-capability-semantics-")
        repo = Path(td.name)
        runtime = repo / gate.RUNTIME_DIR
        runtime.mkdir(parents=True)
        (runtime / "entry.py").write_text(source, encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
        return td, repo

    def _verify_single(self, source: str):
        td, repo = self._repo(source)
        try:
            pinned = {"entry.py": gate._blob_sha(repo, "governance-runtime/entry.py")}
            with mock.patch.object(gate, "PINNED_RUNTIME_BLOBS", pinned), \
                 mock.patch.object(gate, "ENTRY_POINTS", frozenset(pinned)):
                return gate.verify_repo(repo)
        finally:
            td.cleanup()

    def test_re_compile_is_not_python_dynamic_compile_capability(self):
        graph = self._verify_single("import re\nRX = re.compile(r'^[a-z]+$')\n")
        self.assertEqual([], graph["entry.py"])

    def test_application_dictionary_key_named_compile_is_not_builtin_dispatch(self):
        graph = self._verify_single("config = {'compile': 'literal'}\nVALUE = config['compile']\n")
        self.assertEqual([], graph["entry.py"])

    def test_builtin_compile_reference_still_fails_closed(self):
        td, repo = self._repo("fn = compile\n")
        try:
            pinned = {"entry.py": gate._blob_sha(repo, "governance-runtime/entry.py")}
            with mock.patch.object(gate, "PINNED_RUNTIME_BLOBS", pinned), \
                 mock.patch.object(gate, "ENTRY_POINTS", frozenset(pinned)):
                with self.assertRaisesRegex(AssertionError, "dynamic import/lookup/execution capability forbidden"):
                    gate.verify_repo(repo)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
