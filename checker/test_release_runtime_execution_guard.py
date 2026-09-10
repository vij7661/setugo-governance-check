#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "run_candidate_unittests_isolated.py"


class ReleaseRuntimeExecutionGuardTests(unittest.TestCase):
    def _repo(self, files: dict[str, str]):
        td = tempfile.TemporaryDirectory(prefix="setugo-runtime-exec-guard-")
        repo = Path(td.name)
        runtime = repo / "governance-runtime"
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
        return td, repo, runtime

    def _blob(self, repo: Path, relpath: str) -> str:
        out = subprocess.check_output(
            ["git", "ls-tree", "HEAD", "--", f"governance-runtime/{relpath}"],
            cwd=repo,
            text=True,
        ).strip().split()
        return out[2]

    def _run(self, runtime: Path, manifest: dict[str, str], *tests: str):
        encoded = base64.b64encode(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        return subprocess.run(
            [
                sys.executable,
                "-I",
                str(RUNNER),
                str(runtime),
                "--runtime-pin-manifest-b64",
                encoded,
                *tests,
            ],
            cwd=HERE,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def test_exact_pinned_runtime_module_can_load(self):
        td, repo, runtime = self._repo({
            "pinned.py": "import json\nVALUE = json.loads('1')\n",
            "test_entry.py": (
                "import unittest\nimport pinned\n"
                "class T(unittest.TestCase):\n"
                "    def test_value(self): self.assertEqual(1, pinned.VALUE)\n"
            ),
        })
        try:
            result = self._run(runtime, {"pinned.py": self._blob(repo, "pinned.py")}, "test_entry.py")
            self.assertEqual(0, result.returncode, result.stdout)
        finally:
            td.cleanup()

    def test_indirect_import_of_unpinned_candidate_module_fails_closed(self):
        td, repo, runtime = self._repo({
            "pinned.py": (
                "import importlib\n"
                "def load_hidden(): return getattr(importlib, 'import_module')('hidden')\n"
            ),
            "hidden.py": "VALUE = 7\n",
            "test_entry.py": (
                "import unittest\nimport pinned\n"
                "class T(unittest.TestCase):\n"
                "    def test_hidden(self): self.assertEqual(7, pinned.load_hidden().VALUE)\n"
            ),
        })
        try:
            result = self._run(runtime, {"pinned.py": self._blob(repo, "pinned.py")}, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("runtime guard rejected unpinned candidate-local module", result.stdout)
        finally:
            td.cleanup()

    def test_runpy_execution_of_unpinned_candidate_file_fails_closed(self):
        td, repo, runtime = self._repo({
            "pinned.py": (
                "import runpy\nfrom pathlib import Path\n"
                "def load_hidden(): return runpy.run_path(str(Path(__file__).with_name('hidden.py')))\n"
            ),
            "hidden.py": "VALUE = 9\n",
            "test_entry.py": (
                "import unittest\nimport pinned\n"
                "class T(unittest.TestCase):\n"
                "    def test_hidden(self): self.assertEqual(9, pinned.load_hidden()['VALUE'])\n"
            ),
        })
        try:
            result = self._run(runtime, {"pinned.py": self._blob(repo, "pinned.py")}, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("runtime guard rejected execution of unpinned candidate file", result.stdout)
        finally:
            td.cleanup()

    def test_dynamic_exec_obtained_through_builtins_attribute_fails_closed(self):
        td, repo, runtime = self._repo({
            "pinned.py": (
                "import builtins\n"
                "def execute():\n"
                "    fn = builtins.exec\n"
                "    fn('VALUE = 1')\n"
            ),
            "test_entry.py": (
                "import unittest\nimport pinned\n"
                "class T(unittest.TestCase):\n"
                "    def test_exec(self): pinned.execute()\n"
            ),
        })
        try:
            result = self._run(runtime, {"pinned.py": self._blob(repo, "pinned.py")}, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("runtime guard rejected synthetic dynamic code execution", result.stdout)
        finally:
            td.cleanup()

    def test_dynamic_exec_spoofing_pinned_filename_fails_closed(self):
        td, repo, runtime = self._repo({
            "pinned.py": (
                "import builtins\n"
                "def execute():\n"
                "    code = builtins.compile('VALUE = 1', __file__, 'exec')\n"
                "    builtins.exec(code)\n"
            ),
            "test_entry.py": (
                "import unittest\nimport pinned\n"
                "class T(unittest.TestCase):\n"
                "    def test_exec(self): pinned.execute()\n"
            ),
        })
        try:
            result = self._run(runtime, {"pinned.py": self._blob(repo, "pinned.py")}, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("runtime guard rejected direct dynamic code execution", result.stdout)
        finally:
            td.cleanup()

    def test_manifest_blob_substitution_fails_before_test_execution(self):
        td, repo, runtime = self._repo({
            "pinned.py": "VALUE = 1\n",
            "test_entry.py": (
                "import unittest\nimport pinned\n"
                "class T(unittest.TestCase):\n"
                "    def test_value(self): self.assertEqual(1, pinned.VALUE)\n"
            ),
        })
        try:
            result = self._run(runtime, {"pinned.py": "0" * 40}, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("runtime guard blob mismatch", result.stdout)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
