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


def _blob(repo: Path, relpath: str) -> str:
    out = subprocess.check_output(["git", "ls-tree", "HEAD", "--", relpath], cwd=repo, text=True)
    parts = out.strip().split()
    if len(parts) < 3:
        raise AssertionError(relpath)
    return parts[2]


class RuntimeObservationGateTests(unittest.TestCase):
    def _repo(self, files: dict[str, str]):
        td = tempfile.TemporaryDirectory(prefix="setugo-runtime-observation-")
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

    def _run(self, runtime: Path, pins: dict[str, str], test_file: str = "test_entry.py"):
        encoded = base64.b64encode(json.dumps(pins, sort_keys=True).encode("utf-8")).decode("ascii")
        return subprocess.run(
            [sys.executable, "-I", str(RUNNER), str(runtime), "--runtime-pins-b64", encoded, test_file],
            cwd=HERE,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def test_pinned_runtime_module_loaded_during_test_is_accepted(self):
        td, repo, runtime = self._repo({
            "allowed.py": "VALUE = 1\n",
            "test_entry.py": "def test_load():\n    import allowed\n    assert allowed.VALUE == 1\n",
        })
        try:
            pins = {"allowed.py": _blob(repo, "governance-runtime/allowed.py")}
            result = self._run(runtime, pins)
            self.assertEqual(0, result.returncode, result.stdout)
        finally:
            td.cleanup()

    def test_unpinned_module_loaded_via_importlib_fails_at_runtime(self):
        td, repo, runtime = self._repo({
            "hidden.py": "VALUE = 1\n",
            "test_entry.py": "def test_load():\n    import importlib\n    importlib.import_module('hidden')\n",
        })
        try:
            result = self._run(runtime, {})
            self.assertNotEqual(0, result.returncode)
            self.assertIn("unpinned candidate runtime module executed", result.stdout)
        finally:
            td.cleanup()

    def test_unpinned_module_cannot_hide_by_removing_itself_from_sys_modules(self):
        td, repo, runtime = self._repo({
            "hidden.py": "VALUE = 1\n",
            "test_entry.py": "def test_load():\n    import hidden, sys\n    sys.modules.pop('hidden', None)\n",
        })
        try:
            result = self._run(runtime, {})
            self.assertNotEqual(0, result.returncode)
            self.assertIn("unpinned candidate runtime module executed", result.stdout)
        finally:
            td.cleanup()

    def test_low_level_exec_module_of_unpinned_file_fails(self):
        td, repo, runtime = self._repo({
            "hidden.py": "VALUE = 1\n",
            "test_entry.py": (
                "def test_load():\n"
                "    import importlib.util\n"
                "    from pathlib import Path\n"
                "    p = Path(__file__).with_name('hidden.py')\n"
                "    spec = importlib.util.spec_from_file_location('x_hidden', p)\n"
                "    mod = importlib.util.module_from_spec(spec)\n"
                "    spec.loader.exec_module(mod)\n"
            ),
        })
        try:
            result = self._run(runtime, {})
            self.assertNotEqual(0, result.returncode)
            self.assertIn("unpinned candidate runtime module executed", result.stdout)
        finally:
            td.cleanup()

    def test_unpinned_package_submodule_fails_even_when_package_init_is_pinned(self):
        td, repo, runtime = self._repo({
            "pkg/__init__.py": "\n",
            "pkg/sub.py": "VALUE = 1\n",
            "test_entry.py": "def test_load():\n    import pkg.sub\n",
        })
        try:
            pins = {"pkg/__init__.py": _blob(repo, "governance-runtime/pkg/__init__.py")}
            result = self._run(runtime, pins)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("pkg/sub.py", result.stdout)
        finally:
            td.cleanup()

    def test_loaded_module_blob_mismatch_fails_closed(self):
        td, repo, runtime = self._repo({
            "allowed.py": "VALUE = 1\n",
            "test_entry.py": "def test_load():\n    import allowed\n",
        })
        try:
            result = self._run(runtime, {"allowed.py": "0" * 40})
            self.assertNotEqual(0, result.returncode)
            self.assertIn("candidate runtime blob mismatch", result.stdout)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
