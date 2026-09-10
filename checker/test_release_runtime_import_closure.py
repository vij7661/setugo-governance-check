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
            path = runtime / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
        return td, repo

    def _assert_dynamic_rejected(self, source: str) -> None:
        td, repo = self._repo({"entry.py": source})
        try:
            pinned = {"entry.py": gate._blob_sha(repo, "governance-runtime/entry.py")}
            with mock.patch.object(gate, "PINNED_RUNTIME_BLOBS", pinned), \
                 mock.patch.object(gate, "ENTRY_POINTS", frozenset(pinned)):
                with self.assertRaisesRegex(
                    AssertionError,
                    "dynamic import/lookup/execution capability forbidden",
                ):
                    gate.verify_repo(repo)
        finally:
            td.cleanup()

    def test_unpinned_candidate_local_import_fails_closed(self):
        td, repo = self._repo({"entry.py": "import hidden\n", "hidden.py": "VALUE = 1\n"})
        try:
            with mock.patch.object(
                gate,
                "PINNED_RUNTIME_BLOBS",
                {"entry.py": gate._blob_sha(repo, "governance-runtime/entry.py")},
            ), mock.patch.object(gate, "ENTRY_POINTS", frozenset({"entry.py"})):
                with self.assertRaisesRegex(AssertionError, "unpinned candidate-local import"):
                    gate.verify_repo(repo)
        finally:
            td.cleanup()

    def test_direct_and_attribute_dynamic_symbols_fail_closed(self):
        for source in (
            "x = __import__\n",
            "x = exec\n",
            "x = eval\n",
            "x = compile\n",
            "import builtins\nx = builtins.exec\n",
            "import builtins\nx = builtins.eval\n",
            "import builtins\nx = builtins.compile\n",
            "import importlib\nx = importlib.__import__\n",
            "import importlib\nx = importlib.import_module\n",
        ):
            with self.subTest(source=source):
                self._assert_dynamic_rejected(source)

    def test_getattr_dynamic_dispatch_is_rejected_as_capability(self):
        for source in (
            "import builtins\ngetattr(builtins, 'exec')('x=1')\n",
            "import builtins\nname='ex'+'ec'\ngetattr(builtins, name)('x=1')\n",
            "import importlib\ngetattr(importlib, '__import__')('x')\n",
            "obj = object()\ngetattr(obj, 'anything', None)\n",
        ):
            with self.subTest(source=source):
                self._assert_dynamic_rejected(source)

    def test_builtins_subscript_dynamic_dispatch_is_rejected(self):
        for source in (
            "__builtins__['exec']('x=1')\n",
            "__builtins__['eval']('1+1')\n",
            "__builtins__['compile']('x=1','<x>','exec')\n",
            "__builtins__['__import__']('x')\n",
        ):
            with self.subTest(source=source):
                self._assert_dynamic_rejected(source)

    def test_importlib_runpy_and_builtins_imports_fail_closed(self):
        for source in (
            "import importlib\n",
            "import runpy\n",
            "import builtins\n",
            "from importlib import import_module\n",
        ):
            with self.subTest(source=source):
                self._assert_dynamic_rejected(source)

    def test_exec_eval_and_compile_fail_closed(self):
        for source in (
            "exec(\"import hidden\")\n",
            "eval(\"__import__('hidden')\")\n",
            "compile(\"import hidden\", '<x>', 'exec')\n",
        ):
            with self.subTest(source=source):
                self._assert_dynamic_rejected(source)

    def test_unpinned_local_package_import_fails_closed(self):
        td, repo = self._repo({
            "entry.py": "import hiddenpkg\n",
            "hiddenpkg/__init__.py": "VALUE = 1\n",
        })
        try:
            with mock.patch.object(
                gate,
                "PINNED_RUNTIME_BLOBS",
                {"entry.py": gate._blob_sha(repo, "governance-runtime/entry.py")},
            ), mock.patch.object(gate, "ENTRY_POINTS", frozenset({"entry.py"})):
                with self.assertRaisesRegex(
                    AssertionError,
                    r"entry\.py -> hiddenpkg/__init__\.py",
                ):
                    gate.verify_repo(repo)
        finally:
            td.cleanup()

    def test_pinned_local_package_is_audited(self):
        td, repo = self._repo({
            "entry.py": "import pkg\n",
            "pkg/__init__.py": "VALUE = 1\n",
        })
        try:
            pinned = {
                "entry.py": gate._blob_sha(repo, "governance-runtime/entry.py"),
                "pkg/__init__.py": gate._blob_sha(repo, "governance-runtime/pkg/__init__.py"),
            }
            with mock.patch.object(gate, "PINNED_RUNTIME_BLOBS", pinned), \
                 mock.patch.object(gate, "ENTRY_POINTS", frozenset(pinned)):
                graph = gate.verify_repo(repo)
                self.assertEqual(["pkg/__init__.py"], graph["entry.py"])
                self.assertIn("pkg/__init__.py", graph)
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
