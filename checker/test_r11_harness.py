#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
ENTRY = HERE / "falsify_candidate_r10_entry.py"
RUNNER = HERE / "run_candidate_unittests_isolated.py"


def load_entry():
    sys.path.insert(0, str(HERE))
    try:
        spec = importlib.util.spec_from_file_location("r11_entry_under_test", ENTRY)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load R11 entry")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class R11HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry = load_entry()

    def run_runner(self, source: str):
        with tempfile.TemporaryDirectory() as td:
            runtime = Path(td)
            (runtime / "test_sample.py").write_text(source, encoding="utf-8")
            return subprocess.run(
                [sys.executable, "-I", str(RUNNER), str(runtime), "test_sample.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

    def test_sync_zero_arg_top_level_executes(self):
        completed = self.run_runner("def test_sync():\n    assert 2 + 2 == 4\n")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn("PASS test_sample.test_sync", completed.stdout)

    def test_async_top_level_fails_closed(self):
        completed = self.run_runner("async def test_async():\n    raise AssertionError('body')\n")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unsupported async qualification test", completed.stderr + completed.stdout)

    def test_generator_top_level_fails_closed(self):
        completed = self.run_runner("def test_generator():\n    yield 1\n")
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("unsupported generator qualification test", completed.stderr + completed.stdout)

    def test_unittest_discovery_without_explicit_pins_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            runtime = Path(td) / "governance-runtime"
            runtime.mkdir()
            with self.assertRaisesRegex(AssertionError, "not explicitly bound to pinned test modules"):
                self.entry._isolating_run([sys.executable, "-m", "unittest", "discover"], cwd=runtime)

    def test_pytest_path_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            runtime = Path(td) / "governance-runtime"
            runtime.mkdir()
            with self.assertRaisesRegex(AssertionError, "pytest/plugin collection"):
                self.entry._isolating_run([sys.executable, "-m", "pytest", "test_phase_policy.py"], cwd=runtime)

    def test_unknown_test_module_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            runtime = Path(td) / "governance-runtime"
            runtime.mkdir()
            with self.assertRaisesRegex(AssertionError, "ungoverned candidate qualification test"):
                self.entry._isolating_run([sys.executable, "-m", "unittest", "test_unpinned.py"], cwd=runtime)

    def test_comprehensive_stdlib_collision_rejected(self):
        # `email` is deliberately outside the old hand-maintained eight-name list.
        self.assertIn("email", self.entry.STDLIB_NAMES)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runtime = root / "governance-runtime"
            runtime.mkdir()
            (runtime / "email.py").write_text("x = 1\n", encoding="utf-8")
            old = self.entry._original_dependency_closure
            self.entry._original_dependency_closure = lambda _root: None
            try:
                with self.assertRaisesRegex(AssertionError, "stdlib namespace collision"):
                    self.entry._verify_r11_dependency_closure(root)
            finally:
                self.entry._original_dependency_closure = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
