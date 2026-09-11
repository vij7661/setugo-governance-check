#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
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
        spec = importlib.util.spec_from_file_location("release_r2_entry_under_test", ENTRY)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load checker entry")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class ReleaseR2EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.entry = load_entry()

    def run_runner(self, files: dict[str, str], *, env: dict[str, str] | None = None):
        # Mirror the production contract: the runner executes inside an exact
        # Git checkout whose candidate runtime is governance-runtime/.
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            runtime = root / "governance-runtime"
            runtime.mkdir()
            for name, source in files.items():
                path = runtime / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source, encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
            completed = subprocess.run(
                [sys.executable, "-I", str(RUNNER), str(runtime), "test_sample.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
            return completed

    def test_isolated_runner_ignores_pythonpath(self):
        with tempfile.TemporaryDirectory() as injected:
            Path(injected, "poison.py").write_text("MARKER = 'poison'\n", encoding="utf-8")
            env = os.environ.copy()
            env["PYTHONPATH"] = injected
            completed = self.run_runner(
                {"test_sample.py": "import sys\ndef test_no_pythonpath():\n    assert all('" + injected.replace("\\", "\\\\") + "' not in p for p in sys.path)\n"},
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_candidate_sitecustomize_not_executed(self):
        completed = self.run_runner({
            "sitecustomize.py": "raise SystemExit('candidate sitecustomize executed')\n",
            "test_sample.py": "def test_alive():\n    assert True\n",
        })
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_candidate_usercustomize_not_executed(self):
        completed = self.run_runner({
            "usercustomize.py": "raise SystemExit('candidate usercustomize executed')\n",
            "test_sample.py": "def test_alive():\n    assert True\n",
        })
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_candidate_pth_not_processed(self):
        completed = self.run_runner({
            "candidate.pth": "import sys; raise SystemExit('candidate pth executed')\n",
            "test_sample.py": "def test_alive():\n    assert True\n",
        })
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_pytest_and_conftest_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            runtime = Path(td) / "governance-runtime"
            runtime.mkdir()
            (runtime / "conftest.py").write_text("raise SystemExit('conftest executed')\n", encoding="utf-8")
            with self.assertRaisesRegex(AssertionError, "pytest/plugin collection"):
                self.entry._isolating_run([sys.executable, "-m", "pytest", "test_phase_policy.py"], cwd=runtime)

    def test_unittest_discovery_shape_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            runtime = Path(td) / "governance-runtime"
            runtime.mkdir()
            with self.assertRaisesRegex(AssertionError, "not explicitly bound to pinned test modules"):
                self.entry._isolating_run([sys.executable, "-m", "unittest", "discover"], cwd=runtime)

    def test_unpinned_explicit_test_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            runtime = Path(td) / "governance-runtime"
            runtime.mkdir()
            with self.assertRaisesRegex(AssertionError, "ungoverned candidate qualification test"):
                self.entry._isolating_run([sys.executable, "-m", "unittest", "test_unpinned.py"], cwd=runtime)

    def test_zero_test_module_is_rejected(self):
        completed = self.run_runner({"test_sample.py": "VALUE = 1\n"})
        self.assertNotEqual(completed.returncode, 0)
        self.assertIn("zero executable tests", completed.stdout + completed.stderr)

    def test_async_generator_and_generator_shapes_rejected(self):
        vectors = {
            "async": "async def test_async():\n    return None\n",
            "generator": "def test_generator():\n    yield 1\n",
            "async_generator": "async def test_async_generator():\n    yield 1\n",
        }
        for label, source in vectors.items():
            with self.subTest(label=label):
                completed = self.run_runner({"test_sample.py": source})
                self.assertNotEqual(completed.returncode, 0)

    def test_representative_stdlib_collisions_rejected(self):
        names = ["unittest.py", "json.py", "email.py", "pathlib.py", "os.py"]
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as td:
                root = Path(td)
                runtime = root / "governance-runtime"
                runtime.mkdir()
                (runtime / name).write_text("X = 1\n", encoding="utf-8")
                old = self.entry._original_dependency_closure
                self.entry._original_dependency_closure = lambda _root: None
                try:
                    with self.assertRaisesRegex(AssertionError, "stdlib namespace collision"):
                        self.entry._verify_r11_dependency_closure(root)
                finally:
                    self.entry._original_dependency_closure = old


if __name__ == "__main__":
    unittest.main(verbosity=2)
