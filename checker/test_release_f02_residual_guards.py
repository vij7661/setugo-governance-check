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
RUNNER = HERE / "run_candidate_unittests_isolated_v2.py"


class ReleaseF02ResidualGuardTests(unittest.TestCase):
    def _repo(self, runtime_files: dict[str, str]):
        td = tempfile.TemporaryDirectory(prefix="setugo-f02-residual-")
        repo = Path(td.name)
        runtime = repo / "governance-runtime"
        runtime.mkdir(parents=True)
        for relpath, content in runtime_files.items():
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
        parts = subprocess.check_output(
            ["git", "ls-tree", "HEAD", "--", relpath], cwd=repo, text=True
        ).strip().split()
        return parts[2]

    def _run(self, repo: Path, runtime: Path, *tests: str):
        manifest = {
            f"governance-runtime/{name}": self._blob(repo, f"governance-runtime/{name}")
            for name in tests
        }
        if (runtime / "pinned.py").exists():
            manifest["governance-runtime/pinned.py"] = self._blob(repo, "governance-runtime/pinned.py")
        encoded = base64.b64encode(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        return subprocess.run(
            [sys.executable, "-I", str(RUNNER), str(runtime), "--runtime-pin-manifest-b64", encoded, *tests],
            cwd=HERE,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )

    def test_direct_posixsubprocess_fork_exec_fails_closed(self):
        td, repo, runtime = self._repo({
            "pinned.py": "import _posixsubprocess\ndef execute(): _posixsubprocess.fork_exec()\n",
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_x(self): pinned.execute()\n",
        })
        try:
            result = self._run(repo, runtime, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("direct low-level process execution: fork_exec", result.stdout)
        finally:
            td.cleanup()

    def test_direct_subprocess_private_fork_exec_fails_closed(self):
        td, repo, runtime = self._repo({
            "pinned.py": "import subprocess\ndef execute(): subprocess._fork_exec()\n",
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_x(self): pinned.execute()\n",
        })
        try:
            result = self._run(repo, runtime, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("direct low-level process execution: fork_exec", result.stdout)
        finally:
            td.cleanup()

    def test_main_module_exposes_no_original_fork_exec_capability(self):
        td, repo, runtime = self._repo({
            "pinned.py": (
                "import __main__, subprocess, _posixsubprocess\n"
                "def execute():\n"
                "    assert not hasattr(__main__, '_ORIGINAL_FORK_EXEC')\n"
                "    assert not hasattr(__main__, '_FORK_EXEC_STATE')\n"
                "    subprocess._fork_exec()\n"
            ),
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_x(self): pinned.execute()\n",
        })
        try:
            result = self._run(repo, runtime, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("direct low-level process execution: fork_exec", result.stdout)
        finally:
            td.cleanup()

    def test_external_runpy_rejected_regardless_of_extension(self):
        for filename in ("setugo-f02-evil.txt", "setugo-f02-evil", "setugo-f02-evil.pyw", "setugo-f02-evil.PY"):
            with self.subTest(filename=filename):
                td, repo, runtime = self._repo({
                    "pinned.py": (
                        "import runpy, tempfile\nfrom pathlib import Path\n"
                        f"FILENAME={filename!r}\n"
                        "def execute():\n"
                        "    path=Path(tempfile.gettempdir())/FILENAME\n"
                        "    path.write_text('VALUE=17\\n', encoding='utf-8')\n"
                        "    try: return runpy.run_path(str(path))\n"
                        "    finally: path.unlink(missing_ok=True)\n"
                    ),
                    "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_x(self): pinned.execute()\n",
                })
                try:
                    result = self._run(repo, runtime, "test_entry.py")
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("untrusted external file", result.stdout)
                finally:
                    td.cleanup()

    def test_sourcefileloader_temp_python_fails_closed(self):
        td, repo, runtime = self._repo({
            "pinned.py": (
                "import importlib.machinery, tempfile\nfrom pathlib import Path\n"
                "def execute():\n"
                "    path=Path(tempfile.gettempdir())/'setugo-f02-loader-temp.txt'\n"
                "    path.write_text('VALUE=19\\n', encoding='utf-8')\n"
                "    try:\n"
                "        loader=importlib.machinery.SourceFileLoader('setugo_f02_external', str(path))\n"
                "        return loader.load_module()\n"
                "    finally: path.unlink(missing_ok=True)\n"
            ),
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_x(self): pinned.execute()\n",
        })
        try:
            result = self._run(repo, runtime, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("untrusted external file", result.stdout)
        finally:
            td.cleanup()

    def test_arbitrary_subprocess_is_denied_after_crypto_helper_start(self):
        td, repo, runtime = self._repo({
            "pinned.py": "import subprocess, sys\ndef execute(): subprocess.run([sys.executable, '-c', 'print(1)'])\n",
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_x(self): pinned.execute()\n",
        })
        try:
            result = self._run(repo, runtime, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("candidate-originated subprocess execution", result.stdout)
        finally:
            td.cleanup()

    def test_existing_openssl_sandbox_still_allows_exact_der_shape(self):
        td, repo, runtime = self._repo({
            "pinned.py": (
                "import subprocess, tempfile\nfrom pathlib import Path\n"
                "def execute():\n"
                "    with tempfile.TemporaryDirectory(prefix='setugo-f02-openssl-') as td:\n"
                "        root=Path(td); priv=root/'k.pem'; pub=root/'p.pem'; der=root/'p.der'\n"
                "        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(priv)],check=True)\n"
                "        subprocess.run(['openssl','pkey','-in',str(priv),'-pubout','-out',str(pub)],check=True)\n"
                "        subprocess.run(['openssl','pkey','-pubin','-in',str(pub),'-outform','DER','-out',str(der)],check=True)\n"
                "        assert der.read_bytes()\n"
            ),
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_x(self): pinned.execute()\n",
        })
        try:
            result = self._run(repo, runtime, "test_entry.py")
            self.assertEqual(0, result.returncode, result.stdout)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
