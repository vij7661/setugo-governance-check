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
    def _repo(self, runtime_files: dict[str, str], root_files: dict[str, str] | None = None):
        td = tempfile.TemporaryDirectory(prefix="setugo-runtime-exec-guard-")
        repo = Path(td.name)
        runtime = repo / "governance-runtime"
        runtime.mkdir(parents=True)
        for relpath, content in runtime_files.items():
            path = runtime / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        for relpath, content in (root_files or {}).items():
            path = repo / relpath
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
        return td, repo, runtime

    def _blob(self, repo: Path, candidate_relpath: str) -> str:
        out = subprocess.check_output(
            ["git", "ls-tree", "HEAD", "--", candidate_relpath],
            cwd=repo,
            text=True,
        ).strip().split()
        return out[2]

    def _manifest(self, repo: Path, *candidate_relpaths: str) -> dict[str, str]:
        return {relpath: self._blob(repo, relpath) for relpath in candidate_relpaths}

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
            manifest = self._manifest(repo, "governance-runtime/pinned.py", "governance-runtime/test_entry.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertEqual(0, result.returncode, result.stdout)
        finally:
            td.cleanup()

    def test_selected_test_must_itself_be_exact_pinned(self):
        td, repo, runtime = self._repo({
            "pinned.py": "VALUE = 1\n",
            "test_entry.py": (
                "import unittest\nimport pinned\n"
                "class T(unittest.TestCase):\n"
                "    def test_value(self): self.assertEqual(1, pinned.VALUE)\n"
            ),
        })
        try:
            manifest = self._manifest(repo, "governance-runtime/pinned.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("qualification test modules are not exact-pinned", result.stdout)
        finally:
            td.cleanup()

    def test_indirect_import_of_unpinned_runtime_module_fails_closed(self):
        td, repo, runtime = self._repo({
            "pinned.py": "import importlib\ndef load_hidden(): return getattr(importlib, 'import_module')('hidden')\n",
            "hidden.py": "VALUE = 7\n",
            "test_entry.py": (
                "import unittest\nimport pinned\n"
                "class T(unittest.TestCase):\n"
                "    def test_hidden(self): self.assertEqual(7, pinned.load_hidden().VALUE)\n"
            ),
        })
        try:
            manifest = self._manifest(repo, "governance-runtime/pinned.py", "governance-runtime/test_entry.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("runtime guard rejected unpinned candidate-local module", result.stdout)
        finally:
            td.cleanup()

    def test_sys_path_import_of_unpinned_module_outside_runtime_fails_closed(self):
        td, repo, runtime = self._repo(
            {
                "pinned.py": (
                    "import importlib, sys\nfrom pathlib import Path\n"
                    "def load_hidden():\n"
                    "    sys.path.append(str(Path(__file__).resolve().parent.parent / 'other'))\n"
                    "    return importlib.import_module('hidden')\n"
                ),
                "test_entry.py": (
                    "import unittest\nimport pinned\n"
                    "class T(unittest.TestCase):\n"
                    "    def test_hidden(self): self.assertEqual(11, pinned.load_hidden().VALUE)\n"
                ),
            },
            {"other/hidden.py": "VALUE = 11\n"},
        )
        try:
            manifest = self._manifest(repo, "governance-runtime/pinned.py", "governance-runtime/test_entry.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("runtime guard rejected unpinned candidate-local module", result.stdout)
            self.assertIn("other/hidden.py", result.stdout)
        finally:
            td.cleanup()

    def test_runpy_execution_of_unpinned_file_outside_runtime_fails_closed(self):
        td, repo, runtime = self._repo(
            {
                "pinned.py": (
                    "import runpy\nfrom pathlib import Path\n"
                    "def load_hidden():\n"
                    "    path = Path(__file__).resolve().parent.parent / 'other' / 'hidden.py'\n"
                    "    return runpy.run_path(str(path))\n"
                ),
                "test_entry.py": (
                    "import unittest\nimport pinned\n"
                    "class T(unittest.TestCase):\n"
                    "    def test_hidden(self): self.assertEqual(13, pinned.load_hidden()['VALUE'])\n"
                ),
            },
            {"other/hidden.py": "VALUE = 13\n"},
        )
        try:
            manifest = self._manifest(repo, "governance-runtime/pinned.py", "governance-runtime/test_entry.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("runtime guard rejected execution of unpinned candidate file", result.stdout)
            self.assertIn("other/hidden.py", result.stdout)
        finally:
            td.cleanup()

    def test_subprocess_child_interpreter_escape_fails_closed(self):
        td, repo, runtime = self._repo(
            {
                "pinned.py": (
                    "import subprocess, sys\nfrom pathlib import Path\n"
                    "def execute_hidden():\n"
                    "    path = Path(__file__).resolve().parent.parent / 'other' / 'hidden.py'\n"
                    "    subprocess.run([sys.executable, str(path)], check=True)\n"
                ),
                "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_child(self): pinned.execute_hidden()\n",
            },
            {"other/hidden.py": "raise SystemExit(0)\n"},
        )
        try:
            manifest = self._manifest(repo, "governance-runtime/pinned.py", "governance-runtime/test_entry.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("candidate-originated process/native execution: subprocess.Popen", result.stdout)
        finally:
            td.cleanup()

    def test_os_system_escape_fails_closed(self):
        td, repo, runtime = self._repo({
            "pinned.py": "import os\ndef execute(): os.system('true')\n",
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_os(self): pinned.execute()\n",
        })
        try:
            manifest = self._manifest(repo, "governance-runtime/pinned.py", "governance-runtime/test_entry.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("candidate-originated process/native execution: os.system", result.stdout)
        finally:
            td.cleanup()

    def test_exact_frozen_openssl_der_shape_is_allowed(self):
        td, repo, runtime = self._repo({
            "pinned.py": (
                "import subprocess, tempfile\nfrom pathlib import Path\n"
                "def execute():\n"
                "    with tempfile.TemporaryDirectory(prefix='setugo-openssl-positive-') as td:\n"
                "        root=Path(td); priv=root/'k.pem'; pub=root/'p.pem'; der=root/'p.der'\n"
                "        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(priv)],check=True)\n"
                "        subprocess.run(['openssl','pkey','-in',str(priv),'-pubout','-out',str(pub)],check=True)\n"
                "        subprocess.run(['openssl','pkey','-pubin','-in',str(pub),'-outform','DER','-out',str(der)],check=True)\n"
                "        assert der.read_bytes()\n"
            ),
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_openssl(self): pinned.execute()\n",
        })
        try:
            manifest = self._manifest(repo, "governance-runtime/pinned.py", "governance-runtime/test_entry.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertEqual(0, result.returncode, result.stdout)
        finally:
            td.cleanup()

    def test_arbitrary_openssl_command_is_denied(self):
        td, repo, runtime = self._repo({
            "pinned.py": "import subprocess\ndef execute(): subprocess.run(['openssl','version'],check=True)\n",
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_bad(self): pinned.execute()\n",
        })
        try:
            manifest = self._manifest(repo, "governance-runtime/pinned.py", "governance-runtime/test_entry.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("candidate-originated process/native execution: subprocess.Popen", result.stdout)
        finally:
            td.cleanup()

    def test_openssl_candidate_path_operand_is_denied(self):
        td, repo, runtime = self._repo({
            "pinned.py": (
                "import subprocess\nfrom pathlib import Path\n"
                "def execute():\n"
                "    src=Path(__file__); out=src.with_suffix('.der')\n"
                "    subprocess.run(['openssl','pkey','-pubin','-in',str(src),'-outform','DER','-out',str(out)],check=False)\n"
            ),
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_bad_path(self): pinned.execute()\n",
        })
        try:
            manifest = self._manifest(repo, "governance-runtime/pinned.py", "governance-runtime/test_entry.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("candidate-originated process/native execution: subprocess.Popen", result.stdout)
        finally:
            td.cleanup()

    def test_path_rebinding_before_openssl_is_denied(self):
        td, repo, runtime = self._repo({
            "pinned.py": (
                "import os, subprocess, tempfile\nfrom pathlib import Path\n"
                "def execute():\n"
                "    os.environ['PATH']=str(Path(__file__).resolve().parent)+os.pathsep+os.environ['PATH']\n"
                "    with tempfile.TemporaryDirectory(prefix='setugo-openssl-path-') as td:\n"
                "        subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(Path(td)/'k.pem')],check=True)\n"
            ),
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_path(self): pinned.execute()\n",
        })
        try:
            manifest = self._manifest(repo, "governance-runtime/pinned.py", "governance-runtime/test_entry.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("candidate-originated process/native execution: subprocess.Popen", result.stdout)
        finally:
            td.cleanup()

    def test_dynamic_exec_obtained_through_builtins_attribute_fails_closed(self):
        td, repo, runtime = self._repo({
            "pinned.py": "import builtins\ndef execute():\n    fn=builtins.exec\n    fn('VALUE = 1')\n",
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_exec(self): pinned.execute()\n",
        })
        try:
            manifest = self._manifest(repo, "governance-runtime/pinned.py", "governance-runtime/test_entry.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("candidate-originated dynamic compilation", result.stdout)
        finally:
            td.cleanup()

    def test_dynamic_compile_spoofing_pinned_filename_fails_closed(self):
        td, repo, runtime = self._repo({
            "pinned.py": "import builtins\ndef execute():\n    code=builtins.compile('VALUE = 1',__file__,'exec')\n    builtins.exec(code)\n",
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_exec(self): pinned.execute()\n",
        })
        try:
            manifest = self._manifest(repo, "governance-runtime/pinned.py", "governance-runtime/test_entry.py")
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("candidate-originated dynamic compilation", result.stdout)
        finally:
            td.cleanup()

    def test_manifest_blob_substitution_fails_before_test_execution(self):
        td, repo, runtime = self._repo({
            "pinned.py": "VALUE = 1\n",
            "test_entry.py": "import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_value(self): self.assertEqual(1,pinned.VALUE)\n",
        })
        try:
            manifest = self._manifest(repo, "governance-runtime/test_entry.py")
            manifest["governance-runtime/pinned.py"] = "0" * 40
            result = self._run(runtime, manifest, "test_entry.py")
            self.assertNotEqual(0, result.returncode)
            self.assertIn("runtime guard blob mismatch", result.stdout)
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
