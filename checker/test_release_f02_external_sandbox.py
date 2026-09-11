#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import run_candidate_unittests_sandboxed as sandbox


class ReleaseF02ExternalSandboxTests(unittest.TestCase):
    def test_docker_policy_is_fail_closed(self):
        cmd = sandbox._build_docker_cmd(
            Path('/host/candidate'), Path('/host/checker'), Path('/host/io'), 'abc', ['test_entry.py']
        )
        joined = ' '.join(cmd)
        self.assertIn('--network none', joined)
        self.assertIn('--read-only', cmd)
        self.assertIn('--cap-drop ALL', joined)
        self.assertIn('--security-opt no-new-privileges', joined)
        self.assertIn('--pids-limit 1', joined)
        self.assertIn('/host/candidate:/candidate:ro', cmd)
        self.assertIn('/host/checker:/checker:ro', cmd)
        self.assertIn('/host/io:/sandbox-io:rw', cmd)
        self.assertIn('/tmp:rw,nosuid,nodev,noexec,size=16m', cmd)

    def test_host_manifest_rejects_blob_substitution(self):
        with tempfile.TemporaryDirectory(prefix='setugo-sandbox-manifest-') as td:
            repo = Path(td)
            runtime = repo / 'governance-runtime'
            runtime.mkdir()
            (runtime / 'x.py').write_text('VALUE=1\n', encoding='utf-8')
            subprocess.run(['git','init','-q'], cwd=repo, check=True)
            subprocess.run(['git','config','user.email','test@example.invalid'], cwd=repo, check=True)
            subprocess.run(['git','config','user.name','test'], cwd=repo, check=True)
            subprocess.run(['git','add','.'], cwd=repo, check=True)
            subprocess.run(['git','commit','-qm','fixture'], cwd=repo, check=True)
            with self.assertRaisesRegex(RuntimeError, 'blob mismatch'):
                sandbox._validate_manifest(repo, {'governance-runtime/x.py':'0'*40})

    def test_real_docker_sandbox_smoke(self):
        sandbox._docker_available()
        with tempfile.TemporaryDirectory(prefix='setugo-sandbox-smoke-') as td:
            repo = Path(td)
            runtime = repo / 'governance-runtime'
            runtime.mkdir()
            (runtime / 'pinned.py').write_text('VALUE=41\n', encoding='utf-8')
            (runtime / 'test_entry.py').write_text(
                'import unittest\nimport pinned\nclass T(unittest.TestCase):\n    def test_value(self): self.assertEqual(41,pinned.VALUE)\n',
                encoding='utf-8',
            )
            subprocess.run(['git','init','-q'], cwd=repo, check=True)
            subprocess.run(['git','config','user.email','test@example.invalid'], cwd=repo, check=True)
            subprocess.run(['git','config','user.name','test'], cwd=repo, check=True)
            subprocess.run(['git','add','.'], cwd=repo, check=True)
            subprocess.run(['git','commit','-qm','fixture'], cwd=repo, check=True)
            def blob(rel):
                return subprocess.check_output(['git','ls-tree','HEAD','--',rel], cwd=repo, text=True).split()[2]
            manifest = {
                'governance-runtime/pinned.py': blob('governance-runtime/pinned.py'),
                'governance-runtime/test_entry.py': blob('governance-runtime/test_entry.py'),
            }
            encoded = base64.b64encode(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).decode()
            result = subprocess.run([
                'python', str(Path(__file__).with_name('run_candidate_unittests_sandboxed.py')),
                str(runtime), '--runtime-pin-manifest-b64', encoded, 'test_entry.py'
            ], cwd=Path(__file__).resolve().parent, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.assertEqual(0, result.returncode, result.stdout)
            self.assertIn('F02_SANDBOX_POLICY', result.stdout)


if __name__ == '__main__':
    unittest.main()
