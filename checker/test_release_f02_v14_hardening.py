#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import run_candidate_unittests_sandboxed as sandbox
import run_candidate_unittests_sandboxed_v2 as proxy


class ReleaseF02V14HardeningTests(unittest.TestCase):
    def _repo(self):
        td = tempfile.TemporaryDirectory(prefix="setugo-v14-hardening-")
        root = Path(td.name)
        (root / "governance-runtime").mkdir()
        tracked = root / "governance-runtime" / "pinned.py"
        tracked.write_text("VALUE = 1\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=root, check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
        blob = subprocess.check_output(
            ["git", "ls-tree", "HEAD", "--", "governance-runtime/pinned.py"], cwd=root, text=True
        ).strip().split()[2]
        return td, root, tracked, {"governance-runtime/pinned.py": blob}

    def test_dirty_working_tree_is_rejected_before_sandbox_launch(self):
        td, root, tracked, manifest = self._repo()
        try:
            sandbox._verify_working_tree_matches_manifest(root, manifest)
            tracked.write_text("VALUE = 999\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "working tree differs from HEAD"):
                sandbox._verify_working_tree_matches_manifest(root, manifest)
        finally:
            td.cleanup()

    def test_symlink_openssl_operand_is_rejected_at_open_time(self):
        with tempfile.TemporaryDirectory(prefix="setugo-v14-io-") as td:
            root = Path(td)
            outside = root.parent / "setugo-v14-outside.pem"
            outside.write_text("outside", encoding="utf-8")
            (root / "out.der").write_bytes(b"")
            os.symlink(outside, root / "input.pem")
            argv = [
                "openssl", "pkey", "-pubin", "-in", "/sandbox-io/input.pem",
                "-outform", "DER", "-out", "/sandbox-io/out.der",
            ]
            self.assertIsNone(sandbox._prepare_openssl_argv(argv, root, Path("/usr/bin/openssl")))
            outside.unlink(missing_ok=True)

    def test_seccomp_profile_is_explicitly_bound_into_docker_command(self):
        checker_dir = Path(__file__).resolve().parent
        cmd = sandbox._build_docker_cmd(
            Path("/host/candidate"), checker_dir, Path("/host/io"), "abc", ["test_entry.py"]
        )
        seccomp_args = [item for item in cmd if item.startswith("seccomp=")]
        self.assertEqual(1, len(seccomp_args))
        profile = Path(seccomp_args[0].split("=", 1)[1])
        payload = json.loads(profile.read_text(encoding="utf-8"))
        denied = {name for rule in payload["syscalls"] if rule["action"] == "SCMP_ACT_ERRNO" for name in rule["names"]}
        for name in (
            "clone", "clone3", "fork", "vfork", "execve", "execveat",
            "unshare", "setns", "ptrace", "bpf", "mount",
        ):
            self.assertIn(name, denied)

    def test_root_proxy_rejects_redirected_final_url(self):
        url = next(iter(proxy.ALLOWED_ROOT_URLS))

        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return "https://example.com/redirected"
            def read(self): return b"bad"

        with mock.patch.object(proxy._OPENER, "open", return_value=Response()):
            with self.assertRaisesRegex(RuntimeError, "redirect not permitted"):
                proxy._host_fetch(url)


if __name__ == "__main__":
    unittest.main()
