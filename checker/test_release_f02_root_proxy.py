#!/usr/bin/env python3
from __future__ import annotations

import unittest

import run_candidate_unittests_sandboxed_v2 as host


class ReleaseF02RootProxyTests(unittest.TestCase):
    def test_exactly_four_frozen_urls_are_allowed(self):
        self.assertEqual(4, len(host.ALLOWED_ROOT_URLS))
        self.assertTrue(all(url.startswith("https://") for url in host.ALLOWED_ROOT_URLS))
        self.assertTrue(all("setugo-governance-root" in url for url in host.ALLOWED_ROOT_URLS))
        self.assertTrue(any("?ref=5f470774ec8c17f5519da8db2aaae59af114cef9" in url for url in host.ALLOWED_ROOT_URLS))

    def test_host_proxy_rejects_arbitrary_url_before_network(self):
        with self.assertRaisesRegex(RuntimeError, "non-frozen URL"):
            host._host_fetch("https://example.com/escape")

    def test_sandbox_policy_still_has_no_network(self):
        cmd = host._build_docker_cmd_v2(
            __import__('pathlib').Path('/host/candidate'),
            __import__('pathlib').Path('/host/checker'),
            __import__('pathlib').Path('/host/io'),
            'abc', ['test_entry.py'],
        )
        self.assertIn("--network", cmd)
        self.assertEqual("none", cmd[cmd.index("--network") + 1])
        self.assertIn("/checker/run_candidate_unittests_isolated_v4.py", cmd)


if __name__ == "__main__":
    unittest.main()
