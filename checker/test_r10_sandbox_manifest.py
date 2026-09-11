#!/usr/bin/env python3
from __future__ import annotations

import unittest

import falsify_candidate_r10_entry as r10


class R10SandboxManifestTests(unittest.TestCase):
    def test_generic_r10_manifest_is_nonempty_and_frozen(self):
        self.assertTrue(r10.RUNTIME_PINNED_BLOBS)
        self.assertEqual(r10.RUNTIME_PINNED_BLOBS, r10.R10_RUNTIME_BLOBS)

    def test_all_qualification_tests_are_exact_pinned(self):
        for filename, blob in r10.r9.EXPECTED_QUALIFICATION_TEST_BLOBS.items():
            self.assertEqual(
                blob,
                r10.RUNTIME_PINNED_BLOBS.get(f"governance-runtime/{filename}"),
                filename,
            )

    def test_authority_critical_runtime_is_exact_pinned(self):
        expected = {
            "governance-runtime/qualification_boundary_policy_v4.py": r10.checker.EXPECTED_POLICY_BLOB_SHA,
            "governance-runtime/external_governance_root.py": r10.checker.EXPECTED_EXTERNAL_ROOT_MODULE_BLOB_SHA,
            "governance-runtime/manual_authority_verifier.py": r10.checker.EXPECTED_MANUAL_AUTHORITY_VERIFIER_BLOB_SHA,
            "governance-runtime/qualification_boundary_policy.py": r10.checker.EXPECTED_POLICY_FACADE_BLOB_SHA,
        }
        for relpath, blob in expected.items():
            self.assertEqual(blob, r10.RUNTIME_PINNED_BLOBS.get(relpath), relpath)


if __name__ == "__main__":
    unittest.main()
