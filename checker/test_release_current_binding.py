from __future__ import annotations

import unittest

import falsify_candidate_release_current as current_release
import verify_release_merge_authority_current as current_merge


EXPECTED_CANDIDATE = "4200397f21e12f900c309ee1bc66fa8424135f11"
EXPECTED_RELEASE_ROOT_BLOB = "7de7c00519853d5ff0d776d40f94c20c9d5f976d"
EXPECTED_EXTRA_RUNTIME_HELPER = "governance-runtime/verify_external_trust_root_control.py"
EXPECTED_EXTRA_RUNTIME_HELPER_BLOB = "98b48d5f8133f527c9490a4d02b477a56a2ae997"
EXPECTED_IMPORTED_TEST_HELPER = "governance-runtime/test_manual_review_authority_ingress_regression.py"
EXPECTED_IMPORTED_TEST_HELPER_BLOB = "62980bcd63f398cd9209c015c8a2c66af9829e26"


class ReleaseCurrentBindingTests(unittest.TestCase):
    def test_external_falsifier_is_exactly_bound(self):
        self.assertEqual(current_release.CURRENT_RELEASE_CANDIDATE_SHA, EXPECTED_CANDIDATE)
        self.assertEqual(current_release.release.RELEASE_CANDIDATE_SHA, EXPECTED_CANDIDATE)
        self.assertEqual(
            current_release.release.RELEASE_RUNTIME_BLOBS[
                "governance-runtime/release_external_governance_root.py"
            ],
            EXPECTED_RELEASE_ROOT_BLOB,
        )

    def test_release_path_requires_external_sandbox(self):
        self.assertTrue(current_release.release.r10.REQUIRE_EXTERNAL_SANDBOX)
        self.assertTrue(current_release.release.r10.RUNTIME_PINNED_BLOBS)

    def test_runtime_execution_manifest_is_derived_from_all_authoritative_candidate_code_pin_sets(self):
        execution_pins = current_release.release.r10.RUNTIME_PINNED_BLOBS
        for relpath, blob in current_release.runtime_closure.PINNED_RUNTIME_BLOBS.items():
            candidate_relpath = f"governance-runtime/{relpath}"
            self.assertEqual(blob, execution_pins.get(candidate_relpath), candidate_relpath)
        for relpath, blob in current_release.release.EXTRA_EXECUTION_BLOBS.items():
            self.assertEqual(blob, execution_pins.get(relpath), relpath)
        for relpath, blob in current_release.release.r10.r9.EXPECTED_QUALIFICATION_TEST_BLOBS.items():
            candidate_relpath = f"governance-runtime/{relpath}"
            self.assertEqual(blob, execution_pins.get(candidate_relpath), candidate_relpath)
        self.assertEqual(
            EXPECTED_EXTRA_RUNTIME_HELPER_BLOB,
            execution_pins.get(EXPECTED_EXTRA_RUNTIME_HELPER),
        )
        self.assertEqual(
            EXPECTED_IMPORTED_TEST_HELPER_BLOB,
            execution_pins.get(EXPECTED_IMPORTED_TEST_HELPER),
        )

    def test_merge_authority_verifier_is_bound_to_same_candidate(self):
        self.assertEqual(current_merge.CURRENT_RELEASE_CANDIDATE_SHA, EXPECTED_CANDIDATE)
        self.assertEqual(current_merge.verifier.CANDIDATE_SHA, EXPECTED_CANDIDATE)
        self.assertEqual(
            current_merge.verifier.POLICY_HASH,
            "3a1936d3e8956b2521908189139ee73868c48f29be13fcacea84f839ca6b2258",
        )


if __name__ == "__main__":
    unittest.main()
