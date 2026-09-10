from __future__ import annotations

import unittest

import falsify_candidate_release_current as current_release
import verify_release_merge_authority_current as current_merge


EXPECTED_CANDIDATE = "4200397f21e12f900c309ee1bc66fa8424135f11"
EXPECTED_RELEASE_ROOT_BLOB = "7de7c00519853d5ff0d776d40f94c20c9d5f976d"


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

    def test_merge_authority_verifier_is_bound_to_same_candidate(self):
        self.assertEqual(current_merge.CURRENT_RELEASE_CANDIDATE_SHA, EXPECTED_CANDIDATE)
        self.assertEqual(current_merge.verifier.CANDIDATE_SHA, EXPECTED_CANDIDATE)
        self.assertEqual(
            current_merge.verifier.POLICY_HASH,
            "3a1936d3e8956b2521908189139ee73868c48f29be13fcacea84f839ca6b2258",
        )


if __name__ == "__main__":
    unittest.main()
