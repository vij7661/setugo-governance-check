#!/usr/bin/env python3
from __future__ import annotations

import copy
import unittest

import verify_release_review_adjudication as gate


class ReleaseReviewAdjudicationTests(unittest.TestCase):
    def _valid(self):
        return {
            "schema_version": 1,
            "candidate_repository": gate.CANDIDATE_REPO,
            "candidate_sha": gate.CANDIDATE_SHA,
            "pull_request": gate.PR_NUMBER,
            "review_type": gate.REVIEW_TYPE,
            "authority_class": gate.AUTHORITY_CLASS,
            "decision_scope": gate.DECISION_SCOPE,
            "disposition": gate.ELIGIBLE_DISPOSITION,
            "source_kind": gate.SOURCE_KIND,
            "raw_review_ref": "manual-review:example",
            "raw_review_sha256": "a" * 64,
            "reviewed_checker_sha": gate.CHECKER_SHA,
            "qualification_policy_id": gate.POLICY_ID,
            "qualification_policy_version": gate.POLICY_VERSION,
            "qualification_policy_hash": gate.POLICY_HASH,
            "trust_root_id": gate.TRUST_ROOT_ID,
        }

    def test_exact_pass_artifact_shape_is_accepted(self):
        gate.validate_artifact(self._valid())
        self.assertEqual(64, len(gate.adjudication_digest(self._valid())))

    def test_non_pass_dispositions_are_not_authority_eligible(self):
        for disposition in ("BOUNDED_PASS", "CHANGES_REQUIRED", "INSUFFICIENT_EVIDENCE"):
            with self.subTest(disposition=disposition):
                value = self._valid(); value["disposition"] = disposition
                with self.assertRaisesRegex(gate.ReleaseReviewError, "mismatch: disposition"):
                    gate.validate_artifact(value)

    def test_stale_candidate_checker_policy_and_wrong_authority_are_rejected(self):
        mutations = {
            "candidate_sha": "0" * 40,
            "reviewed_checker_sha": "1" * 40,
            "qualification_policy_hash": "2" * 64,
            "authority_class": "HUMAN_RELEASE_AUTHORITY",
            "decision_scope": "TERMINAL_ACTION:RELEASE:MERGE_RELEASE_CANDIDATE",
            "trust_root_id": "SETUGO_RELEASE_GOVERNANCE_ED25519_V1",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                value = self._valid(); value[field] = replacement
                with self.assertRaisesRegex(gate.ReleaseReviewError, f"mismatch: {field}"):
                    gate.validate_artifact(value)

    def test_raw_review_reference_and_digest_are_mandatory(self):
        value = self._valid(); value["raw_review_ref"] = ""
        with self.assertRaisesRegex(gate.ReleaseReviewError, "reference is missing"):
            gate.validate_artifact(value)
        value = self._valid(); value["raw_review_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(gate.ReleaseReviewError, "SHA-256 is invalid"):
            gate.validate_artifact(value)

    def test_unknown_fields_are_rejected(self):
        value = copy.deepcopy(self._valid()); value["self_declared_independent"] = True
        with self.assertRaisesRegex(gate.ReleaseReviewError, "fields are missing or unexpected"):
            gate.validate_artifact(value)


if __name__ == "__main__":
    unittest.main()
