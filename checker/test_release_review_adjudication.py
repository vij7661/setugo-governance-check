#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import unittest
from unittest import mock

import verify_release_review_adjudication as gate


class ReleaseReviewAdjudicationTests(unittest.TestCase):
    def _valid(self):
        review_bytes = b"independent review bytes\n"
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
            "raw_review_ref": "https://raw.githubusercontent.com/vij7661/setugo-governance-check/" + ("a" * 40) + "/evidence/manual-reviews/release-r1-independent-review.md",
            "raw_review_sha256": hashlib.sha256(review_bytes).hexdigest(),
            "reviewed_checker_sha": gate.QUALIFICATION_CHECKER_SHA,
            "qualification_policy_id": gate.POLICY_ID,
            "qualification_policy_version": gate.POLICY_VERSION,
            "qualification_policy_hash": gate.POLICY_HASH,
            "trust_root_id": gate.TRUST_ROOT_ID,
        }

    def test_exact_pass_artifact_shape_is_accepted(self):
        gate.validate_artifact(self._valid())
        self.assertEqual(64, len(gate.adjudication_digest(self._valid())))

    def test_v2_root_contract_is_cross_phase_review_only(self):
        gate.validate_root_metadata(dict(gate.ROOT_EXPECTED_METADATA))
        self.assertEqual("SETUGO_REVIEW_ADJUDICATION_ED25519_V2", gate.TRUST_ROOT_ID)
        self.assertEqual("CROSS_PHASE_REVIEW_ADJUDICATION_EVIDENCE_VERIFICATION_ONLY", gate.ROOT_EXPECTED_METADATA["authority_scope"])
        self.assertEqual(gate.AUTHORITY_CLASS, gate.ROOT_EXPECTED_METADATA["permitted_authority_class"])
        self.assertEqual([gate.DECISION_SCOPE], gate.ROOT_EXPECTED_METADATA["permitted_decision_scopes"])
        self.assertIn("RELEASE", gate.ROOT_EXPECTED_METADATA["permitted_candidate_phases"])
        self.assertEqual("NONE_EVIDENCE_ONLY", gate.ROOT_EXPECTED_METADATA["authority_effect"])

    def test_v2_root_scope_class_decision_and_phase_rebinding_fail_closed(self):
        mutations = {
            "authority_scope": "TESTING_MANUAL_GOVERNANCE_ATTESTATION_VERIFICATION_ONLY",
            "permitted_authority_class": "HUMAN_RELEASE_AUTHORITY",
            "permitted_decision_scopes": ["TERMINAL_ACTION:RELEASE:MERGE_RELEASE_CANDIDATE"],
            "permitted_candidate_phases": ["TESTING"],
            "authority_effect": "MERGE_RELEASE_CANDIDATE_ONLY",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                metadata = dict(gate.ROOT_EXPECTED_METADATA)
                metadata[field] = replacement
                with self.assertRaisesRegex(gate.ReleaseReviewError, f"metadata mismatch: {field}"):
                    gate.validate_root_metadata(metadata)

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
            "trust_root_id": "SETUGO_MANUAL_GOVERNANCE_ED25519_V1",
        }
        for field, replacement in mutations.items():
            with self.subTest(field=field):
                value = self._valid(); value[field] = replacement
                with self.assertRaisesRegex(gate.ReleaseReviewError, f"mismatch: {field}"):
                    gate.validate_artifact(value)

    def test_pre_f08_checker_cannot_be_claimed_as_reviewed_qualification_checker(self):
        value = self._valid()
        value["reviewed_checker_sha"] = "4757ceb036c95739aa695d035fc97df63148a691"
        with self.assertRaisesRegex(gate.ReleaseReviewError, "mismatch: reviewed_checker_sha"):
            gate.validate_artifact(value)

    def test_raw_review_reference_must_be_immutable_checker_owned_url(self):
        for bad in (
            "",
            "manual-review:example",
            "https://example.com/review.md",
            "https://raw.githubusercontent.com/vij7661/setugo-ai-development-framework/" + ("a" * 40) + "/evidence/manual-reviews/review.md",
            "https://raw.githubusercontent.com/vij7661/setugo-governance-check/main/evidence/manual-reviews/review.md",
        ):
            with self.subTest(raw_review_ref=bad):
                value = self._valid(); value["raw_review_ref"] = bad
                with self.assertRaisesRegex(gate.ReleaseReviewError, "immutable checker-owned review URL"):
                    gate.validate_artifact(value)

    def test_raw_review_digest_format_is_mandatory(self):
        value = self._valid(); value["raw_review_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(gate.ReleaseReviewError, "SHA-256 is invalid"):
            gate.validate_artifact(value)

    def test_raw_review_bytes_are_rehashed_and_must_match(self):
        value = self._valid()
        commit = "a" * 40
        with mock.patch.object(gate, "_fetch_json", return_value={"sha": commit}), \
             mock.patch.object(gate, "_fetch_bytes", return_value=b"independent review bytes\n"):
            gate.verify_raw_review_binding(value)

        with mock.patch.object(gate, "_fetch_json", return_value={"sha": commit}), \
             mock.patch.object(gate, "_fetch_bytes", return_value=b"self-authored replacement\n"):
            with self.assertRaisesRegex(gate.ReleaseReviewError, "does not match referenced review bytes"):
                gate.verify_raw_review_binding(value)

    def test_raw_review_commit_identity_must_resolve_exactly(self):
        value = self._valid()
        with mock.patch.object(gate, "_fetch_json", return_value={"sha": "b" * 40}):
            with self.assertRaisesRegex(gate.ReleaseReviewError, "commit identity mismatch"):
                gate.verify_raw_review_binding(value)

    def test_unknown_fields_are_rejected(self):
        value = copy.deepcopy(self._valid()); value["self_declared_independent"] = True
        with self.assertRaisesRegex(gate.ReleaseReviewError, "fields are missing or unexpected"):
            gate.validate_artifact(value)


if __name__ == "__main__":
    unittest.main()
