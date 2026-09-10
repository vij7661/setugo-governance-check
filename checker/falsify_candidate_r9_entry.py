#!/usr/bin/env python3
"""R9 external-checker entry point.

Adds an independently pinned Git-blob manifest for every candidate unittest module
whose success contributes to external qualification. This closes the false-green
path where candidate code could weaken or replace tests while leaving pinned
production files unchanged.

Authority effect remains NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import falsify_candidate_entry as entry

checker = entry.checker
_original_dependency_closure = checker.verify_authority_critical_dependency_closure

EXPECTED_QUALIFICATION_TEST_BLOBS = {
    "test_phase_policy.py": "6479eda90d475c2330bbe3b592d4ab4b0bfe049a",
    "test_manual_authority_verifier.py": "a24c7248f560950a9702ae26b4d366ff146de53f",
    "test_manual_authority_signed_attestation.py": "1c8be9287f6f5db43acd7a562c3d8af6d3d1349a",
    "test_external_governance_root.py": "a022ffa68abf83befe2b7a648faaacbc3fc8cb01",
    "test_external_root_policy_binding.py": "6cda14dbd427ffb0a9bec1ea410c3f28524b8e29",
    "test_external_trust_root_control.py": "38ed5d68d91c97505ab2b214077c522a4b6491c2",
    "test_qualification_boundary_unittest_bridge.py": "022d6fdb45a62ea25e6055a74bedf70ba0fdfc2d",
    "test_review_protocol.py": "8ef98ebe3b22eaad22b0bd1cfcfefb72c14f6e3b",
    "test_review_semantics.py": "1ab6246310e031feb776438964daa04a0e325bc4",
    "test_review_classification.py": "1c363d8333ee4b16e100e0f957e4722d2a4b1cea",
    "test_single_file_review_container.py": "5ac8f6ed158b77397dc157cbe15a48a7330e387d",
    "test_platform_candidate_review_request_integrity.py": "33911b73ebfd62d3ea4a111c19deab5a5abf3298",
}


def _verify_dependency_and_test_closure(root):
    result = _original_dependency_closure(root)
    runtime = root / "governance-runtime"
    for filename, expected_sha in EXPECTED_QUALIFICATION_TEST_BLOBS.items():
        path = runtime / filename
        if not path.is_file():
            raise AssertionError(f"qualification-contributing candidate test missing: {filename}")
        checker.assert_equal(
            checker.git_blob_sha(path),
            expected_sha,
            f"externally pinned qualification test blob {filename}",
        )
    return result


checker.verify_authority_critical_dependency_closure = _verify_dependency_and_test_closure

if __name__ == "__main__":
    raise SystemExit(checker.main())
