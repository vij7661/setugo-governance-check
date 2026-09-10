#!/usr/bin/env python3
"""Exact-current RELEASE external qualification binding.

This checker-owned wrapper preserves the reviewed RELEASE falsifier while
rebinding only the exact candidate SHA, the authenticated RELEASE-root blob,
and the F-08-required independent adjudication App check. It requires both an
exhaustive checker-owned candidate-local static dependency closure and an
execution-time exact-pin guard inside the isolated qualification runner before
RELEASE external qualification can pass. Authority effect: none.
"""
from __future__ import annotations

import falsify_candidate_release_r1 as release
import verify_release_runtime_import_closure as runtime_closure

CURRENT_RELEASE_CANDIDATE_SHA = "4200397f21e12f900c309ee1bc66fa8424135f11"
CURRENT_RELEASE_ROOT_MODULE_BLOB_SHA = "7de7c00519853d5ff0d776d40f94c20c9d5f976d"
REQUIRED_REVIEW_ADJUDICATION_CHECK = "external-release-review-adjudication"
CURRENT_QUALIFICATION_TEST_BLOBS = dict(release.r10.r9.EXPECTED_QUALIFICATION_TEST_BLOBS)

release.RELEASE_CANDIDATE_SHA = CURRENT_RELEASE_CANDIDATE_SHA
release.RELEASE_RUNTIME_BLOBS[
    "governance-runtime/release_external_governance_root.py"
] = CURRENT_RELEASE_ROOT_MODULE_BLOB_SHA
release.RELEASE_REQUIRED_CHECKS = frozenset(
    set(release.RELEASE_REQUIRED_CHECKS) | {REQUIRED_REVIEW_ADJUDICATION_CHECK}
)
runtime_closure.CANDIDATE_SHA = CURRENT_RELEASE_CANDIDATE_SHA
# One checker-owned runtime/helper manifest governs execution-time observation.
# The exact qualification-test blob map is separately supplied to static closure,
# allowing tests to import other exact-pinned tests without conflating tests with
# runtime helpers while rejecting anything outside the union.
release.r10.RUNTIME_PINNED_BLOBS = dict(runtime_closure.PINNED_RUNTIME_BLOBS)

_original_extra_release_paths = release.verify_and_execute_extra_release_paths


def _verify_current_extra_release_paths() -> None:
    graph = runtime_closure.verify(
        CURRENT_RELEASE_CANDIDATE_SHA,
        qualification_test_blobs=CURRENT_QUALIFICATION_TEST_BLOBS,
    )
    if not graph:
        raise AssertionError("RELEASE runtime/test dependency closure produced no audited modules")
    _original_extra_release_paths()


release.verify_and_execute_extra_release_paths = _verify_current_extra_release_paths


if __name__ == "__main__":
    raise SystemExit(release.main())
