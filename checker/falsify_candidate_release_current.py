#!/usr/bin/env python3
"""Exact-current RELEASE external qualification binding.

This checker-owned wrapper preserves the reviewed RELEASE falsifier while
rebinding only the exact candidate SHA, the authenticated RELEASE-root blob,
and the F-08-required independent adjudication App check. It requires both an
exhaustive checker-owned static candidate-local runtime import closure audit and
runtime observation of candidate-local modules actually executed by the
isolated qualification runner. Authority effect: none.
"""
from __future__ import annotations

import base64
import json
import os

import falsify_candidate_release_r1 as release
import verify_release_runtime_import_closure as runtime_closure

CURRENT_RELEASE_CANDIDATE_SHA = "4200397f21e12f900c309ee1bc66fa8424135f11"
CURRENT_RELEASE_ROOT_MODULE_BLOB_SHA = "7de7c00519853d5ff0d776d40f94c20c9d5f976d"
REQUIRED_REVIEW_ADJUDICATION_CHECK = "external-release-review-adjudication"

release.RELEASE_CANDIDATE_SHA = CURRENT_RELEASE_CANDIDATE_SHA
release.RELEASE_RUNTIME_BLOBS[
    "governance-runtime/release_external_governance_root.py"
] = CURRENT_RELEASE_ROOT_MODULE_BLOB_SHA
release.RELEASE_REQUIRED_CHECKS = frozenset(
    set(release.RELEASE_REQUIRED_CHECKS) | {REQUIRED_REVIEW_ADJUDICATION_CHECK}
)
runtime_closure.CANDIDATE_SHA = CURRENT_RELEASE_CANDIDATE_SHA

# Feed the same checker-owned exact runtime blob allowlist into the isolated
# candidate test runner. The runner verifies every candidate-local module it
# actually executes, independently of the static AST closure walk.
os.environ["SETUGO_RELEASE_RUNTIME_PINS_B64"] = base64.b64encode(
    json.dumps(runtime_closure.PINNED_RUNTIME_BLOBS, sort_keys=True, separators=(",", ":")).encode("utf-8")
).decode("ascii")

_original_extra_release_paths = release.verify_and_execute_extra_release_paths


def _verify_current_extra_release_paths() -> None:
    graph = runtime_closure.verify(CURRENT_RELEASE_CANDIDATE_SHA)
    if not graph:
        raise AssertionError("RELEASE runtime import closure produced no audited modules")
    _original_extra_release_paths()


release.verify_and_execute_extra_release_paths = _verify_current_extra_release_paths


if __name__ == "__main__":
    raise SystemExit(release.main())
