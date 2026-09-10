#!/usr/bin/env python3
"""Exact-current RELEASE external qualification binding.

This checker-owned wrapper preserves the reviewed RELEASE falsifier while
rebinding only the exact candidate SHA, the authenticated RELEASE-root blob,
and the F-08-required independent adjudication App check. It requires both an
exhaustive checker-owned candidate-local static import closure audit and an
execution-time exact-pin guard inside the isolated qualification runner before
RELEASE external qualification can pass. Authority effect: none.
"""
from __future__ import annotations

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

# Runtime execution must be authorized by an existing checker-owned exact pin,
# regardless of whether the file is production runtime, an extra execution
# helper, or a qualification test/helper imported by another pinned test.
# Derive one execution manifest from all authoritative pin sets; never maintain
# a separate handwritten runtime allowlist.
_runtime_execution_pins = dict(runtime_closure.PINNED_RUNTIME_BLOBS)


def _add_runtime_pin(runtime_relpath: str, blob: str) -> None:
    existing = _runtime_execution_pins.get(runtime_relpath)
    if existing is not None and existing != blob:
        raise RuntimeError(
            f"conflicting runtime pin for {runtime_relpath}: {existing} != {blob}"
        )
    _runtime_execution_pins[runtime_relpath] = blob


for relpath, blob in release.EXTRA_EXECUTION_BLOBS.items():
    prefix = "governance-runtime/"
    if relpath.startswith(prefix):
        _add_runtime_pin(relpath[len(prefix):], blob)

# The R10/R11 checker owns the exact qualification-test blob map. Tests are
# executable candidate-local Python and may import one another (for example the
# unittest bridge), so they are part of the execution authorization closure.
for runtime_relpath, blob in release.r10.r9.EXPECTED_QUALIFICATION_TEST_BLOBS.items():
    _add_runtime_pin(runtime_relpath, blob)

release.r10.RUNTIME_PINNED_BLOBS = _runtime_execution_pins

_original_extra_release_paths = release.verify_and_execute_extra_release_paths


def _verify_current_extra_release_paths() -> None:
    graph = runtime_closure.verify(CURRENT_RELEASE_CANDIDATE_SHA)
    if not graph:
        raise AssertionError("RELEASE runtime import closure produced no audited modules")
    _original_extra_release_paths()


release.verify_and_execute_extra_release_paths = _verify_current_extra_release_paths


if __name__ == "__main__":
    raise SystemExit(release.main())
