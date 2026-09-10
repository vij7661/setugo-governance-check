#!/usr/bin/env python3
"""Exact-current RELEASE external qualification binding.

This checker-owned wrapper preserves the reviewed RELEASE falsifier while
rebinding only the exact candidate SHA and the one candidate runtime blob that
changed to authenticate live GitHub metadata retrieval. Authority effect: none.
"""
from __future__ import annotations

import falsify_candidate_release_r1 as release

CURRENT_RELEASE_CANDIDATE_SHA = "4200397f21e12f900c309ee1bc66fa8424135f11"
CURRENT_RELEASE_ROOT_MODULE_BLOB_SHA = "7de7c00519853d5ff0d776d40f94c20c9d5f976d"

release.RELEASE_CANDIDATE_SHA = CURRENT_RELEASE_CANDIDATE_SHA
release.RELEASE_RUNTIME_BLOBS[
    "governance-runtime/release_external_governance_root.py"
] = CURRENT_RELEASE_ROOT_MODULE_BLOB_SHA


if __name__ == "__main__":
    raise SystemExit(release.main())
