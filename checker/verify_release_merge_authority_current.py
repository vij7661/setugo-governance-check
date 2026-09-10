#!/usr/bin/env python3
"""Exact-current RELEASE merge-authority verifier binding.

The underlying checker-owned verifier remains unchanged; this wrapper binds it
to the current repaired RELEASE candidate. It grants no authority by itself.
"""
from __future__ import annotations

import verify_release_merge_authority as verifier

CURRENT_RELEASE_CANDIDATE_SHA = "4200397f21e12f900c309ee1bc66fa8424135f11"
verifier.CANDIDATE_SHA = CURRENT_RELEASE_CANDIDATE_SHA


if __name__ == "__main__":
    raise SystemExit(verifier.main())
