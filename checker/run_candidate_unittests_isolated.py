#!/usr/bin/env python3
"""Checker-owned isolated runner for candidate qualification tests.

This file executes under `python -I`. It imports the stdlib test runner before
adding the candidate runtime at the END of sys.path, so candidate files cannot
shadow `unittest` or other standard-library modules through cwd/sys.path[0].
Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import hashlib  # preload from trusted stdlib search path
import importlib
import json
import os
from pathlib import Path
import sys
import unittest

EXPECTED_TOTAL_TESTS = 106


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit("usage: isolated-runner <candidate-runtime> <test.py>...")

    runtime = Path(sys.argv[1]).resolve()
    tests = list(sys.argv[2:])
    if not runtime.is_dir():
        raise SystemExit("candidate runtime directory missing")

    # `-I` must be active; user-site and Python environment injection must be off.
    if sys.flags.isolated != 1 or sys.flags.no_user_site != 1 or sys.flags.ignore_environment != 1:
        raise SystemExit("candidate qualification interpreter is not isolated")

    unittest_origin = Path(unittest.__file__).resolve()
    if _is_under(unittest_origin, runtime):
        raise SystemExit("candidate-controlled unittest shadow detected")

    # The candidate path must not already have import precedence. Add it last,
    # after stdlib/site paths established by isolated mode.
    for item in sys.path:
        try:
            if Path(item).resolve() == runtime:
                raise SystemExit("candidate runtime unexpectedly present before isolated import setup")
        except (OSError, RuntimeError):
            pass
    sys.path.append(str(runtime))

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    counts: dict[str, int] = {}
    for filename in tests:
        if not filename.endswith(".py"):
            raise SystemExit(f"qualification test must be an explicit .py module: {filename}")
        module_name = filename[:-3]
        before_errors = len(loader.errors)
        loaded = loader.loadTestsFromName(module_name)
        if len(loader.errors) != before_errors:
            raise SystemExit(f"failed to load qualification test module: {module_name}")
        count = loaded.countTestCases()
        if count <= 0:
            raise SystemExit(f"qualification test module executed zero tests: {module_name}")
        counts[module_name] = count
        suite.addTests(loaded)

    total = suite.countTestCases()
    if total != EXPECTED_TOTAL_TESTS:
        raise SystemExit(f"qualification test-count mismatch: {total} != {EXPECTED_TOTAL_TESTS}")

    print(json.dumps({
        "isolated": True,
        "no_user_site": bool(sys.flags.no_user_site),
        "ignore_environment": bool(sys.flags.ignore_environment),
        "unittest_origin": str(unittest_origin),
        "candidate_runtime_appended_last": sys.path[-1] == str(runtime),
        "module_test_counts": counts,
        "total_tests": total,
        "authority_effect": "NONE_EVIDENCE_ONLY",
    }, sort_keys=True))

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
