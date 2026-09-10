#!/usr/bin/env python3
"""R10 external-checker entry point.

Closes two R9 successor review blockers:
1. candidate-controlled stdlib/unittest shadowing at the subprocess boundary;
2. unpinned bridge-imported qualification test modules.

Authority effect remains NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import falsify_candidate_r9_entry as r9

checker = r9.checker
_original_run = checker.run

# These modules contribute to qualification through the pinned unittest bridge and
# therefore must be independently blob-pinned as part of the external test closure.
r9.EXPECTED_QUALIFICATION_TEST_BLOBS.update({
    "test_qualification_boundary_policy.py": "7977f8225be8001772531516421091a681295478",
    "test_manual_review_authority_spoofing_regression.py": "7c33e04883931a17bc50cfccba00363a8af461c0",
    "test_manual_review_authority_ingress_regression.py": "62980bcd63f398cd9209c015c8a2c66af9829e26",
})


def _isolating_run(cmd: list[str], cwd: Path | None = None) -> None:
    is_candidate_unittest = (
        len(cmd) >= 4
        and cmd[0] == sys.executable
        and cmd[1:4] == ["-m", "unittest", "-v"]
    )
    if not is_candidate_unittest:
        return _original_run(cmd, cwd=cwd)

    if cwd is None:
        raise AssertionError("candidate unittest execution requires an explicit runtime directory")
    runtime = Path(cwd).resolve()
    tests = list(cmd[4:])
    bootstrap = Path(__file__).resolve().with_name("run_candidate_unittests_isolated.py")
    if not bootstrap.is_file():
        raise AssertionError("checker-owned isolated unittest runner is missing")

    env = os.environ.copy()
    env["PYTHONNOUSERSITE"] = "1"
    # Execute from checker-owned code under Python isolated mode. Candidate runtime
    # is supplied as data and appended after stdlib paths by the bootstrap.
    subprocess.run(
        [sys.executable, "-I", str(bootstrap), str(runtime), *tests],
        cwd=checker.CHECKER_ROOT,
        env=env,
        check=True,
    )


checker.run = _isolating_run

if __name__ == "__main__":
    raise SystemExit(checker.main())
