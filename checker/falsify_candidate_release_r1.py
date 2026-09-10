#!/usr/bin/env python3
"""RELEASE R1/R3 external qualification extension.

Extends the R11 external checker for the exact RELEASE successor, refreshes only
externally observed blobs that changed in the preregistered R3 successor, and
independently executes RELEASE-specific qualification paths.

Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

import falsify_candidate_r10_entry as r10

RELEASE_CANDIDATE_SHA = "6d4fbb9ce266979ca3147a159ae724f33e0362ba"
CANDIDATE_REPO = "https://github.com/vij7661/setugo-ai-development-framework.git"

# Successor-specific authority-critical pins. The TESTING v6 module and external
# TESTING root remain pinned by the inherited checker; only the files actually
# changed to route active policy through v7 are refreshed here.
r10.checker.EXPECTED_MANUAL_AUTHORITY_VERIFIER_BLOB_SHA = "fbcd992d7c3ea1c415bd01e3a0d638865f0f5898"
r10.checker.EXPECTED_POLICY_FACADE_BLOB_SHA = "998cb2a90b6530132239e1a6274718b605680909"

RELEASE_TEST_BLOBS = {
    "test_qualification_boundary_policy.py": "406bd608be28c440209aea12b060c31822ced1fc",
    "test_qualification_boundary_unittest_bridge.py": "74bc4969b83f1f7a8202af05db84f170cfe842dd",
    "test_release_r1_bridge_shape_guard.py": "73efc664eac408b1d581426d736353ef729c3600",
    "test_release_r3_phase_scoped_authority.py": "2666bf3ad24ecccd0e68e1025b786dfbadd0977e",
}

# These newly introduced phase-scoped modules are pinned separately because the
# inherited TESTING checker deliberately knows nothing about RELEASE authority.
RELEASE_RUNTIME_BLOBS = {
    "governance-runtime/qualification_boundary_policy_v7.py": "f981a01b86b5020587bcf1817c484af64604c601",
    "governance-runtime/release_external_governance_root.py": "581e9ce5c2a4a23755d4d61cad6bbde890b4e5d6",
    "governance-runtime/release_manual_authority_verifier.py": "6e71413054d599fccfc4a265228a2a681f9d2ed0",
}

EXTRA_EXECUTION_BLOBS = {
    "governance-runtime/verify_external_trust_root_control.py": "98b48d5f8133f527c9490a4d02b477a56a2ae997",
    "experiments/governed-platform/governance/test_integrated_governed_mvp_slice6_terminal_authority.py": "970b28aed4952d90081e89e781c5711bf26c4f68",
}

r10.r9.EXPECTED_QUALIFICATION_TEST_BLOBS.update(RELEASE_TEST_BLOBS)
r10.QUALIFICATION_TEST_FILES = frozenset(r10.r9.EXPECTED_QUALIFICATION_TEST_BLOBS)

_original_run = r10.checker.run
_original_assert_equal = r10.checker.assert_equal


def _release_assert_equal(actual: object, expected: object, label: str) -> None:
    # The inherited checker intentionally hard-codes TESTING policy v6. For the
    # RELEASE successor the active compatibility facade is externally pinned and
    # must resolve to v7. No other inherited comparison is relaxed.
    if label == "externally pinned qualification policy version":
        return _original_assert_equal(actual, 7, label)
    return _original_assert_equal(actual, expected, label)


def _release_run(cmd: list[str], cwd: Path | None = None) -> None:
    if cwd is not None and Path(cwd).name == "governance-runtime":
        explicit = [str(arg) for arg in cmd if str(arg).endswith(".py") and str(arg).startswith("test_")]
        required = ("test_release_r1_bridge_shape_guard.py", "test_release_r3_phase_scoped_authority.py")
        if explicit:
            cmd = list(cmd)
            for filename in required:
                if filename not in explicit:
                    cmd.append(filename)
    return _original_run(cmd, cwd=cwd)


r10.checker.assert_equal = _release_assert_equal
r10.checker.run = _release_run


def _git_blob_sha(repo: Path, relpath: str) -> str:
    result = subprocess.run(
        ["git", "ls-tree", "HEAD", "--", relpath],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    parts = result.stdout.strip().split()
    if len(parts) < 3:
        raise AssertionError(f"missing pinned RELEASE path: {relpath}")
    return parts[2]


def _reject_stdlib_collisions(directory: Path) -> None:
    stdlib = frozenset(getattr(sys, "stdlib_module_names", ()))
    if not stdlib:
        raise AssertionError("stdlib namespace inventory unavailable")
    for entry in directory.iterdir():
        if entry.name == "__pycache__":
            continue
        if entry.is_dir():
            module_name = entry.name
        elif entry.name.endswith(".py"):
            module_name = entry.name[:-3]
        elif entry.name.endswith((".pyc", ".pyo", ".so", ".pyd", ".dll", ".dylib")):
            module_name = entry.name.split(".", 1)[0]
        else:
            continue
        if module_name in stdlib:
            raise AssertionError(f"candidate stdlib namespace collision in external execution directory: {entry}")


def _run_file_with_sibling_imports(path: Path, *, env: dict[str, str]) -> None:
    directory = path.parent.resolve()
    _reject_stdlib_collisions(directory)
    bootstrap = (
        "import runpy,sys; "
        "d=sys.argv[1]; p=sys.argv[2]; "
        "sys.path.insert(0,d); "
        "runpy.run_path(p,run_name='__main__')"
    )
    subprocess.run(
        [sys.executable, "-I", "-c", bootstrap, str(directory), str(path.resolve())],
        cwd=r10.checker.CHECKER_ROOT,
        env=env,
        check=True,
    )


def _run_unittest_module_isolated(directory: Path, module_name: str, *, env: dict[str, str]) -> None:
    directory = directory.resolve()
    _reject_stdlib_collisions(directory)
    bootstrap = (
        "import sys,unittest; "
        "d=sys.argv[1]; m=sys.argv[2]; "
        "sys.path.insert(0,d); "
        "suite=unittest.defaultTestLoader.loadTestsFromName(m); "
        "r=unittest.TextTestRunner(verbosity=2).run(suite); "
        "raise SystemExit(0 if r.wasSuccessful() and suite.countTestCases()>0 else 1)"
    )
    subprocess.run(
        [sys.executable, "-I", "-c", bootstrap, str(directory), module_name],
        cwd=r10.checker.CHECKER_ROOT,
        env=env,
        check=True,
    )


def verify_and_execute_extra_release_paths() -> None:
    with tempfile.TemporaryDirectory(prefix="setugo-release-r3-") as td:
        repo = Path(td) / "candidate"
        subprocess.run(["git", "clone", "--no-checkout", "--filter=blob:none", CANDIDATE_REPO, str(repo)], check=True)
        subprocess.run(["git", "fetch", "--depth=1", "origin", RELEASE_CANDIDATE_SHA], cwd=repo, check=True)
        subprocess.run(["git", "checkout", "--detach", RELEASE_CANDIDATE_SHA], cwd=repo, check=True)
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        if actual != RELEASE_CANDIDATE_SHA:
            raise AssertionError("external RELEASE checkout is not exact candidate SHA")

        for relpath, expected_blob in {**RELEASE_RUNTIME_BLOBS, **EXTRA_EXECUTION_BLOBS}.items():
            actual_blob = _git_blob_sha(repo, relpath)
            if actual_blob != expected_blob:
                raise AssertionError(
                    f"RELEASE external execution blob mismatch for {relpath}: {actual_blob} != {expected_blob}"
                )

        env = os.environ.copy()
        env["PYTHONNOUSERSITE"] = "1"
        _run_file_with_sibling_imports(
            repo / "governance-runtime/verify_external_trust_root_control.py",
            env=env,
        )
        _run_unittest_module_isolated(
            repo / "governance-runtime",
            "test_release_r3_phase_scoped_authority",
            env=env,
        )
        _run_unittest_module_isolated(
            repo / "experiments/governed-platform/governance",
            "test_integrated_governed_mvp_slice6_terminal_authority",
            env=env,
        )


def main() -> int:
    if "--sha" not in sys.argv:
        raise AssertionError("RELEASE external qualification requires explicit --sha")
    index = sys.argv.index("--sha")
    if index + 1 >= len(sys.argv) or sys.argv[index + 1] != RELEASE_CANDIDATE_SHA:
        raise AssertionError("RELEASE external qualification is not bound to exact candidate SHA")

    result = r10.checker.main()
    if result not in (None, 0):
        return int(result)
    verify_and_execute_extra_release_paths()
    print(f"RELEASE_EXTERNAL_COVERAGE_PASS candidate_sha={RELEASE_CANDIDATE_SHA}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
