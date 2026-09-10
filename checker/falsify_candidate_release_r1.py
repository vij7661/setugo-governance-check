#!/usr/bin/env python3
"""RELEASE R1/R3 external qualification extension.

Extends the R11 external checker for the exact RELEASE successor, pins the
repaired bridge plus RELEASE shape-guard regression, and independently executes
candidate-side qualification paths. Authority effect: NONE_EVIDENCE_ONLY.
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

RELEASE_TEST_BLOBS = {
    "test_qualification_boundary_unittest_bridge.py": "74bc4969b83f1f7a8202af05db84f170cfe842dd",
    "test_release_r1_bridge_shape_guard.py": "73efc664eac408b1d581426d736353ef729c3600",
}

EXTRA_EXECUTION_BLOBS = {
    "governance-runtime/verify_external_trust_root_control.py": "98b48d5f8133f527c9490a4d02b477a56a2ae997",
    "experiments/governed-platform/governance/test_integrated_governed_mvp_slice6_terminal_authority.py": "970b28aed4952d90081e89e781c5711bf26c4f68",
}

r10.r9.EXPECTED_QUALIFICATION_TEST_BLOBS.update(RELEASE_TEST_BLOBS)
r10.QUALIFICATION_TEST_FILES = frozenset(r10.r9.EXPECTED_QUALIFICATION_TEST_BLOBS)

_original_run = r10.checker.run


def _release_run(cmd: list[str], cwd: Path | None = None) -> None:
    if cwd is not None and Path(cwd).name == "governance-runtime":
        explicit = [str(arg) for arg in cmd if str(arg).endswith(".py") and str(arg).startswith("test_")]
        if explicit and "test_release_r1_bridge_shape_guard.py" not in explicit:
            cmd = list(cmd) + ["test_release_r1_bridge_shape_guard.py"]
    return _original_run(cmd, cwd=cwd)


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
    with tempfile.TemporaryDirectory(prefix="setugo-release-r1-") as td:
        repo = Path(td) / "candidate"
        subprocess.run(["git", "clone", "--no-checkout", "--filter=blob:none", CANDIDATE_REPO, str(repo)], check=True)
        subprocess.run(["git", "fetch", "--depth=1", "origin", RELEASE_CANDIDATE_SHA], cwd=repo, check=True)
        subprocess.run(["git", "checkout", "--detach", RELEASE_CANDIDATE_SHA], cwd=repo, check=True)
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        if actual != RELEASE_CANDIDATE_SHA:
            raise AssertionError("external RELEASE checkout is not exact candidate SHA")

        for relpath, expected_blob in EXTRA_EXECUTION_BLOBS.items():
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
