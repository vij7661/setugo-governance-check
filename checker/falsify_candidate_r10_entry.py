#!/usr/bin/env python3
"""R11-hardened external-checker entry point for the R10 qualification path.

Qualification test execution is routed through a checker-owned out-of-process
sandbox. Candidate code does not execute directly in the checker interpreter.
Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import sys

import falsify_candidate_r9_entry as r9

checker = r9.checker
_original_run = checker.run
_original_dependency_closure = checker.verify_authority_critical_dependency_closure

r9.EXPECTED_QUALIFICATION_TEST_BLOBS.update({
    "test_qualification_boundary_policy.py": "7977f8225be8001772531516421091a681295478",
    "test_manual_review_authority_spoofing_regression.py": "7c33e04883931a17bc50cfccba00363a8af461c0",
    "test_manual_review_authority_ingress_regression.py": "62980bcd63f398cd9209c015c8a2c66af9829e26",
})

QUALIFICATION_TEST_FILES = frozenset(r9.EXPECTED_QUALIFICATION_TEST_BLOBS)
RUNTIME_PINNED_BLOBS: dict[str, str] = {}

STDLIB_NAMES = frozenset(getattr(sys, "stdlib_module_names", ()))
if not STDLIB_NAMES:
    raise RuntimeError("interpreter does not expose a comprehensive stdlib module-name set")


def _candidate_module_name(path: Path) -> str | None:
    name = path.name
    if name == "__pycache__":
        return None
    if path.is_dir():
        return name
    if name.endswith(".py"):
        return name[:-3]
    if name.endswith((".pyc", ".pyo")):
        return name.split(".", 1)[0]
    if name.endswith((".so", ".pyd", ".dll", ".dylib")):
        return name.split(".", 1)[0]
    return None


def _verify_r11_dependency_closure(root: Path):
    result = _original_dependency_closure(root)
    runtime = root / "governance-runtime"
    for entry in runtime.iterdir():
        module_name = _candidate_module_name(entry)
        if module_name and module_name in STDLIB_NAMES:
            rel = entry.relative_to(root)
            raise AssertionError(f"candidate stdlib namespace collision present: {rel}")
    return result


def _looks_like_test_runner(cmd: list[str]) -> bool:
    lowered = [str(part).lower() for part in cmd]
    markers = ("unittest", "pytest", "py.test", "nose", "nose2", "discover")
    return any(any(marker == token or marker in token for marker in markers) for token in lowered)


def _manifest_b64() -> str:
    raw = json.dumps(RUNTIME_PINNED_BLOBS, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _isolating_run(cmd: list[str], cwd: Path | None = None) -> None:
    if cwd is None:
        return _original_run(cmd, cwd=cwd)

    runtime = Path(cwd).resolve()
    if runtime.name != "governance-runtime":
        return _original_run(cmd, cwd=cwd)

    explicit_test_args = [str(arg) for arg in cmd if str(arg).endswith(".py") and str(arg).startswith("test_")]
    unknown = [arg for arg in explicit_test_args if arg not in QUALIFICATION_TEST_FILES]
    if unknown:
        raise AssertionError(f"ungoverned candidate qualification test requested: {unknown}")

    if any("pytest" in str(arg).lower() or "py.test" in str(arg).lower() for arg in cmd):
        raise AssertionError("candidate-controlled pytest/plugin collection is not an allowed qualification path")

    if explicit_test_args:
        if not RUNTIME_PINNED_BLOBS:
            raise AssertionError("RELEASE sandbox execution manifest is empty")
        launcher = Path(__file__).resolve().with_name("run_candidate_unittests_sandboxed.py")
        if not launcher.is_file():
            raise AssertionError("checker-owned RELEASE sandbox launcher is missing")
        runner_cmd = [
            sys.executable,
            str(launcher),
            str(runtime),
            "--runtime-pin-manifest-b64",
            _manifest_b64(),
            *explicit_test_args,
        ]
        subprocess.run(
            runner_cmd,
            cwd=checker.CHECKER_ROOT,
            env={"PATH": str(Path(sys.executable).resolve().parent) + ":/usr/local/bin:/usr/bin:/bin"},
            check=True,
        )
        return

    if _looks_like_test_runner(cmd):
        raise AssertionError(
            "candidate qualification test-runner invocation was not explicitly bound to pinned test modules"
        )

    return _original_run(cmd, cwd=cwd)


checker.verify_authority_critical_dependency_closure = _verify_r11_dependency_closure
checker.run = _isolating_run

if __name__ == "__main__":
    raise SystemExit(checker.main())
