#!/usr/bin/env python3
"""R11-hardened external-checker entry point for the R10 qualification path.

Qualification test execution is routed through a checker-owned out-of-process
sandbox. Candidate code has no network; the host launcher may use the existing
governance token only for the frozen governance-root proxy contract. The generic
R10 path owns an explicit exact-blob execution manifest for its frozen TESTING
candidate; RELEASE may replace this map with its own stricter exact-candidate
manifest before execution.
Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import base64
import json
import os
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

# Frozen TESTING-candidate execution closure for the generic R10 regression.
# This is checker-owned exact evidence, not discovered dynamically from the
# candidate checkout. RELEASE replaces RUNTIME_PINNED_BLOBS with its own exact
# candidate manifest in falsify_candidate_release_current.py.
R10_RUNTIME_BLOBS = {
    "governance-runtime/qualification_boundary_policy_v4.py": "019b89f32deba5a7bc93274ff41ad7e61a1aaad3",
    "governance-runtime/external_governance_root.py": "c83b4aa9f1253f2cbd5a26b6857af8ded8bbc808",
    "governance-runtime/manual_authority_verifier.py": "5d955a9cb74b97853d15bcf64662e2774ad71693",
    "governance-runtime/qualification_boundary_policy.py": "8aac9f913df76f3d8d7760ab2989610a47da14bf",
    "governance-runtime/phase_policy.py": "219d406d0335a318d91c8c940b19b8a39ad63a03",
    "governance-runtime/review_protocol.py": "1bf92a5775a780f0f32d166fb6c6a0c522bbf490",
    "governance-runtime/platform_candidate_review.py": "b6a3f8be0c2a59993e207fb5b6a75ecbd01e9f8b",
    "governance-runtime/build_portable_review_packet.py": "7fd7fb621e8a1884eb34fd3e2d07db3f94242b58",
    "governance-runtime/verify_external_trust_root_control.py": "98b48d5f8133f527c9490a4d02b477a56a2ae997",
}
for _filename, _blob in r9.EXPECTED_QUALIFICATION_TEST_BLOBS.items():
    _relpath = f"governance-runtime/{_filename}"
    _existing = R10_RUNTIME_BLOBS.get(_relpath)
    if _existing is not None and _existing != _blob:
        raise RuntimeError(f"conflicting R10 execution pin for {_relpath}: {_existing} != {_blob}")
    R10_RUNTIME_BLOBS[_relpath] = _blob

RUNTIME_PINNED_BLOBS: dict[str, str] = dict(R10_RUNTIME_BLOBS)

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
        launcher = Path(__file__).resolve().with_name("run_candidate_unittests_sandboxed_v2.py")
        if not launcher.is_file():
            raise AssertionError("checker-owned RELEASE sandbox/root-proxy launcher is missing")
        runner_cmd = [
            sys.executable,
            str(launcher),
            str(runtime),
            "--runtime-pin-manifest-b64",
            _manifest_b64(),
            *explicit_test_args,
        ]
        host_env = {"PATH": str(Path(sys.executable).resolve().parent) + ":/usr/local/bin:/usr/bin:/bin"}
        token = os.environ.get("GOVERNANCE_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if token:
            host_env["GOVERNANCE_GITHUB_TOKEN"] = token
        subprocess.run(runner_cmd, cwd=checker.CHECKER_ROOT, env=host_env, check=True)
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
