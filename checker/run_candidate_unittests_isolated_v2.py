#!/usr/bin/env python3
"""Second-layer F-02 residual guard for the isolated qualification runner.

This wrapper preserves the reviewed whole-checkout exact-pin/OpenSSL sandbox in
`run_candidate_unittests_isolated.py` and closes two residual capability paths:

1. direct low-level `_posixsubprocess.fork_exec` / `subprocess._fork_exec` use;
2. execution of untrusted Python source outside the candidate checkout (for
   example a candidate-written `/tmp/evil.py` via runpy or SourceFileLoader).

Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import sysconfig
import threading

_BASE_PATH = Path(__file__).resolve().with_name("run_candidate_unittests_isolated.py")
_BASE_SPEC = importlib.util.spec_from_file_location("setugo_isolated_runner_base", _BASE_PATH)
if _BASE_SPEC is None or _BASE_SPEC.loader is None:
    raise RuntimeError("unable to load checker-owned isolated runner base")
base = importlib.util.module_from_spec(_BASE_SPEC)
sys.modules[_BASE_SPEC.name] = base
_BASE_SPEC.loader.exec_module(base)


_TRUSTED_PYTHON_ROOTS = tuple(
    Path(value).resolve()
    for value in {
        sysconfig.get_paths().get("stdlib"),
        sysconfig.get_paths().get("platstdlib"),
    }
    if value
)
_TRUSTED_SUBPROCESS_FILE = Path(subprocess.__file__).resolve()
_ORIGINAL_FORK_EXEC = getattr(subprocess, "_fork_exec", None)
_FORK_EXEC_STATE = threading.local()
_original_subprocess_allowed = base._candidate_subprocess_allowed
_original_install_runtime_guard = base._install_runtime_guard


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _trusted_python_path(path: Path) -> bool:
    return any(_is_under(path, root) for root in _TRUSTED_PYTHON_ROOTS)


def _python_code_path(path: Path) -> bool:
    return path.suffix.lower() in {".py", ".pyc", ".pyo"}


def _guarded_fork_exec(*args, **kwargs):
    if _ORIGINAL_FORK_EXEC is None:
        raise RuntimeError("runtime guard rejected unavailable low-level process execution")
    try:
        caller = Path(sys._getframe(1).f_code.co_filename).resolve()
    except (ValueError, OSError, RuntimeError):
        caller = None
    if caller != _TRUSTED_SUBPROCESS_FILE or not getattr(_FORK_EXEC_STATE, "openssl_permit", False):
        raise RuntimeError("runtime guard rejected direct low-level process execution: fork_exec")
    _FORK_EXEC_STATE.openssl_permit = False
    return _ORIGINAL_FORK_EXEC(*args, **kwargs)


def _subprocess_allowed_with_fork_permit(audit_args: tuple[object, ...], candidate_root: Path) -> bool:
    allowed = _original_subprocess_allowed(audit_args, candidate_root)
    if allowed:
        _FORK_EXEC_STATE.openssl_permit = True
    return allowed


def _install_low_level_fork_guard() -> None:
    if _ORIGINAL_FORK_EXEC is None:
        return
    subprocess._fork_exec = _guarded_fork_exec
    module = sys.modules.get("_posixsubprocess")
    if module is not None:
        module.fork_exec = _guarded_fork_exec


def _external_python_audit(candidate_root: Path):
    def audit(event, args):
        if event != "exec" or not args or not base._stack_contains_candidate(candidate_root, 2):
            return
        filename = getattr(args[0], "co_filename", "")
        if not isinstance(filename, str) or not filename or filename.startswith("<"):
            return
        try:
            resolved = Path(filename).resolve()
        except (OSError, RuntimeError):
            return
        if _is_under(resolved, candidate_root):
            return
        if _python_code_path(resolved) and not _trusted_python_path(resolved):
            raise RuntimeError(
                f"runtime guard rejected execution of untrusted external Python file: {resolved}"
            )
    return audit


def _install_runtime_guard_v2(candidate_root: Path, runtime: Path, selected: list[str], manifest: dict[str, str]) -> None:
    _original_install_runtime_guard(candidate_root, runtime, selected, manifest)
    _install_low_level_fork_guard()
    sys.addaudithook(_external_python_audit(candidate_root))


base._candidate_subprocess_allowed = _subprocess_allowed_with_fork_permit
base._install_runtime_guard = _install_runtime_guard_v2


if __name__ == "__main__":
    raise SystemExit(base.main())
