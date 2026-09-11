#!/usr/bin/env python3
"""Second-layer F-02 capability guard for the isolated qualification runner.

This wrapper preserves the reviewed whole-checkout exact-pin policy while
removing low-level process creation from the candidate interpreter entirely.
A checker-controlled helper is started before candidate code loads and is the
only component allowed to execute the frozen OpenSSL Ed25519/DER operations.
The candidate interpreter permanently denies direct fork_exec access and routes
only exact approved OpenSSL requests to that helper. It also rejects candidate-
triggered execution of any real external file outside the checkout and trusted
stdlib roots, regardless of filename extension.

Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import importlib.util
import multiprocessing
import os
from pathlib import Path
import subprocess
import sys
import sysconfig

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
_original_install_runtime_guard = base._install_runtime_guard


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _trusted_python_path(path: Path) -> bool:
    return any(_is_under(path, root) for root in _TRUSTED_PYTHON_ROOTS)


def _safe_temp_operand(value: object, candidate_root: Path, temp_root: Path) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        resolved = Path(value).resolve()
    except (OSError, RuntimeError):
        return False
    return _is_under(resolved, temp_root) and not _is_under(resolved, candidate_root)


def _helper_argv_allowed(argv: object, candidate_root: Path, temp_root: Path, trusted_openssl: Path) -> bool:
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(x, str) for x in argv):
        return False
    args = list(argv)
    if args[0] not in {"openssl", str(trusted_openssl)}:
        return False
    if len(args) == 9 and args[1:4] == ["pkey", "-pubin", "-in"] and args[5:8] == ["-outform", "DER", "-out"]:
        return _safe_temp_operand(args[4], candidate_root, temp_root) and _safe_temp_operand(args[8], candidate_root, temp_root)
    if len(args) == 6 and args[1:5] == ["genpkey", "-algorithm", "ED25519", "-out"]:
        return _safe_temp_operand(args[5], candidate_root, temp_root)
    if len(args) == 7 and args[1:3] == ["pkey", "-in"] and args[4:6] == ["-pubout", "-out"]:
        return _safe_temp_operand(args[3], candidate_root, temp_root) and _safe_temp_operand(args[6], candidate_root, temp_root)
    if len(args) == 10 and args[1:3] == ["pkeyutl", "-sign"] and args[3] == "-inkey" and args[5:7] == ["-rawin", "-in"] and args[8] == "-out":
        return all(_safe_temp_operand(args[i], candidate_root, temp_root) for i in (4, 7, 9))
    if len(args) == 11 and args[1:5] == ["pkeyutl", "-verify", "-pubin", "-inkey"] and args[6:8] == ["-rawin", "-in"] and args[9] == "-sigfile":
        return all(_safe_temp_operand(args[i], candidate_root, temp_root) for i in (5, 8, 10))
    return False


def _crypto_helper(conn, candidate_root_s: str, temp_root_s: str, trusted_openssl_s: str) -> None:
    candidate_root = Path(candidate_root_s).resolve()
    temp_root = Path(temp_root_s).resolve()
    trusted_openssl = Path(trusted_openssl_s).resolve()
    while True:
        try:
            request = conn.recv()
        except EOFError:
            return
        if request == {"op": "stop"}:
            return
        if not isinstance(request, dict) or request.get("op") != "openssl":
            conn.send({"ok": False, "error": "invalid helper request"})
            continue
        argv = request.get("argv")
        if not _helper_argv_allowed(argv, candidate_root, temp_root, trusted_openssl):
            conn.send({"ok": False, "error": "OpenSSL request outside frozen contract"})
            continue
        timeout = request.get("timeout")
        if timeout is not None and not isinstance(timeout, (int, float)):
            conn.send({"ok": False, "error": "invalid timeout"})
            continue
        try:
            result = subprocess.run(
                list(argv),
                stdout=subprocess.PIPE if request.get("capture_stdout") else None,
                stderr=subprocess.PIPE if request.get("capture_stderr") else None,
                timeout=timeout,
                check=False,
            )
            conn.send({"ok": True, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
        except Exception as exc:
            conn.send({"ok": False, "error": f"helper execution failed: {type(exc).__name__}"})


def _deny_fork_exec(*args, **kwargs):
    raise RuntimeError("runtime guard rejected direct low-level process execution: fork_exec")


def _external_execution_audit(candidate_root: Path):
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
        if _is_under(resolved, candidate_root) or _trusted_python_path(resolved):
            return
        if resolved.is_file():
            raise RuntimeError(
                f"runtime guard rejected execution of untrusted external file: {resolved}"
            )
    return audit


def _install_runtime_guard_v2(candidate_root: Path, runtime: Path, selected: list[str], manifest: dict[str, str]) -> None:
    # First perform all base exact-blob checks while checker subprocess support is
    # still intact. Candidate code has not been imported yet.
    _original_install_runtime_guard(candidate_root, runtime, selected, manifest)

    trusted_openssl = base.TRUSTED_OPENSSL_PATH
    if trusted_openssl is None or not trusted_openssl.is_file():
        raise RuntimeError("trusted OpenSSL unavailable before candidate execution")

    parent_conn, child_conn = multiprocessing.Pipe(duplex=True)
    helper = multiprocessing.Process(
        target=_crypto_helper,
        args=(child_conn, str(candidate_root), str(base.SYSTEM_TEMP_ROOT), str(trusted_openssl)),
        daemon=True,
    )
    helper.start()
    child_conn.close()

    def guarded_run(argv, *args, **kwargs):
        if args:
            raise RuntimeError("runtime guard rejected unsupported subprocess positional arguments")
        allowed_keys = {"stdout", "stderr", "timeout", "check"}
        if set(kwargs) - allowed_keys:
            raise RuntimeError("runtime guard rejected unsupported subprocess options")
        if not base._openssl_argv_allowed(argv, candidate_root):
            raise RuntimeError("runtime guard rejected candidate-originated subprocess execution")
        parent_conn.send({
            "op": "openssl",
            "argv": list(argv),
            "capture_stdout": kwargs.get("stdout") == subprocess.PIPE,
            "capture_stderr": kwargs.get("stderr") == subprocess.PIPE,
            "timeout": kwargs.get("timeout"),
        })
        response = parent_conn.recv()
        if not isinstance(response, dict) or not response.get("ok"):
            raise RuntimeError("runtime guard crypto helper rejected request")
        completed = subprocess.CompletedProcess(
            list(argv), response["returncode"], response.get("stdout"), response.get("stderr")
        )
        if kwargs.get("check") and completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode, completed.args, output=completed.stdout, stderr=completed.stderr
            )
        return completed

    # Candidate interpreter no longer retains a usable low-level process primitive.
    subprocess._fork_exec = _deny_fork_exec
    low = sys.modules.get("_posixsubprocess")
    if low is not None:
        low.fork_exec = _deny_fork_exec
    subprocess.run = guarded_run

    sys.addaudithook(_external_execution_audit(candidate_root))


base._install_runtime_guard = _install_runtime_guard_v2

if __name__ == "__main__":
    raise SystemExit(base.main())
