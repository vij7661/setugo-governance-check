#!/usr/bin/env python3
"""Sandbox-side qualification runner.

The trusted host launcher verifies every manifest Git blob before this process
starts. Inside the one-PID sandbox, the base runner reuses that verified map
without spawning git. Exact frozen OpenSSL operations are proxied to the host
helper over AF_UNIX. All direct process/native capabilities remain denied in
process as defense in depth; the outer sandbox is the authority boundary.

Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

_V2_PATH = Path(__file__).resolve().with_name("run_candidate_unittests_isolated_v2.py")
_SPEC = importlib.util.spec_from_file_location("setugo_runner_v2", _V2_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load checker-owned v2 runner")
v2 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = v2
_SPEC.loader.exec_module(v2)
base = v2.base

_HELPER_SOCKET: Path | None = None
_original_install_runtime_guard = v2._original_install_runtime_guard


def _deny_capability(*args, **kwargs):
    raise RuntimeError("runtime guard rejected forbidden candidate execution capability")


def _recv_line(sock: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
        if b"\n" in chunk:
            break
    return b"".join(chunks).split(b"\n", 1)[0]


def _helper_request(payload: dict[str, object]) -> dict[str, object]:
    if _HELPER_SOCKET is None:
        raise RuntimeError("sandbox crypto helper socket is not configured")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(str(_HELPER_SOCKET))
        sock.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
        raw = _recv_line(sock)
    response = json.loads(raw.decode("utf-8"))
    if not isinstance(response, dict):
        raise RuntimeError("sandbox crypto helper returned non-object response")
    return response


def _install_process_denials() -> None:
    import os as os_module
    try:
        import posix as posix_module
    except ImportError:
        posix_module = None
    names = (
        "system", "fork", "forkpty",
        "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
        "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
        "posix_spawn", "posix_spawnp",
    )
    for name in names:
        if hasattr(os_module, name):
            setattr(os_module, name, _deny_capability)
        if posix_module is not None and hasattr(posix_module, name):
            setattr(posix_module, name, _deny_capability)
    subprocess._fork_exec = _deny_capability
    low = sys.modules.get("_posixsubprocess")
    if low is not None and hasattr(low, "fork_exec"):
        low.fork_exec = _deny_capability


def _install_ctypes_denials() -> None:
    try:
        import ctypes
    except ImportError:
        ctypes = None
    v2._install_low_level_ctypes_guard()
    if ctypes is None:
        return
    for name in ("_dlopen", "CDLL", "PyDLL", "OleDLL", "WinDLL", "LibraryLoader", "pythonapi", "pydll"):
        if hasattr(ctypes, name):
            try:
                setattr(ctypes, name, _deny_capability)
            except (AttributeError, TypeError) as exc:
                raise RuntimeError(f"runtime guard could not neutralize ctypes.{name}") from exc


def _install_runtime_guard_v3(candidate_root: Path, runtime: Path, selected: list[str], manifest: dict[str, str]) -> None:
    if not manifest:
        raise RuntimeError("host-verified execution manifest is empty")
    original_git_blob_sha = base._git_blob_sha
    def verified_blob_lookup(root: Path, relpath: str) -> str:
        if root.resolve() != candidate_root.resolve():
            raise RuntimeError("sandbox manifest lookup escaped candidate root")
        try:
            return manifest[Path(relpath).as_posix()]
        except KeyError as exc:
            raise RuntimeError(f"sandbox manifest missing authorized path: {relpath}") from exc
    base._git_blob_sha = verified_blob_lookup
    try:
        _original_install_runtime_guard(candidate_root, runtime, selected, manifest)
    finally:
        base._git_blob_sha = original_git_blob_sha
    _install_process_denials()
    _install_ctypes_denials()
    v2._install_subinterpreter_guard()

    def guarded_run(argv, *args, **kwargs):
        if args:
            raise RuntimeError("runtime guard rejected unsupported subprocess positional arguments")
        allowed_keys = {"stdout", "stderr", "timeout", "check", "text", "encoding", "errors"}
        if set(kwargs) - allowed_keys:
            raise RuntimeError("runtime guard rejected unsupported subprocess options")
        if not base._openssl_argv_allowed(argv, candidate_root):
            raise RuntimeError("runtime guard rejected candidate-originated subprocess execution")
        response = _helper_request({
            "op": "openssl",
            "argv": list(argv),
            "capture_stdout": kwargs.get("stdout") == subprocess.PIPE,
            "capture_stderr": kwargs.get("stderr") == subprocess.PIPE,
            "timeout": kwargs.get("timeout"),
            "text": kwargs.get("text") is True,
            "encoding": kwargs.get("encoding"),
            "errors": kwargs.get("errors"),
        })
        if not response.get("ok"):
            raise RuntimeError("runtime guard crypto helper rejected request")
        def decode_field(name: str):
            value = response.get(name)
            if value is None:
                return None
            if response.get(f"{name}_b64"):
                return base64.b64decode(str(value))
            return value
        completed = subprocess.CompletedProcess(
            list(argv), int(response["returncode"]), decode_field("stdout"), decode_field("stderr")
        )
        if kwargs.get("check") and completed.returncode != 0:
            raise subprocess.CalledProcessError(
                completed.returncode, completed.args, output=completed.stdout, stderr=completed.stderr
            )
        return completed

    subprocess.run = guarded_run
    immediate = getattr(base, "_immediate_caller_is_candidate", None)
    stack_check = getattr(base, "_stack_contains_candidate", None)
    if not callable(immediate) or not callable(stack_check):
        raise RuntimeError("runner contract violation: candidate stack helpers unavailable")
    sys.addaudithook(v2._execution_capability_audit(candidate_root))


base._install_runtime_guard = _install_runtime_guard_v3


def main() -> int:
    global _HELPER_SOCKET
    args = list(sys.argv[1:])
    if len(args) < 4 or args[1:2] != ["--helper-socket"]:
        raise SystemExit(
            "usage: sandbox-child <candidate-runtime> --helper-socket PATH "
            "[--runtime-pin-manifest-b64 B64] <test.py>..."
        )
    runtime = args[0]
    _HELPER_SOCKET = Path(args[2]).resolve()
    sys.argv = [sys.argv[0], runtime, *args[3:]]
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
