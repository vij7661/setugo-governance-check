#!/usr/bin/env python3
"""Host-side launcher for F-02 RELEASE qualification sandbox.

Runs the exact candidate qualification corpus in a Docker sandbox with no
network, read-only root/candidate/checker filesystems, all capabilities dropped,
no-new-privileges, and a one-PID candidate container. Exact frozen OpenSSL
operations are delegated to a checker-owned host helper over AF_UNIX.

Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading

SANDBOX_IMAGE = "python:3.12-bookworm"
CONTAINER_CANDIDATE = Path("/candidate")
CONTAINER_CHECKER = Path("/checker")
CONTAINER_IO = Path("/sandbox-io")


def _recv_line(conn: socket.socket) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = conn.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
        if b"\n" in chunk:
            break
    return b"".join(chunks).split(b"\n", 1)[0]


def _map_temp_path(value: object, host_io: Path) -> Path | None:
    if not isinstance(value, str) or not value.startswith(str(CONTAINER_IO) + "/"):
        return None
    rel = Path(value).relative_to(CONTAINER_IO)
    if ".." in rel.parts:
        return None
    host = (host_io / rel).resolve()
    try:
        host.relative_to(host_io.resolve())
    except ValueError:
        return None
    return host


def _map_argv(argv: object, host_io: Path, trusted_openssl: Path) -> list[str] | None:
    if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
        return None
    args = list(argv)
    if args[0] not in {"openssl", str(trusted_openssl)}:
        return None
    args[0] = str(trusted_openssl)
    path_positions: tuple[int, ...] | None = None
    if len(args) == 9 and args[1:4] == ["pkey", "-pubin", "-in"] and args[5:8] == ["-outform", "DER", "-out"]:
        path_positions = (4, 8)
    elif len(args) == 6 and args[1:5] == ["genpkey", "-algorithm", "ED25519", "-out"]:
        path_positions = (5,)
    elif len(args) == 7 and args[1:3] == ["pkey", "-in"] and args[4:6] == ["-pubout", "-out"]:
        path_positions = (3, 6)
    elif len(args) == 10 and args[1:3] == ["pkeyutl", "-sign"] and args[3] == "-inkey" and args[5:7] == ["-rawin", "-in"] and args[8] == "-out":
        path_positions = (4, 7, 9)
    elif len(args) == 11 and args[1:5] == ["pkeyutl", "-verify", "-pubin", "-inkey"] and args[6:8] == ["-rawin", "-in"] and args[9] == "-sigfile":
        path_positions = (5, 8, 10)
    else:
        return None
    for index in path_positions:
        mapped = _map_temp_path(args[index], host_io)
        if mapped is None:
            return None
        args[index] = str(mapped)
    return args


def _serve_helper(sock_path: Path, host_io: Path, stop: threading.Event, errors: list[str]) -> None:
    trusted = shutil.which("openssl")
    if trusted is None:
        errors.append("trusted OpenSSL unavailable on checker host")
        return
    trusted_path = Path(trusted).resolve()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(sock_path))
        os.chmod(sock_path, 0o666)
        server.listen(8)
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            with conn:
                try:
                    request = json.loads(_recv_line(conn).decode("utf-8"))
                    argv = _map_argv(request.get("argv"), host_io, trusted_path) if isinstance(request, dict) and request.get("op") == "openssl" else None
                    timeout = request.get("timeout") if isinstance(request, dict) else None
                    text = request.get("text") is True if isinstance(request, dict) else False
                    encoding = request.get("encoding") if isinstance(request, dict) else None
                    errmode = request.get("errors") if isinstance(request, dict) else None
                    if argv is None or (timeout is not None and not isinstance(timeout, (int, float))):
                        response = {"ok": False, "error": "request outside frozen OpenSSL contract"}
                    elif encoding is not None and not isinstance(encoding, str):
                        response = {"ok": False, "error": "invalid encoding"}
                    elif errmode is not None and not isinstance(errmode, str):
                        response = {"ok": False, "error": "invalid errors"}
                    else:
                        result = subprocess.run(
                            argv,
                            stdout=subprocess.PIPE if request.get("capture_stdout") else None,
                            stderr=subprocess.PIPE if request.get("capture_stderr") else None,
                            timeout=timeout,
                            text=text,
                            encoding=encoding,
                            errors=errmode,
                            check=False,
                            cwd=host_io,
                            env={"PATH": os.environ.get("PATH", "")},
                        )
                        response = {"ok": True, "returncode": result.returncode}
                        for name, value in (("stdout", result.stdout), ("stderr", result.stderr)):
                            if isinstance(value, bytes):
                                response[name] = base64.b64encode(value).decode("ascii")
                                response[f"{name}_b64"] = True
                            else:
                                response[name] = value
                    conn.sendall(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
                except Exception as exc:
                    conn.sendall(json.dumps({"ok": False, "error": type(exc).__name__}).encode("utf-8") + b"\n")
    finally:
        server.close()
        sock_path.unlink(missing_ok=True)


def _docker_available() -> None:
    if shutil.which("docker") is None:
        raise RuntimeError("Docker unavailable: RELEASE sandbox must fail closed")
    subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], check=True, stdout=subprocess.PIPE, text=True)


def _build_docker_cmd(candidate_root: Path, checker_dir: Path, host_io: Path, manifest_b64: str, tests: list[str]) -> list[str]:
    return [
        "docker", "run", "--rm",
        "--network", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--pids-limit", "1",
        "--memory", "512m",
        "--cpus", "1.0",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-e", "TMPDIR=/sandbox-io",
        "-e", "GIT_CONFIG_COUNT=1",
        "-e", "GIT_CONFIG_KEY_0=safe.directory",
        "-e", "GIT_CONFIG_VALUE_0=/candidate",
        "-v", f"{candidate_root}:{CONTAINER_CANDIDATE}:ro",
        "-v", f"{checker_dir}:{CONTAINER_CHECKER}:ro",
        "-v", f"{host_io}:{CONTAINER_IO}:rw",
        "-w", str(CONTAINER_CHECKER),
        SANDBOX_IMAGE,
        "python", "-I", "/checker/run_candidate_unittests_isolated_v3.py",
        "/candidate/governance-runtime",
        "--helper-socket", "/sandbox-io/crypto.sock",
        "--runtime-pin-manifest-b64", manifest_b64,
        *tests,
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate_runtime")
    parser.add_argument("--runtime-pin-manifest-b64", required=True)
    parser.add_argument("tests", nargs="+")
    ns = parser.parse_args()
    _docker_available()
    runtime = Path(ns.candidate_runtime).resolve()
    candidate_root = runtime.parent
    checker_dir = Path(__file__).resolve().parent
    if runtime.name != "governance-runtime" or not (candidate_root / ".git").exists():
        raise RuntimeError("sandbox candidate checkout shape invalid")

    with tempfile.TemporaryDirectory(prefix="setugo-release-sandbox-") as td:
        host_io = Path(td).resolve()
        os.chmod(host_io, 0o777)
        socket_path = host_io / "crypto.sock"
        stop = threading.Event()
        helper_errors: list[str] = []
        thread = threading.Thread(target=_serve_helper, args=(socket_path, host_io, stop, helper_errors), daemon=True)
        thread.start()
        for _ in range(100):
            if socket_path.exists() or helper_errors:
                break
            stop.wait(0.02)
        if helper_errors or not socket_path.exists():
            stop.set(); thread.join(timeout=1)
            raise RuntimeError(helper_errors[0] if helper_errors else "crypto helper socket did not start")

        cmd = _build_docker_cmd(candidate_root, checker_dir, host_io, ns.runtime_pin_manifest_b64, ns.tests)
        print("F02_SANDBOX_POLICY network=none rootfs=ro caps=none no_new_privs=true pids=1 candidate=ro checker=ro")
        try:
            result = subprocess.run(cmd, check=False)
        finally:
            stop.set(); thread.join(timeout=2)
        if helper_errors:
            raise RuntimeError(helper_errors[0])
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
