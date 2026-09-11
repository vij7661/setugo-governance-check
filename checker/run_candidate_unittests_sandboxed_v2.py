#!/usr/bin/env python3
"""Successor host launcher adding an exact governance-root read proxy.

The candidate container remains network=none. This wrapper extends the existing
checker-owned AF_UNIX helper so only four frozen governance-root URLs may be
fetched by the trusted host. Redirects fail closed. All other requests fail
closed. Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import urllib.error
import urllib.request

import run_candidate_unittests_sandboxed as base

ROOT_REPO = "vij7661/setugo-governance-root"
ROOT_COMMIT = "5f470774ec8c17f5519da8db2aaae59af114cef9"
ROOT_ID = "SETUGO_MANUAL_GOVERNANCE_ED25519_V1"
ROOT_METADATA = f"trust-roots/{ROOT_ID}.json"
ROOT_PEM = f"trust-roots/{ROOT_ID}.pem"
ALLOWED_ROOT_URLS = frozenset({
    f"https://api.github.com/repos/{ROOT_REPO}",
    f"https://api.github.com/repos/{ROOT_REPO}/contents/{ROOT_METADATA}?ref={ROOT_COMMIT}",
    f"https://raw.githubusercontent.com/{ROOT_REPO}/{ROOT_COMMIT}/{ROOT_METADATA}",
    f"https://raw.githubusercontent.com/{ROOT_REPO}/{ROOT_COMMIT}/{ROOT_PEM}",
})
_original_build = base._build_docker_cmd


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _host_fetch(url: object) -> bytes:
    if not isinstance(url, str) or url not in ALLOWED_ROOT_URLS:
        raise RuntimeError("governance-root proxy rejected non-frozen URL")
    headers = {"User-Agent": "setugo-sandbox-governance-root-proxy"}
    if url.startswith("https://api.github.com/"):
        headers.update({"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
        token = os.environ.get("GOVERNANCE_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with _OPENER.open(request, timeout=10) as response:
            if response.geturl() != url:
                raise RuntimeError(f"governance-root proxy redirect not permitted: {response.geturl()}")
            return response.read()
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"governance-root proxy HTTP error: {exc.code}") from exc


def _serve_helper_v2(sock_path: Path, host_io: Path, stop, errors: list[str]) -> None:
    trusted = base.shutil.which("openssl")
    if trusted is None:
        errors.append("trusted OpenSSL unavailable on checker host")
        return
    trusted_path = Path(trusted).resolve()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        server.bind(str(sock_path)); os.chmod(sock_path, 0o666); server.listen(8); server.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            with conn:
                try:
                    request = json.loads(base._recv_line(conn).decode("utf-8"))
                    if isinstance(request, dict) and request.get("op") == "governance_root_http":
                        body = _host_fetch(request.get("url"))
                        response = {"ok": True, "body_b64": base64.b64encode(body).decode("ascii")}
                    else:
                        prepared = base._prepare_openssl_argv(request.get("argv"), host_io, trusted_path) if isinstance(request, dict) and request.get("op") == "openssl" else None
                        timeout = request.get("timeout") if isinstance(request, dict) else None
                        text = request.get("text") is True if isinstance(request, dict) else False
                        encoding = request.get("encoding") if isinstance(request, dict) else None
                        errmode = request.get("errors") if isinstance(request, dict) else None
                        if prepared is None or (timeout is not None and not isinstance(timeout, (int, float))):
                            response = {"ok": False, "error": "request outside frozen helper contract"}
                        elif encoding is not None and not isinstance(encoding, str):
                            response = {"ok": False, "error": "invalid encoding"}
                        elif errmode is not None and not isinstance(errmode, str):
                            response = {"ok": False, "error": "invalid errors"}
                        else:
                            argv, fds = prepared
                            try:
                                result = subprocess.run(
                                    argv,
                                    stdout=subprocess.PIPE if request.get("capture_stdout") else None,
                                    stderr=subprocess.PIPE if request.get("capture_stderr") else None,
                                    timeout=timeout, text=text, encoding=encoding, errors=errmode,
                                    check=False, cwd=host_io, env={"PATH": os.environ.get("PATH", "")},
                                    pass_fds=fds,
                                )
                            finally:
                                for fd in fds:
                                    os.close(fd)
                            response = {"ok": True, "returncode": result.returncode}
                            for name, value in (("stdout", result.stdout), ("stderr", result.stderr)):
                                if isinstance(value, bytes):
                                    response[name] = base64.b64encode(value).decode("ascii"); response[f"{name}_b64"] = True
                                else:
                                    response[name] = value
                    conn.sendall(json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n")
                except Exception as exc:
                    conn.sendall(json.dumps({"ok": False, "error": type(exc).__name__}).encode("utf-8") + b"\n")
    finally:
        server.close(); sock_path.unlink(missing_ok=True)


def _build_docker_cmd_v2(candidate_root: Path, checker_dir: Path, host_io: Path, manifest_b64: str, tests: list[str]) -> list[str]:
    cmd = _original_build(candidate_root, checker_dir, host_io, manifest_b64, tests)
    old = "/checker/run_candidate_unittests_isolated_v3.py"
    new = "/checker/run_candidate_unittests_isolated_v4.py"
    return [new if item == old else item for item in cmd]


base._serve_helper = _serve_helper_v2
base._build_docker_cmd = _build_docker_cmd_v2

if __name__ == "__main__":
    raise SystemExit(base.main())
