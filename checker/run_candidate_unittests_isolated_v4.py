#!/usr/bin/env python3
"""Networkless sandbox child successor with exact governance-root proxy.

The container has no network. Candidate urllib requests are denied except the
four frozen TESTING governance-root URLs, which are relayed over the existing
checker-owned AF_UNIX helper. Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import base64
import importlib.util
import io
from pathlib import Path
import sys
import urllib.request

_V3_PATH = Path(__file__).resolve().with_name("run_candidate_unittests_isolated_v3.py")
_SPEC = importlib.util.spec_from_file_location("setugo_runner_v3", _V3_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load checker-owned v3 runner")
v3 = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = v3
_SPEC.loader.exec_module(v3)

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
_original_install = v3._install_runtime_guard_v3


class _ProxyResponse:
    def __init__(self, body: bytes):
        self._stream = io.BytesIO(body)
    def read(self, *args, **kwargs):
        return self._stream.read(*args, **kwargs)
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        self._stream.close()
        return False


def _guarded_urlopen(request, *args, **kwargs):
    if args or set(kwargs) - {"timeout"}:
        raise RuntimeError("sandbox governance-root proxy rejected unsupported urlopen options")
    url = request.full_url if isinstance(request, urllib.request.Request) else request
    if not isinstance(url, str) or url not in ALLOWED_ROOT_URLS:
        raise RuntimeError("sandbox denied candidate network request")
    response = v3._helper_request({"op": "governance_root_http", "url": url})
    if not response.get("ok") or not isinstance(response.get("body_b64"), str):
        raise RuntimeError("sandbox governance-root proxy rejected request")
    return _ProxyResponse(base64.b64decode(response["body_b64"], validate=True))


def _install_runtime_guard_v4(candidate_root, runtime, selected, manifest):
    _original_install(candidate_root, runtime, selected, manifest)
    urllib.request.urlopen = _guarded_urlopen


v3.base._install_runtime_guard = _install_runtime_guard_v4

if __name__ == "__main__":
    raise SystemExit(v3.main())
