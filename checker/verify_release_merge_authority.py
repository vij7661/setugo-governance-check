#!/usr/bin/env python3
"""Independent verifier for RELEASE merge authority.

This module is checker-owned. It never executes candidate code. A successful
result means a human-signed RELEASE authority attestation is cryptographically
valid for the exact frozen candidate and current RELEASE policy binding.
The result itself does not mint authority.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from typing import Any, Mapping
from urllib.request import Request, urlopen

CANDIDATE_REPO = "vij7661/setugo-ai-development-framework"
CANDIDATE_SHA = "b0b843356bb3d281e525284d85f79204ba9d4460"
PR_NUMBER = 37
REQUIRED_BASE = "phase/release"

POLICY_ID = "QUALIFICATION_BOUNDARY_OWNERSHIP"
POLICY_VERSION = 7
POLICY_HASH = "3a1936d3e8956b2521908189139ee73868c48f29be13fcacea84f839ca6b2258"

TRUST_ROOT_ID = "SETUGO_RELEASE_GOVERNANCE_ED25519_V1"
ROOT_REPO = "vij7661/setugo-release-governance-root"
ROOT_REPO_ID = 1364609306
ROOT_COMMIT = "7300b9b0d27611bcb5ccc1638fb1d16e53dc5994"
ROOT_METADATA_PATH = f"trust-roots/{TRUST_ROOT_ID}.json"
ROOT_PEM_PATH = f"trust-roots/{TRUST_ROOT_ID}.pem"
ROOT_METADATA_BLOB = "da5c1892307bbf23fb1a3a105e55e8ba215d9065"
ROOT_DER_SHA256 = "91355cf1049a27aac52ea56f5ba1664054aded93500203cd23d557a710b0444c"

AUTHORITY_CLASS = "HUMAN_RELEASE_AUTHORITY"
DECISION_SCOPE = "TERMINAL_ACTION:RELEASE:MERGE_RELEASE_CANDIDATE"
SOURCE_KIND = "MANUAL_GOVERNANCE_ATTESTATION"
SCHEMA_VERSION = 1

REQUIRED_FIELDS = frozenset({
    "schema_version", "candidate_sha", "authority_class", "decision_scope",
    "evidence_ref", "source_kind", "qualification_policy_id",
    "qualification_policy_version", "qualification_policy_hash", "trust_root_id",
})


class ReleaseAuthorityError(RuntimeError):
    pass


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _fetch_json(url: str) -> Mapping[str, Any]:
    req = Request(url, headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "setugo-release-merge-authority"})
    try:
        with urlopen(req, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise ReleaseAuthorityError(f"unable to fetch JSON evidence: {type(exc).__name__}") from exc
    if not isinstance(payload, Mapping):
        raise ReleaseAuthorityError("JSON evidence is not an object")
    return payload


def _fetch_bytes(url: str) -> bytes:
    req = Request(url, headers={"User-Agent": "setugo-release-merge-authority"})
    try:
        with urlopen(req, timeout=15) as response:
            return response.read()
    except Exception as exc:
        raise ReleaseAuthorityError(f"unable to fetch byte evidence: {type(exc).__name__}") from exc


def verify_pr_binding(candidate_sha: str) -> None:
    pr = _fetch_json(f"https://api.github.com/repos/{CANDIDATE_REPO}/pulls/{PR_NUMBER}")
    if pr.get("state") != "open":
        raise ReleaseAuthorityError("release PR is not open")
    head = pr.get("head")
    base = pr.get("base")
    if not isinstance(head, Mapping) or head.get("sha") != candidate_sha:
        raise ReleaseAuthorityError("candidate SHA is not the current release PR head")
    if not isinstance(base, Mapping) or base.get("ref") != REQUIRED_BASE:
        raise ReleaseAuthorityError("release PR does not target phase/release")


def _root_public_key() -> bytes:
    repo = _fetch_json(f"https://api.github.com/repos/{ROOT_REPO}")
    if repo.get("id") != ROOT_REPO_ID or repo.get("full_name") != ROOT_REPO:
        raise ReleaseAuthorityError("release root repository identity mismatch")
    if repo.get("private") is not False or repo.get("archived") is not True:
        raise ReleaseAuthorityError("release root repository must be public and archived")
    metadata_api = _fetch_json(f"https://api.github.com/repos/{ROOT_REPO}/contents/{ROOT_METADATA_PATH}?ref={ROOT_COMMIT}")
    if metadata_api.get("sha") != ROOT_METADATA_BLOB:
        raise ReleaseAuthorityError("release root metadata blob mismatch")
    base = f"https://raw.githubusercontent.com/{ROOT_REPO}/{ROOT_COMMIT}"
    try:
        metadata = json.loads(_fetch_bytes(f"{base}/{ROOT_METADATA_PATH}").decode("utf-8"))
    except Exception as exc:
        raise ReleaseAuthorityError("release root metadata is malformed") from exc
    expected_metadata = {
        "schema_version": 1, "trust_root_id": TRUST_ROOT_ID, "algorithm": "Ed25519",
        "public_key_path": ROOT_PEM_PATH, "public_key_der_sha256": ROOT_DER_SHA256,
        "authority_scope": "RELEASE_TERMINAL_AUTHORITY_ATTESTATION_VERIFICATION_ONLY",
        "permitted_authority_class": AUTHORITY_CLASS,
        "permitted_decision_scopes": ["TERMINAL_ACTION:RELEASE:MERGE_RELEASE_CANDIDATE", "TERMINAL_ACTION:RELEASE:BEGIN_PRODUCTION_QUALIFICATION"],
        "private_key_location": "EXTERNAL_OFF_REPOSITORY_USER_CONTROLLED",
        "private_key_must_never_be_committed": True, "authority_effect": "NONE_BY_ITSELF",
    }
    if not isinstance(metadata, Mapping):
        raise ReleaseAuthorityError("release root metadata is not an object")
    for key, value in expected_metadata.items():
        if metadata.get(key) != value:
            raise ReleaseAuthorityError(f"release root metadata mismatch: {key}")
    pem = _fetch_bytes(f"{base}/{ROOT_PEM_PATH}")
    with tempfile.TemporaryDirectory(prefix="setugo-release-root-fingerprint-") as td:
        root = Path(td); pem_path = root / "root.pem"; der_path = root / "root.der"
        pem_path.write_bytes(pem)
        result = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(pem_path), "-outform", "DER", "-out", str(der_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode != 0:
            raise ReleaseAuthorityError("release root PEM is invalid")
        if hashlib.sha256(der_path.read_bytes()).hexdigest() != ROOT_DER_SHA256:
            raise ReleaseAuthorityError("release root public key fingerprint mismatch")
    return pem


def decode_attestation(attestation_b64: str) -> Mapping[str, Any]:
    if not isinstance(attestation_b64, str) or not attestation_b64:
        raise ReleaseAuthorityError("release authority attestation is missing")
    try:
        raw = base64.b64decode(attestation_b64, validate=True); payload = json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReleaseAuthorityError("release authority attestation is malformed") from exc
    if not isinstance(payload, Mapping):
        raise ReleaseAuthorityError("release authority attestation is not an object")
    return payload


def validate_attestation(attestation: Mapping[str, Any], candidate_sha: str) -> None:
    supplied = dict(attestation)
    if set(supplied) != REQUIRED_FIELDS:
        raise ReleaseAuthorityError("release authority attestation fields are missing or unexpected")
    expected = {
        "schema_version": SCHEMA_VERSION, "candidate_sha": candidate_sha,
        "authority_class": AUTHORITY_CLASS, "decision_scope": DECISION_SCOPE,
        "source_kind": SOURCE_KIND, "qualification_policy_id": POLICY_ID,
        "qualification_policy_version": POLICY_VERSION, "qualification_policy_hash": POLICY_HASH,
        "trust_root_id": TRUST_ROOT_ID,
    }
    for key, value in expected.items():
        if supplied.get(key) != value:
            raise ReleaseAuthorityError(f"release authority attestation mismatch: {key}")
    if not isinstance(supplied.get("evidence_ref"), str) or not supplied["evidence_ref"]:
        raise ReleaseAuthorityError("release authority evidence reference is missing")


def verify_signature(attestation: Mapping[str, Any], signature_b64: str, public_key: bytes) -> None:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReleaseAuthorityError("release authority signature is not valid base64") from exc
    if len(signature) != 64:
        raise ReleaseAuthorityError("release authority signature length is invalid")
    with tempfile.TemporaryDirectory(prefix="setugo-release-authority-") as td:
        root = Path(td); key_path = root / "public.pem"; payload_path = root / "attestation.json"; sig_path = root / "signature.bin"
        key_path.write_bytes(public_key); payload_path.write_bytes(_canonical(attestation)); sig_path.write_bytes(signature)
        result = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(key_path), "-rawin", "-in", str(payload_path), "-sigfile", str(sig_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode != 0:
            raise ReleaseAuthorityError("release authority Ed25519 signature is invalid")


def verify(candidate_sha: str, attestation_b64: str, signature_b64: str) -> Mapping[str, Any]:
    if candidate_sha != CANDIDATE_SHA:
        raise ReleaseAuthorityError("requested SHA is not the frozen RELEASE R3 candidate")
    verify_pr_binding(candidate_sha)
    attestation = decode_attestation(attestation_b64)
    validate_attestation(attestation, candidate_sha)
    public_key = _root_public_key()
    verify_signature(attestation, signature_b64, public_key)
    return attestation


def main() -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--candidate", required=True); parser.add_argument("--attestation-b64", default=""); parser.add_argument("--signature-b64", default=""); args = parser.parse_args()
    try:
        attestation = verify(args.candidate, args.attestation_b64, args.signature_b64)
    except ReleaseAuthorityError as exc:
        print(json.dumps({"result": "REJECTED", "candidate_sha": args.candidate, "authority_effect": "NONE", "reason": str(exc)}, sort_keys=True)); return 1
    print(json.dumps({"result": "VERIFIED", "candidate_sha": args.candidate, "authority_class": attestation["authority_class"], "decision_scope": attestation["decision_scope"], "evidence_ref": attestation["evidence_ref"], "authority_effect": "MERGE_RELEASE_CANDIDATE_ONLY"}, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
