#!/usr/bin/env python3
"""Checker-owned verifier for exact-SHA independent RELEASE adjudication.

A verified adjudication is evidence only. It does not grant RELEASE terminal
authority. The adjudication must be signed by the independent review-adjudicator
trust root and must itself bind the raw review bytes, candidate, frozen
qualification checker, PR, policy, and PASS disposition.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Any, Mapping
from urllib.request import Request, urlopen

CANDIDATE_REPO = "vij7661/setugo-ai-development-framework"
CANDIDATE_SHA = "4200397f21e12f900c309ee1bc66fa8424135f11"
PR_NUMBER = 37
QUALIFICATION_CHECKER_SHA = "77ad64c177b1eed516b9e58699c1f5128ba058a6"
POLICY_ID = "QUALIFICATION_BOUNDARY_OWNERSHIP"
POLICY_VERSION = 7
POLICY_HASH = "3a1936d3e8956b2521908189139ee73868c48f29be13fcacea84f839ca6b2258"

TRUST_ROOT_ID = "SETUGO_REVIEW_ADJUDICATION_ED25519_V2"
ROOT_REPO = "vij7661/setugo-governance-root"
ROOT_REPO_ID = 1363676838
ROOT_COMMIT = "243c93a453eac0a1b0bc7f41061dfa99ab42e74b"
ROOT_METADATA_PATH = f"trust-roots/{TRUST_ROOT_ID}.json"
ROOT_PEM_PATH = f"trust-roots/{TRUST_ROOT_ID}.pem"
ROOT_METADATA_BLOB = "f39c5262bfc80f2cd65f6d2c3fe164f764e1e98c"
ROOT_DER_SHA256 = "2b1b97ab0bf99e71f4a93f51fd8e6c3eb30063d83ba2eb4c091492a95f9c11f2"

RAW_REVIEW_REPO = "vij7661/setugo-governance-check"
RAW_REVIEW_REF_RE = re.compile(
    r"^https://raw\.githubusercontent\.com/vij7661/setugo-governance-check/"
    r"(?P<commit>[0-9a-f]{40})/evidence/manual-reviews/"
    r"(?P<filename>[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.md)$"
)

SCHEMA_VERSION = 1
REVIEW_TYPE = "INDEPENDENT_RELEASE_ADJUDICATION"
AUTHORITY_CLASS = "INDEPENDENT_GOVERNANCE_ADJUDICATOR"
DECISION_SCOPE = "REVIEW_FINDING_ADJUDICATION"
ELIGIBLE_DISPOSITION = "PASS"
SOURCE_KIND = "MANUAL_INDEPENDENT_RELEASE_REVIEW"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

REQUIRED_FIELDS = frozenset({
    "schema_version", "candidate_repository", "candidate_sha", "pull_request",
    "review_type", "authority_class", "decision_scope", "disposition",
    "source_kind", "raw_review_ref", "raw_review_sha256", "reviewed_checker_sha",
    "qualification_policy_id", "qualification_policy_version",
    "qualification_policy_hash", "trust_root_id",
})

ROOT_EXPECTED_METADATA = {
    "schema_version": 2,
    "trust_root_id": TRUST_ROOT_ID,
    "algorithm": "Ed25519",
    "public_key_path": ROOT_PEM_PATH,
    "public_key_der_sha256": ROOT_DER_SHA256,
    "authority_scope": "CROSS_PHASE_REVIEW_ADJUDICATION_EVIDENCE_VERIFICATION_ONLY",
    "permitted_authority_class": AUTHORITY_CLASS,
    "permitted_decision_scopes": [DECISION_SCOPE],
    "permitted_candidate_phases": ["TESTING", "RELEASE", "PRODUCTION"],
    "private_key_location": "EXTERNAL_OFF_REPOSITORY_USER_CONTROLLED",
    "private_key_must_never_be_committed": True,
    "authority_effect": "NONE_EVIDENCE_ONLY",
}

class ReleaseReviewError(RuntimeError):
    pass


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return json.dumps(dict(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def adjudication_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _fetch_json(url: str) -> Mapping[str, Any]:
    req = Request(url, headers={"Accept":"application/vnd.github+json","X-GitHub-Api-Version":"2022-11-28","User-Agent":"setugo-release-review-adjudication"})
    try:
        with urlopen(req, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise ReleaseReviewError(f"unable to fetch adjudication JSON evidence: {type(exc).__name__}") from exc
    if not isinstance(payload, Mapping):
        raise ReleaseReviewError("adjudication JSON evidence is not an object")
    return payload


def _fetch_bytes(url: str) -> bytes:
    req = Request(url, headers={"User-Agent":"setugo-release-review-adjudication"})
    try:
        with urlopen(req, timeout=15) as response:
            return response.read()
    except Exception as exc:
        raise ReleaseReviewError(f"unable to fetch adjudication byte evidence: {type(exc).__name__}") from exc


def validate_root_metadata(metadata: Mapping[str, Any]) -> None:
    for key, value in ROOT_EXPECTED_METADATA.items():
        if metadata.get(key) != value:
            raise ReleaseReviewError(f"adjudicator root metadata mismatch: {key}")


def _root_public_key() -> bytes:
    repo = _fetch_json(f"https://api.github.com/repos/{ROOT_REPO}")
    if repo.get("id") != ROOT_REPO_ID or repo.get("full_name") != ROOT_REPO:
        raise ReleaseReviewError("adjudicator root repository identity mismatch")
    if repo.get("private") is not False or repo.get("archived") is not True:
        raise ReleaseReviewError("adjudicator root repository must be public and archived")
    metadata_api = _fetch_json(f"https://api.github.com/repos/{ROOT_REPO}/contents/{ROOT_METADATA_PATH}?ref={ROOT_COMMIT}")
    if metadata_api.get("sha") != ROOT_METADATA_BLOB:
        raise ReleaseReviewError("adjudicator root metadata blob mismatch")
    base = f"https://raw.githubusercontent.com/{ROOT_REPO}/{ROOT_COMMIT}"
    metadata = json.loads(_fetch_bytes(f"{base}/{ROOT_METADATA_PATH}").decode("utf-8"))
    if not isinstance(metadata, Mapping):
        raise ReleaseReviewError("adjudicator root metadata is not an object")
    validate_root_metadata(metadata)
    pem = _fetch_bytes(f"{base}/{ROOT_PEM_PATH}")
    with tempfile.TemporaryDirectory(prefix="setugo-review-root-") as td:
        root = Path(td); pem_path = root / "root.pem"; der_path = root / "root.der"
        pem_path.write_bytes(pem)
        result = subprocess.run(["openssl","pkey","-pubin","-in",str(pem_path),"-outform","DER","-out",str(der_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode != 0 or hashlib.sha256(der_path.read_bytes()).hexdigest() != ROOT_DER_SHA256:
            raise ReleaseReviewError("adjudicator root public key fingerprint mismatch")
    return pem


def decode_artifact(artifact_b64: str) -> Mapping[str, Any]:
    if not artifact_b64:
        raise ReleaseReviewError("independent RELEASE adjudication is missing")
    try:
        value = json.loads(base64.b64decode(artifact_b64, validate=True).decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ReleaseReviewError("independent RELEASE adjudication is malformed") from exc
    if not isinstance(value, Mapping):
        raise ReleaseReviewError("independent RELEASE adjudication is not an object")
    return value


def validate_artifact(artifact: Mapping[str, Any]) -> None:
    supplied = dict(artifact)
    if set(supplied) != REQUIRED_FIELDS:
        raise ReleaseReviewError("independent RELEASE adjudication fields are missing or unexpected")
    expected = {
        "schema_version": SCHEMA_VERSION,
        "candidate_repository": CANDIDATE_REPO,
        "candidate_sha": CANDIDATE_SHA,
        "pull_request": PR_NUMBER,
        "review_type": REVIEW_TYPE,
        "authority_class": AUTHORITY_CLASS,
        "decision_scope": DECISION_SCOPE,
        "disposition": ELIGIBLE_DISPOSITION,
        "source_kind": SOURCE_KIND,
        "reviewed_checker_sha": QUALIFICATION_CHECKER_SHA,
        "qualification_policy_id": POLICY_ID,
        "qualification_policy_version": POLICY_VERSION,
        "qualification_policy_hash": POLICY_HASH,
        "trust_root_id": TRUST_ROOT_ID,
    }
    for key, value in expected.items():
        if supplied.get(key) != value:
            raise ReleaseReviewError(f"independent RELEASE adjudication mismatch: {key}")
    raw_ref = supplied.get("raw_review_ref")
    if not isinstance(raw_ref, str) or RAW_REVIEW_REF_RE.fullmatch(raw_ref) is None:
        raise ReleaseReviewError("raw independent review reference is not an immutable checker-owned review URL")
    raw_hash = supplied.get("raw_review_sha256")
    if not isinstance(raw_hash, str) or SHA256_RE.fullmatch(raw_hash) is None:
        raise ReleaseReviewError("raw independent review SHA-256 is invalid")


def verify_raw_review_binding(artifact: Mapping[str, Any]) -> None:
    raw_ref = str(artifact["raw_review_ref"])
    match = RAW_REVIEW_REF_RE.fullmatch(raw_ref)
    if match is None:
        raise ReleaseReviewError("raw independent review reference is not an immutable checker-owned review URL")
    commit = match.group("commit")
    commit_api = _fetch_json(f"https://api.github.com/repos/{RAW_REVIEW_REPO}/commits/{commit}")
    if commit_api.get("sha") != commit:
        raise ReleaseReviewError("raw independent review commit identity mismatch")
    raw_review = _fetch_bytes(raw_ref)
    actual = hashlib.sha256(raw_review).hexdigest()
    if actual != artifact.get("raw_review_sha256"):
        raise ReleaseReviewError("raw independent review SHA-256 does not match referenced review bytes")


def verify_signature(artifact: Mapping[str, Any], signature_b64: str, public_key: bytes) -> None:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReleaseReviewError("independent adjudication signature is not valid base64") from exc
    if len(signature) != 64:
        raise ReleaseReviewError("independent adjudication signature length is invalid")
    with tempfile.TemporaryDirectory(prefix="setugo-review-adjudication-") as td:
        root = Path(td); key = root / "public.pem"; payload = root / "artifact.json"; sig = root / "artifact.sig"
        key.write_bytes(public_key); payload.write_bytes(canonical_bytes(artifact)); sig.write_bytes(signature)
        result = subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",str(key),"-rawin","-in",str(payload),"-sigfile",str(sig)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode != 0:
            raise ReleaseReviewError("independent adjudication Ed25519 signature is invalid")


def verify(artifact_b64: str, signature_b64: str) -> Mapping[str, Any]:
    artifact = decode_artifact(artifact_b64)
    validate_artifact(artifact)
    verify_raw_review_binding(artifact)
    verify_signature(artifact, signature_b64, _root_public_key())
    return artifact


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-b64", default="")
    parser.add_argument("--signature-b64", default="")
    args = parser.parse_args()
    try:
        artifact = verify(args.artifact_b64, args.signature_b64)
    except ReleaseReviewError as exc:
        print(json.dumps({"result":"REJECTED","candidate_sha":CANDIDATE_SHA,"authority_effect":"NONE","reason":str(exc)}, sort_keys=True))
        return 1
    digest = adjudication_digest(artifact)
    print(json.dumps({"result":"VERIFIED","candidate_sha":CANDIDATE_SHA,"disposition":artifact["disposition"],"adjudication_digest":digest,"evidence_ref":"sha256:" + digest,"authority_effect":"NONE_EVIDENCE_ONLY"}, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
