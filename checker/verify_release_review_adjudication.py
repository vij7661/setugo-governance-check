#!/usr/bin/env python3
"""Checker-owned verifier for exact-SHA independent RELEASE adjudication.

A verified adjudication is evidence only. It does not grant RELEASE terminal
authority. The adjudication must be signed by the independent governance
adjudicator trust root and must itself bind the raw review digest, candidate,
checker, PR, policy, and PASS disposition.
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
CHECKER_SHA = "4757ceb036c95739aa695d035fc97df63148a691"
POLICY_ID = "QUALIFICATION_BOUNDARY_OWNERSHIP"
POLICY_VERSION = 7
POLICY_HASH = "3a1936d3e8956b2521908189139ee73868c48f29be13fcacea84f839ca6b2258"

TRUST_ROOT_ID = "SETUGO_MANUAL_GOVERNANCE_ED25519_V1"
ROOT_REPO = "vij7661/setugo-governance-root"
ROOT_REPO_ID = 1363676838
ROOT_COMMIT = "5f470774ec8c17f5519da8db2aaae59af114cef9"
ROOT_METADATA_PATH = f"trust-roots/{TRUST_ROOT_ID}.json"
ROOT_PEM_PATH = f"trust-roots/{TRUST_ROOT_ID}.pem"
ROOT_METADATA_BLOB = "882178e631b98903de872c04aaa23c67b80a75ed"
ROOT_DER_SHA256 = "2b1b97ab0bf99e71f4a93f51fd8e6c3eb30063d83ba2eb4c091492a95f9c11f2"

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
        raise ReleaseReviewError(f"unable to fetch adjudication trust metadata: {type(exc).__name__}") from exc
    if not isinstance(payload, Mapping):
        raise ReleaseReviewError("adjudication trust metadata is not an object")
    return payload


def _fetch_bytes(url: str) -> bytes:
    req = Request(url, headers={"User-Agent":"setugo-release-review-adjudication"})
    try:
        with urlopen(req, timeout=15) as response:
            return response.read()
    except Exception as exc:
        raise ReleaseReviewError(f"unable to fetch adjudication trust material: {type(exc).__name__}") from exc


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
    expected = {
        "schema_version": 1,
        "trust_root_id": TRUST_ROOT_ID,
        "algorithm": "Ed25519",
        "public_key_path": ROOT_PEM_PATH,
        "public_key_der_sha256": ROOT_DER_SHA256,
        "authority_scope": "TESTING_MANUAL_GOVERNANCE_ATTESTATION_VERIFICATION_ONLY",
        "private_key_location": "EXTERNAL_OFF_REPOSITORY_USER_CONTROLLED",
        "private_key_must_never_be_committed": True,
        "authority_effect": "NONE_BY_ITSELF",
    }
    if not isinstance(metadata, Mapping):
        raise ReleaseReviewError("adjudicator root metadata is not an object")
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise ReleaseReviewError(f"adjudicator root metadata mismatch: {key}")
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
        "reviewed_checker_sha": CHECKER_SHA,
        "qualification_policy_id": POLICY_ID,
        "qualification_policy_version": POLICY_VERSION,
        "qualification_policy_hash": POLICY_HASH,
        "trust_root_id": TRUST_ROOT_ID,
    }
    for key, value in expected.items():
        if supplied.get(key) != value:
            raise ReleaseReviewError(f"independent RELEASE adjudication mismatch: {key}")
    if not isinstance(supplied.get("raw_review_ref"), str) or not supplied["raw_review_ref"].strip():
        raise ReleaseReviewError("raw independent review reference is missing")
    raw_hash = supplied.get("raw_review_sha256")
    if not isinstance(raw_hash, str) or SHA256_RE.fullmatch(raw_hash) is None:
        raise ReleaseReviewError("raw independent review SHA-256 is invalid")


def verify_signature(artifact: Mapping[str, Any], signature_b64: str, public_key: bytes) -> None:
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ReleaseReviewError("independent adjudication signature is not valid base64") from exc
    if len(signature) != 64:
        raise ReleaseReviewError("independent adjudication signature length is invalid")
    with tempfile.TemporaryDirectory(prefix="setugo-review-adjudication-") as td:
        root = Path(td); key = root/"public.pem"; payload=root/"artifact.json"; sig=root/"artifact.sig"
        key.write_bytes(public_key); payload.write_bytes(canonical_bytes(artifact)); sig.write_bytes(signature)
        result = subprocess.run(["openssl","pkeyutl","-verify","-pubin","-inkey",str(key),"-rawin","-in",str(payload),"-sigfile",str(sig)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if result.returncode != 0:
            raise ReleaseReviewError("independent adjudication Ed25519 signature is invalid")


def verify(artifact_b64: str, signature_b64: str) -> Mapping[str, Any]:
    artifact = decode_artifact(artifact_b64)
    validate_artifact(artifact)
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
    print(json.dumps({"result":"VERIFIED","candidate_sha":CANDIDATE_SHA,"disposition":artifact["disposition"],"adjudication_digest":digest,"evidence_ref":"sha256:"+digest,"authority_effect":"NONE_EVIDENCE_ONLY"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
