#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from typing import Any
from urllib.request import Request, urlopen

CANDIDATE_REPO = "vij7661/setugo-ai-development-framework"
SOURCE_SHA = "15d50cc25ae524fc64e2c65269c91135e0361846"
RELEASE_BASE_SHA = "a5726dcb9236e31028ec70603bee35b30b9dbe66"
RULESET_ID = 22789078
RELEASE_REF = "refs/heads/phase/release"
REQUIRED_CHECK = "external-release-entry-qualification"
REQUIRED_APP_ID = 4895420
ROOT_REPO = "vij7661/setugo-governance-root"
ROOT_SHA = "5f470774ec8c17f5519da8db2aaae59af114cef9"
ROOT_PEM = "trust-roots/SETUGO_MANUAL_GOVERNANCE_ED25519_V1.pem"
ROOT_DER_SHA256 = "2b1b97ab0bf99e71f4a93f51fd8e6c3eb30063d83ba2eb4c091492a95f9c11f2"
POLICY_HASH = "562443115808f069f00bf6ea91608f2e77245d652d6c80738211e79dcc96d8a7"
HERE = Path(__file__).resolve().parents[1]
ATTESTATION = HERE / "evidence/release-entry/R11-15d50cc2-READY-TO-BEGIN-RELEASE.attestation.json"
SIGNATURE = HERE / "evidence/release-entry/R11-15d50cc2-READY-TO-BEGIN-RELEASE.attestation.sig.b64"


def get_json(url: str, token: str | None = None) -> Any:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "setugo-release-entry-check"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urlopen(Request(url, headers=headers), timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def get_bytes(url: str) -> bytes:
    with urlopen(Request(url, headers={"User-Agent": "setugo-release-entry-check"}), timeout=20) as response:
        return response.read()


def verify_attestation() -> None:
    payload = json.loads(ATTESTATION.read_text(encoding="utf-8"))
    expected = {
        "schema_version": 1,
        "candidate_sha": SOURCE_SHA,
        "authority_class": "HUMAN_GOVERNANCE_OWNER",
        "decision_scope": "TERMINAL_ACTION:TESTING:READY_TO_BEGIN_RELEASE_QUALIFICATION",
        "source_kind": "MANUAL_GOVERNANCE_ATTESTATION",
        "qualification_policy_id": "QUALIFICATION_BOUNDARY_OWNERSHIP",
        "qualification_policy_version": 6,
        "qualification_policy_hash": POLICY_HASH,
        "trust_root_id": "SETUGO_MANUAL_GOVERNANCE_ED25519_V1",
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise AssertionError(f"terminal attestation mismatch: {key}")
    if not isinstance(payload.get("evidence_ref"), str) or not payload["evidence_ref"]:
        raise AssertionError("terminal attestation evidence_ref missing")

    pem = get_bytes(f"https://raw.githubusercontent.com/{ROOT_REPO}/{ROOT_SHA}/{ROOT_PEM}")
    signature = base64.b64decode(SIGNATURE.read_text(encoding="utf-8").strip(), validate=True)
    if len(signature) != 64:
        raise AssertionError("Ed25519 signature length invalid")

    with tempfile.TemporaryDirectory(prefix="setugo-release-entry-") as td:
        td = Path(td)
        pub = td / "root.pem"
        der = td / "root.der"
        sig = td / "attestation.sig"
        canonical = td / "attestation.json"
        pub.write_bytes(pem)
        sig.write_bytes(signature)
        canonical.write_bytes(ATTESTATION.read_bytes())
        subprocess.run(["openssl", "pkey", "-pubin", "-in", str(pub), "-outform", "DER", "-out", str(der)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if hashlib.sha256(der.read_bytes()).hexdigest() != ROOT_DER_SHA256:
            raise AssertionError("external governance root fingerprint mismatch")
        result = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(pub), "-rawin", "-in", str(canonical), "-sigfile", str(sig)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode != 0:
            raise AssertionError("terminal attestation signature invalid")


def verify_lineage() -> None:
    comparison = get_json(f"https://api.github.com/repos/{CANDIDATE_REPO}/compare/{RELEASE_BASE_SHA}...{SOURCE_SHA}")
    if comparison.get("status") != "ahead" or comparison.get("behind_by") != 0:
        raise AssertionError("RELEASE base is not an ancestor of exact TESTING source")
    if comparison.get("merge_base_commit", {}).get("sha") != RELEASE_BASE_SHA:
        raise AssertionError("unexpected RELEASE merge base")


def verify_ruleset(token: str | None) -> None:
    ruleset = get_json(f"https://api.github.com/repos/{CANDIDATE_REPO}/rulesets/{RULESET_ID}", token)
    if ruleset.get("enforcement") != "active":
        raise AssertionError("RELEASE ruleset inactive")
    include = ruleset.get("conditions", {}).get("ref_name", {}).get("include")
    if include != [RELEASE_REF]:
        raise AssertionError(f"RELEASE ruleset target mismatch: {include}")
    if ruleset.get("bypass_actors") not in ([], None):
        raise AssertionError("RELEASE ruleset has bypass actors")
    if ruleset.get("current_user_can_bypass") not in ("never", None):
        raise AssertionError("RELEASE ruleset reports bypass capability")

    rules = ruleset.get("rules", [])
    types = {rule.get("type") for rule in rules}
    for required in ("deletion", "non_fast_forward", "pull_request"):
        if required not in types:
            raise AssertionError(f"RELEASE ruleset missing {required}")
    pr = next(rule for rule in rules if rule.get("type") == "pull_request").get("parameters", {})
    if pr.get("required_approving_review_count") != 0:
        raise AssertionError("RELEASE single-owner profile requires zero approvals")
    if pr.get("required_review_thread_resolution") is not True:
        raise AssertionError("RELEASE review-thread resolution not required")

    status_rules = [rule for rule in rules if rule.get("type") == "required_status_checks"]
    if len(status_rules) != 1:
        raise AssertionError("RELEASE required external status rule missing")
    params = status_rules[0].get("parameters", {})
    if params.get("strict_required_status_checks_policy") is not True:
        raise AssertionError("RELEASE required status checks are not strict")
    checks = params.get("required_status_checks") or []
    matches = [item for item in checks if item.get("context") == REQUIRED_CHECK]
    if len(matches) != 1:
        raise AssertionError("external RELEASE-entry qualification status missing or duplicated")
    if matches[0].get("integration_id") != REQUIRED_APP_ID:
        raise AssertionError("external RELEASE-entry qualification not bound to governance App")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sha", required=True)
    parser.add_argument("--token", default=None)
    args = parser.parse_args()
    if args.sha != SOURCE_SHA:
        raise AssertionError("RE-01 wrong candidate SHA")
    verify_attestation()
    verify_lineage()
    verify_ruleset(args.token)
    print(json.dumps({"result": "PASS_BOUNDED_EVIDENCE_ONLY", "candidate_sha": SOURCE_SHA, "release_base_sha": RELEASE_BASE_SHA, "ruleset_id": RULESET_ID, "authority_effect": "NONE_BY_CHECKER"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
