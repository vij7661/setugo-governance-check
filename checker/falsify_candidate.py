#!/usr/bin/env python3
"""External falsifier for the Setugo TESTING qualification boundary.

The candidate repository is untrusted input. This checker intentionally keeps its
qualification floor outside that repository. Passing is evidence only.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

TARGET_REPOSITORY = "vij7661/setugo-ai-development-framework"
EXPECTED_EXTERNAL_ROOT_REPOSITORY = "vij7661/setugo-governance-root"
EXPECTED_EXTERNAL_ROOT_REPOSITORY_ID = 1363676838
EXPECTED_EXTERNAL_ROOT_COMMIT = "5f470774ec8c17f5519da8db2aaae59af114cef9"
EXPECTED_EXTERNAL_ROOT_DER_SHA256 = "2b1b97ab0bf99e71f4a93f51fd8e6c3eb30063d83ba2eb4c091492a95f9c11f2"
EXPECTED_POLICY_BLOB_SHA = "23615ec522a234bf41216165cf368079a17f38cf"
EXPECTED_EXTERNAL_ROOT_MODULE_BLOB_SHA = "c83b4aa9f1253f2cbd5a26b6857af8ded8bbc808"
EXPECTED_RULE_PHASES = {
    "TESTING_ACCEPTANCE_BOUNDARY": "TESTING",
    "TESTING_ROOT_CAUSE_CLASSIFICATION": "TESTING",
    "TESTING_REVIEW_ADJUDICATION": "TESTING",
    "TESTING_QUALIFICATION_BOUNDARY_OWNERSHIP": "TESTING",
    "RELEASE_INTEGRATION_QUALIFICATION": "RELEASE",
    "PRODUCTION_ENVIRONMENT_QUALIFICATION": "PRODUCTION",
}


def run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def output(cmd: list[str], cwd: Path | None = None) -> str:
    return subprocess.check_output(cmd, cwd=cwd, text=True).strip()


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location("candidate_policy", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def assert_equal(actual, expected, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label} mismatch: {actual!r} != {expected!r}")


def github_repo_metadata(repo: str) -> dict[str, object]:
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repo}",
        headers={"Accept": "application/vnd.github+json", "User-Agent": "setugo-governance-check"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def git_blob_sha(path: Path) -> str:
    return output(["git", "hash-object", str(path)])


def verify_live_external_root(work: Path) -> None:
    # R7-04: lifecycle/identity is checked by the external enforcement point itself.
    metadata = github_repo_metadata(EXPECTED_EXTERNAL_ROOT_REPOSITORY)
    assert_equal(metadata.get("full_name"), EXPECTED_EXTERNAL_ROOT_REPOSITORY, "live root repository name")
    assert_equal(metadata.get("id"), EXPECTED_EXTERNAL_ROOT_REPOSITORY_ID, "live root repository id")
    assert_equal(metadata.get("private"), False, "live root repository private flag")
    assert_equal(metadata.get("archived"), True, "live root repository archived flag")

    root = work / "governance-root"
    run(["git", "clone", "--no-checkout", f"https://github.com/{EXPECTED_EXTERNAL_ROOT_REPOSITORY}.git", str(root)])
    run(["git", "fetch", "--depth=1", "origin", EXPECTED_EXTERNAL_ROOT_COMMIT], cwd=root)
    run(["git", "checkout", "--detach", EXPECTED_EXTERNAL_ROOT_COMMIT], cwd=root)
    assert_equal(output(["git", "rev-parse", "HEAD"], cwd=root), EXPECTED_EXTERNAL_ROOT_COMMIT, "external root checkout")

    pem = root / "trust-roots" / "SETUGO_MANUAL_GOVERNANCE_ED25519_V1.pem"
    if not pem.is_file():
        raise AssertionError("external root public key missing at pinned commit")
    der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(pem), "-outform", "DER"])
    assert_equal(hashlib.sha256(der).hexdigest(), EXPECTED_EXTERNAL_ROOT_DER_SHA256, "external root DER fingerprint")

    meta_path = root / "trust-roots" / "SETUGO_MANUAL_GOVERNANCE_ED25519_V1.json"
    if not meta_path.is_file():
        raise AssertionError("external root metadata missing at pinned commit")
    root_meta = json.loads(meta_path.read_text())
    assert_equal(root_meta.get("trust_root_id"), "SETUGO_MANUAL_GOVERNANCE_ED25519_V1", "external trust-root id")
    assert_equal(root_meta.get("public_key_der_sha256"), EXPECTED_EXTERNAL_ROOT_DER_SHA256, "external metadata fingerprint")
    assert_equal(root_meta.get("private_key_must_never_be_committed"), True, "external root private-key prohibition")


def falsify(repo: str, sha: str) -> dict[str, object]:
    if repo != TARGET_REPOSITORY:
        raise AssertionError("unexpected candidate repository")
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha.lower()):
        raise AssertionError("candidate SHA must be a full 40-character Git SHA")

    with tempfile.TemporaryDirectory(prefix="setugo-governance-check-") as td:
        work = Path(td)
        verify_live_external_root(work)

        root = work / "candidate"
        run(["git", "clone", "--no-checkout", f"https://github.com/{repo}.git", str(root)])
        run(["git", "fetch", "--depth=1", "origin", sha], cwd=root)
        run(["git", "checkout", "--detach", sha], cwd=root)
        actual_sha = output(["git", "rev-parse", "HEAD"], cwd=root)
        assert_equal(actual_sha, sha, "checked-out candidate SHA")

        policy_path = root / "governance-runtime" / "qualification_boundary_policy_v4.py"
        ext_path = root / "governance-runtime" / "external_governance_root.py"
        if not policy_path.is_file() or not ext_path.is_file():
            raise AssertionError("qualification policy or external-root module missing")

        # R7-05: the whole active policy implementation is externally pinned. A candidate
        # cannot silently change policy code and make its locally recomputed hash authoritative.
        assert_equal(git_blob_sha(policy_path), EXPECTED_POLICY_BLOB_SHA, "externally pinned qualification policy blob")
        # R7-02: the candidate mirror of root resolution is externally pinned too.
        assert_equal(git_blob_sha(ext_path), EXPECTED_EXTERNAL_ROOT_MODULE_BLOB_SHA, "externally pinned external-root module blob")

        policy = load_module(policy_path)

        # R7-01: naked caller-controlled role/provenance/current booleans must never grant authority.
        allowed, _ = policy.terminal_authority_allowed(
            phase="TESTING",
            action="READY_TO_BEGIN_RELEASE_QUALIFICATION",
            issuer_class="HUMAN_GOVERNANCE_OWNER",
            provenance_verified=True,
            current=True,
        )
        if allowed:
            raise AssertionError("R7-01 FAILED: naked HUMAN_GOVERNANCE_OWNER + booleans granted terminal authority")

        # R7-02: root identity/pin in the candidate mirror must match the independent floor.
        ext = load_module(ext_path)
        assert_equal(ext.EXTERNAL_REPOSITORY, EXPECTED_EXTERNAL_ROOT_REPOSITORY, "external root repository")
        assert_equal(ext.EXTERNAL_REPOSITORY_ID, EXPECTED_EXTERNAL_ROOT_REPOSITORY_ID, "external root repository id")
        assert_equal(ext.EXTERNAL_ROOT_COMMIT, EXPECTED_EXTERNAL_ROOT_COMMIT, "external root commit")
        assert_equal(ext.EXPECTED_PUBLIC_KEY_DER_SHA256, EXPECTED_EXTERNAL_ROOT_DER_SHA256, "external root key fingerprint")

        # R7-06: candidate cannot remap current TESTING defects into later phases.
        assert_equal(dict(policy.GOVERNED_RULE_PHASES), EXPECTED_RULE_PHASES, "governed rule phase map")

        # Candidate tests are useful execution evidence but never the authority source.
        run([
            sys.executable, "-m", "unittest", "-v",
            "test_phase_policy.py",
            "test_manual_authority_verifier.py",
            "test_manual_authority_signed_attestation.py",
            "test_external_governance_root.py",
            "test_external_root_policy_binding.py",
            "test_external_trust_root_control.py",
            "test_qualification_boundary_unittest_bridge.py",
            "test_review_protocol.py",
            "test_review_semantics.py",
            "test_review_classification.py",
            "test_single_file_review_container.py",
            "test_platform_candidate_review_request_integrity.py",
        ], cwd=root / "governance-runtime")

        return {
            "candidate_repository": repo,
            "candidate_sha": sha,
            "result": "PASS_BOUNDED_EVIDENCE_ONLY",
            "authority_effect": "NONE_EVIDENCE_ONLY",
            "external_checker": True,
            "external_root_live_verified": True,
            "policy_blob_externally_pinned": EXPECTED_POLICY_BLOB_SHA,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    try:
        result = falsify(args.repo, args.sha.lower())
    except Exception as exc:
        print(json.dumps({"result": "FAIL_CLOSED", "error": str(exc), "authority_effect": "NONE_EVIDENCE_ONLY"}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
