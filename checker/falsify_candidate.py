#!/usr/bin/env python3
"""External falsifier for the Setugo TESTING qualification boundary.

The candidate repository is untrusted input. This checker intentionally keeps its
qualification floor outside that repository.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

TARGET_REPOSITORY = "vij7661/setugo-ai-development-framework"
EXPECTED_EXTERNAL_ROOT_REPOSITORY = "vij7661/setugo-governance-root"
EXPECTED_EXTERNAL_ROOT_REPOSITORY_ID = 1363740797
EXPECTED_EXTERNAL_ROOT_COMMIT = "5f470774ec8c17f5519da8db2aaae59af114cef9"
EXPECTED_EXTERNAL_ROOT_DER_SHA256 = "2b1b97ab0bf99e71f4a93f51fd8e6c3eb30063d83ba2eb4c091492a95f9c11f2"
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


def falsify(repo: str, sha: str) -> dict[str, object]:
    if repo != TARGET_REPOSITORY:
        raise AssertionError("unexpected candidate repository")
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha.lower()):
        raise AssertionError("candidate SHA must be a full 40-character Git SHA")

    with tempfile.TemporaryDirectory(prefix="setugo-governance-check-") as td:
        root = Path(td) / "candidate"
        run(["git", "clone", "--no-checkout", f"https://github.com/{repo}.git", str(root)])
        run(["git", "fetch", "--depth=1", "origin", sha], cwd=root)
        run(["git", "checkout", "--detach", sha], cwd=root)
        actual_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
        assert_equal(actual_sha, sha, "checked-out candidate SHA")

        policy_path = root / "governance-runtime" / "qualification_boundary_policy_v4.py"
        if not policy_path.is_file():
            raise AssertionError("qualification policy missing")
        policy = load_module(policy_path)

        # R7-01: naked caller-controlled role/provenance/current booleans must never grant authority.
        allowed, reason = policy.terminal_authority_allowed(
            phase="TESTING",
            action="READY_TO_BEGIN_RELEASE_QUALIFICATION",
            issuer_class="HUMAN_GOVERNANCE_OWNER",
            provenance_verified=True,
            current=True,
        )
        if allowed:
            raise AssertionError(
                "R7-01 FAILED: naked HUMAN_GOVERNANCE_OWNER + booleans granted terminal authority"
            )

        # R7-02/R7-05: external root identity and policy inputs are checked against an external floor.
        ext = load_module(root / "governance-runtime" / "external_governance_root.py")
        assert_equal(ext.EXTERNAL_REPOSITORY, EXPECTED_EXTERNAL_ROOT_REPOSITORY, "external root repository")
        assert_equal(ext.EXTERNAL_REPOSITORY_ID, EXPECTED_EXTERNAL_ROOT_REPOSITORY_ID, "external root repository id")
        assert_equal(ext.EXTERNAL_ROOT_COMMIT, EXPECTED_EXTERNAL_ROOT_COMMIT, "external root commit")
        assert_equal(ext.EXPECTED_PUBLIC_KEY_DER_SHA256, EXPECTED_EXTERNAL_ROOT_DER_SHA256, "external root key fingerprint")

        # R7-06: candidate cannot remap current TESTING defects into later phases.
        assert_equal(dict(policy.GOVERNED_RULE_PHASES), EXPECTED_RULE_PHASES, "governed rule phase map")

        # Candidate's own tests remain useful evidence but are never the authority source.
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
