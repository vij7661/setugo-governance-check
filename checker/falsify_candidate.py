#!/usr/bin/env python3
"""External falsifier for the Setugo TESTING qualification boundary.

The candidate repository is untrusted input. This checker keeps its qualification
floor outside that repository. Passing is evidence only and grants no authority.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
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

# Authority-critical candidate dependency closure for policy v6.
EXPECTED_POLICY_BLOB_SHA = "019b89f32deba5a7bc93274ff41ad7e61a1aaad3"
EXPECTED_EXTERNAL_ROOT_MODULE_BLOB_SHA = "c83b4aa9f1253f2cbd5a26b6857af8ded8bbc808"
EXPECTED_MANUAL_AUTHORITY_VERIFIER_BLOB_SHA = "5d955a9cb74b97853d15bcf64662e2774ad71693"
EXPECTED_POLICY_FACADE_BLOB_SHA = "8aac9f913df76f3d8d7760ab2989610a47da14bf"

EXPECTED_RULESET_ID = 22736961
EXPECTED_RULESET_NAME = "phase/testing"
EXPECTED_RULESET_TARGET_REF = "refs/heads/phase/testing"
EXPECTED_EXTERNAL_CHECK_CONTEXT = "external-governance-qualification"
EXPECTED_EXTERNAL_CHECK_APP_ID = 4895420
EXPECTED_GITHUB_ACTIONS_APP_ID = 15368

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


def assert_equal(actual, expected, label: str) -> None:
    if actual != expected:
        raise AssertionError(f"{label} mismatch: {actual!r} != {expected!r}")


def github_json(url: str, *, require_app_token: bool = False) -> dict[str, object]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "setugo-governance-check",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GOVERNANCE_GITHUB_TOKEN", "").strip()
    if require_app_token and not token:
        raise AssertionError("GitHub App token required for authoritative ruleset evidence")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=20) as response:
        value = json.load(response)
    if not isinstance(value, dict):
        raise AssertionError(f"GitHub response is not an object: {url}")
    return value


def github_repo_metadata(repo: str) -> dict[str, object]:
    return github_json(f"https://api.github.com/repos/{repo}")


def git_blob_sha(path: Path) -> str:
    return output(["git", "hash-object", str(path)])


def load_runtime_facade(path: Path):
    # Exercise the same compatibility import surface used by candidate consumers.
    for name in (
        "qualification_boundary_policy",
        "qualification_boundary_policy_v4",
        "manual_authority_verifier",
        "external_governance_root",
    ):
        sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location("qualification_boundary_policy", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["qualification_boundary_policy"] = module
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def verify_live_external_root(work: Path) -> None:
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


def verify_live_candidate_ruleset() -> None:
    # R8-02/R8-07: use the dedicated GitHub App token with Administration:read so
    # bypass actors and required-check integration binding are evaluated outside
    # the candidate tree. Missing/unobservable fields fail closed.
    ruleset = github_json(
        f"https://api.github.com/repos/{TARGET_REPOSITORY}/rulesets/{EXPECTED_RULESET_ID}",
        require_app_token=True,
    )
    assert_equal(ruleset.get("id"), EXPECTED_RULESET_ID, "ruleset id")
    assert_equal(ruleset.get("name"), EXPECTED_RULESET_NAME, "ruleset name")
    assert_equal(ruleset.get("target"), "branch", "ruleset target kind")
    assert_equal(ruleset.get("enforcement"), "active", "ruleset enforcement")
    assert_equal(ruleset.get("bypass_actors"), [], "ruleset bypass actors")
    if ruleset.get("current_user_can_bypass") not in ("never", False):
        raise AssertionError("ruleset does not prove non-bypassable state")

    conditions = ruleset.get("conditions")
    if not isinstance(conditions, dict):
        raise AssertionError("ruleset conditions missing")
    ref_name = conditions.get("ref_name")
    if not isinstance(ref_name, dict):
        raise AssertionError("ruleset ref condition missing")
    includes = ref_name.get("include")
    if not isinstance(includes, list) or EXPECTED_RULESET_TARGET_REF not in includes:
        raise AssertionError("ruleset does not target phase/testing")

    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        raise AssertionError("ruleset rules missing")
    by_type = {r.get("type"): r for r in rules if isinstance(r, dict)}
    for required_type in ("deletion", "non_fast_forward", "pull_request", "required_status_checks"):
        if required_type not in by_type:
            raise AssertionError(f"ruleset missing {required_type}")

    pr_params = by_type["pull_request"].get("parameters")
    if not isinstance(pr_params, dict) or pr_params.get("required_review_thread_resolution") is not True:
        raise AssertionError("ruleset review-thread resolution is not required")

    status_params = by_type["required_status_checks"].get("parameters")
    if not isinstance(status_params, dict):
        raise AssertionError("required-status-check parameters missing")
    assert_equal(status_params.get("strict_required_status_checks_policy"), True, "strict required checks")
    checks = status_params.get("required_status_checks")
    if not isinstance(checks, list):
        raise AssertionError("required status checks missing")
    external = [
        item for item in checks
        if isinstance(item, dict) and item.get("context") == EXPECTED_EXTERNAL_CHECK_CONTEXT
    ]
    assert_equal(
        external,
        [{"context": EXPECTED_EXTERNAL_CHECK_CONTEXT, "integration_id": EXPECTED_EXTERNAL_CHECK_APP_ID}],
        "dedicated external App source binding",
    )
    if any(item.get("context") == EXPECTED_EXTERNAL_CHECK_CONTEXT and item.get("integration_id") == EXPECTED_GITHUB_ACTIONS_APP_ID
           for item in checks if isinstance(item, dict)):
        raise AssertionError("external governance context is incorrectly source-bound to GitHub Actions")


def verify_authority_critical_dependency_closure(root: Path) -> tuple[Path, Path]:
    runtime = root / "governance-runtime"
    paths = {
        "policy": runtime / "qualification_boundary_policy_v4.py",
        "external_root": runtime / "external_governance_root.py",
        "verifier": runtime / "manual_authority_verifier.py",
        "facade": runtime / "qualification_boundary_policy.py",
    }
    for label, path in paths.items():
        if not path.is_file():
            raise AssertionError(f"authority-critical runtime file missing: {label}")

    expected = {
        "policy": EXPECTED_POLICY_BLOB_SHA,
        "external_root": EXPECTED_EXTERNAL_ROOT_MODULE_BLOB_SHA,
        "verifier": EXPECTED_MANUAL_AUTHORITY_VERIFIER_BLOB_SHA,
        "facade": EXPECTED_POLICY_FACADE_BLOB_SHA,
    }
    for label, expected_sha in expected.items():
        assert_equal(git_blob_sha(paths[label]), expected_sha, f"externally pinned {label} blob")
    return paths["facade"], paths["external_root"]


def falsify(repo: str, sha: str) -> dict[str, object]:
    if repo != TARGET_REPOSITORY:
        raise AssertionError("unexpected candidate repository")
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha.lower()):
        raise AssertionError("candidate SHA must be a full 40-character Git SHA")

    with tempfile.TemporaryDirectory(prefix="setugo-governance-check-") as td:
        work = Path(td)
        verify_live_external_root(work)
        verify_live_candidate_ruleset()

        root = work / "candidate"
        run(["git", "clone", "--no-checkout", f"https://github.com/{repo}.git", str(root)])
        run(["git", "fetch", "--depth=1", "origin", sha], cwd=root)
        run(["git", "checkout", "--detach", sha], cwd=root)
        assert_equal(output(["git", "rev-parse", "HEAD"], cwd=root), sha, "checked-out candidate SHA")

        facade_path, ext_path = verify_authority_critical_dependency_closure(root)
        policy = load_runtime_facade(facade_path)
        assert_equal(policy.POLICY_VERSION, 6, "externally pinned qualification policy version")

        allowed, _ = policy.terminal_authority_allowed(
            phase="TESTING",
            action="READY_TO_BEGIN_RELEASE_QUALIFICATION",
            issuer_class="HUMAN_GOVERNANCE_OWNER",
            provenance_verified=True,
            current=True,
        )
        if allowed:
            raise AssertionError("R7-01 FAILED: naked HUMAN_GOVERNANCE_OWNER + booleans granted terminal authority")

        ext = load_module(ext_path, "candidate_external_root")
        assert_equal(ext.EXTERNAL_REPOSITORY, EXPECTED_EXTERNAL_ROOT_REPOSITORY, "external root repository")
        assert_equal(ext.EXTERNAL_REPOSITORY_ID, EXPECTED_EXTERNAL_ROOT_REPOSITORY_ID, "external root repository id")
        assert_equal(ext.EXTERNAL_ROOT_COMMIT, EXPECTED_EXTERNAL_ROOT_COMMIT, "external root commit")
        assert_equal(ext.EXPECTED_PUBLIC_KEY_DER_SHA256, EXPECTED_EXTERNAL_ROOT_DER_SHA256, "external root key fingerprint")
        assert_equal(dict(policy.GOVERNED_RULE_PHASES), EXPECTED_RULE_PHASES, "governed rule phase map")

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
            "live_ruleset_source_binding_verified": True,
            "policy_blob_externally_pinned": EXPECTED_POLICY_BLOB_SHA,
            "manual_authority_verifier_blob_externally_pinned": EXPECTED_MANUAL_AUTHORITY_VERIFIER_BLOB_SHA,
            "policy_facade_blob_externally_pinned": EXPECTED_POLICY_FACADE_BLOB_SHA,
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
