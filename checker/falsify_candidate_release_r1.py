#!/usr/bin/env python3
"""RELEASE external qualification for the exact repaired candidate.

Extends the TESTING external checker, independently pins RELEASE qualification
runtime closure, live-verifies the RELEASE governance root and RELEASE ruleset,
and proves the merge-authority policy binding. Passing is evidence only.

Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import falsify_candidate_r10_entry as r10
import verify_release_merge_authority as merge_authority

RELEASE_CANDIDATE_SHA = "b0b843356bb3d281e525284d85f79204ba9d4460"
CANDIDATE_REPO = "https://github.com/vij7661/setugo-ai-development-framework.git"
RELEASE_RULESET_ID = 22789078
RELEASE_RULESET_REF = "refs/heads/phase/release"
RELEASE_REQUIRED_APP_ID = 4895420
RELEASE_REQUIRED_CHECKS = frozenset({
    "external-release-entry-qualification",
    "external-release-qualification",
    "external-release-merge-authority",
})

# Successor-specific authority-critical pins.
r10.checker.EXPECTED_MANUAL_AUTHORITY_VERIFIER_BLOB_SHA = "fbcd992d7c3ea1c415bd01e3a0d638865f0f5898"
r10.checker.EXPECTED_POLICY_FACADE_BLOB_SHA = "998cb2a90b6530132239e1a6274718b605680909"

RELEASE_TEST_BLOBS = {
    "test_qualification_boundary_policy.py": "406bd608be28c440209aea12b060c31822ced1fc",
    "test_qualification_boundary_unittest_bridge.py": "228476966201aba4ce6cc9ea17eda18d5240ce5f",
    "test_release_r1_bridge_shape_guard.py": "73efc664eac408b1d581426d736353ef729c3600",
    "test_release_r3_phase_scoped_authority.py": "2666bf3ad24ecccd0e68e1025b786dfbadd0977e",
}

RELEASE_RUNTIME_BLOBS = {
    "governance-runtime/qualification_boundary_policy_v7.py": "f981a01b86b5020587bcf1817c484af64604c601",
    "governance-runtime/release_external_governance_root.py": "581e9ce5c2a4a23755d4d61cad6bbde890b4e5d6",
    "governance-runtime/release_manual_authority_verifier.py": "6e71413054d599fccfc4a265228a2a681f9d2ed0",
}

# Every previously exposed qualification-contributing runtime import is pinned.
QUALIFICATION_RUNTIME_CLOSURE_BLOBS = {
    "governance-runtime/review_protocol.py": "1bf92a5775a780f0f32d166fb6c6a0c522bbf490",
    "governance-runtime/phase_policy.py": "219d406d0335a318d91c8c940b19b8a39ad63a03",
    "governance-runtime/build_portable_review_packet.py": "7fd7fb621e8a1884eb34fd3e2d07db3f94242b58",
    "governance-runtime/platform_candidate_review.py": "b6a3f8be0c2a59993e207fb5b6a75ecbd01e9f8b",
}

EXTRA_EXECUTION_BLOBS = {
    "governance-runtime/verify_external_trust_root_control.py": "98b48d5f8133f527c9490a4d02b477a56a2ae997",
    "experiments/governed-platform/governance/test_integrated_governed_mvp_slice6_terminal_authority.py": "970b28aed4952d90081e89e781c5711bf26c4f68",
}

r10.r9.EXPECTED_QUALIFICATION_TEST_BLOBS.update(RELEASE_TEST_BLOBS)
r10.QUALIFICATION_TEST_FILES = frozenset(r10.r9.EXPECTED_QUALIFICATION_TEST_BLOBS)

_original_run = r10.checker.run
_original_assert_equal = r10.checker.assert_equal


def _release_assert_equal(actual: object, expected: object, label: str) -> None:
    if label == "externally pinned qualification policy version":
        return _original_assert_equal(actual, 7, label)
    return _original_assert_equal(actual, expected, label)


def _release_run(cmd: list[str], cwd: Path | None = None) -> None:
    if cwd is not None and Path(cwd).name == "governance-runtime":
        explicit = [str(arg) for arg in cmd if str(arg).endswith(".py") and str(arg).startswith("test_")]
        required = ("test_release_r1_bridge_shape_guard.py", "test_release_r3_phase_scoped_authority.py")
        if explicit:
            cmd = list(cmd)
            for filename in required:
                if filename not in explicit:
                    cmd.append(filename)
    return _original_run(cmd, cwd=cwd)


r10.checker.assert_equal = _release_assert_equal
r10.checker.run = _release_run


def _git_blob_sha(repo: Path, relpath: str) -> str:
    result = subprocess.run(
        ["git", "ls-tree", "HEAD", "--", relpath], cwd=repo, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    )
    parts = result.stdout.strip().split()
    if len(parts) < 3:
        raise AssertionError(f"missing pinned RELEASE path: {relpath}")
    return parts[2]


def _reject_committed_bytecode(repo: Path) -> None:
    tracked = subprocess.check_output(["git", "ls-files"], cwd=repo, text=True).splitlines()
    bad = [p for p in tracked if "/__pycache__/" in f"/{p}" or p.endswith((".pyc", ".pyo"))]
    if bad:
        raise AssertionError(f"committed Python bytecode/cache in RELEASE candidate: {bad}")


def _reject_stdlib_collisions(directory: Path) -> None:
    stdlib = frozenset(getattr(sys, "stdlib_module_names", ()))
    if not stdlib:
        raise AssertionError("stdlib namespace inventory unavailable")
    for entry in directory.iterdir():
        if entry.name == "__pycache__":
            continue
        if entry.is_dir():
            module_name = entry.name
        elif entry.name.endswith(".py"):
            module_name = entry.name[:-3]
        elif entry.name.endswith((".pyc", ".pyo", ".so", ".pyd", ".dll", ".dylib")):
            module_name = entry.name.split(".", 1)[0]
        else:
            continue
        if module_name in stdlib:
            raise AssertionError(f"candidate stdlib namespace collision in external execution directory: {entry}")


def _run_file_with_sibling_imports(path: Path, *, env: dict[str, str]) -> None:
    directory = path.parent.resolve()
    _reject_stdlib_collisions(directory)
    bootstrap = "import runpy,sys; d=sys.argv[1]; p=sys.argv[2]; sys.path.insert(0,d); runpy.run_path(p,run_name='__main__')"
    subprocess.run([sys.executable, "-I", "-c", bootstrap, str(directory), str(path.resolve())],
                   cwd=r10.checker.CHECKER_ROOT, env=env, check=True)


def _run_unittest_module_isolated(directory: Path, module_name: str, *, env: dict[str, str]) -> None:
    directory = directory.resolve()
    _reject_stdlib_collisions(directory)
    bootstrap = (
        "import sys,unittest; d=sys.argv[1]; m=sys.argv[2]; sys.path.insert(0,d); "
        "suite=unittest.defaultTestLoader.loadTestsFromName(m); "
        "r=unittest.TextTestRunner(verbosity=2).run(suite); "
        "raise SystemExit(0 if r.wasSuccessful() and suite.countTestCases()>0 else 1)"
    )
    subprocess.run([sys.executable, "-I", "-c", bootstrap, str(directory), module_name],
                   cwd=r10.checker.CHECKER_ROOT, env=env, check=True)


def _expect_release_root_failure(module, mutate, label: str) -> None:
    restore = mutate(module)
    try:
        try:
            module.fetch_release_external_public_key()
        except module.ReleaseExternalGovernanceRootError:
            return
        raise AssertionError(f"negative RELEASE root control unexpectedly passed: {label}")
    finally:
        restore()


def _verify_live_release_root(repo: Path):
    module = r10.checker.load_module(
        repo / "governance-runtime/release_external_governance_root.py",
        "candidate_release_external_governance_root",
    )
    pem = module.fetch_release_external_public_key()
    if not pem:
        raise AssertionError("live RELEASE governance root returned no public key")

    baseline_repo = {
        "id": module.RELEASE_EXTERNAL_REPOSITORY_ID,
        "full_name": module.RELEASE_EXTERNAL_REPOSITORY,
        "private": False,
        "archived": True,
    }
    for field, value, label in (("private", True, "private repository"), ("archived", False, "unarchived repository")):
        bad = dict(baseline_repo)
        bad[field] = value
        ok, _ = module.validate_release_repository_metadata(bad)
        if ok:
            raise AssertionError(f"negative RELEASE root control unexpectedly passed: {label}")

    expected_metadata = {
        "schema_version": 1,
        "trust_root_id": module.RELEASE_TRUST_ROOT_ID,
        "algorithm": "Ed25519",
        "public_key_path": module.RELEASE_TRUST_ROOT_PEM_PATH,
        "public_key_der_sha256": module.RELEASE_EXPECTED_PUBLIC_KEY_DER_SHA256,
        "authority_scope": "RELEASE_TERMINAL_AUTHORITY_ATTESTATION_VERIFICATION_ONLY",
        "permitted_authority_class": "HUMAN_RELEASE_AUTHORITY",
        "permitted_decision_scopes": [
            "TERMINAL_ACTION:RELEASE:MERGE_RELEASE_CANDIDATE",
            "TERMINAL_ACTION:RELEASE:BEGIN_PRODUCTION_QUALIFICATION",
        ],
        "private_key_location": "EXTERNAL_OFF_REPOSITORY_USER_CONTROLLED",
        "private_key_must_never_be_committed": True,
        "authority_effect": "NONE_BY_ITSELF",
    }
    bad_scope = dict(expected_metadata)
    bad_scope["authority_scope"] = "WRONG_SCOPE"
    if module.validate_release_root_metadata(bad_scope)[0]:
        raise AssertionError("negative RELEASE root control unexpectedly passed: wrong scope")

    original_der = module.RELEASE_EXPECTED_PUBLIC_KEY_DER_SHA256
    module.RELEASE_EXPECTED_PUBLIC_KEY_DER_SHA256 = "0" * 64
    try:
        if module.validate_release_public_key_bytes(pem)[0]:
            raise AssertionError("negative RELEASE root control unexpectedly passed: wrong DER")
    finally:
        module.RELEASE_EXPECTED_PUBLIC_KEY_DER_SHA256 = original_der

    def wrong_commit(m):
        old = m.RELEASE_EXTERNAL_ROOT_COMMIT
        m.RELEASE_EXTERNAL_ROOT_COMMIT = "0" * 40
        return lambda: setattr(m, "RELEASE_EXTERNAL_ROOT_COMMIT", old)

    def wrong_blob(m):
        old = m.RELEASE_METADATA_BLOB_SHA
        m.RELEASE_METADATA_BLOB_SHA = "0" * 40
        return lambda: setattr(m, "RELEASE_METADATA_BLOB_SHA", old)

    _expect_release_root_failure(module, wrong_commit, "wrong commit")
    _expect_release_root_failure(module, wrong_blob, "wrong metadata blob")
    return module


def _verify_live_release_ruleset() -> None:
    ruleset = r10.checker.github_json(
        f"https://api.github.com/repos/{r10.checker.TARGET_REPOSITORY}/rulesets/{RELEASE_RULESET_ID}",
        require_app_token=True,
    )
    if ruleset.get("id") != RELEASE_RULESET_ID or ruleset.get("enforcement") != "active":
        raise AssertionError("live RELEASE ruleset identity/enforcement mismatch")
    conditions = ruleset.get("conditions") or {}
    include = (conditions.get("ref_name") or {}).get("include")
    if include != [RELEASE_RULESET_REF]:
        raise AssertionError(f"live RELEASE ruleset target mismatch: {include}")
    if ruleset.get("bypass_actors") not in (None, []):
        raise AssertionError("live RELEASE ruleset has bypass actors")
    if ruleset.get("current_user_can_bypass") not in (None, "never"):
        raise AssertionError("live RELEASE ruleset reports bypass capability")

    rules = ruleset.get("rules")
    if not isinstance(rules, list):
        raise AssertionError("live RELEASE ruleset rules missing")
    by_type = {rule.get("type"): rule for rule in rules if isinstance(rule, dict)}
    for required in ("deletion", "non_fast_forward", "pull_request", "required_status_checks"):
        if required not in by_type:
            raise AssertionError(f"live RELEASE ruleset missing {required}")
    status = by_type["required_status_checks"].get("parameters") or {}
    if status.get("strict_required_status_checks_policy") is not True:
        raise AssertionError("live RELEASE required status checks are not strict")
    checks = status.get("required_status_checks") or []
    observed = {
        item.get("context"): item.get("integration_id")
        for item in checks if isinstance(item, dict) and item.get("context") in RELEASE_REQUIRED_CHECKS
    }
    expected = {context: RELEASE_REQUIRED_APP_ID for context in RELEASE_REQUIRED_CHECKS}
    if observed != expected:
        raise AssertionError(f"live RELEASE App-bound checks mismatch: {observed!r} != {expected!r}")


def _verify_policy_hash_binding(repo: Path) -> str:
    policy = r10.checker.load_runtime_facade(repo / "governance-runtime/qualification_boundary_policy.py")
    binding = policy.policy_binding()
    if binding.get("qualification_policy_id") != merge_authority.POLICY_ID:
        raise AssertionError("merge-authority policy id does not match candidate policy")
    if binding.get("qualification_policy_version") != merge_authority.POLICY_VERSION:
        raise AssertionError("merge-authority policy version does not match candidate policy")
    computed = binding.get("qualification_policy_hash")
    if computed != merge_authority.POLICY_HASH:
        raise AssertionError(f"merge-authority policy hash mismatch: {computed} != {merge_authority.POLICY_HASH}")
    return str(computed)


def verify_and_execute_extra_release_paths() -> None:
    with tempfile.TemporaryDirectory(prefix="setugo-release-r3-") as td:
        repo = Path(td) / "candidate"
        subprocess.run(["git", "clone", "--no-checkout", "--filter=blob:none", CANDIDATE_REPO, str(repo)], check=True)
        subprocess.run(["git", "fetch", "--depth=1", "origin", RELEASE_CANDIDATE_SHA], cwd=repo, check=True)
        subprocess.run(["git", "checkout", "--detach", RELEASE_CANDIDATE_SHA], cwd=repo, check=True)
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        if actual != RELEASE_CANDIDATE_SHA:
            raise AssertionError("external RELEASE checkout is not exact candidate SHA")

        _reject_committed_bytecode(repo)
        all_pins = {**RELEASE_RUNTIME_BLOBS, **QUALIFICATION_RUNTIME_CLOSURE_BLOBS, **EXTRA_EXECUTION_BLOBS}
        for relpath, expected_blob in all_pins.items():
            actual_blob = _git_blob_sha(repo, relpath)
            if actual_blob != expected_blob:
                raise AssertionError(f"RELEASE external execution blob mismatch for {relpath}: {actual_blob} != {expected_blob}")

        _verify_live_release_root(repo)
        _verify_live_release_ruleset()
        policy_hash = _verify_policy_hash_binding(repo)

        env = os.environ.copy()
        env["PYTHONNOUSERSITE"] = "1"
        _run_file_with_sibling_imports(repo / "governance-runtime/verify_external_trust_root_control.py", env=env)
        _run_unittest_module_isolated(repo / "governance-runtime", "test_release_r3_phase_scoped_authority", env=env)
        _run_unittest_module_isolated(
            repo / "experiments/governed-platform/governance",
            "test_integrated_governed_mvp_slice6_terminal_authority",
            env=env,
        )
        print("RELEASE_POLICY_HASH=" + policy_hash)


def main() -> int:
    if "--sha" not in sys.argv:
        raise AssertionError("RELEASE external qualification requires explicit --sha")
    index = sys.argv.index("--sha")
    if index + 1 >= len(sys.argv) or sys.argv[index + 1] != RELEASE_CANDIDATE_SHA:
        raise AssertionError("RELEASE external qualification is not bound to exact candidate SHA")

    result = r10.checker.main()
    if result not in (None, 0):
        return int(result)
    verify_and_execute_extra_release_paths()
    print(json.dumps({
        "result": "RELEASE_EXTERNAL_COVERAGE_PASS",
        "candidate_sha": RELEASE_CANDIDATE_SHA,
        "authority_effect": "NONE_EVIDENCE_ONLY",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
