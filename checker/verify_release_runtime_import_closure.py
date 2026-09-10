#!/usr/bin/env python3
"""Checker-owned exhaustive candidate-local import closure verifier for RELEASE.

This verifier never trusts candidate declarations about its dependency closure.
It checks exact Git blobs for every allowed authority-relevant runtime module,
statically walks candidate-local imports from every entry point, rejects any
reachable local module outside the allowlist, and rejects dynamic import calls
inside the governed closure. Passing is evidence only.
"""
from __future__ import annotations

import ast
from pathlib import Path
import subprocess
import tempfile

CANDIDATE_REPO = "https://github.com/vij7661/setugo-ai-development-framework.git"
CANDIDATE_SHA = "4200397f21e12f900c309ee1bc66fa8424135f11"
RUNTIME_DIR = "governance-runtime"

PINNED_RUNTIME_BLOBS = {
    "qualification_boundary_policy.py": "998cb2a90b6530132239e1a6274718b605680909",
    "qualification_boundary_policy_v7.py": "f981a01b86b5020587bcf1817c484af64604c601",
    "qualification_boundary_policy_v4.py": "019b89f32deba5a7bc93274ff41ad7e61a1aaad3",
    "manual_authority_verifier.py": "fbcd992d7c3ea1c415bd01e3a0d638865f0f5898",
    "external_governance_root.py": "c83b4aa9f1253f2cbd5a26b6857af8ded8bbc808",
    "release_manual_authority_verifier.py": "6e71413054d599fccfc4a265228a2a681f9d2ed0",
    "release_external_governance_root.py": "7de7c00519853d5ff0d776d40f94c20c9d5f976d",
    "review_protocol.py": "1bf92a5775a780f0f32d166fb6c6a0c522bbf490",
    "phase_policy.py": "219d406d0335a318d91c8c940b19b8a39ad63a03",
    "build_portable_review_packet.py": "7fd7fb621e8a1884eb34fd3e2d07db3f94242b58",
    "platform_candidate_review.py": "b6a3f8be0c2a59993e207fb5b6a75ecbd01e9f8b",
}

ENTRY_POINTS = frozenset(PINNED_RUNTIME_BLOBS)


def _blob_sha(repo: Path, relpath: str) -> str:
    result = subprocess.run(
        ["git", "ls-tree", "HEAD", "--", relpath],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    parts = result.stdout.strip().split()
    if len(parts) < 3:
        raise AssertionError(f"missing governed runtime path: {relpath}")
    return parts[2]


def _local_module_file(runtime: Path, module_name: str) -> Path | None:
    if not module_name:
        return None
    root = module_name.split(".", 1)[0]
    candidate = runtime / f"{root}.py"
    return candidate if candidate.is_file() else None


def _dynamic_import_call(node: ast.Call) -> bool:
    fn = node.func
    if isinstance(fn, ast.Name) and fn.id in {"__import__", "import_module"}:
        return True
    return isinstance(fn, ast.Attribute) and fn.attr == "import_module"


def _imports_and_dynamic_calls(path: Path) -> tuple[set[str], list[int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    dynamic_lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Call) and _dynamic_import_call(node):
            dynamic_lines.append(getattr(node, "lineno", -1))
    return imported, dynamic_lines


def verify_repo(repo: Path) -> dict[str, list[str]]:
    runtime = repo / RUNTIME_DIR
    if not runtime.is_dir():
        raise AssertionError("candidate governance-runtime directory missing")

    for filename, expected_blob in PINNED_RUNTIME_BLOBS.items():
        relpath = f"{RUNTIME_DIR}/{filename}"
        actual = _blob_sha(repo, relpath)
        if actual != expected_blob:
            raise AssertionError(f"runtime closure blob mismatch: {relpath}: {actual} != {expected_blob}")

    visited: set[str] = set()
    edges: dict[str, list[str]] = {}
    queue = list(sorted(ENTRY_POINTS))
    while queue:
        filename = queue.pop(0)
        if filename in visited:
            continue
        visited.add(filename)
        path = runtime / filename
        imports, dynamic_lines = _imports_and_dynamic_calls(path)
        if dynamic_lines:
            raise AssertionError(
                f"dynamic import construct forbidden in governed runtime closure: {filename}:{dynamic_lines}"
            )
        local_targets: list[str] = []
        for module in sorted(imports):
            local = _local_module_file(runtime, module)
            if local is None:
                continue
            target = local.name
            if target not in PINNED_RUNTIME_BLOBS:
                raise AssertionError(
                    f"unpinned candidate-local import reachable from governed runtime: {filename} -> {target}"
                )
            local_targets.append(target)
            if target not in visited:
                queue.append(target)
        edges[filename] = local_targets

    missing = set(PINNED_RUNTIME_BLOBS) - visited
    if missing:
        raise AssertionError(f"pinned runtime entries were not audited: {sorted(missing)}")
    return {name: edges[name] for name in sorted(edges)}


def verify(candidate_sha: str = CANDIDATE_SHA) -> dict[str, list[str]]:
    if candidate_sha != CANDIDATE_SHA:
        raise AssertionError("runtime closure verifier is not bound to exact RELEASE candidate")
    with tempfile.TemporaryDirectory(prefix="setugo-release-import-closure-") as td:
        repo = Path(td) / "candidate"
        subprocess.run(["git", "clone", "--no-checkout", "--filter=blob:none", CANDIDATE_REPO, str(repo)], check=True)
        subprocess.run(["git", "fetch", "--depth=1", "origin", candidate_sha], cwd=repo, check=True)
        subprocess.run(["git", "checkout", "--detach", candidate_sha], cwd=repo, check=True)
        actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        if actual != candidate_sha:
            raise AssertionError("runtime closure checkout is not exact candidate SHA")
        return verify_repo(repo)


if __name__ == "__main__":
    graph = verify()
    for source, targets in graph.items():
        print(source + " -> " + ",".join(targets))
    print("RELEASE_RUNTIME_IMPORT_CLOSURE_PASS")
