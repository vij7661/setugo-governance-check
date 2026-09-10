#!/usr/bin/env python3
"""Checker-owned exhaustive candidate-local import closure verifier for RELEASE.

This verifier never trusts candidate declarations about its dependency closure.
It checks exact Git blobs for every allowed authority-relevant runtime module,
statically walks candidate-local imports from every entry point, rejects any
reachable local module or package outside the allowlist, and rejects dynamic
import/lookup/execution capability inside the governed closure. Passing is
evidence only.
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
    "verify_external_trust_root_control.py": "98b48d5f8133f527c9490a4d02b477a56a2ae997",
    "review_protocol.py": "1bf92a5775a780f0f32d166fb6c6a0c522bbf490",
    "phase_policy.py": "219d406d0335a318d91c8c940b19b8a39ad63a03",
    "build_portable_review_packet.py": "7fd7fb621e8a1884eb34fd3e2d07db3f94242b58",
    "platform_candidate_review.py": "b6a3f8be0c2a59993e207fb5b6a75ecbd01e9f8b",
}

ENTRY_POINTS = frozenset(PINNED_RUNTIME_BLOBS)
FORBIDDEN_DYNAMIC_SYMBOLS = frozenset({
    "__import__", "import_module", "exec", "eval", "compile", "getattr",
})
FORBIDDEN_DYNAMIC_MODULES = frozenset({"importlib", "runpy", "builtins"})
FORBIDDEN_DYNAMIC_BASES = frozenset({"importlib", "builtins", "__builtins__"})


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


def _local_module_relpath(runtime: Path, module_name: str) -> str | None:
    if not module_name:
        return None
    parts = module_name.split(".")
    module_file = runtime.joinpath(*parts).with_suffix(".py")
    if module_file.is_file():
        return module_file.relative_to(runtime).as_posix()
    package_init = runtime.joinpath(*parts, "__init__.py")
    if package_init.is_file():
        return package_init.relative_to(runtime).as_posix()
    root = parts[0]
    module_file = runtime / f"{root}.py"
    if module_file.is_file():
        return f"{root}.py"
    package_init = runtime / root / "__init__.py"
    if package_init.is_file():
        return f"{root}/__init__.py"
    return None


def _constant_string(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _attribute_root(node: ast.AST) -> str | None:
    current = node
    while isinstance(current, ast.Attribute):
        current = current.value
    return current.id if isinstance(current, ast.Name) else None


def _forbidden_dynamic_node(node: ast.AST) -> bool:
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        return node.id in FORBIDDEN_DYNAMIC_SYMBOLS
    if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
        return (
            node.attr in FORBIDDEN_DYNAMIC_SYMBOLS
            and _attribute_root(node) in FORBIDDEN_DYNAMIC_BASES
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr":
        return True
    if isinstance(node, ast.Subscript):
        key = _constant_string(node.slice)
        base = _attribute_root(node.value)
        if isinstance(node.value, ast.Name):
            base = node.value.id
        return base in {"builtins", "__builtins__"} and key in FORBIDDEN_DYNAMIC_SYMBOLS
    return False


def _imports_and_forbidden_nodes(path: Path) -> tuple[set[str], list[int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imported: set[str] = set()
    forbidden_lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                imported.add(root)
                if root in FORBIDDEN_DYNAMIC_MODULES:
                    forbidden_lines.add(getattr(node, "lineno", -1))
        elif isinstance(node, ast.ImportFrom) and node.module:
            root = node.module.split(".", 1)[0]
            imported.add(root)
            if root in FORBIDDEN_DYNAMIC_MODULES:
                forbidden_lines.add(getattr(node, "lineno", -1))
        if _forbidden_dynamic_node(node):
            forbidden_lines.add(getattr(node, "lineno", -1))
    return imported, sorted(forbidden_lines)


def verify_repo(repo: Path) -> dict[str, list[str]]:
    runtime = repo / RUNTIME_DIR
    if not runtime.is_dir():
        raise AssertionError("candidate governance-runtime directory missing")

    for runtime_relpath, expected_blob in PINNED_RUNTIME_BLOBS.items():
        relpath = f"{RUNTIME_DIR}/{runtime_relpath}"
        actual = _blob_sha(repo, relpath)
        if actual != expected_blob:
            raise AssertionError(
                f"runtime closure blob mismatch: {relpath}: {actual} != {expected_blob}"
            )

    visited: set[str] = set()
    edges: dict[str, list[str]] = {}
    queue = list(sorted(ENTRY_POINTS))
    while queue:
        runtime_relpath = queue.pop(0)
        if runtime_relpath in visited:
            continue
        visited.add(runtime_relpath)
        path = runtime / runtime_relpath
        imports, forbidden_lines = _imports_and_forbidden_nodes(path)
        if forbidden_lines:
            raise AssertionError(
                "dynamic import/lookup/execution capability forbidden in governed runtime closure: "
                f"{runtime_relpath}:{forbidden_lines}"
            )
        local_targets: list[str] = []
        for module in sorted(imports):
            target = _local_module_relpath(runtime, module)
            if target is None:
                continue
            if target not in PINNED_RUNTIME_BLOBS:
                raise AssertionError(
                    "unpinned candidate-local import reachable from governed runtime: "
                    f"{runtime_relpath} -> {target}"
                )
            local_targets.append(target)
            if target not in visited:
                queue.append(target)
        edges[runtime_relpath] = local_targets

    missing = set(PINNED_RUNTIME_BLOBS) - visited
    if missing:
        raise AssertionError(f"pinned runtime entries were not audited: {sorted(missing)}")
    return {name: edges[name] for name in sorted(edges)}


def verify(candidate_sha: str = CANDIDATE_SHA) -> dict[str, list[str]]:
    if candidate_sha != CANDIDATE_SHA:
        raise AssertionError("runtime closure verifier is not bound to exact RELEASE candidate")
    with tempfile.TemporaryDirectory(prefix="setugo-release-import-closure-") as td:
        repo = Path(td) / "candidate"
        subprocess.run(
            ["git", "clone", "--no-checkout", "--filter=blob:none", CANDIDATE_REPO, str(repo)],
            check=True,
        )
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
