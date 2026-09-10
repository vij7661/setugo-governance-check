#!/usr/bin/env python3
"""Checker-owned isolated runner for candidate qualification tests.

This file executes under `python -I`. It imports trusted stdlib machinery before
adding the candidate runtime at the END of sys.path, so candidate files cannot
shadow the test runner or standard-library modules through cwd/sys.path[0].

The candidate qualification corpus intentionally mixes unittest.TestCase tests
with top-level zero-argument `test_*` functions. Because every selected module is
independently Git-blob pinned by the external checker, this runner can execute
both shapes without delegating collection to candidate-controlled pytest hooks,
plugins, or conftest files.

Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import hashlib  # preload from trusted stdlib search path
import importlib
import inspect
import json
import os
from pathlib import Path
import sys
import unittest


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _top_level_tests(module):
    tests = []
    for name, value in vars(module).items():
        if not name.startswith("test_") or not inspect.isfunction(value):
            continue
        if getattr(value, "__module__", None) != module.__name__:
            continue
        signature = inspect.signature(value)
        required = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.default is inspect.Signature.empty
            and parameter.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
            )
        ]
        if required:
            names = ", ".join(parameter.name for parameter in required)
            raise SystemExit(
                f"top-level qualification test requires unsupported fixture/arguments: "
                f"{module.__name__}.{name}({names})"
            )
        tests.append((name, value))
    return sorted(tests, key=lambda item: item[0])


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit("usage: isolated-runner <candidate-runtime> <test.py>...")

    runtime = Path(sys.argv[1]).resolve()
    selected = list(sys.argv[2:])
    if not runtime.is_dir():
        raise SystemExit("candidate runtime directory missing")

    # `-I` must be active; user-site and Python environment injection must be off.
    if sys.flags.isolated != 1 or sys.flags.no_user_site != 1 or sys.flags.ignore_environment != 1:
        raise SystemExit("candidate qualification interpreter is not isolated")

    unittest_origin = Path(unittest.__file__).resolve()
    if _is_under(unittest_origin, runtime):
        raise SystemExit("candidate-controlled unittest shadow detected")

    # Candidate code must not have import precedence while the trusted collector
    # and stdlib are imported. Add candidate runtime only after that boundary.
    for item in sys.path:
        try:
            if Path(item).resolve() == runtime:
                raise SystemExit("candidate runtime unexpectedly present before isolated import setup")
        except (OSError, RuntimeError):
            pass
    sys.path.append(str(runtime))

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    module_counts: dict[str, dict[str, int]] = {}
    plain_functions = []

    for filename in selected:
        if not filename.endswith(".py"):
            raise SystemExit(f"qualification test must be an explicit .py module: {filename}")
        module_name = filename[:-3]
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:
            raise SystemExit(f"failed to import qualification test module {module_name}: {exc}") from exc

        loaded = loader.loadTestsFromModule(module)
        if loader.errors:
            raise SystemExit(f"unittest loader error for {module_name}: {loader.errors[-1]}")
        unittest_count = loaded.countTestCases()
        top_level = _top_level_tests(module)
        top_level_count = len(top_level)
        if unittest_count + top_level_count <= 0:
            raise SystemExit(f"qualification test module contributed zero executable tests: {module_name}")

        suite.addTests(loaded)
        plain_functions.extend((module_name, name, fn) for name, fn in top_level)
        module_counts[module_name] = {
            "unittest_cases": unittest_count,
            "top_level_functions": top_level_count,
        }

    unittest_total = suite.countTestCases()
    top_level_total = len(plain_functions)
    total = unittest_total + top_level_total
    if total <= 0:
        raise SystemExit("qualification corpus executed zero tests")

    print(json.dumps({
        "isolated": True,
        "no_user_site": bool(sys.flags.no_user_site),
        "ignore_environment": bool(sys.flags.ignore_environment),
        "unittest_origin": str(unittest_origin),
        "candidate_runtime_appended_last": sys.path[-1] == str(runtime),
        "module_test_counts": module_counts,
        "unittest_total": unittest_total,
        "top_level_total": top_level_total,
        "total_tests": total,
        "collector": "CHECKER_OWNED_UNITTEST_PLUS_ZERO_ARG_TOP_LEVEL",
        "authority_effect": "NONE_EVIDENCE_ONLY",
    }, sort_keys=True))

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1

    for module_name, name, function in plain_functions:
        print(f"RUN {module_name}.{name}")
        function()
        print(f"PASS {module_name}.{name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
