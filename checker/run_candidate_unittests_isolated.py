#!/usr/bin/env python3
"""Checker-owned isolated runner for pinned candidate qualification tests.

Runs under `python -I`, imports trusted stdlib machinery before candidate runtime,
appends the candidate runtime last, explicitly loads only caller-selected `.py`
modules, and supports only unittest.TestCase plus synchronous zero-argument top-
level `test_*` functions. Unsupported async/generator shapes fail closed.

Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import importlib
import inspect
from pathlib import Path
import sys
import unittest


def _is_under(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _assert_candidate_last(runtime: Path) -> None:
    resolved = []
    for item in sys.path:
        try:
            resolved.append(Path(item).resolve())
        except (OSError, RuntimeError):
            continue
    positions = [i for i, value in enumerate(resolved) if value == runtime]
    if positions != [len(resolved) - 1]:
        raise SystemExit("candidate runtime import precedence changed or duplicated")


def _top_level_tests(module):
    tests = []
    for name, value in vars(module).items():
        if not name.startswith("test_") or not inspect.isfunction(value):
            continue
        if getattr(value, "__module__", None) != module.__name__:
            continue
        if inspect.iscoroutinefunction(value):
            raise SystemExit(f"unsupported async qualification test: {module.__name__}.{name}")
        if inspect.isasyncgenfunction(value):
            raise SystemExit(f"unsupported async-generator qualification test: {module.__name__}.{name}")
        if inspect.isgeneratorfunction(value):
            raise SystemExit(f"unsupported generator qualification test: {module.__name__}.{name}")
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
    if len(selected) != len(set(selected)):
        raise SystemExit("duplicate qualification test module requested")

    if sys.flags.isolated != 1 or sys.flags.no_user_site != 1 or sys.flags.ignore_environment != 1:
        raise SystemExit("candidate qualification interpreter is not isolated")

    unittest_origin = Path(unittest.__file__).resolve()
    if _is_under(unittest_origin, runtime):
        raise SystemExit("candidate-controlled unittest shadow detected")

    # Candidate runtime may not already have precedence. Add it exactly once and last.
    for item in sys.path:
        try:
            if Path(item).resolve() == runtime:
                raise SystemExit("candidate runtime unexpectedly present before isolated import setup")
        except (OSError, RuntimeError):
            pass
    sys.path.append(str(runtime))
    _assert_candidate_last(runtime)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    module_counts: dict[str, dict[str, int]] = {}
    plain_functions = []

    for filename in selected:
        if not filename.endswith(".py") or "/" in filename or "\\" in filename:
            raise SystemExit(f"qualification test must be an explicit top-level .py module: {filename}")
        module_name = filename[:-3]
        before_errors = len(loader.errors)
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:
            raise SystemExit(f"failed to import qualification test module {module_name}: {exc}") from exc
        _assert_candidate_last(runtime)

        origin = getattr(module, "__file__", None)
        expected_origin = (runtime / filename).resolve()
        if origin is None or Path(origin).resolve() != expected_origin:
            raise SystemExit(
                f"qualification test module resolved outside candidate runtime: "
                f"{module_name} -> {origin!r}"
            )

        loaded = loader.loadTestsFromModule(module)
        if len(loader.errors) != before_errors:
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

    if suite.countTestCases() + len(plain_functions) <= 0:
        raise SystemExit("qualification corpus executed zero tests")

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful():
        return 1

    for module_name, name, function in plain_functions:
        _assert_candidate_last(runtime)
        print(f"RUN {module_name}.{name}")
        value = function()
        if inspect.isawaitable(value):
            raise SystemExit(f"qualification test returned awaitable without execution: {module_name}.{name}")
        if inspect.isgenerator(value):
            raise SystemExit(f"qualification test returned generator without execution: {module_name}.{name}")
        if inspect.isasyncgen(value):
            raise SystemExit(f"qualification test returned async generator without execution: {module_name}.{name}")
        print(f"PASS {module_name}.{name}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
