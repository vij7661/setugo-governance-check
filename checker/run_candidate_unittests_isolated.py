#!/usr/bin/env python3
"""Checker-owned isolated runner for pinned candidate qualification tests.

Runs under `python -I`, imports trusted stdlib machinery before candidate runtime,
appends the candidate runtime last, explicitly loads only caller-selected `.py`
modules, supports only unittest.TestCase plus synchronous zero-argument top-level
`test_*` functions, and optionally enforces an exact candidate-runtime blob
manifest against modules actually executed during the qualification run.
Unsupported async/generator shapes fail closed.

Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import base64
import importlib
import importlib.util
import inspect
import json
from pathlib import Path
import subprocess
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


def _decode_runtime_pins(value: str | None) -> dict[str, str] | None:
    if value is None:
        return None
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
        raw = json.loads(decoded)
    except Exception as exc:
        raise SystemExit("runtime pin manifest is malformed") from exc
    if not isinstance(raw, dict):
        raise SystemExit("runtime pin manifest is not an object")
    pins: dict[str, str] = {}
    for relpath, blob in raw.items():
        if not isinstance(relpath, str) or not relpath or relpath.startswith("/") or ".." in Path(relpath).parts:
            raise SystemExit("runtime pin manifest contains invalid path")
        if not isinstance(blob, str) or len(blob) != 40 or any(ch not in "0123456789abcdef" for ch in blob):
            raise SystemExit("runtime pin manifest contains invalid Git blob SHA")
        pins[relpath] = blob
    return pins


def _source_relpath_for_origin(origin: str, runtime: Path) -> str | None:
    if not origin or origin.startswith("<"):
        return None
    try:
        path = Path(origin).resolve()
    except (OSError, RuntimeError):
        return None
    if not _is_under(path, runtime):
        return None

    if path.suffix in {".pyc", ".pyo"} and path.parent.name == "__pycache__":
        try:
            path = Path(importlib.util.source_from_cache(str(path))).resolve()
        except (ValueError, OSError, RuntimeError):
            raise SystemExit(f"candidate runtime bytecode origin cannot be mapped to source: {origin}")
    if not _is_under(path, runtime):
        raise SystemExit(f"candidate runtime origin escaped governed directory: {origin}")
    if path.suffix != ".py":
        raise SystemExit(f"unsupported candidate runtime executable module type: {origin}")
    return path.relative_to(runtime).as_posix()


def _git_blob_sha(runtime: Path, relpath: str) -> str:
    repo = runtime.parent
    result = subprocess.run(
        ["git", "ls-tree", "HEAD", "--", f"governance-runtime/{relpath}"],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    parts = result.stdout.strip().split()
    if len(parts) < 3:
        raise SystemExit(f"candidate runtime executed untracked or missing source: {relpath}")
    return parts[2]


def _verify_runtime_origin(origin: str, runtime: Path, pins: dict[str, str], selected_tests: set[str]) -> None:
    relpath = _source_relpath_for_origin(origin, runtime)
    if relpath is None or relpath in selected_tests:
        return
    expected = pins.get(relpath)
    if expected is None:
        raise SystemExit(f"unpinned candidate runtime module executed: {relpath}")
    actual = _git_blob_sha(runtime, relpath)
    if actual != expected:
        raise SystemExit(f"candidate runtime blob mismatch: {relpath}: {actual} != {expected}")


def _install_runtime_audit(runtime: Path, pins: dict[str, str], selected_tests: set[str]) -> None:
    def audit(event: str, args) -> None:
        if event == "import" and len(args) > 1 and isinstance(args[1], str):
            _verify_runtime_origin(args[1], runtime, pins, selected_tests)
        elif event == "exec" and args:
            code = args[0]
            origin = getattr(code, "co_filename", None)
            if isinstance(origin, str):
                _verify_runtime_origin(origin, runtime, pins, selected_tests)

    sys.addaudithook(audit)


def _verify_loaded_modules(runtime: Path, pins: dict[str, str], selected_tests: set[str]) -> None:
    for module in tuple(sys.modules.values()):
        origin = getattr(module, "__file__", None)
        if isinstance(origin, str):
            _verify_runtime_origin(origin, runtime, pins, selected_tests)
        spec = getattr(module, "__spec__", None)
        spec_origin = getattr(spec, "origin", None)
        if isinstance(spec_origin, str):
            _verify_runtime_origin(spec_origin, runtime, pins, selected_tests)


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
        raise SystemExit("usage: isolated-runner <candidate-runtime> [--runtime-pins-b64 <manifest>] <test.py>...")

    runtime = Path(sys.argv[1]).resolve()
    args = list(sys.argv[2:])
    runtime_pins_b64 = None
    if args[:1] == ["--runtime-pins-b64"]:
        if len(args) < 3:
            raise SystemExit("runtime pin manifest flag requires a value and at least one test")
        runtime_pins_b64 = args[1]
        args = args[2:]
    selected = args
    selected_tests = set(selected)
    pins = _decode_runtime_pins(runtime_pins_b64)

    if not runtime.is_dir():
        raise SystemExit("candidate runtime directory missing")
    if len(selected) != len(set(selected)):
        raise SystemExit("duplicate qualification test module requested")

    if sys.flags.isolated != 1 or sys.flags.no_user_site != 1 or sys.flags.ignore_environment != 1:
        raise SystemExit("candidate qualification interpreter is not isolated")

    unittest_origin = Path(unittest.__file__).resolve()
    if _is_under(unittest_origin, runtime):
        raise SystemExit("candidate-controlled unittest shadow detected")

    for item in sys.path:
        try:
            if Path(item).resolve() == runtime:
                raise SystemExit("candidate runtime unexpectedly present before isolated import setup")
        except (OSError, RuntimeError):
            pass
    sys.path.append(str(runtime))
    _assert_candidate_last(runtime)

    if pins is not None:
        _install_runtime_audit(runtime, pins, selected_tests)
        _verify_loaded_modules(runtime, pins, selected_tests)

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
        if pins is not None:
            _verify_loaded_modules(runtime, pins, selected_tests)

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
    if pins is not None:
        _verify_loaded_modules(runtime, pins, selected_tests)
    if not result.wasSuccessful():
        return 1

    for module_name, name, function in plain_functions:
        _assert_candidate_last(runtime)
        print(f"RUN {module_name}.{name}")
        value = function()
        if pins is not None:
            _verify_loaded_modules(runtime, pins, selected_tests)
        if inspect.isawaitable(value):
            raise SystemExit(f"qualification test returned awaitable without execution: {module_name}.{name}")
        if inspect.isgenerator(value):
            raise SystemExit(f"qualification test returned generator without execution: {module_name}.{name}")
        if inspect.isasyncgen(value):
            raise SystemExit(f"qualification test returned async generator without execution: {module_name}.{name}")
        print(f"PASS {module_name}.{name}")

    if pins is not None:
        _verify_loaded_modules(runtime, pins, selected_tests)
        print("RUNTIME_MODULE_OBSERVATION_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
