#!/usr/bin/env python3
"""Checker-owned isolated runner for pinned candidate qualification tests.

Runs under `python -I`, imports trusted stdlib machinery before candidate runtime,
appends the candidate runtime last, explicitly loads only caller-selected `.py`
modules, and supports only unittest.TestCase plus synchronous zero-argument top-
level `test_*` functions. When a RELEASE runtime pin manifest is supplied, the
runner also denies candidate-local module loads outside that exact manifest and
fails closed on direct dynamic code execution from candidate runtime frames.

Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import base64
import importlib
from importlib.abc import MetaPathFinder
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


def _decode_manifest(value: str) -> dict[str, str]:
    try:
        decoded = base64.b64decode(value, validate=True)
        payload = json.loads(decoded.decode("utf-8"))
    except Exception as exc:
        raise SystemExit("runtime pin manifest is malformed") from exc
    if not isinstance(payload, dict) or not payload:
        raise SystemExit("runtime pin manifest is empty or not an object")
    normalized: dict[str, str] = {}
    for relpath, blob in payload.items():
        if not isinstance(relpath, str) or not relpath or relpath.startswith("/") or ".." in Path(relpath).parts:
            raise SystemExit("runtime pin manifest contains invalid relative path")
        if not isinstance(blob, str) or len(blob) != 40 or any(ch not in "0123456789abcdef" for ch in blob):
            raise SystemExit("runtime pin manifest contains invalid Git blob SHA")
        normalized[Path(relpath).as_posix()] = blob
    return normalized


def _git_blob_sha(runtime: Path, runtime_relpath: str) -> str:
    repo = runtime.parent
    relpath = f"governance-runtime/{runtime_relpath}"
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
        raise SystemExit(f"runtime guard could not resolve pinned path: {relpath}")
    return parts[2]


def _candidate_relpath_for_name(runtime: Path, fullname: str) -> str | None:
    parts = fullname.split(".")
    module_file = runtime.joinpath(*parts).with_suffix(".py")
    if module_file.is_file():
        return module_file.relative_to(runtime).as_posix()
    package_init = runtime.joinpath(*parts, "__init__.py")
    if package_init.is_file():
        return package_init.relative_to(runtime).as_posix()
    return None


def _origin_relpath(runtime: Path, origin: str | None) -> str | None:
    if not origin or origin in {"built-in", "frozen"}:
        return None
    try:
        resolved = Path(origin).resolve()
    except (OSError, RuntimeError):
        return None
    if not _is_under(resolved, runtime):
        return None
    return resolved.relative_to(runtime).as_posix()


class _RuntimePinFinder(MetaPathFinder):
    def __init__(self, runtime: Path, allowed: set[str]):
        self.runtime = runtime
        self.allowed = allowed

    def find_spec(self, fullname, path=None, target=None):
        relpath = _candidate_relpath_for_name(self.runtime, fullname)
        if relpath is not None and relpath not in self.allowed:
            raise ImportError(f"runtime guard rejected unpinned candidate-local module: {fullname} -> {relpath}")
        return None


def _candidate_frame_present(runtime: Path) -> bool:
    frame = sys._getframe(1)
    while frame is not None:
        filename = frame.f_code.co_filename
        if filename and not filename.startswith("<"):
            try:
                if _is_under(Path(filename).resolve(), runtime):
                    return True
            except (OSError, RuntimeError):
                pass
        frame = frame.f_back
    return False


def _install_runtime_guard(runtime: Path, selected: list[str], manifest: dict[str, str]) -> None:
    allowed = set(manifest) | set(selected)
    for relpath, expected_blob in manifest.items():
        actual = _git_blob_sha(runtime, relpath)
        if actual != expected_blob:
            raise SystemExit(
                f"runtime guard blob mismatch for governance-runtime/{relpath}: {actual} != {expected_blob}"
            )

    sys.meta_path.insert(0, _RuntimePinFinder(runtime, allowed))

    def audit(event, args):
        if event != "exec" or not args:
            return
        code = args[0]
        filename = getattr(code, "co_filename", "")
        if not isinstance(filename, str):
            return

        # Code executed from a candidate-local file must be an explicitly pinned
        # runtime file or one of the explicitly selected pinned test modules.
        relpath = _origin_relpath(runtime, filename)
        if relpath is not None:
            if relpath not in allowed:
                raise RuntimeError(f"runtime guard rejected execution of unpinned candidate file: {relpath}")
            # Direct exec/eval of dynamically created code can spoof a pinned
            # filename. Normal module execution is invoked by import machinery,
            # not directly from a candidate-runtime frame.
            caller = sys._getframe(1)
            caller_file = caller.f_code.co_filename
            if caller_file and not caller_file.startswith("<"):
                try:
                    if _is_under(Path(caller_file).resolve(), runtime):
                        raise RuntimeError("runtime guard rejected direct dynamic code execution from candidate runtime")
                except (OSError, RuntimeError) as exc:
                    if isinstance(exc, RuntimeError):
                        raise
            return

        # eval/exec/compile commonly emit synthetic filenames such as <string>.
        # If such code executes while any candidate-runtime frame is active,
        # reject regardless of how the callable was obtained (alias/getattr/
        # __builtins__/loader indirection).
        if filename.startswith("<") and _candidate_frame_present(runtime):
            raise RuntimeError("runtime guard rejected synthetic dynamic code execution from candidate runtime")

    sys.addaudithook(audit)


def _verify_loaded_candidate_modules(runtime: Path, selected: list[str], manifest: dict[str, str]) -> None:
    allowed = set(manifest) | set(selected)
    unexpected = []
    for name, module in list(sys.modules.items()):
        relpath = _origin_relpath(runtime, getattr(module, "__file__", None))
        if relpath is not None and relpath not in allowed:
            unexpected.append(f"{name}:{relpath}")
    if unexpected:
        raise SystemExit(f"runtime guard observed unpinned candidate modules: {sorted(unexpected)}")


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit("usage: isolated-runner <candidate-runtime> [--runtime-pin-manifest-b64 B64] <test.py>...")

    runtime = Path(sys.argv[1]).resolve()
    args = list(sys.argv[2:])
    manifest: dict[str, str] = {}
    if args[:1] == ["--runtime-pin-manifest-b64"]:
        if len(args) < 3:
            raise SystemExit("runtime pin manifest argument is missing")
        manifest = _decode_manifest(args[1])
        args = args[2:]
    selected = args

    if not runtime.is_dir():
        raise SystemExit("candidate runtime directory missing")
    if not selected:
        raise SystemExit("no qualification test modules requested")
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

    if manifest:
        _install_runtime_guard(runtime, selected, manifest)

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
                f"qualification test module resolved outside candidate runtime: {module_name} -> {origin!r}"
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

    if manifest:
        _verify_loaded_candidate_modules(runtime, selected, manifest)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
