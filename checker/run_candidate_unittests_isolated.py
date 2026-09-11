#!/usr/bin/env python3
"""Checker-owned isolated runner for pinned candidate qualification tests.

Runs under `python -I`, imports trusted stdlib machinery before candidate code,
appends the candidate governance runtime last, explicitly loads only selected
pinned test modules, and enforces an exact Git-blob execution manifest across
the entire candidate checkout. Candidate-originated child-process, OS execution,
and native-library loading capabilities fail closed during qualification.

Authority effect: NONE_EVIDENCE_ONLY.
"""
from __future__ import annotations

import base64
import importlib
from importlib.abc import MetaPathFinder
from importlib.machinery import PathFinder
import inspect
import json
from pathlib import Path
import subprocess
import sys
import unittest


PROCESS_NATIVE_AUDIT_EVENTS = frozenset({
    "subprocess.Popen",
    "os.system",
    "os.exec",
    "os.posix_spawn",
    "os.posix_spawnp",
    "os.fork",
    "os.forkpty",
    "pty.spawn",
    "ctypes.dlopen",
    "ctypes.dlsym",
})


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
            raise SystemExit("runtime pin manifest contains invalid candidate-relative path")
        if not isinstance(blob, str) or len(blob) != 40 or any(ch not in "0123456789abcdef" for ch in blob):
            raise SystemExit("runtime pin manifest contains invalid Git blob SHA")
        normalized[Path(relpath).as_posix()] = blob
    return normalized


def _git_blob_sha(candidate_root: Path, candidate_relpath: str) -> str:
    result = subprocess.run(
        ["git", "ls-tree", "HEAD", "--", candidate_relpath],
        cwd=candidate_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    parts = result.stdout.strip().split()
    if len(parts) < 3:
        raise SystemExit(f"runtime guard could not resolve pinned path: {candidate_relpath}")
    return parts[2]


def _origin_relpath(candidate_root: Path, origin: str | None) -> str | None:
    if not origin or origin in {"built-in", "frozen"}:
        return None
    try:
        resolved = Path(origin).resolve()
    except (OSError, RuntimeError):
        return None
    if not _is_under(resolved, candidate_root):
        return None
    return resolved.relative_to(candidate_root).as_posix()


def _stack_contains_candidate(candidate_root: Path, start_depth: int = 2) -> bool:
    try:
        frame = sys._getframe(start_depth)
    except ValueError:
        return False
    while frame is not None:
        filename = frame.f_code.co_filename
        if filename and not filename.startswith("<"):
            try:
                if _is_under(Path(filename).resolve(), candidate_root):
                    return True
            except (OSError, RuntimeError):
                pass
        frame = frame.f_back
    return False


def _immediate_caller_is_candidate(candidate_root: Path) -> bool:
    try:
        frame = sys._getframe(2)
    except ValueError:
        return False
    filename = frame.f_code.co_filename if frame is not None else ""
    if not filename or filename.startswith("<"):
        return False
    try:
        return _is_under(Path(filename).resolve(), candidate_root)
    except (OSError, RuntimeError):
        return False


class _CandidatePinFinder(MetaPathFinder):
    def __init__(self, candidate_root: Path, allowed: set[str]):
        self.candidate_root = candidate_root
        self.allowed = allowed

    def find_spec(self, fullname, path=None, target=None):
        spec = PathFinder.find_spec(fullname, path, target)
        if spec is None:
            return None
        relpath = _origin_relpath(self.candidate_root, getattr(spec, "origin", None))
        if relpath is not None and relpath not in self.allowed:
            raise ImportError(
                f"runtime guard rejected unpinned candidate-local module: {fullname} -> {relpath}"
            )
        return None


def _install_runtime_guard(
    candidate_root: Path,
    runtime: Path,
    selected: list[str],
    manifest: dict[str, str],
) -> None:
    allowed = set(manifest)
    selected_relpaths = {f"governance-runtime/{filename}" for filename in selected}
    missing_selected = sorted(selected_relpaths - allowed)
    if missing_selected:
        raise SystemExit(
            f"qualification test modules are not exact-pinned in runtime manifest: {missing_selected}"
        )

    for relpath, expected_blob in manifest.items():
        actual = _git_blob_sha(candidate_root, relpath)
        if actual != expected_blob:
            raise SystemExit(
                f"runtime guard blob mismatch for {relpath}: {actual} != {expected_blob}"
            )

    sys.meta_path.insert(0, _CandidatePinFinder(candidate_root, allowed))

    def audit(event, args):
        if event in PROCESS_NATIVE_AUDIT_EVENTS and _stack_contains_candidate(candidate_root, 2):
            raise RuntimeError(
                f"runtime guard rejected candidate-originated process/native execution: {event}"
            )

        if event == "import" and args:
            # Resolution is enforced by _CandidatePinFinder. This branch makes
            # import activity explicit in the audit policy and protects direct
            # import machinery that still produces an import audit event.
            filename = args[1] if len(args) > 1 and isinstance(args[1], str) else None
            relpath = _origin_relpath(candidate_root, filename)
            if relpath is not None and relpath not in allowed:
                raise RuntimeError(
                    f"runtime guard rejected import of unpinned candidate file: {relpath}"
                )
            return

        if event == "compile" and _stack_contains_candidate(candidate_root, 2):
            raise RuntimeError("runtime guard rejected candidate-originated dynamic compilation")

        if event != "exec" or not args:
            return
        code = args[0]
        filename = getattr(code, "co_filename", "")
        if not isinstance(filename, str):
            return

        relpath = _origin_relpath(candidate_root, filename)
        if relpath is not None:
            if relpath not in allowed:
                raise RuntimeError(
                    f"runtime guard rejected execution of unpinned candidate file: {relpath}"
                )
            # Normal module execution is invoked by import machinery. A direct
            # candidate executor using a spoofed pinned filename is rejected.
            if _immediate_caller_is_candidate(candidate_root):
                raise RuntimeError(
                    "runtime guard rejected direct dynamic code execution from candidate checkout"
                )
            return

        if filename.startswith("<frozen "):
            if _immediate_caller_is_candidate(candidate_root):
                raise RuntimeError(
                    "runtime guard rejected direct dynamic code execution from candidate checkout"
                )
            return

        if filename.startswith("<") and _stack_contains_candidate(candidate_root, 2):
            raise RuntimeError(
                "runtime guard rejected synthetic dynamic code execution from candidate checkout"
            )

    sys.addaudithook(audit)


def _verify_loaded_candidate_modules(candidate_root: Path, manifest: dict[str, str]) -> None:
    allowed = set(manifest)
    unexpected = []
    for name, module in list(sys.modules.items()):
        relpath = _origin_relpath(candidate_root, getattr(module, "__file__", None))
        if relpath is not None and relpath not in allowed:
            unexpected.append(f"{name}:{relpath}")
    if unexpected:
        raise SystemExit(
            f"runtime guard observed unpinned candidate modules: {sorted(unexpected)}"
        )


def main() -> int:
    if len(sys.argv) < 3:
        raise SystemExit(
            "usage: isolated-runner <candidate-runtime> "
            "[--runtime-pin-manifest-b64 B64] <test.py>..."
        )

    runtime = Path(sys.argv[1]).resolve()
    candidate_root = runtime.parent.resolve()
    args = list(sys.argv[2:])
    manifest: dict[str, str] = {}
    if args[:1] == ["--runtime-pin-manifest-b64"]:
        if len(args) < 3:
            raise SystemExit("runtime pin manifest argument is missing")
        manifest = _decode_manifest(args[1])
        args = args[2:]
    selected = args

    if not runtime.is_dir() or runtime.name != "governance-runtime":
        raise SystemExit("candidate governance-runtime directory missing or unexpected")
    if not (candidate_root / ".git").exists():
        raise SystemExit("candidate checkout root is not a Git checkout")
    if not selected:
        raise SystemExit("no qualification test modules requested")
    if len(selected) != len(set(selected)):
        raise SystemExit("duplicate qualification test module requested")

    if sys.flags.isolated != 1 or sys.flags.no_user_site != 1 or sys.flags.ignore_environment != 1:
        raise SystemExit("candidate qualification interpreter is not isolated")

    unittest_origin = Path(unittest.__file__).resolve()
    if _is_under(unittest_origin, candidate_root):
        raise SystemExit("candidate-controlled unittest shadow detected")

    for item in sys.path:
        try:
            if _is_under(Path(item).resolve(), candidate_root):
                raise SystemExit("candidate checkout unexpectedly present before isolated import setup")
        except (OSError, RuntimeError):
            pass
    sys.path.append(str(runtime))
    _assert_candidate_last(runtime)

    if manifest:
        _install_runtime_guard(candidate_root, runtime, selected, manifest)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    plain_functions = []

    for filename in selected:
        if not filename.endswith(".py") or "/" in filename or "\\" in filename:
            raise SystemExit(
                f"qualification test must be an explicit top-level .py module: {filename}"
            )
        module_name = filename[:-3]
        before_errors = len(loader.errors)
        try:
            module = importlib.import_module(module_name)
        except Exception as exc:
            raise SystemExit(
                f"failed to import qualification test module {module_name}: {exc}"
            ) from exc
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
        if unittest_count + len(top_level) <= 0:
            raise SystemExit(
                f"qualification test module contributed zero executable tests: {module_name}"
            )

        suite.addTests(loaded)
        plain_functions.extend((module_name, name, fn) for name, fn in top_level)

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
            raise SystemExit(
                f"qualification test returned awaitable without execution: {module_name}.{name}"
            )
        if inspect.isgenerator(value):
            raise SystemExit(
                f"qualification test returned generator without execution: {module_name}.{name}"
            )
        if inspect.isasyncgen(value):
            raise SystemExit(
                f"qualification test returned async generator without execution: {module_name}.{name}"
            )
        print(f"PASS {module_name}.{name}")

    if manifest:
        _verify_loaded_candidate_modules(candidate_root, manifest)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
