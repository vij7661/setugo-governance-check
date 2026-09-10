#!/usr/bin/env python3
"""Entry point that preserves strict checker semantics while comparing ISO-8601 timestamps by instant.

GitHub may serialize the same ruleset updated_at instant as UTC (Z) while the signed
administrative attestation records an equivalent explicit offset. Only the specific
live-ruleset timestamp comparison is normalized; every other checker comparison remains exact.
"""
from __future__ import annotations

from datetime import datetime, timezone

import falsify_candidate as checker

_original_assert_equal = checker.assert_equal


def _parse_instant(value: object) -> datetime:
    if not isinstance(value, str):
        raise AssertionError(f"timestamp is not a string: {value!r}")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise AssertionError(f"timestamp is not valid ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None:
        raise AssertionError(f"timestamp lacks timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def _strict_with_timestamp_instant(actual: object, expected: object, label: str) -> None:
    if label == "live ruleset update timestamp":
        if _parse_instant(actual) != _parse_instant(expected):
            raise AssertionError(f"{label} mismatch: {actual!r} != {expected!r}")
        return
    _original_assert_equal(actual, expected, label)


checker.assert_equal = _strict_with_timestamp_instant

if __name__ == "__main__":
    raise SystemExit(checker.main())
