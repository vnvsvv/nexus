"""The nf-lite-1 fixture comparison policy (``contracts/flow-features.md``, "Fixture comparison").

Exact: ``feature_version``, the 24 feature names and their order, the vector length, and the integer features.
Tolerant: the float features, which are computed, compared with ``math.isclose(rel_tol=1e-12, abs_tol=1e-12)``.
Which feature is an integer and which a float comes from the annotations of ``nexus_contracts.NfLite1``.
NaN, infinity and non-numeric values always fail. Every function returns a list of problems (empty = match).
"""
from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

from nexus_contracts import FEATURE_VERSION, NfLite1

FEATURE_ORDER: tuple[str, ...] = tuple(NfLite1.model_fields["ORDER"].default)
REL_TOL = 1e-12
ABS_TOL = 1e-12


def _kind(name: str) -> type:
    annotation = NfLite1.model_fields[name].annotation
    if annotation not in (int, float):
        raise TypeError(f"NfLite1.{name} is {annotation!r}; the comparison policy knows only int and float")
    return annotation


FLOAT_FEATURES: frozenset[str] = frozenset(name for name in FEATURE_ORDER if _kind(name) is float)
INTEGER_FEATURES: frozenset[str] = frozenset(FEATURE_ORDER) - FLOAT_FEATURES


def _value_problem(name: str, value: Any) -> str | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return f"{name}: {value!r} ({type(value).__name__}) is not a number"
    if not math.isfinite(value):
        return f"{name}: {value!r} is not finite"
    if name in INTEGER_FEATURES and not float(value).is_integer():
        return f"{name}: {value!r} is not an integer value"
    return None


def vector_problems(vector: Any, label: str) -> list[str]:
    """Shape and value checks for one vector: a list of 24 finite numbers, integral where NfLite1 says int."""
    if not isinstance(vector, list):
        return [f"{label}: expected a list of {len(FEATURE_ORDER)} numbers, got {type(vector).__name__}"]
    if len(vector) != len(FEATURE_ORDER):
        return [f"{label}: expected {len(FEATURE_ORDER)} features, got {len(vector)}"]
    return [f"{label}: {problem}" for name, value in zip(FEATURE_ORDER, vector)
            if (problem := _value_problem(name, value)) is not None]


def fixture_problems(fixture: Mapping[str, Any]) -> list[str]:
    """The fixture itself: version, exact names and order, and a valid expected vector."""
    problems: list[str] = []
    if fixture.get("feature_version") != FEATURE_VERSION:
        problems.append(f"fixture: feature_version is {fixture.get('feature_version')!r}, expected {FEATURE_VERSION!r}")
    names = fixture.get("expected_names")
    if names != list(FEATURE_ORDER):
        problems.append(f"fixture: expected_names must equal NfLite1.ORDER exactly ({len(FEATURE_ORDER)} names, in "
                        f"order), got {names!r}")
    return problems + vector_problems(fixture.get("expected_vector"), "fixture expected_vector")


def compare_vector(computed: Any, expected: list[Any], label: str) -> list[str]:
    """Compare a computed vector with the fixture's expected vector, feature by feature."""
    problems = vector_problems(computed, label) + vector_problems(expected, "fixture expected_vector")
    if problems:
        return problems
    for index, (name, got, want) in enumerate(zip(FEATURE_ORDER, computed, expected), 1):
        if name in FLOAT_FEATURES:
            if not math.isclose(got, want, rel_tol=REL_TOL, abs_tol=ABS_TOL):
                relative = abs(got - want) / abs(want) if want else math.inf
                problems.append(f"{label}: {name} (#{index}) = {got!r}, fixture {want!r}: relative difference "
                                f"{relative:.3g} exceeds rel_tol={REL_TOL:g} (abs_tol={ABS_TOL:g})")
        elif got != want:
            problems.append(f"{label}: {name} (#{index}) = {got!r}, fixture {want!r}: integer features must match "
                            "exactly")
    return problems
