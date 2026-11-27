"""The nf-lite-1 fixture comparison policy (tools/feature_parity.py) and how validate_fixtures.py applies it.

None of these tests needs the real nexus_ml: the helper is pure, and the validator is run with a stub package or with
nexus_ml hidden, so the results are the same whether or not ml/ is installed.
"""
import json
import math
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(1, str(ROOT / "tools"))

from feature_parity import (  # noqa: E402
    ABS_TOL, FEATURE_ORDER, FLOAT_FEATURES, INTEGER_FEATURES, REL_TOL, compare_vector, fixture_problems,
)

FIXTURE = json.loads((ROOT / "contracts" / "fixtures" / "flow_feature_fixture.json").read_text(encoding="utf-8"))
EXPECTED = FIXTURE["expected_vector"]
RATE = FEATURE_ORDER.index("src_to_dst_second_bytes")
COMPUTED_RATE = 1812 / max(2088, 1) * 1000          # the contract formula: 867.816091954023, one ulp above the fixture


def changed(index: int, value, base: list | None = None) -> list:
    vector = list(EXPECTED if base is None else base)
    vector[index] = value
    return vector


def at(name: str) -> int:
    return FEATURE_ORDER.index(name)


# ------------------------------------------------------------------ the policy's inputs
def test_numeric_kinds_come_from_the_contract_model():
    assert len(FEATURE_ORDER) == 24 and len(INTEGER_FEATURES) == 19
    assert FLOAT_FEATURES == {"mean_pkt_size", "src_to_dst_second_bytes", "dst_to_src_second_bytes",
                              "src_to_dst_avg_throughput", "dst_to_src_avg_throughput"}
    assert (REL_TOL, ABS_TOL) == (1e-12, 1e-12)


def test_the_canonical_fixture_is_valid_and_keeps_its_published_value():
    assert fixture_problems(FIXTURE) == []
    assert EXPECTED[RATE] == 867.8160919540229 and COMPUTED_RATE == math.nextafter(EXPECTED[RATE], math.inf)


# ------------------------------------------------------------------ accepted
def test_an_identical_vector_matches():
    assert compare_vector(list(EXPECTED), EXPECTED, "dataset path") == []


def test_the_contract_formula_one_ulp_from_the_fixture_matches():
    assert compare_vector(changed(RATE, COMPUTED_RATE), EXPECTED, "dataset path") == []


@pytest.mark.parametrize("name", sorted(FLOAT_FEATURES))
@pytest.mark.parametrize("direction", [math.inf, -math.inf])
def test_one_ulp_on_any_float_feature_matches(name, direction):
    index = at(name)
    assert compare_vector(changed(index, math.nextafter(EXPECTED[index], direction)), EXPECTED, "x") == []


@pytest.mark.parametrize("relative", [1e-13, -1e-13, 9e-13])
def test_small_rounding_differences_match(relative):
    assert compare_vector(changed(RATE, EXPECTED[RATE] * (1 + relative)), EXPECTED, "x") == []


def test_the_absolute_tolerance_applies_only_near_zero():
    zero = changed(at("mean_pkt_size"), 0.0)
    assert compare_vector(changed(at("mean_pkt_size"), 5e-13, zero), zero, "x") == []
    assert compare_vector(changed(at("mean_pkt_size"), 2e-12, zero), zero, "x") != []


def test_an_integer_feature_given_as_int_matches_its_float_value():
    assert compare_vector(changed(at("in_bytes"), 1812), EXPECTED, "x") == []


# ------------------------------------------------------------------ rejected
@pytest.mark.parametrize("wrong, label", [
    (EXPECTED[RATE] * (1 + 1e-11), "relative error above the tolerance"),
    (1812 / 2087 * 1000, "off-by-one millisecond denominator"),
    (1812 / 2088, "missing *1000"),
    (0.0, "zero"),
])
def test_significant_float_errors_fail_with_a_feature_specific_message(wrong, label):
    (problem,) = compare_vector(changed(RATE, wrong), EXPECTED, "dataset path")
    assert problem.startswith("dataset path: src_to_dst_second_bytes (#16) = ")
    assert repr(wrong) in problem and repr(EXPECTED[RATE]) in problem and "rel_tol=1e-12" in problem


def test_the_wrong_duration_on_another_rate_fails():
    (problem,) = compare_vector(changed(at("dst_to_src_second_bytes"), 614 / 2088 * 1000), EXPECTED, "x")
    assert "dst_to_src_second_bytes (#17)" in problem


@pytest.mark.parametrize("name", sorted(INTEGER_FEATURES))
def test_every_integer_feature_must_match_exactly(name):
    index = at(name)
    (problem,) = compare_vector(changed(index, EXPECTED[index] + 1), EXPECTED, "x")
    assert f"{name} (#{index + 1})" in problem and "integer features must match exactly" in problem


def test_an_integer_feature_gets_no_tolerance():
    index = at("l4_dst_port")
    (problem,) = compare_vector(changed(index, math.nextafter(8443.0, math.inf)), EXPECTED, "x")
    assert "l4_dst_port: 8443.000000000002 is not an integer value" in problem


def test_swapped_directions_fail():
    swapped = changed(at("out_bytes"), 1812.0, changed(at("in_bytes"), 614.0))
    problems = compare_vector(swapped, EXPECTED, "x")
    assert [p.split(" (#")[0] for p in problems] == ["x: in_bytes", "x: out_bytes"]


@pytest.mark.parametrize("value", [None, "867.8", True, False, [1.0], {"v": 1.0}])
@pytest.mark.parametrize("name", ["src_to_dst_second_bytes", "in_pkts"])
def test_invalid_types_fail(name, value):
    (problem,) = compare_vector(changed(at(name), value), EXPECTED, "x")
    assert problem.startswith(f"x: {name}: ") and "is not a number" in problem


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
@pytest.mark.parametrize("name", ["mean_pkt_size", "src_to_dst_avg_throughput", "protocol"])
def test_non_finite_values_fail_in_the_computed_vector(name, value):
    (problem,) = compare_vector(changed(at(name), value), EXPECTED, "x")
    assert problem == f"x: {name}: {value!r} is not finite"


@pytest.mark.parametrize("value", [math.nan, math.inf])
def test_non_finite_values_fail_in_the_fixture(value):
    broken = changed(RATE, value)
    assert compare_vector(list(EXPECTED), broken, "x") == [f"fixture expected_vector: src_to_dst_second_bytes: "
                                                            f"{value!r} is not finite"]
    assert fixture_problems({**FIXTURE, "expected_vector": broken}) != []


@pytest.mark.parametrize("vector, message", [
    (EXPECTED[:-1], "expected 24 features, got 23"),
    (EXPECTED + [0.0], "expected 24 features, got 25"),
    ([], "expected 24 features, got 0"),
    (tuple(EXPECTED), "expected a list of 24 numbers, got tuple"),
    (None, "expected a list of 24 numbers, got NoneType"),
    (dict(zip(FEATURE_ORDER, EXPECTED)), "expected a list of 24 numbers, got dict"),
])
def test_a_wrong_length_or_container_fails(vector, message):
    assert compare_vector(vector, EXPECTED, "x") == [f"x: {message}"]


@pytest.mark.parametrize("names", [
    list(reversed(FEATURE_ORDER)),
    [FEATURE_ORDER[1], FEATURE_ORDER[0], *FEATURE_ORDER[2:]],
    list(FEATURE_ORDER[:-1]),
    [*FEATURE_ORDER, "l4_src_port"],
    [*FEATURE_ORDER[:-1], "num_pkts_1024_to_1500_bytes"],
    None,
])
def test_fixture_names_must_match_the_contract_order_exactly(names):
    (problem,) = fixture_problems({**FIXTURE, "expected_names": names})
    assert "expected_names must equal NfLite1.ORDER exactly" in problem


def test_the_fixture_version_must_be_nf_lite_1():
    (problem,) = fixture_problems({**FIXTURE, "feature_version": "nf-lite-2"})
    assert "feature_version is 'nf-lite-2'" in problem


def test_a_non_integral_integer_feature_in_the_fixture_fails():
    (problem,) = fixture_problems({**FIXTURE, "expected_vector": changed(at("in_pkts"), 9.5)})
    assert problem == "fixture expected_vector: in_pkts: 9.5 is not an integer value"


# ------------------------------------------------------------------ validate_fixtures.py
def validator(tmp_path: Path, *args: str, stub: str | None = None, hide_ml: bool = False) -> subprocess.CompletedProcess:
    """Run the validator in a fresh interpreter, with a stub nexus_ml first on the path, or with nexus_ml hidden."""
    setup = ["import runpy, sys"]
    if hide_ml:                                                    # importing it fails exactly as when not installed
        setup += ["class Hide:",
                  "    def find_spec(self, name, path=None, target=None):",
                  "        if name.split('.')[0] == 'nexus_ml':",
                  "            raise ModuleNotFoundError(f'No module named {name!r}', name=name)",
                  "sys.meta_path.insert(0, Hide())"]
    if stub is not None:
        package = tmp_path / "stub" / "nexus_ml"
        package.mkdir(parents=True)
        (package / "__init__.py").write_text("", encoding="utf-8")
        (package / "features.py").write_text(stub, encoding="utf-8")
        setup.append(f"sys.path.insert(0, {str(package.parent)!r})")
    script = str(ROOT / "tools" / "validate_fixtures.py")
    setup += [f"sys.argv = [{script!r}, *{list(args)!r}]", f"runpy.run_path({script!r}, run_name='__main__')"]
    return subprocess.run([sys.executable, "-c", "\n".join(setup)], cwd=ROOT, capture_output=True, text=True,
                          timeout=120)


def converters(dataset: list, nflow: list | None = None) -> str:
    return (f"def from_dataset_row(row):\n    return {dataset!r}\n\n"
            f"def from_nflow_fields(fields):\n    return {(dataset if nflow is None else nflow)!r}\n")


def test_without_nexus_ml_the_check_is_skipped(tmp_path):
    run = validator(tmp_path, hide_ml=True)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "nexus_ml not installed; feature parity fixture skipped" in run.stdout


def test_without_nexus_ml_require_ml_fails(tmp_path):
    run = validator(tmp_path, "--require-ml", hide_ml=True)
    assert run.returncode == 1
    assert "nexus_ml is required (--require-ml) but not installed" in run.stdout


@pytest.mark.parametrize("args", [(), ("--require-ml",)])
def test_converters_one_ulp_from_the_fixture_pass(tmp_path, args):
    run = validator(tmp_path, *args, stub=converters(changed(RATE, COMPUTED_RATE)))
    assert run.returncode == 0, run.stdout + run.stderr
    assert "feature parity fixture OK (dataset and NFStream paths)" in run.stdout


def test_a_wrong_nfstream_vector_fails_naming_the_path_and_feature(tmp_path):
    run = validator(tmp_path, stub=converters(list(EXPECTED), changed(RATE, EXPECTED[RATE] * 1.001)))
    assert run.returncode == 1
    assert "feature parity: NFStream path: src_to_dst_second_bytes (#16)" in run.stdout
    assert "dataset path" not in run.stdout


def test_a_wrong_dataset_vector_fails(tmp_path):
    run = validator(tmp_path, stub=converters(EXPECTED[:-1], list(EXPECTED)))
    assert run.returncode == 1 and "feature parity: dataset path: expected 24 features, got 23" in run.stdout


@pytest.mark.parametrize("args", [(), ("--require-ml",)])
def test_a_broken_internal_import_fails_instead_of_skipping(tmp_path, args):
    run = validator(tmp_path, *args, stub="import nfstream_is_not_installed_here\n")
    assert run.returncode == 1
    assert "nexus_ml is installed but importing nexus_ml.features failed" in run.stdout
    assert "nfstream_is_not_installed_here" in run.stdout and "skipped" not in run.stdout


def test_any_import_time_error_fails(tmp_path):
    run = validator(tmp_path, stub="raise RuntimeError('bad import-time state')\n")
    assert run.returncode == 1 and "RuntimeError('bad import-time state')" in run.stdout


def test_a_converter_exception_is_reported(tmp_path):
    stub = converters(list(EXPECTED)) + "\ndef from_nflow_fields(fields):\n    raise ValueError('udps.b128 missing')\n"
    run = validator(tmp_path, stub=stub)
    assert run.returncode == 1
    assert "NFStream path: nexus_ml.features.from_nflow_fields raised ValueError('udps.b128 missing')" in run.stdout


def test_a_missing_converter_is_reported(tmp_path):
    run = validator(tmp_path, stub="def from_dataset_row(row):\n    return []\n")
    assert run.returncode == 1
    assert "from_nflow_fields raised AttributeError" in run.stdout


def test_an_unknown_argument_is_refused(tmp_path):
    run = validator(tmp_path, "--require-m1", hide_ml=True)
    assert run.returncode == 2 and "unrecognized arguments" in run.stderr
