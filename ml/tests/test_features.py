import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nexus_ml.features import (
    FEATURE_ORDER,
    flags_mask,
    from_dataset_row,
    from_nflow,
    from_nflow_fields,
)

FIXTURE_PATH = (
    Path(__file__).resolve().parents[2] / "contracts/fixtures/flow_feature_fixture.json"
)


@pytest.fixture
def flow_fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_dataset_and_nfstream_match(flow_fixture):
    row = flow_fixture["dataset_row"]
    fields = flow_fixture["nflow_fields"]
    dataset = from_dataset_row(row)
    live = from_nflow_fields(fields)
    assert FEATURE_ORDER == tuple(flow_fixture["expected_names"])
    assert dataset == live

    # The published src_to_dst_second_bytes differs in the last digits.
    # Keep every other feature under exact comparison pending a contract decision.
    expected = flow_fixture["expected_vector"]
    rate_index = FEATURE_ORDER.index("src_to_dst_second_bytes")
    assert dataset[:rate_index] == expected[:rate_index]
    assert dataset[rate_index] == pytest.approx(expected[rate_index], rel=1e-15, abs=0)
    assert dataset[rate_index + 1 :] == expected[rate_index + 1 :]
    assert from_dataset_row(row, recompute_rates=False) == expected


def test_nflow_object_uses_the_field_path(flow_fixture):
    fields = flow_fixture["nflow_fields"]
    flow = SimpleNamespace(**{**fields, "udps": SimpleNamespace(**fields["udps"])})
    assert from_nflow(flow) == from_nflow_fields(fields)


@pytest.mark.parametrize(
    ("flag", "bit"),
    [("fin", 1), ("syn", 2), ("rst", 4), ("psh", 8), ("ack", 16),
     ("urg", 32), ("ece", 64), ("cwr", 128)],
)
def test_flags_encode_presence(flag, bit):
    flags = dict.fromkeys(("fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"), 0)
    flags[flag] = 4
    counts = {f"src2dst_{name}_packets": count for name, count in flags.items()}
    assert flags_mask(counts, "src2dst") == bit


def test_zero_duration_uses_one_millisecond(flow_fixture):
    row = dict(flow_fixture["dataset_row"])
    row.update(IN_BYTES=10, OUT_BYTES=4, DURATION_IN=0, DURATION_OUT=2)
    row["FLOW_DURATION_MILLISECONDS"] = 0
    values = dict(zip(FEATURE_ORDER, from_dataset_row(row), strict=True))
    assert values["in_bytes"] == 10
    assert values["out_bytes"] == 4
    assert values["src_to_dst_second_bytes"] == 10_000
    assert values["dst_to_src_second_bytes"] == 2_000
    assert values["src_to_dst_avg_throughput"] == 80_000
    assert values["dst_to_src_avg_throughput"] == 32_000


def test_empty_flow_mean_is_zero(flow_fixture):
    row = dict(flow_fixture["dataset_row"], IN_BYTES=0, OUT_BYTES=0, IN_PKTS=0, OUT_PKTS=0)
    assert from_dataset_row(row)[FEATURE_ORDER.index("mean_pkt_size")] == 0.0


def test_missing_dataset_column_is_rejected(flow_fixture):
    row = flow_fixture["dataset_row"]
    del row["IN_BYTES"]
    with pytest.raises(KeyError, match="IN_BYTES"):
        from_dataset_row(row)


def test_missing_nfstream_bin_is_rejected(flow_fixture):
    fields = flow_fixture["nflow_fields"]
    del fields["udps"]["b128"]
    with pytest.raises(KeyError, match="b128"):
        from_nflow_fields(fields)


@pytest.mark.parametrize("value", [-1, 1.5, float("nan")])
def test_invalid_count_is_rejected(flow_fixture, value):
    row = dict(flow_fixture["dataset_row"], IN_PKTS=value)
    with pytest.raises(ValueError, match="IN_PKTS"):
        from_dataset_row(row)
