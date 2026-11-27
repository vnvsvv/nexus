"""Convert dataset rows and NFStream flows into canonical nf-lite-1 vectors."""

from collections.abc import Mapping
from math import isfinite
from typing import Any, cast

from nexus_contracts import NfLite1

FEATURE_ORDER = cast(tuple[str, ...], NfLite1.model_fields["ORDER"].default)

# Each entry maps a canonical feature to its dataset and NFStream input.
_COUNTER_FIELDS = {
    "protocol": ("PROTOCOL", "protocol"),
    "l4_dst_port": ("L4_DST_PORT", "dst_port"),
    "in_bytes": ("IN_BYTES", "src2dst_bytes"),
    "out_bytes": ("OUT_BYTES", "dst2src_bytes"),
    "in_pkts": ("IN_PKTS", "src2dst_packets"),
    "out_pkts": ("OUT_PKTS", "dst2src_packets"),
    "flow_duration_ms": ("FLOW_DURATION_MILLISECONDS", "bidirectional_duration_ms"),
    "duration_in_ms": ("DURATION_IN", "src2dst_duration_ms"),
    "duration_out_ms": ("DURATION_OUT", "dst2src_duration_ms"),
    "longest_flow_pkt": ("LONGEST_FLOW_PKT", "bidirectional_max_ps"),
    "shortest_flow_pkt": ("SHORTEST_FLOW_PKT", "bidirectional_min_ps"),
}
_BINS = {
    "num_pkts_up_to_128_bytes": "b128",
    "num_pkts_128_to_256_bytes": "b256",
    "num_pkts_256_to_512_bytes": "b512",
    "num_pkts_512_to_1024_bytes": "b1024",
    "num_pkts_1024_to_1514_bytes": "b1514",
}
_FLAG_PREFIXES = {
    "tcp_flags": "bidirectional",
    "client_tcp_flags": "src2dst",
    "server_tcp_flags": "dst2src",
}
_TCP_FLAGS = ("fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr")
_RATE_FIELDS = (
    "src_to_dst_second_bytes",
    "dst_to_src_second_bytes",
    "src_to_dst_avg_throughput",
    "dst_to_src_avg_throughput",
)


def _counter(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a non-negative integer")
    try:
        count = int(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a non-negative integer") from exc
    if count < 0 or (not isinstance(value, str) and count != value):
        raise ValueError(f"{field} must be a non-negative integer")
    return count


def flags_mask(fields: Mapping[str, Any], prefix: str) -> int:
    """Encode which flags appeared in one direction or in the whole flow."""
    mask = 0
    for bit, flag in enumerate(_TCP_FLAGS):
        field = f"{prefix}_{flag}_packets"
        if _counter(fields[field], field):
            mask |= 1 << bit
    return mask


def _rates(counters: Mapping[str, int]) -> dict[str, float]:
    in_bytes = counters["in_bytes"]
    out_bytes = counters["out_bytes"]
    flow_ms = max(counters["flow_duration_ms"], 1)
    return {
        "src_to_dst_second_bytes": in_bytes / max(counters["duration_in_ms"], 1) * 1000,
        "dst_to_src_second_bytes": out_bytes / max(counters["duration_out_ms"], 1) * 1000,
        "src_to_dst_avg_throughput": in_bytes * 8 / flow_ms * 1000,
        "dst_to_src_avg_throughput": out_bytes * 8 / flow_ms * 1000,
    }


def _vector(features: Mapping[str, Any]) -> list[float]:
    model = NfLite1.model_validate(features)
    vector = model.vector()
    if any(not isfinite(value) or value < 0 for value in vector):
        raise ValueError("nf-lite-1 features must be finite and non-negative")
    return vector


def from_dataset_row(
    row: Mapping[str, Any], *, recompute_rates: bool = True
) -> list[float]:
    """Convert a UQ NetFlow v2 row, recomputing rates with the live formulas by default."""
    features = {
        name: _counter(row[column], column)
        for name, (column, _) in _COUNTER_FIELDS.items()
    }
    for name in (*_FLAG_PREFIXES, *_BINS):
        column = name.upper()
        features[name] = _counter(row[column], column)
    packets = features["in_pkts"] + features["out_pkts"]
    mean_size = (features["in_bytes"] + features["out_bytes"]) / packets if packets else 0.0
    rates = (
        _rates(features)
        if recompute_rates
        else {name: float(row[name.upper()]) for name in _RATE_FIELDS}
    )
    return _vector({**features, **rates, "mean_pkt_size": mean_size})


def from_nflow_fields(fields: Mapping[str, Any]) -> list[float]:
    """Convert NFStream attributes with packet-size counters in a nested udps mapping."""
    features = {
        name: _counter(fields[attr], attr)
        for name, (_, attr) in _COUNTER_FIELDS.items()
    }
    for name, prefix in _FLAG_PREFIXES.items():
        features[name] = flags_mask(fields, prefix)
    bins = fields["udps"]
    for name, attr in _BINS.items():
        features[name] = _counter(bins[attr], f"udps.{attr}")
    return _vector(
        {**features, **_rates(features), "mean_pkt_size": fields["bidirectional_mean_ps"]}
    )


def from_nflow(flow: Any) -> list[float]:
    """Read an NFlow object without requiring NFStream at import time."""
    fields = {attr: getattr(flow, attr) for _, attr in _COUNTER_FIELDS.values()}
    fields["bidirectional_mean_ps"] = flow.bidirectional_mean_ps
    for prefix in _FLAG_PREFIXES.values():
        for flag in _TCP_FLAGS:
            attr = f"{prefix}_{flag}_packets"
            fields[attr] = getattr(flow, attr)
    fields["udps"] = {attr: getattr(flow.udps, attr) for attr in _BINS.values()}
    return from_nflow_fields(fields)
