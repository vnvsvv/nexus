"""Explicitly unresolved Linux ancestry on a trustworthy process (task A3a, review of the engine for A4).

The Linux adapter can report a native, observed ``process_start`` with ``attributes.parent_unresolved`` set and no
parent id. The engine's root flags do not report that. The graph keeps the first reason on its runtime
``ProcessNode.parent_unresolved`` so it outlives the event; the requirement for the incident builder (A4) is in
``endpoint-core/README.md``. The events here are built to the adapter's shape: the adapter itself is Linux only and is
not run by these tests.
"""
from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from nexus_contracts import HostEvent, load_schema, validate_against_schema
from nexus_contracts import ProcessNode as ContractProcessNode
from nexus_contracts import RuleMatch as ContractRuleMatch
from nexus_endpoint_core import EngineMatch, ProcessGraph, RuleEngine, load_rules
from nexus_endpoint_core.rules import RuleSet

RULES = Path(__file__).resolve().parents[2] / "contracts" / "rules"
LIN = "linux-vm-01"
REASONS = ("sensor_task_walk", "conflicting_sensor_parent")
OTHER_REASON = {"sensor_task_walk": "conflicting_sensor_parent", "conflicting_sensor_parent": "sensor_task_walk"}
TOP, JOB = f"{LIN}:top", f"{LIN}:job"
_ids = itertools.count(1)


@pytest.fixture(scope="module")
def shipped() -> RuleSet:
    return load_rules(RULES, strict=True)


def event(proc: str, kind: str = "process_start", *, parent: str | None = None, unresolved: Any = None,
          resolution: str = "native", hit: bool = False, second: int = 0) -> HostEvent:
    """A Linux event of ``proc`` in the adapter's shape; ``hit`` makes NX-ANY-001 match a ``process_start``."""
    number = next(_ids)
    attributes: dict[str, Any] = {"sensor": "tetragon", "identity_resolution": resolution}
    if unresolved is not None:
        attributes["parent_unresolved"] = unresolved
    if resolution == "placeholder":
        attributes["placeholder"] = True
    if hit:
        attributes["ti_hash_hit"] = True
    body: dict[str, Any] = {
        "schema_version": "1.0", "event_id": f"{LIN}:evt-{number:012x}", "endpoint_id": LIN, "os": "linux",
        "event_type": kind, "timestamp_utc": f"2026-11-15T10:00:{second:02d}.000Z",
        "process_instance_id": f"{LIN}:{proc}", "pid": 1000 + sum(map(ord, proc)), "binary": "/usr/bin/python3",
        "attributes": attributes}
    if parent is not None:
        body["parent_process_instance_id"] = f"{LIN}:{parent}"
    if kind == "file_access":
        body["file"] = {"path": "/tmp/report", "operation": "read"}
    if kind == "network_connect":
        body["network"] = {"protocol": "TCP", "src_ip": "10.0.0.1", "src_port": 40000, "dst_ip": "10.0.0.2",
                           "dst_port": 80, "direction": "outbound"}
    if kind == "dns_query":
        body["dns"] = {"query": "example.test"}
    assert validate_against_schema("host_event", body) == []
    return HostEvent.model_validate(body)


def applied(*events: HostEvent, graph: ProcessGraph | None = None) -> ProcessGraph:
    graph = ProcessGraph() if graph is None else graph
    for item in events:
        graph.apply(item)
    return graph


def detect(shipped: RuleSet, *events: HostEvent, graph: ProcessGraph | None = None
           ) -> tuple[RuleEngine, ProcessGraph, EngineMatch]:
    """Apply and evaluate each event in order; the last one must produce exactly one NX-ANY-001 match."""
    engine = RuleEngine(shipped, endpoint_id=LIN, strict=True)
    graph = ProcessGraph() if graph is None else graph
    for item in events:
        graph.apply(item)
        result = engine.evaluate(graph, item)
        assert result.disposition == "evaluated"
    (match,) = result.matches
    assert match.rule.id == "NX-ANY-001"
    return engine, graph, match


def reported(match: EngineMatch) -> list[object]:
    return [item.attributes.get("parent_unresolved") for item in match.events.values()]


def root_facts(match: EngineMatch) -> tuple[object, ...]:
    return (match.root_parent_missing, match.root_parent_is_placeholder, match.placeholder_process_ids,
            match.identity_inferred_event_ids)


def cached_reasons(graph: ProcessGraph) -> list[object]:
    return [item.attributes["parent_unresolved"] for item in graph.events.values()
            if "parent_unresolved" in item.attributes]


def assert_unlinked(graph: ProcessGraph, process: str, nodes: int = 1) -> None:
    """The reason invented no ancestry: no parent id, no ancestor, no placeholder parent."""
    node = graph.get(process)
    assert node is not None and node.parent_process_instance_id is None
    assert graph.ancestors(process) == [] and len(graph) == nodes


# ------------------------------------------------------------------ what a detection shows
@pytest.mark.parametrize("reason", REASONS)
def test_a_native_start_with_unresolved_ancestry_matches_and_keeps_the_reason(shipped, reason):
    start = event("job", unresolved=reason, hit=True)
    engine, graph, match = detect(shipped, start)
    assert match.root_process_instance_id == JOB and set(match.process_by_step.values()) == {JOB}
    assert list(match.events.values()) == [start] and reported(match) == [reason]
    # native identity stays native: neither inferred nor a seeded placeholder
    assert match.identity_inferred_event_ids == () and match.placeholder_process_ids == ()
    assert engine.stats().placeholder_starts_skipped == 0
    node = graph.get(JOB)
    assert node is not None and node.placeholder is False and node.identity_resolution == "native"
    assert node.parent_unresolved == reason
    # the root flags report no gap: they do not prove that the ancestry is complete
    assert (match.root_parent_missing, match.root_parent_is_placeholder) == (False, False)
    assert start.parent_process_instance_id is None
    assert_unlinked(graph, JOB)


@pytest.mark.parametrize("reason", REASONS)
def test_contract_serialization_is_unchanged(shipped, reason):
    start = event("job", unresolved=reason, hit=True)
    before = start.model_dump(mode="json", by_alias=True, exclude_none=True)
    _, _, match = detect(shipped, start)
    assert start.model_dump(mode="json", by_alias=True, exclude_none=True) == before      # apply rewrites no event
    contract = match.to_contract()
    body = contract.model_dump(mode="json", exclude_none=True)
    assert set(body) == {"rule_id", "rule_version", "matched_at_utc", "bindings"}
    assert body["rule_id"] == "NX-ANY-001" and list(body["bindings"].values()) == [start.event_id]
    schema = load_schema("incident")["properties"]["rule_matches"]["items"]
    assert list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(body)) == []
    assert ContractRuleMatch.model_validate(body) == contract
    # the field is runtime-only: the frozen incident process node has no such property
    assert "parent_unresolved" not in ContractProcessNode.model_fields
    assert "parent_unresolved" not in load_schema("incident")["properties"]["process_nodes"]["items"]["properties"]


@pytest.mark.parametrize("reason", REASONS)
def test_without_a_marker_no_reason_is_recorded(shipped, reason):
    # Negative control: the same parentless start without a marker. The root flags cannot tell the two apart; the
    # node can. No reason is not proof of complete ancestry either.
    _, plain_graph, plain = detect(shipped, event("job", hit=True))
    _, marked_graph, marked = detect(shipped, event("job", unresolved=reason, hit=True))
    assert reported(plain) == [None] and reported(marked) == [reason]
    assert plain_graph.get(JOB).parent_unresolved is None
    assert marked_graph.get(JOB).parent_unresolved == reason
    assert root_facts(plain) == root_facts(marked) == (False, False, (), ())
    for graph in (plain_graph, marked_graph):
        assert_unlinked(graph, JOB)


def test_no_unmarked_path_records_a_reason():
    graph = applied(event("job", "file_access", second=0), event("job", second=1), event("job", second=2),
                    event("job", "network_connect", second=3), event("job", "dns_query", second=4),
                    event("job", parent="top", second=5), event("job", "process_exit", second=6))
    assert graph.get(JOB).parent_unresolved is None and graph.get(TOP).parent_unresolved is None


@pytest.mark.parametrize("reason", REASONS)
def test_a_suppressed_repeat_keeps_the_reason(shipped, reason):
    engine, graph, _ = detect(shipped, event("job", unresolved=reason, hit=True))
    again = event("job", unresolved=reason, hit=True, second=1)
    graph.apply(again)
    (repeat,) = engine.evaluate(graph, again).suppressed
    assert [item.attributes["parent_unresolved"] for item in repeat.events.values()] == [reason]
    assert graph.get(JOB).parent_unresolved == reason


@pytest.mark.parametrize("reason", REASONS)
def test_an_unresolved_ancestor_is_reported_on_its_node_when_a_child_matches(shipped, reason):
    # Bound events are not enough: the child matches, the climb ends at the unresolved ancestor, and no bound event
    # carries the marker.
    _, graph, match = detect(shipped, event("top", unresolved=reason), event("job", parent="top", hit=True, second=1))
    assert match.root_process_instance_id == TOP
    assert (match.root_parent_missing, match.root_parent_is_placeholder) == (False, False)
    assert reported(match) == [None]
    assert graph.get(TOP).parent_unresolved == reason and graph.get(JOB).parent_unresolved is None
    assert graph.get(TOP).identity_resolution == "native" and match.identity_inferred_event_ids == ()
    assert [node.process_instance_id for node in graph.ancestors(JOB)] == [TOP]
    assert_unlinked(graph, TOP, nodes=2)


# ------------------------------------------------------------------ cache eviction
@pytest.mark.parametrize("reason", REASONS)
def test_the_reason_survives_eviction_of_the_original_start_event(shipped, reason):
    first = event("top", unresolved=reason)
    _, graph, match = detect(shipped, first, event("job", parent="top", hit=True, second=1),
                             graph=ProcessGraph(max_events=1))
    root = graph.get(match.root_process_instance_id)
    assert root is not None and root.process_instance_id == TOP
    assert first.event_id not in graph.events and root.start_event_id is None and cached_reasons(graph) == []
    assert root.parent_unresolved == reason
    assert (match.root_parent_missing, match.root_parent_is_placeholder) == (False, False) and reported(match) == [None]
    assert_unlinked(graph, TOP, nodes=2)


@pytest.mark.parametrize("reason", REASONS)
def test_the_reason_survives_long_eviction_and_later_unmarked_events(reason):
    graph = applied(event("job", unresolved=reason), graph=ProcessGraph(max_events=2, max_events_per_node=1))
    for second in range(1, 20):
        graph.apply(event("job", "file_access", second=second))
    assert cached_reasons(graph) == [] and graph.get(JOB).parent_unresolved == reason


# ------------------------------------------------------------------ placeholder-to-native upgrade
@pytest.mark.parametrize("reason", REASONS)
@pytest.mark.parametrize("first_kind", ["process_start", "file_access"])
def test_a_reason_seen_on_a_placeholder_survives_the_native_upgrade(reason, first_kind):
    seeded = event("job", first_kind, unresolved=reason,
                   resolution="placeholder" if first_kind == "process_start" else "unknown")
    graph = applied(seeded)
    assert graph.get(JOB).placeholder and graph.get(JOB).parent_unresolved == reason
    graph.apply(event("job", second=1))                                      # the real start, without the marker
    node = graph.get(JOB)
    assert not node.placeholder and node.identity_resolution == "native" and node.parent_unresolved == reason
    assert_unlinked(graph, JOB)


@pytest.mark.parametrize("reason", REASONS)
def test_a_reason_first_seen_on_the_upgrading_start_is_recorded(reason):
    graph = applied(event("job", resolution="placeholder"), event("job", unresolved=reason, second=1))
    node = graph.get(JOB)
    assert not node.placeholder and node.identity_resolution == "native" and node.parent_unresolved == reason
    assert_unlinked(graph, JOB)


@pytest.mark.parametrize("reason", REASONS)
def test_a_placeholder_parent_gets_the_reason_only_from_its_own_events(reason):
    graph = applied(event("job", parent="top", unresolved=reason))           # the child's reason is the child's
    assert graph.get(TOP).placeholder and graph.get(TOP).parent_unresolved is None
    assert graph.get(JOB).parent_unresolved == reason
    graph.apply(event("top", unresolved=OTHER_REASON[reason], second=1))
    assert not graph.get(TOP).placeholder and graph.get(TOP).parent_unresolved == OTHER_REASON[reason]
    assert graph.get(JOB).parent_unresolved == reason


# ------------------------------------------------------------------ later events of an existing process
@pytest.mark.parametrize("reason", REASONS)
def test_a_repeated_start_fills_in_a_missing_reason_although_it_is_not_cached(reason):
    first, repeat = event("job"), event("job", unresolved=reason, second=1)
    graph = applied(first, repeat)
    node = graph.get(JOB)
    assert node.start_event_id == first.event_id and repeat.event_id not in graph.events
    assert node.parent_unresolved == reason and node.identity_resolution == "native"
    assert_unlinked(graph, JOB)


@pytest.mark.parametrize("reason", REASONS)
@pytest.mark.parametrize("kind", ["file_access", "network_connect", "dns_query", "process_exit"])
def test_a_later_event_of_any_kind_records_the_reason(reason, kind):
    graph = applied(event("job"), event("job", kind, unresolved=reason, second=1))
    assert graph.get(JOB).parent_unresolved == reason
    assert_unlinked(graph, JOB)


@pytest.mark.parametrize("reason", REASONS)
def test_a_duplicate_exit_can_still_report_the_reason(reason):
    first = event("job", "process_exit", second=1)
    graph = applied(event("job"), first, event("job", "process_exit", unresolved=reason, second=2))
    node = graph.get(JOB)
    assert node.exit_event_id == first.event_id and node.parent_unresolved == reason


@pytest.mark.parametrize("reason", REASONS)
def test_the_exit_of_a_process_never_seen_records_nothing(reason):
    graph = ProcessGraph()
    assert graph.apply(event("job", "process_exit", unresolved=reason)) is None
    assert len(graph) == 0


@pytest.mark.parametrize("reason", REASONS)
@pytest.mark.parametrize("kind", ["process_start", "file_access", "process_exit"])
def test_the_first_reason_wins_and_is_never_erased(reason, kind):
    graph = applied(event("job", unresolved=reason),
                    event("job", kind, unresolved=OTHER_REASON[reason], second=1),
                    event("job", kind, second=2))
    assert graph.get(JOB).parent_unresolved == reason


@pytest.mark.parametrize("value", ["", True, 7, ["sensor_task_walk"], {"reason": "x"}])
def test_only_a_non_empty_string_is_recorded_and_it_does_not_block_a_later_one(value):
    graph = applied(event("job", unresolved=value))
    assert graph.get(JOB).parent_unresolved is None
    graph.apply(event("job", "file_access", unresolved="sensor_task_walk", second=1))
    graph.apply(event("job", "file_access", unresolved=value, second=2))
    assert graph.get(JOB).parent_unresolved == "sensor_task_walk"


def test_a_reason_the_core_does_not_know_is_kept_verbatim():
    assert applied(event("job", unresolved="a_future_reason")).get(JOB).parent_unresolved == "a_future_reason"


def test_a_rejected_event_records_nothing():
    graph = applied(event("job"))
    bad = event("job", "file_access", unresolved="sensor_task_walk", second=1)
    with pytest.raises(ValueError):
        graph.apply(bad.model_copy(update={"timestamp_utc": "not-a-time"}))
    assert graph.get(JOB).parent_unresolved is None


# ------------------------------------------------------------------ a parent established later
@pytest.mark.parametrize("reason", REASONS)
@pytest.mark.parametrize("kind", ["process_start", "file_access"])
def test_a_later_observed_parent_keeps_the_history(shipped, reason, kind):
    _, graph, match = detect(shipped, event("top"), event("job", unresolved=reason, hit=True, second=1))
    assert match.root_process_instance_id == JOB and graph.ancestors(JOB) == []
    graph.apply(event("job", kind, parent="top", second=2))                  # the relationship is now observed
    node, parent = graph.get(JOB), graph.get(TOP)
    assert node.parent_process_instance_id == TOP and JOB in parent.children and not parent.placeholder
    assert node.parent_unresolved == reason and parent.parent_unresolved is None
    assert node.identity_resolution == "native" and len(graph) == 2


@pytest.mark.parametrize("reason", REASONS)
def test_the_climb_uses_the_current_parent_and_the_history_stays_on_the_path(shipped, reason):
    engine, graph, _ = detect(shipped, event("top"), event("job", unresolved=reason, hit=True, second=1))
    graph.apply(event("job", "file_access", parent="top", second=2))
    child = event("child", parent="job", hit=True, second=3)
    graph.apply(child)
    (match,) = engine.evaluate(graph, child).matches                         # another root: not suppressed
    assert match.root_process_instance_id == TOP and root_facts(match) == (False, False, (), ())
    path = [graph.get(f"{LIN}:child"), *graph.ancestors(f"{LIN}:child")]
    assert [node.parent_unresolved for node in path] == [None, reason, None]


@pytest.mark.parametrize("reason", REASONS)
def test_a_later_parent_never_seen_is_a_placeholder_not_a_verified_parent(reason):
    graph = applied(event("job", unresolved=reason), event("job", "file_access", parent="top", second=1))
    assert graph.get(JOB).parent_process_instance_id == TOP and graph.get(TOP).placeholder
    assert graph.get(JOB).parent_unresolved == reason and graph.get(TOP).parent_unresolved is None


# ------------------------------------------------------------------ documented limits
@pytest.mark.parametrize("reason", REASONS)
def test_removing_the_node_loses_the_reason(reason):
    clock = [datetime(2026, 11, 15, 10, tzinfo=timezone.utc)]
    graph = ProcessGraph(retention_seconds=1, auto_gc_interval=0, clock=lambda: clock[0])
    applied(event("job", unresolved=reason), event("job", "process_exit", second=1), graph=graph)
    clock[0] += timedelta(hours=1)
    assert graph.gc() == 1 and graph.get(JOB) is None
    graph.apply(event("job", "file_access", second=2))                       # the same id again: a fresh node
    assert graph.get(JOB).parent_unresolved is None
