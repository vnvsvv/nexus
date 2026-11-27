"""Explicitly unresolved Linux ancestry on a trustworthy process (task A3a, review of the engine for A4).

The Linux adapter can report a native, observed ``process_start`` with ``attributes.parent_unresolved`` set and no
parent id. The engine's root flags do not report that, so the incident builder (A4) has to read the attribute; the
requirement is in ``endpoint-core/README.md``. The events here are built to that shape: the adapter itself is Linux only
and is not run by these tests.
"""
from __future__ import annotations

import itertools
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from nexus_contracts import HostEvent, load_schema, validate_against_schema
from nexus_contracts import RuleMatch as ContractRuleMatch
from nexus_endpoint_core import EngineMatch, ProcessGraph, RuleEngine, load_rules
from nexus_endpoint_core.rules import RuleSet

RULES = Path(__file__).resolve().parents[2] / "contracts" / "rules"
LIN = "linux-vm-01"
REASONS = ("sensor_task_walk", "conflicting_sensor_parent")
_ids = itertools.count(1)


@pytest.fixture(scope="module")
def shipped() -> RuleSet:
    return load_rules(RULES, strict=True)


def start(proc: str, *, parent: str | None = None, unresolved: str | None = None, hit: bool = False,
          second: int = 0) -> HostEvent:
    """A real (not procFS) Linux ``process_start`` with a native identity; ``hit`` makes NX-ANY-001 match it."""
    number = next(_ids)
    attributes: dict[str, object] = {"sensor": "tetragon", "sensor_event_id": "process_exec",
                                     "identity_resolution": "native"}
    if unresolved is not None:
        attributes["parent_unresolved"] = unresolved
    if hit:
        attributes["ti_hash_hit"] = True
    body: dict[str, object] = {
        "schema_version": "1.0", "event_id": f"{LIN}:evt-{number:012x}", "endpoint_id": LIN, "os": "linux",
        "event_type": "process_start", "timestamp_utc": f"2026-11-15T10:00:{second:02d}.000Z",
        "process_instance_id": f"{LIN}:{proc}", "pid": 1000 + number, "binary": "/usr/bin/python3",
        "attributes": attributes}
    if parent is not None:
        body["parent_process_instance_id"] = f"{LIN}:{parent}"
    assert validate_against_schema("host_event", body) == []
    return HostEvent.model_validate(body)


def detect(shipped: RuleSet, *events: HostEvent, graph: ProcessGraph | None = None
           ) -> tuple[RuleEngine, ProcessGraph, EngineMatch]:
    """Apply and evaluate each event in order; the last one must produce exactly one NX-ANY-001 match."""
    engine = RuleEngine(shipped, endpoint_id=LIN, strict=True)
    graph = ProcessGraph() if graph is None else graph
    for event in events:
        graph.apply(event)
        result = engine.evaluate(graph, event)
        assert result.disposition == "evaluated"
    (match,) = result.matches
    assert match.rule.id == "NX-ANY-001"
    return engine, graph, match


def reported(match: EngineMatch) -> list[object]:
    return [event.attributes.get("parent_unresolved") for event in match.events.values()]


def root_facts(match: EngineMatch) -> tuple[object, ...]:
    return (match.root_parent_missing, match.root_parent_is_placeholder, match.placeholder_process_ids,
            match.identity_inferred_event_ids)


@pytest.mark.parametrize("reason", REASONS)
def test_a_native_start_with_unresolved_ancestry_matches_and_keeps_the_reason(shipped, reason):
    event = start("job", unresolved=reason, hit=True)
    engine, graph, match = detect(shipped, event)
    process = f"{LIN}:job"
    assert match.root_process_instance_id == process and set(match.process_by_step.values()) == {process}
    assert list(match.events.values()) == [event] and reported(match) == [reason]
    # native identity: neither inferred nor a seeded placeholder
    assert match.identity_inferred_event_ids == () and match.placeholder_process_ids == ()
    assert engine.stats().placeholder_starts_skipped == 0
    node = graph.get(process)
    assert node is not None and node.placeholder is False and node.identity_resolution == "native"
    # the current flags report no gap: they do not prove that the ancestry is complete
    assert (match.root_parent_missing, match.root_parent_is_placeholder) == (False, False)
    # no ancestry is invented: no parent id, no placeholder parent, no ancestor
    assert event.parent_process_instance_id is None and node.parent_process_instance_id is None
    assert graph.ancestors(process) == [] and len(graph) == 1


@pytest.mark.parametrize("reason", REASONS)
def test_the_match_stays_compatible_with_the_frozen_rule_match(shipped, reason):
    event = start("job", unresolved=reason, hit=True)
    _, _, match = detect(shipped, event)
    contract = match.to_contract()
    body = contract.model_dump(mode="json", exclude_none=True)
    assert set(body) == {"rule_id", "rule_version", "matched_at_utc", "bindings"}
    assert body["rule_id"] == "NX-ANY-001" and list(body["bindings"].values()) == [event.event_id]
    schema = load_schema("incident")["properties"]["rule_matches"]["items"]
    assert list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(body)) == []
    assert ContractRuleMatch.model_validate(body) == contract


@pytest.mark.parametrize("reason", REASONS)
def test_only_the_event_attribute_tells_an_unresolved_parent_from_no_marker(shipped, reason):
    # Negative control: the same parentless start without a marker. A4 gets no reason to report, which is
    # not proof of complete ancestry either.
    _, plain_graph, plain = detect(shipped, start("job", hit=True))
    _, marked_graph, marked = detect(shipped, start("job", unresolved=reason, hit=True))
    assert reported(plain) == [None] and reported(marked) == [reason]
    assert "parent_unresolved" not in next(iter(plain.events.values())).attributes
    assert plain.root_process_instance_id == marked.root_process_instance_id == f"{LIN}:job"
    assert root_facts(plain) == root_facts(marked) == (False, False, (), ())
    for graph in (plain_graph, marked_graph):
        assert graph.ancestors(f"{LIN}:job") == [] and len(graph) == 1


@pytest.mark.parametrize("reason", REASONS)
def test_a_suppressed_repeat_keeps_the_reason(shipped, reason):
    first = start("job", unresolved=reason, hit=True)
    engine, graph, _ = detect(shipped, first)
    again = start("job", unresolved=reason, hit=True, second=1)
    graph.apply(again)
    (repeat,) = engine.evaluate(graph, again).suppressed
    assert [event.attributes["parent_unresolved"] for event in repeat.events.values()] == [reason]


@pytest.mark.parametrize("reason", REASONS)
def test_an_unresolved_ancestor_is_visible_only_on_its_own_start_event(shipped, reason):
    # Bound events are not enough: the child matches, the climb ends at the unresolved ancestor, and the marker
    # is on the ancestor's start, which the graph caches but the match does not carry.
    _, graph, match = detect(shipped, start("top", unresolved=reason),
                             start("job", parent="top", hit=True, second=1))
    assert match.root_process_instance_id == f"{LIN}:top"
    assert (match.root_parent_missing, match.root_parent_is_placeholder) == (False, False)
    assert reported(match) == [None]
    root = graph.get(match.root_process_instance_id)
    assert root is not None and root.start_event_id is not None
    assert graph.events[root.start_event_id].attributes["parent_unresolved"] == reason
    assert [node.process_instance_id for node in graph.ancestors(f"{LIN}:job")] == [f"{LIN}:top"]


@pytest.mark.parametrize("reason", REASONS)
def test_an_ancestor_reason_is_lost_when_its_start_event_leaves_the_cache(shipped, reason):
    # Documented limitation: the graph node does not retain the attribute, so A4 must treat completeness as unknown.
    _, graph, match = detect(shipped, start("top", unresolved=reason),
                             start("job", parent="top", hit=True, second=1), graph=ProcessGraph(max_events=1))
    root = graph.get(match.root_process_instance_id)
    assert root is not None and root.process_instance_id == f"{LIN}:top" and root.start_event_id is None
    assert (match.root_parent_missing, match.root_parent_is_placeholder) == (False, False)
    assert reported(match) == [None]
    assert all("parent_unresolved" not in event.attributes for event in graph.events.values())
