"""Sequence-rule detection (task A3b phase 1) with the shipped rules NX-LIN-001, NX-LIN-003 and NX-WIN-001.

Every test follows the calling contract (``graph.apply`` then ``engine.evaluate``) and checks actual matches and
bindings. Linux and Windows events are synthetic or come from ``contracts/fixtures/rules``; no live sensor is involved,
and passing these tests says nothing about the adapters.
"""
from __future__ import annotations

import itertools
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from nexus_contracts import HostEvent, load_schema
from nexus_contracts import RuleMatch as ContractRuleMatch
from nexus_endpoint_core import (EngineLimits, EngineMatch, EngineResult, ProcessGraph, RuleEngine, SuppressedMatch,
                                 load_rule, load_rules)
from nexus_endpoint_core import engine as engine_module
from nexus_endpoint_core.rules import Rule, RuleSet

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "contracts" / "rules"
FIXTURES = ROOT / "contracts" / "fixtures" / "rules"
LIN, WIN = "linux-vm-01", "windows-vm-01"
NOW = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
PY, BASH, CAT, CURL = "/usr/bin/python3", "/usr/bin/bash", "/usr/bin/cat", "/usr/bin/curl"
CMD = "C:\\Windows\\System32\\cmd.exe"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
BYPASS = "powershell.exe -ExecutionPolicy Bypass -File C:\\Lab\\scenarios\\w1_stage.ps1"
SEQUENCE_COUNTERS = ("sequence_candidates_expired", "sequence_candidates_evicted", "sequence_searches_truncated",
                     "sequence_searches_exhausted", "sequence_candidates_unavailable")
_ids = itertools.count(1)


@pytest.fixture(scope="module")
def shipped() -> RuleSet:
    return load_rules(RULES, strict=True)


# ------------------------------------------------------------------ builders
def stamp(offset: float) -> str:
    moment = NOW + timedelta(seconds=offset)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def ev(endpoint: str, etype: str, proc: str, t: float, parent: str | None = None, binary: str | None = None,
       **extra: Any) -> HostEvent:
    linux = endpoint == LIN
    body: dict[str, Any] = {
        "event_id": f"{endpoint}:evt-{next(_ids):012x}", "endpoint_id": endpoint, "os": "linux" if linux else "windows",
        "timestamp_utc": stamp(t), "event_type": etype, "process_instance_id": f"{endpoint}:{proc}",
        "pid": 100 + sum(map(ord, proc)), "binary": binary or (CURL if linux else PS)}
    if parent is not None:
        body["parent_process_instance_id"] = f"{endpoint}:{parent}"
    if etype == "file_access":
        body["file"] = ({"path": "/lab/protected/confidential.txt", "operation": "read"} if linux
                        else {"path": "C:\\Lab\\staging\\report.zip", "operation": "create"})
    if etype == "network_connect":
        body["network"] = {"protocol": "TCP", "src_ip": "192.168.10.10" if linux else "192.168.20.10", "src_port": 50000,
                           "dst_ip": "192.168.20.10" if linux else "192.168.10.10", "dst_port": 8443,
                           "direction": "outbound"}
    for key, value in extra.items():
        if key in ("file", "network"):
            body[key] = {**body[key], **value}
        else:
            body[key] = value
    return HostEvent.model_validate(body)


def lin(etype: str, proc: str, t: float, parent: str | None = None, binary: str | None = None, **extra: Any) -> HostEvent:
    return ev(LIN, etype, proc, t, parent, binary, **extra)


def win(etype: str, proc: str, t: float, parent: str | None = None, binary: str | None = None, **extra: Any) -> HostEvent:
    return ev(WIN, etype, proc, t, parent, binary, **extra)


def feed(engine: RuleEngine, graph: ProcessGraph, *events: HostEvent) -> list[EngineResult]:
    results = []
    for event in events:
        graph.apply(event)
        results.append(engine.evaluate(graph, event))
    return results


def engine_for(rules: RuleSet | list[Rule], endpoint: str, **kw: Any) -> tuple[RuleEngine, ProcessGraph]:
    return RuleEngine(rules, endpoint_id=endpoint, **kw), ProcessGraph()


def only(rules: RuleSet, *ids: str) -> list[Rule]:
    return [rules.get(i) for i in ids]


def found(results: list[EngineResult], rule_id: str) -> list[EngineMatch]:
    return [m for r in results for m in r.matches if m.rule.id == rule_id]


def repeats(results: list[EngineResult], rule_id: str) -> list[SuppressedMatch]:
    return [m for r in results for m in r.suppressed if m.rule.id == rule_id]


def counters(engine: RuleEngine) -> dict[str, int]:
    stats = engine.stats()
    return {name: getattr(stats, name) for name in SEQUENCE_COUNTERS}


def l1(t0: float = 0.0, **times: float) -> dict[str, HostEvent]:
    """An NX-LIN-001 story: python3 -> bash -> cat (reads the canary), bash -> curl (connects out)."""
    at = {"interp": 0.0, "shell": 1.0, "cat": 2.0, "read": 2.1, "curl": 3.0, "net": 4.0, **times}
    return {"interp": lin("process_start", "py", t0 + at["interp"], parent="login", binary=PY),
            "shell": lin("process_start", "bash", t0 + at["shell"], parent="py", binary=BASH),
            "cat": lin("process_start", "cat", t0 + at["cat"], parent="bash", binary=CAT),
            "read": lin("file_access", "cat", t0 + at["read"], parent="bash", binary=CAT),
            "curl": lin("process_start", "curl", t0 + at["curl"], parent="bash", binary=CURL),
            "net": lin("network_connect", "curl", t0 + at["net"], parent="bash", binary=CURL)}


def variant(base: str, mutate, tmp_path: Path) -> Rule:
    data = yaml.safe_load((RULES / f"{base}.yaml").read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / f"{base}.yaml"
    path.write_text(yaml.safe_dump(json.loads(json.dumps(data)), sort_keys=False), encoding="utf-8")
    return load_rule(path)


def fixture_events(name: str) -> list[HostEvent]:
    text = (FIXTURES / f"{name}.events.jsonl").read_text(encoding="utf-8")
    return [HostEvent.model_validate(json.loads(line)) for line in text.splitlines() if line.strip()]


# ------------------------------------------------------------------ the shipped rule fixtures
@pytest.mark.parametrize("name", ["NX-LIN-001", "NX-WIN-001"])
def test_the_rule_fixture_fires_with_its_expected_bindings_root_and_processes(shipped, name):
    expect = json.loads((FIXTURES / f"{name}.expect.json").read_text(encoding="utf-8"))
    events = fixture_events(name)
    engine, graph = engine_for(shipped, events[0].endpoint_id, strict=True)
    results = feed(engine, graph, *events)
    (match,) = found(results, expect["rule_id"])
    assert dict(match.bindings) == expect["bindings"]
    assert match.root_process_instance_id == expect["root_process_instance_id"]
    # the fixture lists the incident's processes: the bound ones plus the root
    assert set(match.process_by_step.values()) | {match.root_process_instance_id} == set(expect["expected_process_instance_ids"])
    assert match.trigger_event_id == events[-1].event_id == list(match.bindings.values())[-1]
    assert {name: e.event_id for name, e in match.events.items()} == expect["bindings"]
    assert match.matched_at == engine_module.parse_utc(events[-1].timestamp_utc)
    # the root's parent was never observed: reported, not filled in
    assert match.root_parent_is_placeholder is True and match.root_parent_missing is False
    assert match.response_target_process_id is None and match.placeholder_process_ids == ()


def test_the_benign_fixture_does_not_fire(shipped):
    events = fixture_events("NX-LIN-001.benign")
    engine, graph = engine_for(shipped, LIN, strict=True)
    assert found(feed(engine, graph, *events), "NX-LIN-001") == []
    assert engine.stats().events_evaluated == len(events) and engine.state_sizes()["candidate_events"] == 1


def test_the_linux_fixture_fires_when_its_events_arrive_out_of_order(shipped):
    events = fixture_events("NX-LIN-001")                       # deliver the network event before the protected read
    reordered = [events[i] for i in (0, 1, 2, 5, 6, 3, 4)]
    engine, graph = engine_for(shipped, LIN)
    results = feed(engine, graph, *reordered)
    (match,) = found(results, "NX-LIN-001")
    assert match.trigger_event_id == events[3].event_id          # the late read completed the sequence
    assert dict(match.bindings) == json.loads((FIXTURES / "NX-LIN-001.expect.json").read_text())["bindings"]
    assert match.matched_at == engine_module.parse_utc(events[6].timestamp_utc)   # the latest bound event, not the trigger


def test_the_windows_fixture_contract_conversion(shipped):
    engine, graph = engine_for(shipped, WIN)
    (match,) = found(feed(engine, graph, *fixture_events("NX-WIN-001")), "NX-WIN-001")
    body = match.to_contract().model_dump(mode="json", exclude_none=True)
    assert set(body) == {"rule_id", "rule_version", "matched_at_utc", "bindings"}
    assert body["matched_at_utc"] == "2026-11-15T10:30:12.000Z" and body["bindings"] == dict(match.bindings)
    schema = load_schema("incident")["properties"]["rule_matches"]["items"]
    from jsonschema import Draft202012Validator, FormatChecker
    assert list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(body)) == []
    assert ContractRuleMatch.model_validate(body) == match.to_contract()


# ------------------------------------------------------------------ NX-LIN-001
def test_nx_lin_001_binds_each_step_to_its_event(shipped):
    story = l1()
    engine, graph = engine_for(shipped, LIN)
    results = feed(engine, graph, *story.values())
    (match,) = found(results, "NX-LIN-001")
    assert dict(match.bindings) == {k: story[k].event_id for k in ("interp", "shell", "read", "net")}
    assert dict(match.process_by_step) == {"interp": f"{LIN}:py", "shell": f"{LIN}:bash", "read": f"{LIN}:cat",
                                           "net": f"{LIN}:curl"}
    assert match.root_process_instance_id == f"{LIN}:py" and match.identity_inferred_event_ids == ()
    assert [len(r.matches) for r in results] == [0, 0, 0, 0, 0, 1]          # only the last step completes it


@pytest.mark.parametrize("missing", ["interp", "shell", "read", "net"])
def test_nx_lin_001_needs_every_step(shipped, missing):
    story = l1()
    if missing == "interp":                                  # bash's parent exists but is not an interpreter start
        story["interp"] = lin("process_start", "py", 0, parent="login", binary="/usr/bin/env")
    elif missing == "shell":
        story["shell"] = lin("process_start", "bash", 1, parent="py", binary="/usr/bin/ls")
    else:
        del story[missing]
    engine, graph = engine_for(shipped, LIN)
    assert found(feed(engine, graph, *story.values()), "NX-LIN-001") == []


def test_nx_lin_001_wrong_lineage_does_not_match(shipped):
    story = l1()
    story["shell"] = lin("process_start", "bash", 1, parent="other", binary=BASH)   # bash is not under python3
    engine, graph = engine_for(shipped, LIN)
    assert found(feed(engine, graph, *story.values()), "NX-LIN-001") == []


@pytest.mark.parametrize("hops, fires", [(1, True), (2, True), (3, False)])
def test_nx_lin_001_shell_depth_under_the_interpreter(shipped, hops, fires):
    chain = [lin("process_start", "py", 0, parent="login", binary=PY)]
    parent = "py"
    for n in range(hops - 1):
        chain.append(lin("process_start", f"mid{n}", 0.5, parent=parent, binary="/usr/bin/env"))
        parent = f"mid{n}"
    chain += [lin("process_start", "bash", 1, parent=parent, binary=BASH),
              lin("file_access", "bash", 2, parent=parent, binary=BASH),          # include_self: bash reads it itself
              lin("network_connect", "bash", 3, parent=parent, binary=BASH)]
    engine, graph = engine_for(shipped, LIN)
    assert bool(found(feed(engine, graph, *chain), "NX-LIN-001")) is fires


def test_nx_lin_001_a_read_outside_the_shells_lineage_does_not_count(shipped):
    story = l1()
    story["cat"] = lin("process_start", "cat", 2, parent="py", binary=CAT)        # a sibling of bash, not its child
    story["read"] = lin("file_access", "cat", 2.1, parent="py", binary=CAT)
    engine, graph = engine_for(shipped, LIN)
    assert found(feed(engine, graph, *story.values()), "NX-LIN-001") == []


def test_nx_lin_001_wrong_order_does_not_match(shipped):
    story = l1(read=0.5)                                      # the read is stamped before the shell started
    engine, graph = engine_for(shipped, LIN)
    assert found(feed(engine, graph, *story.values()), "NX-LIN-001") == []


@pytest.mark.parametrize("net_at, fires", [(60.0, True), (60.001, False)])
def test_nx_lin_001_window_boundary_is_inclusive(shipped, net_at, fires):
    engine, graph = engine_for(shipped, LIN)
    assert bool(found(feed(engine, graph, *l1(net=net_at, curl=59.0).values()), "NX-LIN-001")) is fires


def test_the_window_spans_all_bound_events_not_only_the_distance_to_the_trigger(shipped):
    story = l1(read=30.0, net=61.0, curl=60.5)                 # read is within 60 s of both ends, the ends are 61 s apart
    order = [story[k] for k in ("interp", "shell", "cat", "curl", "net", "read")]   # the read arrives last
    engine, graph = engine_for(shipped, LIN)
    assert found(feed(engine, graph, *order), "NX-LIN-001") == []


def test_the_root_climb_starts_at_the_earliest_bound_process(shipped):
    engine, graph = engine_for(shipped, LIN)               # observed, ordinary ancestors above the interpreter
    feed(engine, graph, lin("process_start", "sess", -2, parent="login", binary="/usr/bin/tmux"),
         lin("process_start", "term", -1, parent="sess", binary="/usr/bin/xterm"))
    story = l1()
    story["interp"] = lin("process_start", "py", 0, parent="term", binary=PY)
    (match,) = found(feed(engine, graph, *story.values()), "NX-LIN-001")
    # max_ancestors=3 above python3 reaches tmux; counted from curl it would stop at xterm
    assert match.root_process_instance_id == f"{LIN}:sess"


def test_a_loopback_destination_is_not_outbound_exfiltration(shipped):
    story = l1()
    story["net"] = lin("network_connect", "curl", 4, parent="bash", binary=CURL, network={"dst_ip": "127.0.0.1"})
    engine, graph = engine_for(shipped, LIN)
    assert found(feed(engine, graph, *story.values()), "NX-LIN-001") == []


# ------------------------------------------------------------------ ordering, time and arrival
def test_equal_timestamps_are_ordered_by_arrival(shipped):
    engine, graph = engine_for(shipped, LIN)
    story = l1(shell=0.0)                                     # interpreter and shell share a millisecond
    (match,) = found(feed(engine, graph, *story.values()), "NX-LIN-001")
    assert match.bindings["interp"] == story["interp"].event_id

    late_parent, other_graph = engine_for(shipped, LIN)       # same timestamps, the shell is accepted first
    story = l1(shell=0.0)
    order = [story[k] for k in ("shell", "interp", "cat", "read", "curl", "net")]
    assert found(feed(late_parent, other_graph, *order), "NX-LIN-001") == []


def test_event_ids_never_decide_the_order(shipped):
    for prefix in ("evt-000000000001", "evt-ffffffffffff"):  # the same story under ascending and descending ids
        story = l1(shell=0.0)
        story["interp"] = story["interp"].model_copy(update={"event_id": f"{LIN}:{prefix}"})
        engine, graph = engine_for(shipped, LIN)
        assert len(found(feed(engine, graph, *story.values()), "NX-LIN-001")) == 1


def test_an_old_candidate_is_not_dropped_because_newer_timestamps_arrived(shipped):
    engine, graph = engine_for(shipped, LIN)
    story = l1()
    feed(engine, graph, story["interp"], story["shell"])
    feed(engine, graph, lin("process_start", "noise", 500, parent="login", binary="/usr/bin/ls"),
         lin("network_connect", "noise", 501, parent="login", binary="/usr/bin/ls"))  # far later, unrelated
    (match,) = found(feed(engine, graph, story["cat"], story["read"], story["curl"], story["net"]), "NX-LIN-001")
    assert match.bindings["interp"] == story["interp"].event_id
    assert counters(engine) == dict.fromkeys(SEQUENCE_COUNTERS, 0)


def test_competing_candidates_choose_the_nearest_then_the_latest_arrival(shipped):
    engine, graph = engine_for(shipped, LIN)
    story = l1()
    early = lin("file_access", "cat", 2.0, parent="bash", binary=CAT)
    near_a = lin("file_access", "cat", 2.5, parent="bash", binary=CAT)
    near_b = lin("file_access", "cat", 2.5, parent="bash", binary=CAT)
    del story["read"]
    feed(engine, graph, story["interp"], story["shell"], story["cat"], early, near_a, near_b, story["curl"])
    (match,) = found(feed(engine, graph, story["net"]), "NX-LIN-001")
    assert match.bindings["read"] == near_b.event_id            # nearest in time; tie broken by the later arrival

    again, other = engine_for(shipped, LIN)                     # the same input gives the same binding every time
    feed(again, other, story["interp"], story["shell"], story["cat"], early, near_a, near_b, story["curl"])
    assert found(feed(again, other, story["net"]), "NX-LIN-001")[0].bindings == match.bindings


def nested_interpreters(second_is_interpreter: bool = True) -> list[HostEvent]:
    """a -> b -> c -> d -> py1 -> py2 -> bash -> {cat reads, curl connects}. With both py1 and py2 interpreters, the
    interp step has two valid candidates, and max_ancestors=3 gives them different roots (c above py2, b above py1)."""
    chain = [lin("process_start", "a", -5, parent="login", binary="/usr/bin/env")]
    for name, parent, t in (("b", "a", -4), ("c", "b", -3), ("d", "c", -2)):
        chain.append(lin("process_start", name, t, parent=parent, binary="/usr/bin/env"))
    chain += [lin("process_start", "py1", 0, parent="d", binary=PY),
              lin("process_start", "py2", 0.5, parent="py1", binary=PY if second_is_interpreter else "/usr/bin/env"),
              lin("process_start", "bash", 1, parent="py2", binary=BASH),
              lin("process_start", "cat", 2, parent="bash", binary=CAT),
              lin("file_access", "cat", 2.1, parent="bash", binary=CAT),
              lin("process_start", "curl", 3, parent="bash", binary=CURL),
              lin("network_connect", "curl", 4, parent="bash", binary=CURL)]
    return chain


def roots_of(matches: list[EngineMatch] | list[SuppressedMatch]) -> list[str]:
    return [m.root_process_instance_id.split(":", 1)[1] for m in matches]


def test_two_valid_bindings_with_different_roots_are_both_reported(shipped):
    # Before the fix only root c was reported and the equally valid root b was dropped without a counter.
    events = nested_interpreters()
    engine, graph = engine_for(shipped, LIN)
    results = feed(engine, graph, *events)
    by_id = {e.event_id: e for e in events}
    assert [len(r.matches) for r in results[:-1]] == [0] * (len(events) - 1)
    c, b = results[-1].matches                                                  # both from the one connection event
    assert roots_of([c, b]) == ["c", "b"]                                       # discovery order: py2 is nearer
    shared = {k: by_id[c.bindings[k]] for k in ("shell", "read", "net")}
    for match, interp in ((c, "py2"), (b, "py1")):
        assert match.process_by_step == {"interp": f"{LIN}:{interp}", "shell": f"{LIN}:bash", "read": f"{LIN}:cat",
                                         "net": f"{LIN}:curl"}
        assert match.events["interp"].process_instance_id == f"{LIN}:{interp}"        # its own interpreter evidence
        assert {k: match.events[k] for k in ("shell", "read", "net")} == shared
        assert match.trigger_event_id == events[-1].event_id and match.matched_at == c.matched_at
        assert match.placeholder_process_ids == () and match.identity_inferred_event_ids == ()
        assert match.response_target_process_id is None
        assert match.to_contract().bindings == dict(match.bindings)
    assert list(engine._suppression) == [("NX-LIN-001", f"{LIN}:c"), ("NX-LIN-001", f"{LIN}:b")]
    assert engine.stats().matches_emitted == 2
    assert counters(engine) == dict.fromkeys(SEQUENCE_COUNTERS, 0)             # the enumeration was exhaustive


def test_distinct_root_enumeration_is_deterministic(shipped):
    outcomes = []
    for _ in range(3):
        engine, graph = engine_for(shipped, LIN)
        results = feed(engine, graph, *nested_interpreters())
        outcomes.append([(m.root_process_instance_id, dict(m.process_by_step)) for m in found(results, "NX-LIN-001")])
    assert outcomes[0] == outcomes[1] == outcomes[2] and len(outcomes[0]) == 2


def test_the_second_root_is_the_one_found_when_it_is_the_only_binding(shipped):
    engine, graph = engine_for(shipped, LIN)
    (match,) = found(feed(engine, graph, *nested_interpreters(second_is_interpreter=False)), "NX-LIN-001")
    assert match.process_by_step["interp"] == f"{LIN}:py1" and match.root_process_instance_id == f"{LIN}:b"


def test_equivalent_bindings_of_one_root_give_one_match_in_an_ordered_rule(shipped):
    engine, graph = engine_for(shipped, LIN)
    story = l1()
    extra = lin("file_access", "cat", 2.5, parent="bash", binary=CAT)       # a second valid read: same root
    results = feed(engine, graph, *[story[k] for k in ("interp", "shell", "cat", "read")], extra, story["curl"], story["net"])
    (match,) = found(results, "NX-LIN-001")
    assert match.bindings["read"] == extra.event_id                         # the preferred (nearest) binding
    assert list(engine._suppression) == [("NX-LIN-001", f"{LIN}:py")] and engine.stats().matches_emitted == 1


def test_equivalent_bindings_of_one_root_give_one_match_in_an_unordered_rule(shipped, tmp_path):
    rule = variant("NX-LIN-001", lambda d: d.__setitem__("ordered", False), tmp_path)
    engine, graph = engine_for([rule], LIN)
    story = l1()
    extra = lin("file_access", "cat", 2.5, parent="bash", binary=CAT)
    results = feed(engine, graph, *[story[k] for k in ("interp", "shell", "cat", "read")], extra, story["curl"], story["net"])
    (match,) = found(results, "NX-LIN-001")
    assert match.bindings["read"] == extra.event_id and engine.stats().matches_emitted == 1
    assert engine.stats().matches_suppressed == 0                           # one registration per root and event


def test_each_root_keeps_its_own_suppression_window(shipped):
    events = nested_interpreters()
    retimed = {"py1": 0, "py2": 5, "bash": 6, "cat": 7, "curl": 8}         # net at 9: both interpreters in the window
    chain = []
    for e in events:
        name = e.process_instance_id.split(":", 1)[1]
        if e.event_type == "process_start" and name in retimed:
            e = e.model_copy(update={"timestamp_utc": stamp(retimed[name])})
        elif e.event_type == "file_access":
            e = e.model_copy(update={"timestamp_utc": stamp(7.1)})
        elif e.event_type == "network_connect":
            e = e.model_copy(update={"timestamp_utc": stamp(9)})
        chain.append(e)
    engine, graph = engine_for(shipped, LIN)
    first = feed(engine, graph, *chain)[-1]
    assert roots_of(list(first.matches)) == ["c", "b"] and first.suppressed == ()   # neither suppresses the other
    both = feed(engine, graph, lin("network_connect", "curl", 30, parent="bash", binary=CURL))[0]
    assert both.matches == () and roots_of(list(both.suppressed)) == ["c", "b"]     # both repeat, each once
    b_entry = engine._suppression[("NX-LIN-001", f"{LIN}:b")]
    only_c = feed(engine, graph, lin("network_connect", "curl", 62, parent="bash", binary=CURL))[0]
    assert only_c.matches == () and roots_of(list(only_c.suppressed)) == ["c"]       # py1 (t=0) left the window
    assert engine._suppression[("NX-LIN-001", f"{LIN}:b")] == b_entry                # root b's window is untouched
    t62 = engine_module._to_ms(NOW) + 62_000
    assert engine._suppression[("NX-LIN-001", f"{LIN}:c")] == (t62, t62 + 120_000)


def test_one_event_can_be_new_for_one_root_and_a_repeat_for_another(shipped):
    events = nested_interpreters()
    py1_start = next(e for e in events if e.process_instance_id == f"{LIN}:py1" and e.event_type == "process_start")
    rest = [e for e in events if e is not py1_start]
    engine, graph = engine_for(shipped, LIN)
    first = feed(engine, graph, *rest)[-1]                                  # py1's start has not arrived: placeholder
    assert roots_of(list(first.matches)) == ["py2"]                         # the climb stops below the placeholder
    late = feed(engine, graph, py1_start)[0]                                # the late start completes interp = py1
    assert roots_of(list(late.matches)) == ["b"] and late.suppressed == ()
    again = feed(engine, graph, lin("network_connect", "curl", 10, parent="bash", binary=CURL))[0]
    assert roots_of(list(again.matches)) == ["c"]                           # py1 is observed now: py2's root is c
    assert roots_of(list(again.suppressed)) == ["b"]                        # b is still in its window


def net_evaluation(shipped: RuleSet, **limits: int) -> tuple[list[str], dict[str, int]]:
    """Feed the nested-interpreter chain and return the roots and counter changes of the final connection event."""
    engine, graph = engine_for(shipped, LIN, limits=EngineLimits(**limits))
    events = nested_interpreters()
    feed(engine, graph, *events[:-1])
    before = counters(engine)
    (result,) = feed(engine, graph, events[-1])
    after = counters(engine)
    return roots_of(found([result], "NX-LIN-001")), {k: after[k] - before[k] for k in after}


def test_a_partial_search_returns_what_it_found_and_reports_incomplete_coverage(shipped):
    # The connection's search examines interp py2, shell, read (root c), then interp py1, shell, read (root b): 6.
    outcomes = {n: net_evaluation(shipped, max_search_nodes=n) for n in range(1, 12)}
    complete = min(n for n, (_, delta) in outcomes.items() if delta["sequence_searches_exhausted"] == 0)
    first_root = min(n for n, (roots, _) in outcomes.items() if roots)
    assert (first_root, complete) == (3, 6)
    for n in range(first_root, complete):                                   # one root found, the budget ran out
        roots, delta = outcomes[n]
        assert roots == ["c"] and delta["sequence_searches_exhausted"] == 1
    roots, delta = outcomes[complete]                                       # ends exactly at its budget: not counted
    assert roots == ["c", "b"] and delta == dict.fromkeys(SEQUENCE_COUNTERS, 0)
    assert outcomes[complete] == net_evaluation(shipped, max_search_nodes=complete)  # deterministic


def test_one_budget_covers_every_anchor_position(shipped, tmp_path):
    # An unordered variant with two network steps: the second connection is an anchor at both positions. Each
    # position examines 4 candidates (interp, shell, read, the other connection), so the evaluation needs 8 in all;
    # with a fresh budget per position, 4 would have been enough.
    def mutate(d: dict) -> None:
        d["ordered"] = False
        d["steps"].append({**d["steps"][3], "step": "net2"})
    rule = variant("NX-LIN-001", mutate, tmp_path)

    def last_event(budget: int) -> tuple[int, int]:
        engine, graph = engine_for([rule], LIN, limits=EngineLimits(max_search_nodes=budget))
        feed(engine, graph, *l1().values())
        before = counters(engine)["sequence_searches_exhausted"]
        (result,) = feed(engine, graph, lin("network_connect", "curl", 5, parent="bash", binary=CURL))
        return len(result.matches), counters(engine)["sequence_searches_exhausted"] - before

    assert last_event(8) == (1, 0)              # the whole evaluation fits exactly: not exhausted
    assert last_event(7) == (1, 1)              # the root was found at the first position, the second ran out: once
    assert last_event(4) == (1, 1)
    assert last_event(3) == (0, 1)


def test_truncation_is_reported_even_when_another_root_matched(shipped):
    narrow = net_evaluation(shipped, max_search_candidates=1, max_candidates_per_step=4, max_total_candidate_events=100)
    assert narrow == (["c"], {**dict.fromkeys(SEQUENCE_COUNTERS, 0), "sequence_searches_truncated": 1})
    wide = net_evaluation(shipped, max_search_candidates=2, max_candidates_per_step=4, max_total_candidate_events=100)
    assert wide == (["c", "b"], dict.fromkeys(SEQUENCE_COUNTERS, 0))


def test_a_failure_while_building_the_second_root_leaves_no_state(shipped, monkeypatch):
    events = nested_interpreters()
    engine, graph = engine_for(shipped, LIN)
    feed(engine, graph, *events[:-1])
    before = snapshot(engine)
    real, calls = engine_module.EngineMatch, []

    def second_fails(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("defect while building root b")
        return real(*args, **kwargs)

    monkeypatch.setattr(engine_module, "EngineMatch", second_fails)
    graph.apply(events[-1])
    with pytest.raises(RuntimeError):
        engine.evaluate(graph, events[-1])
    assert snapshot(engine)[:3] == before[:3]                                 # no candidate, suppression or seen change
    monkeypatch.setattr(engine_module, "EngineMatch", real)
    assert roots_of(list(engine.evaluate(graph, events[-1]).matches)) == ["c", "b"]


def test_the_trigger_is_always_one_of_the_bindings(shipped):
    for events in (list(l1().values()), nested_interpreters(), fixture_events("NX-LIN-001"),
                   [fixture_events("NX-LIN-001")[i] for i in (0, 1, 2, 5, 6, 3, 4)]):
        engine, graph = engine_for(shipped, LIN)
        for result in feed(engine, graph, *events):
            for detection in (*result.matches, *result.suppressed):
                assert detection.trigger_event_id in detection.bindings.values()


def test_one_event_never_fills_two_steps(shipped, tmp_path):
    def mutate(d: dict) -> None:                                # two process_start steps, the second "same" as the first
        d["steps"][1] = {"step": "again", "event_type": "process_start", "where": {"binary": {"endswith_any": ["/python3"]}},
                         "lineage": {"relation": "same", "of": "interp"}}
        del d["steps"][2:]
    rule = variant("NX-LIN-001", mutate, tmp_path)
    engine, graph = engine_for([rule], LIN)
    first = lin("process_start", "py", 0, parent="login", binary=PY)
    assert found(feed(engine, graph, first), "NX-LIN-001") == []
    repeat = lin("process_start", "py", 1, parent="login", binary=PY)   # a second start record of the same process
    (match,) = found(feed(engine, graph, repeat), "NX-LIN-001")
    assert dict(match.bindings) == {"interp": first.event_id, "again": repeat.event_id}


def test_two_stored_steps_never_share_one_event(shipped, tmp_path):
    # Unordered, because in an ordered rule the strict (timestamp, arrival) order already keeps one event to one step.
    def mutate(d: dict) -> None:                                # two start steps, then a connection: the anchor is the net
        d["ordered"] = False
        d["steps"][1] = {"step": "again", "event_type": "process_start", "where": {"binary": {"endswith_any": ["/python3"]}},
                         "lineage": {"relation": "same", "of": "interp"}}
        d["steps"][2] = {**d["steps"][3], "lineage": {"relation": "same", "of": "interp"}}
        del d["steps"][3:]
    rule = variant("NX-LIN-001", mutate, tmp_path)
    engine, graph = engine_for([rule], LIN)
    start = lin("process_start", "py", 0, parent="login", binary=PY)
    net = lin("network_connect", "py", 2, parent="login", binary=PY)
    assert found(feed(engine, graph, start, net), "NX-LIN-001") == []      # one start cannot be both steps
    second = lin("process_start", "py", 1, parent="login", binary=PY)
    engine, graph = engine_for([rule], LIN)
    (match,) = found(feed(engine, graph, start, second, net), "NX-LIN-001")
    # unordered, so the two starts are interchangeable: the step listed first takes the one nearest the anchor
    assert dict(match.bindings) == {"interp": second.event_id, "again": start.event_id, "net": net.event_id}


# ------------------------------------------------------------------ duplicates and suppression
def test_a_redelivered_event_is_a_duplicate_and_adds_no_candidate(shipped):
    engine, graph = engine_for(shipped, LIN)
    story = l1()
    feed(engine, graph, *story.values())
    sizes = dict(engine.state_sizes())
    (again,) = feed(engine, graph, story["net"])
    assert again.disposition == "duplicate" and again.matches == () and again.suppressed == ()
    assert dict(engine.state_sizes()) == sizes


def test_after_the_seen_horizon_a_redelivery_is_a_suppressed_repeat_and_the_store_stays_deduplicated(shipped):
    engine, graph = engine_for(shipped, LIN, limits=EngineLimits(max_seen_events=1))
    story = l1()
    results = feed(engine, graph, *story.values())
    assert len(found(results, "NX-LIN-001")) == 1
    candidates = engine.state_sizes()["candidate_events"]
    changed = story["interp"].model_copy(update={"timestamp_utc": stamp(40)})   # same id, later content
    (again,) = feed(engine, graph, changed)                    # left the horizon long ago
    assert again.disposition == "evaluated" and engine.state_sizes()["candidate_events"] == candidates
    (kept,) = engine._candidates[("NX-LIN-001", 0)].values()
    assert kept.event is story["interp"] and kept.t_ms == engine_module._to_ms(NOW)   # the first arrival wins
    (repeat,) = repeats(feed(engine, graph, story["net"]), "NX-LIN-001")
    assert repeat.trigger_event_id == story["net"].event_id and dict(repeat.bindings) == dict(found(results, "NX-LIN-001")[0].bindings)


def test_a_second_connection_in_the_incident_window_is_suppressed_with_full_evidence(shipped):
    engine, graph = engine_for(shipped, LIN)
    story = l1()
    feed(engine, graph, *story.values())
    second = lin("network_connect", "curl", 30, parent="bash", binary=CURL, network={"dst_port": 9000})
    (repeat,) = repeats(feed(engine, graph, second), "NX-LIN-001")
    assert repeat.root_process_instance_id == f"{LIN}:py" and repeat.trigger_event_id == second.event_id
    assert repeat.bindings["net"] == second.event_id and repeat.events["net"] is second
    assert {k: repeat.bindings[k] for k in ("interp", "shell", "read")} == {k: story[k].event_id for k in ("interp", "shell", "read")}
    assert engine.stats().matches_emitted == 1 and engine.stats().matches_suppressed == 1


def nx_lin_003_pair(proc: str, t: float, parent: str = "shell") -> tuple[HostEvent, HostEvent]:
    return (lin("process_start", proc, t, parent=parent, binary=f"/lab/bin/{proc}"),
            lin("network_connect", proc, t, parent=parent, binary=f"/lab/bin/{proc}"))


def test_a_late_trigger_keeps_the_chronology_and_suppression_uses_matched_at(shipped):
    events = fixture_events("NX-LIN-001")
    engine, graph = engine_for(shipped, LIN)
    (match,) = found(feed(engine, graph, *[events[i] for i in (0, 1, 2, 5, 6, 3, 4)]), "NX-LIN-001")
    bound = [match.events[s] for s in ("interp", "shell", "read", "net")]
    assert [e.timestamp_utc for e in bound] == sorted(e.timestamp_utc for e in bound)   # rule order = event-time order
    assert match.trigger_event_id == events[3].event_id                                   # the late read
    latest_ms = engine_module._to_ms(match.matched_at)
    assert latest_ms == engine_module._to_ms(engine_module.parse_utc(events[6].timestamp_utc))
    assert engine._suppression[("NX-LIN-001", match.root_process_instance_id)] == (latest_ms, latest_ms + 120_000)


@pytest.mark.parametrize("second_at, outcome", [(120.999, "suppressed"), (121.0, "new")])
def test_suppression_boundary_for_a_shared_root(shipped, second_at, outcome):
    engine, graph = engine_for(only(shipped, "NX-LIN-003"), LIN)
    feed(engine, graph, lin("process_start", "shell", 0, parent="login", binary=BASH))
    first = found(feed(engine, graph, *nx_lin_003_pair("beacon1", 1.0)), "NX-LIN-003")
    assert [m.root_process_instance_id for m in first] == [f"{LIN}:shell"]          # the climb reaches bash
    results = feed(engine, graph, *nx_lin_003_pair("beacon2", second_at))
    assert (len(found(results, "NX-LIN-003")), len(repeats(results, "NX-LIN-003"))) == ((0, 1) if outcome == "suppressed" else (1, 0))


# ------------------------------------------------------------------ NX-LIN-003 and response targets
def test_nx_lin_003_fires_for_the_same_process_and_targets_it(shipped):
    engine, graph = engine_for(shipped, LIN)
    start, net = nx_lin_003_pair("beacon", 0, parent="login")
    (match,) = found(feed(engine, graph, start, net), "NX-LIN-003")
    assert dict(match.bindings) == {"bin": start.event_id, "net": net.event_id}
    assert match.response_target_process_id == f"{LIN}:beacon" == match.process_by_step["bin"]


def test_nx_lin_003_a_connection_from_a_child_is_not_the_same_process(shipped):
    engine, graph = engine_for(shipped, LIN)
    start = lin("process_start", "beacon", 0, parent="login", binary="/lab/bin/beacon")
    child_net = lin("network_connect", "child", 1, parent="beacon", binary=CURL)
    assert found(feed(engine, graph, start, child_net), "NX-LIN-003") == []


def test_nx_lin_003_identity_is_the_process_instance_not_the_pid(shipped):
    engine, graph = engine_for(shipped, LIN)
    start = lin("process_start", "beacon", 0, parent="login", binary="/lab/bin/beacon", pid=4242)
    other = lin("network_connect", "reused", 1, parent="login", binary=CURL, pid=4242)    # same PID, another instance
    assert found(feed(engine, graph, start, other), "NX-LIN-003") == []


@pytest.mark.parametrize("dst", ["127.0.0.1", "192.168.10.1"])
def test_nx_lin_003_ignores_loopback_and_the_gateway(shipped, dst):
    engine, graph = engine_for(shipped, LIN)
    start, net = nx_lin_003_pair("beacon", 0, parent="login")
    assert found(feed(engine, graph, start, net.model_copy(update={"network": net.network.model_copy(update={"dst_ip": dst})})),
                 "NX-LIN-003") == []


@pytest.mark.parametrize("gap, fires", [(30.0, True), (30.001, False)])
def test_nx_lin_003_window(shipped, gap, fires):
    engine, graph = engine_for(shipped, LIN)
    start = lin("process_start", "beacon", 0, parent="login", binary="/lab/bin/beacon")
    net = lin("network_connect", "beacon", gap, parent="login", binary="/lab/bin/beacon")
    assert bool(found(feed(engine, graph, start, net), "NX-LIN-003")) is fires


# ------------------------------------------------------------------ NX-WIN-001
def w1(**times: float) -> dict[str, HostEvent]:
    at = {"cmd": 0.0, "ps": 0.5, "stage": 1.2, "net": 2.0, **times}
    return {"cmd": win("process_start", "cmd", at["cmd"], parent="explorer", binary=CMD),
            "ps": win("process_start", "ps", at["ps"], parent="cmd", binary=PS, command_line=BYPASS),
            "stage": win("file_access", "ps", at["stage"], parent="cmd"),
            "net": win("network_connect", "ps", at["net"], parent="cmd")}


def test_nx_win_001_fires_and_roots_at_the_observed_parent(shipped):
    story = w1()
    engine, graph = engine_for(shipped, WIN)
    (match,) = found(feed(engine, graph, *story.values()), "NX-WIN-001")
    assert dict(match.bindings) == {k: story[k].event_id for k in ("ps", "stage", "net")}
    assert match.root_process_instance_id == f"{WIN}:cmd" and match.root_parent_is_placeholder is True


def test_nx_win_001_needs_the_suspicious_flags(shipped):
    story = w1()
    story["ps"] = win("process_start", "ps", 0.5, parent="cmd", binary=PS, command_line="powershell.exe -File x.ps1")
    engine, graph = engine_for(shipped, WIN)
    assert found(feed(engine, graph, *story.values()), "NX-WIN-001") == []


def test_nx_win_001_compares_paths_without_case(shipped):
    story = w1()
    story["ps"] = win("process_start", "ps", 0.5, parent="cmd", binary=PS.upper(), command_line=BYPASS.upper())
    story["stage"] = win("file_access", "ps", 1.2, parent="cmd", file={"path": "c:/lab/STAGING/report.zip"})
    engine, graph = engine_for(shipped, WIN)
    assert len(found(feed(engine, graph, *story.values()), "NX-WIN-001")) == 1


def test_nx_win_001_staging_by_a_grandchild_counts_but_not_by_an_unrelated_process(shipped):
    story = w1()
    story["stage"] = win("file_access", "zip", 1.2, parent="ps", binary="C:\\Lab\\bin\\zip.exe")    # a child of ps
    engine, graph = engine_for(shipped, WIN)
    assert len(found(feed(engine, graph, *story.values()), "NX-WIN-001")) == 1
    story = w1()
    story["stage"] = win("file_access", "other", 1.2, parent="explorer", binary="C:\\Lab\\bin\\zip.exe")
    engine, graph = engine_for(shipped, WIN)
    assert found(feed(engine, graph, *story.values()), "NX-WIN-001") == []


def test_an_unordered_variant_matches_in_any_order_the_ordered_rule_does_not(shipped, tmp_path):
    story = w1(net=1.0, stage=2.0)                              # the connection happens before the staging write
    in_time_order = [story[k] for k in ("cmd", "ps", "net", "stage")]
    engine, graph = engine_for(shipped, WIN)
    assert found(feed(engine, graph, *in_time_order), "NX-WIN-001") == []
    unordered = variant("NX-WIN-001", lambda d: d.__setitem__("ordered", False), tmp_path)
    engine, graph = engine_for([unordered], WIN)
    (match,) = found(feed(engine, graph, *in_time_order), "NX-WIN-001")
    assert match.trigger_event_id == story["stage"].event_id and match.matched_at == engine_module.parse_utc(story["stage"].timestamp_utc)


def test_each_os_keeps_its_own_sequence_state(shipped):
    engine, graph = engine_for(shipped, LIN)
    feed(engine, graph, *l1().values())
    assert {key[0] for key in engine._candidates} == {"NX-LIN-001", "NX-LIN-003"}          # never a Windows rule
    (foreign,) = feed(engine, graph, w1()["ps"])
    assert foreign.disposition == "foreign"
    engine, graph = engine_for(shipped, WIN)
    feed(engine, graph, *w1().values())
    assert {key[0] for key in engine._candidates} == {"NX-WIN-001"}


# ------------------------------------------------------------------ placeholders, inferred identity, missing nodes
def test_a_path_through_a_placeholder_counts_and_is_reported(shipped):
    engine, graph = engine_for(shipped, LIN)
    events = [lin("process_start", "py", 0, parent="login", binary=PY),
              lin("file_access", "mid", 0.5, parent="py", binary="<unknown>",          # start never observed
                  file={"path": "/tmp/x"}),
              lin("process_start", "bash", 1, parent="mid", binary=BASH),
              lin("file_access", "bash", 2, parent="mid", binary=BASH),
              lin("network_connect", "bash", 3, parent="mid", binary=BASH)]
    (match,) = found(feed(engine, graph, *events), "NX-LIN-001")
    assert graph.get(f"{LIN}:mid").placeholder
    assert match.placeholder_process_ids == (f"{LIN}:mid",)                       # on the path, not a bound process


def test_an_inferred_identity_on_a_bound_event_is_reported(shipped):
    story = l1()
    story["read"] = lin("file_access", "cat", 2.1, parent="bash", binary=CAT, attributes={"identity_resolution": "pid_start_time"})
    engine, graph = engine_for(shipped, LIN)
    (match,) = found(feed(engine, graph, *story.values()), "NX-LIN-001")
    assert match.identity_inferred_event_ids == (story["read"].event_id,)


def test_a_seeded_placeholder_start_never_becomes_a_candidate(shipped):
    story = l1()
    story["interp"] = lin("process_start", "py", 0, parent="login", binary=PY, attributes={"placeholder": True})
    engine, graph = engine_for(shipped, LIN)
    assert found(feed(engine, graph, *story.values()), "NX-LIN-001") == []
    assert engine.stats().placeholder_starts_skipped == 1 and ("NX-LIN-001", 0) not in engine._candidates


def test_a_candidate_whose_process_left_the_graph_is_not_bound_and_is_counted(shipped):
    engine = RuleEngine(shipped, endpoint_id=LIN)
    graph = ProcessGraph(max_nodes=3, auto_gc_interval=0)
    story = l1()
    feed(engine, graph, story["interp"], lin("process_exit", "py", 0.5, parent="login", binary=PY),
         story["shell"], story["cat"], story["read"])
    assert graph.gc() == 1 and f"{LIN}:py" not in graph                         # the exited interpreter is evicted
    results = feed(engine, graph, story["curl"], story["net"])
    assert found(results, "NX-LIN-001") == []
    assert counters(engine)["sequence_candidates_unavailable"] == 1


# ------------------------------------------------------------------ resource limits
def test_state_is_bounded_and_reported(shipped):
    limits = EngineLimits(max_candidates_per_step=2, max_search_candidates=2, max_total_candidate_events=100)
    engine, graph = engine_for(shipped, LIN, limits=limits)
    for n in range(6):
        feed(engine, graph, lin("process_start", f"py{n}", n * 100.0, parent="login", binary=PY))
    store = engine._candidates[("NX-LIN-001", 0)]
    assert len(store) == 2 and engine.state_sizes()["candidate_events"] <= engine.state_bounds()["candidate_events"]
    assert counters(engine)["sequence_candidates_expired"] == 4 and counters(engine)["sequence_candidates_evicted"] == 0
    assert [c.event.process_instance_id for c in store.values()] == [f"{LIN}:py4", f"{LIN}:py5"]   # the oldest went


def test_an_in_window_eviction_is_counted_and_warned(shipped, caplog):
    limits = EngineLimits(max_candidates_per_step=2, max_search_candidates=2, max_total_candidate_events=100)
    engine, graph = engine_for(shipped, LIN, limits=limits)
    with caplog.at_level(logging.WARNING, logger="nexus_endpoint_core.engine"):
        for n in range(3):
            feed(engine, graph, lin("process_start", f"py{n}", n, parent="login", binary=PY))
    assert counters(engine)["sequence_candidates_evicted"] == 1
    assert any("candidate store NX-LIN-001 step 0 is full" in r.getMessage() for r in caplog.records)


def test_a_late_event_older_than_everything_in_a_full_store_is_the_one_dropped(shipped):
    limits = EngineLimits(max_candidates_per_step=1, max_search_candidates=1, max_total_candidate_events=100)
    engine, graph = engine_for(only(shipped, "NX-LIN-003"), LIN, limits=limits)
    feed(engine, graph, lin("process_start", "a", 10.0, parent="login", binary="/lab/bin/a"))
    late_start = lin("process_start", "b", 5.0, parent="login", binary="/lab/bin/b")
    feed(engine, graph, late_start)
    (kept,) = engine._candidates[("NX-LIN-003", 0)].values()
    assert kept.event.process_instance_id == f"{LIN}:a" and kept.event.event_id != late_start.event_id
    assert counters(engine)["sequence_candidates_evicted"] == 1           # inside the window: a possible loss


def test_a_truncated_search_is_counted_and_a_wider_one_finds_the_binding(shipped):
    def run(width: int) -> RuleEngine:
        limits = EngineLimits(max_candidates_per_step=4, max_search_candidates=width, max_total_candidate_events=100)
        engine, graph = engine_for(only(shipped, "NX-LIN-003"), LIN, limits=limits)
        feed(engine, graph, lin("process_start", "beacon", 0, parent="login", binary="/lab/bin/beacon"),
             lin("process_start", "decoy", 1, parent="login", binary="/lab/bin/decoy"))    # nearer in time, wrong process
        results = feed(engine, graph, lin("network_connect", "beacon", 1.5, parent="login", binary="/lab/bin/beacon"))
        engine.found = found(results, "NX-LIN-003")
        return engine
    narrow, wide = run(1), run(2)
    assert narrow.found == [] and counters(narrow)["sequence_searches_truncated"] == 1
    assert len(wide.found) == 1 and counters(wide)["sequence_searches_truncated"] == 0


def test_an_exhausted_search_is_counted_and_warned(shipped, caplog):
    engine, graph = engine_for(shipped, LIN, limits=EngineLimits(max_search_nodes=1))
    story = l1()
    with caplog.at_level(logging.WARNING, logger="nexus_endpoint_core.engine"):
        results = feed(engine, graph, *story.values())
    assert found(results, "NX-LIN-001") == [] and counters(engine)["sequence_searches_exhausted"] >= 1
    assert any("max_search_nodes" in r.getMessage() for r in caplog.records)
    roomy, other = engine_for(shipped, LIN)
    assert len(found(feed(roomy, other, *l1().values()), "NX-LIN-001")) == 1


def test_a_genuine_miss_is_not_counted_as_coverage_loss(shipped):
    engine, graph = engine_for(shipped, LIN)
    story = l1()
    del story["read"]
    feed(engine, graph, *story.values())
    assert counters(engine) == dict.fromkeys(SEQUENCE_COUNTERS, 0)


# ------------------------------------------------------------------ exception safety
def snapshot(engine: RuleEngine) -> tuple:
    stats = engine.stats()
    return ({k: list(v.items()) for k, v in engine._candidates.items()}, engine._suppression.copy(),
            engine._seen.copy(), {n: getattr(stats, n) for n in vars(stats)})


def test_a_failing_predicate_leaves_no_partial_sequence_state(shipped, monkeypatch):
    engine, graph = engine_for(shipped, LIN)
    story = l1()
    feed(engine, graph, *[story[k] for k in ("interp", "shell", "cat", "read", "curl")])
    before = snapshot(engine)
    net_where = shipped.get("NX-LIN-001").steps[3].where
    real = engine_module.evaluate_where

    def failing(preds, event, **kw):
        if preds is net_where:
            raise RuntimeError("backend defect")
        return real(preds, event, **kw)

    monkeypatch.setattr(engine_module, "evaluate_where", failing)
    graph.apply(story["net"])
    with pytest.raises(RuntimeError):
        engine.evaluate(graph, story["net"])
    after = snapshot(engine)
    assert after[:3] == before[:3]
    assert {k: v for k, v in after[3].items() if k != "events_received"} == {k: v for k, v in before[3].items() if k != "events_received"}
    monkeypatch.setattr(engine_module, "evaluate_where", real)
    assert len(found([engine.evaluate(graph, story["net"])], "NX-LIN-001")) == 1    # the retry detects it


def test_a_failure_while_building_a_sequence_match_inserts_no_candidate(shipped, monkeypatch):
    engine, graph = engine_for(shipped, LIN)
    story = l1()
    feed(engine, graph, *[story[k] for k in ("interp", "shell", "cat", "read", "curl")])
    before = snapshot(engine)
    real = engine_module.EngineMatch

    def flaky(*args, **kwargs):
        if kwargs.get("rule") is not None and kwargs["rule"].kind == "sequence":
            raise RuntimeError("defect while building")
        return real(*args, **kwargs)

    monkeypatch.setattr(engine_module, "EngineMatch", flaky)
    graph.apply(story["net"])
    with pytest.raises(RuntimeError):
        engine.evaluate(graph, story["net"])
    assert snapshot(engine)[:3] == before[:3]
    monkeypatch.setattr(engine_module, "EngineMatch", real)
    assert len(found([engine.evaluate(graph, story["net"])], "NX-LIN-001")) == 1


# ------------------------------------------------------------------ API compatibility
def test_results_keep_the_a3a_shapes(shipped):
    engine, graph = engine_for(shipped, LIN)
    results = feed(engine, graph, *l1().values())
    assert all(isinstance(r, EngineResult) and isinstance(r.matches, tuple) and isinstance(r.suppressed, tuple) for r in results)
    (match,) = found(results, "NX-LIN-001")
    assert match.counted_process_id is None and match.distinct_count is None
    with pytest.raises(TypeError):
        match.bindings["x"] = "y"                                                 # still immutable
    assert set(engine.state_sizes()) == {"seen_events", "suppression_entries", "candidate_events"}
