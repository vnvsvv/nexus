"""Engine foundation tests (task A3a step 2): construction, startup policy, indexes, limits, safeguards, structures.

Nothing here matches a rule: the foundation's ``evaluate`` only classifies events (its ``disposition``) and counts.
"""
from __future__ import annotations

import copy
import itertools
import json
import logging
import pickle
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from nexus_contracts import HostEvent
from nexus_endpoint_core import ProcessGraph, load_rule, load_rules, parse_utc
from nexus_endpoint_core import engine as engine_module
from nexus_endpoint_core import predicates as predicates_module
from nexus_endpoint_core.engine import (DEFAULT_ROOT_STOP_BINARIES, DisabledRule, EngineLimits, EngineMatch,
                                        EngineResult, EngineStats, IndexEntry, RuleEngine, RuleEngineError,
                                        SuppressedMatch)
from nexus_endpoint_core.rules import Rule, RuleError, RuleSet

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "contracts" / "rules"
FIX = ROOT / "contracts" / "fixtures"
LOG = "nexus_endpoint_core.engine"
NOW = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
_ids = itertools.count(1)
EMPTY_STATE = {"seen_events": 0, "suppression_entries": 0}


# ------------------------------------------------------------------ builders
@pytest.fixture(scope="module")
def shipped() -> RuleSet:
    return load_rules(RULES, strict=True)


def stamp(offset_seconds: float = 0.0) -> str:
    moment = NOW + timedelta(seconds=offset_seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def mk(endpoint: str = "linux-vm-01", os_: str = "linux", etype: str = "process_start", proc: str = "p1",
       t: float = 0.0, event_id: str | None = None, **extra: Any) -> HostEvent:
    body: dict[str, Any] = {
        "event_id": event_id or f"{endpoint}:evt-{next(_ids):012x}", "endpoint_id": endpoint, "os": os_,
        "timestamp_utc": stamp(t), "event_type": etype, "process_instance_id": f"{endpoint}:{proc}", "pid": 10,
        "binary": "/usr/bin/python3" if os_ == "linux" else "C:\\Windows\\System32\\cmd.exe"}
    if etype == "network_connect":
        body["network"] = {"protocol": "TCP", "src_ip": "10.0.0.1", "src_port": 5, "dst_ip": "10.0.0.2", "dst_port": 80,
                           "direction": "outbound"}
    if etype == "file_access":
        body["file"] = {"path": "/f", "operation": "read"}
    if etype == "dns_query":
        body["dns"] = {"query": "a.test"}
    body.update(extra)
    return HostEvent.model_validate(body)


def feed(engine: RuleEngine, graph: ProcessGraph, event: HostEvent) -> EngineResult:
    """The documented calling contract: graph.apply first, then evaluate."""
    graph.apply(event)
    return engine.evaluate(graph, event)


def fixture_events(name: str) -> list[HostEvent]:
    return [HostEvent.model_validate(json.loads(line)) for line in (FIX / name).read_text(encoding="utf-8").splitlines() if line.strip()]


def variant(base: str, mutate, tmp_path: Path) -> Rule:
    """A shipped rule, edited and loaded back through the A2 loader (so it is a genuine validated Rule)."""
    data = yaml.safe_load((RULES / f"{base}.yaml").read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / f"{base}.yaml"
    path.write_text(yaml.safe_dump(json.loads(json.dumps(data)), sort_keys=False), encoding="utf-8")
    return load_rule(path)


def regex_sequence_rule(tmp_path: Path) -> Rule:
    return variant("NX-WIN-001", lambda d: d["steps"][0]["where"].__setitem__("command_line", {"regex": r"-e(nc)?\s"}), tmp_path)


def regex_threshold_rule(tmp_path: Path) -> Rule:
    return variant("NX-LIN-002", lambda d: d["threshold"]["where"].__setitem__("command_line", {"regex": r"scan\d+"}), tmp_path)


class Backend:
    enforces_time_limit = True                      # the declaration the engine requires; real approval is a later review

    def search(self, pattern: str, text: str) -> bool:
        return True


# ------------------------------------------------------------------ construction and indexes
def test_the_engine_starts_with_all_seven_shipped_rules(shipped):
    engine = RuleEngine(shipped, strict=True)
    assert [r.id for r in engine.enabled_rules] == [r.id for r in shipped] and len(engine.enabled_rules) == 7
    assert engine.disabled_rules == () and engine.load_errors == () and engine.strict is True
    assert engine.limits == EngineLimits() and engine.endpoint_id is None and engine.arrival_count == 0
    stats = engine.stats()
    assert (stats.rules_enabled, stats.rules_disabled, stats.rules_rejected_at_load) == (7, 0, 0)
    assert all(getattr(stats, f) == 0 for f in ("events_received", "events_evaluated", "seen_evicted"))
    assert RuleEngine(list(shipped.rules)).enabled_rules == engine.enabled_rules               # an iterable works too


EXPECTED_INDEX = {
    ("linux", "process_start"): [("NX-ANY-001", 0), ("NX-LIN-001", 0), ("NX-LIN-001", 1), ("NX-LIN-003", 0)],
    ("linux", "file_access"): [("NX-LIN-001", 2)],
    ("linux", "network_connect"): [("NX-LIN-001", 3), ("NX-LIN-002", None), ("NX-LIN-003", 1)],
    ("windows", "process_start"): [("NX-ANY-001", 0), ("NX-WIN-001", 0), ("NX-WIN-002", 0)],
    ("windows", "file_access"): [("NX-WIN-001", 1)],
    ("windows", "network_connect"): [("NX-WIN-001", 2), ("NX-WIN-003", None)],
}


def test_the_index_is_exact_and_deterministic(shipped):
    engine = RuleEngine(shipped)
    for key, expected in EXPECTED_INDEX.items():
        assert [(e.rule_id, e.step_index) for e in engine.index_for(*key)] == expected, key
    assert engine.index_for("linux", "dns_query") == () and engine.index_for("linux", "process_exit") == ()
    assert engine.index_for("macos", "process_start") == ()
    entry = engine.index_for("linux", "network_connect")[1]
    assert entry == IndexEntry("NX-LIN-002", "threshold", None, None)
    assert engine.index_for("linux", "process_start")[1] == IndexEntry("NX-LIN-001", "sequence", 0, "interp")
    assert engine.index_for("windows", "process_start")[2].kind == "single"
    assert list(engine._index) == sorted(engine._index)                                       # keys are sorted too
    with pytest.raises(TypeError):
        engine._index[("linux", "x")] = ()                                                     # read-only


def test_rule_order_and_container_do_not_change_the_result(shipped):
    reference = RuleEngine(shipped)
    rules = list(shipped.rules)
    for seed in range(5):
        shuffled = random.Random(seed).sample(rules, len(rules))
        other = RuleEngine(shuffled)
        assert other.enabled_rules == reference.enabled_rules and dict(other._index) == dict(reference._index)
    assert dict(RuleEngine(reversed(rules))._index) == dict(reference._index)


def test_state_bounds_count_items_for_the_enabled_rules(shipped):
    bounds = RuleEngine(shipped).state_bounds()
    assert dict(bounds) == {"candidate_events": 9 * 128, "threshold_keys": 1024, "threshold_value_records": 1024 * 128,
                            "suppression_entries": 4096, "seen_event_ids": 50_000}
    only_single = RuleEngine([shipped.get("NX-WIN-002")]).state_bounds()
    assert only_single["candidate_events"] == 0 and only_single["threshold_keys"] == 0 and only_single["threshold_value_records"] == 0
    assert dict(RuleEngine([]).state_bounds()) == {k: 0 for k in bounds}
    custom = RuleEngine(shipped, limits=EngineLimits(max_candidates_per_step=10, max_search_candidates=5, max_threshold_keys=7,
                                                      max_values_per_key=20)).state_bounds()
    assert custom["candidate_events"] == 90 and custom["threshold_value_records"] == 140


def test_nothing_is_preallocated(shipped):
    engine = RuleEngine(shipped)
    assert dict(engine.state_sizes()) == EMPTY_STATE
    assert len(engine._seen) == 0 and engine.arrival_count == 0


def test_the_default_root_stop_list_is_configurable_and_normalized(shipped):
    assert RuleEngine(shipped).root_stop_binaries == DEFAULT_ROOT_STOP_BINARIES
    assert {"systemd", "explorer.exe", "svchost.exe"} <= DEFAULT_ROOT_STOP_BINARIES
    assert RuleEngine(shipped, root_stop_binaries=[" Foo.EXE ", "bar"]).root_stop_binaries == frozenset({"foo.exe", "bar"})
    assert RuleEngine(shipped, root_stop_binaries=()).root_stop_binaries == frozenset()
    for bad in ([""], ["/usr/bin/systemd"], ["C:\\x.exe"], [5], ["  "]):
        with pytest.raises(ValueError):
            RuleEngine(shipped, root_stop_binaries=bad)


# ------------------------------------------------------------------ startup policy, regex fail closed
def test_a_regex_rule_is_disabled_visibly_without_a_backend(shipped, tmp_path, caplog):
    rule = regex_sequence_rule(tmp_path)
    rules = [rule if r.id == rule.id else r for r in shipped]
    with caplog.at_level(logging.INFO, logger=LOG):
        engine = RuleEngine(rules)
    assert [d.rule_id for d in engine.disabled_rules] == ["NX-WIN-001"] and len(engine.enabled_rules) == 6
    disabled = engine.disabled_rules[0]
    assert disabled.code == "regex_backend_unavailable" and "steps[0].where['command_line']" in disabled.reason
    assert "fail closed" in disabled.reason
    assert not any(e.rule_id == "NX-WIN-001" for key in engine._index for e in engine._index[key])         # not indexed
    assert [e.rule_id for e in engine.index_for("windows", "file_access")] == []
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and "NX-WIN-001" in errors[0].getMessage() and "regex" in errors[0].getMessage()
    assert engine.stats().rules_disabled == 1 and engine.stats().rules_enabled == 6


def test_a_regex_in_a_threshold_where_disables_the_rule_too(shipped, tmp_path):
    rule = regex_threshold_rule(tmp_path)
    engine = RuleEngine([rule if r.id == rule.id else r for r in shipped])
    assert [(d.rule_id, d.code) for d in engine.disabled_rules] == [("NX-LIN-002", "regex_backend_unavailable")]
    assert "threshold.where['command_line']" in engine.disabled_rules[0].reason
    assert all(e.rule_id != "NX-LIN-002" for e in engine.index_for("linux", "network_connect"))


def test_strict_startup_refuses_a_rule_set_that_cannot_be_fully_enabled(shipped, tmp_path, caplog):
    rules = [regex_sequence_rule(tmp_path) if r.id == "NX-WIN-001" else r for r in shipped]
    with caplog.at_level(logging.ERROR, logger=LOG), pytest.raises(RuleEngineError) as caught:
        RuleEngine(rules, strict=True)
    assert [d.rule_id for d in caught.value.disabled] == ["NX-WIN-001"] and caught.value.load_errors == ()
    assert "strict startup refused" in str(caught.value) and "NX-WIN-001" in str(caught.value)
    assert any("strict startup refused" in r.getMessage() for r in caplog.records)


def test_a_safe_backend_enables_regex_rules(shipped, tmp_path):
    rules = [regex_sequence_rule(tmp_path) if r.id == "NX-WIN-001" else r for r in shipped]
    engine = RuleEngine(rules, regex_backend=Backend(), strict=True)
    assert len(engine.enabled_rules) == 7 and engine.disabled_rules == ()
    assert [e.rule_id for e in engine.index_for("windows", "file_access")] == ["NX-WIN-001"]


def test_a_backend_without_search_is_rejected_at_construction(shipped):
    with pytest.raises(TypeError, match="search"):
        RuleEngine(shipped, regex_backend=object())


def test_an_arbitrary_unsafe_callback_is_never_treated_as_an_approved_backend(shipped, tmp_path):
    import re as stdlib_re

    class NaiveBackend:                                     # runs the standard engine with no time limit: exactly what must never be trusted
        def search(self, pattern: str, text: str) -> bool:
            return stdlib_re.search(pattern, text) is not None

    class Pretender(NaiveBackend):
        enforces_time_limit = "yes"                         # only the literal True counts

    class Honest(NaiveBackend):
        enforces_time_limit = False

    rules = [regex_sequence_rule(tmp_path) if r.id == "NX-WIN-001" else r for r in shipped]
    for backend in (NaiveBackend(), Pretender(), Honest(), lambda pattern, text: True):
        with pytest.raises(TypeError, match="enforces_time_limit|search"):
            RuleEngine(rules, regex_backend=backend)
    engine = RuleEngine(rules)                              # and the default stays fail closed
    assert [d.rule_id for d in engine.disabled_rules] == ["NX-WIN-001"]


def test_loader_rejections_are_reported_and_fatal_in_strict_mode(shipped, tmp_path, caplog):
    rejected = RuleError(tmp_path / "NX-WIN-009.yaml", ["severity: bad"])
    ruleset = RuleSet(shipped.rules, (rejected,))
    with caplog.at_level(logging.ERROR, logger=LOG):
        engine = RuleEngine(ruleset)
    assert engine.load_errors == (rejected,) and engine.stats().rules_rejected_at_load == 1 and len(engine.enabled_rules) == 7
    assert any("NX-WIN-009.yaml" in r.getMessage() for r in caplog.records if r.levelno == logging.ERROR)
    with pytest.raises(RuleEngineError, match="NX-WIN-009.yaml") as caught:
        RuleEngine(ruleset, strict=True)
    assert caught.value.load_errors == (rejected,)


def test_an_empty_rule_set_warns_and_is_fatal_in_strict_mode(caplog):
    with caplog.at_level(logging.WARNING, logger=LOG):
        engine = RuleEngine([])
    assert engine.enabled_rules == () and any("no enabled rules" in r.getMessage() for r in caplog.records)
    with pytest.raises(RuleEngineError, match="no rules were given"):
        RuleEngine([], strict=True)


def test_a_threshold_that_could_never_fire_is_disabled(shipped):
    engine = RuleEngine(shipped, limits=EngineLimits(max_values_per_key=10))
    assert sorted((d.rule_id, d.code) for d in engine.disabled_rules) == [
        ("NX-LIN-002", "min_distinct_exceeds_limit"), ("NX-WIN-003", "min_distinct_exceeds_limit")]
    assert "min_distinct 15 exceeds max_values_per_key 10" in engine.disabled_rules[0].reason
    assert RuleEngine(shipped, limits=EngineLimits(max_values_per_key=15)).disabled_rules == ()                 # the boundary is allowed
    with pytest.raises(RuleEngineError):
        RuleEngine(shipped, limits=EngineLimits(max_values_per_key=10), strict=True)


def test_several_reasons_are_all_reported_with_the_first_as_the_code(shipped, tmp_path):
    rule = variant("NX-LIN-002", lambda d: d["threshold"]["where"].__setitem__("command_line", {"regex": "x"}), tmp_path)
    engine = RuleEngine([rule], limits=EngineLimits(max_values_per_key=10))
    (disabled,) = engine.disabled_rules
    assert disabled.code == "regex_backend_unavailable" and "min_distinct 15" in disabled.reason and "regex" in disabled.reason


def test_too_many_sequence_steps_for_the_candidate_budget_is_a_configuration_error(shipped):
    tight = EngineLimits(max_candidates_per_step=100, max_search_candidates=50, max_total_candidate_events=800)
    for strict in (False, True):
        with pytest.raises(RuleEngineError, match="candidate slots"):
            RuleEngine(shipped, limits=tight, strict=strict)                                    # 9 steps x 100 = 900 > 800
    assert len(RuleEngine(shipped, limits=EngineLimits(max_candidates_per_step=100, max_search_candidates=50,
                                                       max_total_candidate_events=900)).enabled_rules) == 7


def test_bad_constructor_arguments_are_rejected(shipped):
    with pytest.raises(ValueError, match="duplicate rule ids: NX-WIN-002"):
        RuleEngine([shipped.get("NX-WIN-002"), shipped.get("NX-WIN-002")])
    with pytest.raises(TypeError, match="validated Rule objects"):
        RuleEngine([shipped.get("NX-WIN-002"), {"id": "NX-WIN-003"}])
    with pytest.raises(TypeError, match="EngineLimits"):
        RuleEngine(shipped, limits={"max_seen_events": 5})
    with pytest.raises(TypeError, match="clock"):
        RuleEngine(shipped, clock=5)
    for bad in ("", "Linux-VM", "a b", "a:b", 5):
        with pytest.raises(ValueError, match="endpoint_id"):
            RuleEngine(shipped, endpoint_id=bad)
    assert RuleEngine(shipped, endpoint_id="windows-vm-01").endpoint_id == "windows-vm-01"


# ------------------------------------------------------------------ EngineLimits
@pytest.mark.parametrize("field, value", [
    ("max_candidates_per_step", 0), ("max_candidates_per_step", -1), ("max_candidates_per_step", 10_001),
    ("max_candidates_per_step", "128"), ("max_candidates_per_step", 128.0), ("max_candidates_per_step", True),
    ("max_candidates_per_step", None), ("max_search_candidates", 0), ("max_search_nodes", 0), ("max_search_nodes", 1_000_001),
    ("max_total_candidate_events", 0), ("max_threshold_keys", 0), ("max_threshold_keys", 1_000_001), ("max_values_per_key", 0),
    ("max_values_per_key", 100_001), ("max_threshold_bindings", 0), ("max_threshold_bindings", 201),
    ("max_suppression_entries", 0), ("max_seen_events", 0), ("max_seen_events", 10_000_001),
    ("max_future_skew_seconds", -1), ("max_future_skew_seconds", 86_401), ("max_future_skew_seconds", 1.5),
    ("max_seen_events", True), ("max_suppression_entries", True), ("max_future_skew_seconds", False),   # a bool is not a count
])
def test_invalid_limits_are_rejected_at_construction(field, value):
    with pytest.raises(ValueError, match=field):
        EngineLimits(**{field: value})


def test_limit_relationships_are_enforced():
    with pytest.raises(ValueError, match="max_search_candidates"):
        EngineLimits(max_search_candidates=129)
    with pytest.raises(ValueError, match="max_candidates_per_step"):
        EngineLimits(max_candidates_per_step=100, max_search_candidates=10, max_total_candidate_events=99)
    with pytest.raises(ValueError, match="max_threshold_keys \\* max_values_per_key"):
        EngineLimits(max_threshold_keys=100_000, max_values_per_key=100)
    with pytest.raises(TypeError):
        EngineLimits(bogus=1)
    both = pytest.raises(ValueError)
    with both as caught:
        EngineLimits(max_seen_events=0, max_search_nodes=0)
    assert "max_seen_events" in str(caught.value) and "max_search_nodes" in str(caught.value)       # every problem at once


def test_valid_limits_are_frozen_and_boundaries_are_accepted():
    limits = EngineLimits(max_future_skew_seconds=0, max_threshold_bindings=200, max_candidates_per_step=1, max_search_candidates=1,
                          max_total_candidate_events=1)
    assert limits.max_future_skew_seconds == 0
    with pytest.raises(AttributeError):
        limits.max_seen_events = 5
    assert EngineLimits() == EngineLimits() and hash(EngineLimits()) == hash(EngineLimits())


# ------------------------------------------------------------------ the calling contract and per-event safeguards
def test_an_accepted_event_is_classified_counted_and_produces_no_match(shipped):
    engine, graph = RuleEngine(shipped), ProcessGraph()
    result = feed(engine, graph, mk())
    assert result == EngineResult() and result.disposition == "evaluated" and result.matches == () and result.suppressed == ()
    assert engine.arrival_count == 1 and engine.endpoint_id == "linux-vm-01"
    assert engine.stats().events_received == 1 and engine.stats().events_evaluated == 1


def test_events_nobody_listens_to_are_skipped_untracked_and_counted(shipped):
    engine, graph = RuleEngine(shipped), ProcessGraph()
    for etype in ("dns_query", "process_exit"):
        graph.apply(mk(etype="process_start", proc="p1"))
        result = feed(engine, graph, mk(etype=etype, proc="p1"))
        assert result.disposition == "no_rules"
    assert engine.stats().events_ignored_no_rules == 2 and dict(engine.state_sizes()) == EMPTY_STATE
    assert engine.arrival_count == 0 and engine.endpoint_id is None           # a skipped event never fixes the engine's identity


def test_a_duplicate_event_id_is_ignored_and_does_not_advance_the_arrival_rank(shipped):
    engine, graph = RuleEngine(shipped), ProcessGraph()
    first = mk(event_id="linux-vm-01:evt-aaaaaaaaaaaa")
    assert feed(engine, graph, first).disposition == "evaluated"
    again = mk(event_id="linux-vm-01:evt-aaaaaaaaaaaa", t=5)                  # same id, different content: first arrival wins
    assert feed(engine, graph, again).disposition == "duplicate"
    assert feed(engine, graph, first).disposition == "duplicate"
    assert engine.arrival_count == 1 and engine.stats().events_ignored_duplicate == 2 and engine.state_sizes()["seen_events"] == 1


def test_duplicate_tracking_is_bounded_and_the_eviction_is_counted(shipped):
    engine, graph = RuleEngine(shipped, limits=EngineLimits(max_seen_events=3)), ProcessGraph()
    events = [mk(proc=f"p{i}", t=i) for i in range(4)]
    for e in events:
        assert feed(engine, graph, e).disposition == "evaluated"
    assert engine.state_sizes()["seen_events"] == 3 and engine.stats().seen_evicted == 1
    assert engine.evaluate(graph, events[3]).disposition == "duplicate"        # still remembered
    assert engine.evaluate(graph, events[0]).disposition == "evaluated"        # forgotten: bounded memory means it is processed again
    assert engine.stats().seen_evicted == 2 and engine.state_sizes()["seen_events"] == 3 and engine.arrival_count == 5


def test_an_event_that_was_not_applied_to_the_graph_is_reported(shipped, caplog):
    engine, graph = RuleEngine(shipped), ProcessGraph()
    with caplog.at_level(logging.WARNING, logger=LOG):
        result = engine.evaluate(graph, mk())                                  # graph.apply was skipped
        engine.evaluate(graph, mk(proc="p2"))
    assert result.disposition == "not_in_graph" and engine.stats().events_ignored_not_in_graph == 2
    assert len([r for r in caplog.records if "not_in_graph" in r.getMessage()]) == 1            # rate-limited: first only
    assert engine.arrival_count == 0 and dict(engine.state_sizes()) == EMPTY_STATE
    fresh, other_graph = RuleEngine(shipped), ProcessGraph()
    exit_event = mk(etype="process_exit", proc="never-seen")                    # A1 ignores such an exit; the engine stays quiet
    assert other_graph.apply(exit_event) is None
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger=LOG):
        assert fresh.evaluate(other_graph, exit_event).disposition == "not_in_graph"
    assert fresh.stats().events_ignored_not_in_graph == 1 and not caplog.records


def test_events_of_another_endpoint_or_os_never_reach_the_state(shipped, caplog):
    engine = RuleEngine(shipped, endpoint_id="linux-vm-01")
    graph = ProcessGraph()
    with caplog.at_level(logging.WARNING, logger=LOG):
        foreign = feed(engine, graph, mk(endpoint="other-vm", proc="x"))
    assert foreign.disposition == "foreign" and engine.stats().events_rejected_foreign == 1 and dict(engine.state_sizes()) == EMPTY_STATE
    assert engine.endpoint_id == "linux-vm-01" and any("other-vm" in r.getMessage() for r in caplog.records)
    assert feed(engine, graph, mk(proc="ok")).disposition == "evaluated"
    wrong_os = feed(engine, graph, mk(os_="windows", proc="w"))                 # same endpoint id, other OS
    assert wrong_os.disposition == "foreign" and engine.stats().events_rejected_foreign == 2
    assert engine.state_sizes()["seen_events"] == 1


def test_an_unbound_engine_binds_to_the_first_accepted_event_only(shipped):
    engine, graph = RuleEngine(shipped), ProcessGraph()
    assert feed(engine, graph, mk(endpoint="ep-a", etype="dns_query", proc="a")).disposition == "no_rules"
    assert engine.endpoint_id is None
    assert feed(engine, graph, mk(endpoint="ep-b", proc="b")).disposition == "evaluated" and engine.endpoint_id == "ep-b"
    assert feed(engine, graph, mk(endpoint="ep-a", proc="a2")).disposition == "foreign"
    assert feed(engine, graph, mk(endpoint="ep-b", proc="b2")).disposition == "evaluated"
    assert engine.arrival_count == 2 and engine.state_sizes()["seen_events"] == 2


def test_a_process_id_from_another_endpoint_is_rejected_before_any_state(shipped):
    engine, graph = RuleEngine(shipped), ProcessGraph()
    bad = mk(proc="p1").model_copy(update={"process_instance_id": "windows-vm-01:{abc}"})
    assert feed(engine, graph, bad).disposition == "bad_identity"
    assert engine.stats().events_rejected_bad_identity == 1 and engine.endpoint_id is None and dict(engine.state_sizes()) == EMPTY_STATE
    sneaky = mk(proc="p1").model_copy(update={"process_instance_id": "linux-vm-011:p"})        # a prefix that is not the id
    assert engine.evaluate(graph, sneaky).disposition == "bad_identity"


def test_two_engines_keep_two_endpoints_apart(shipped):
    linux, windows = RuleEngine(shipped, endpoint_id="linux-vm-01"), RuleEngine(shipped, endpoint_id="windows-vm-01")
    g1, g2 = ProcessGraph(), ProcessGraph()
    for event in fixture_events("linux_l1_events.jsonl"):
        feed(linux, g1, event)
        assert windows.evaluate(g1, event).disposition == "foreign"
    for event in fixture_events("windows_w1_events.jsonl"):
        feed(windows, g2, event)
        assert linux.evaluate(g2, event).disposition == "foreign"
    assert linux.stats().events_evaluated == 6 and windows.stats().events_evaluated == 4
    assert linux.stats().events_rejected_foreign == 4 and windows.stats().events_rejected_foreign == 7


# ------------------------------------------------------------------ future timestamps, clocks, replay
def test_a_clock_enables_future_event_protection_with_an_inclusive_boundary(shipped, caplog):
    engine, graph = RuleEngine(shipped, clock=lambda: NOW), ProcessGraph()
    assert feed(engine, graph, mk(proc="past", t=-3600)).disposition == "evaluated"
    assert feed(engine, graph, mk(proc="now", t=0)).disposition == "evaluated"
    assert feed(engine, graph, mk(proc="edge", t=300.0)).disposition == "evaluated"            # exactly the allowed skew
    with caplog.at_level(logging.WARNING, logger=LOG):
        assert feed(engine, graph, mk(proc="late", t=300.001)).disposition == "future"
        assert feed(engine, graph, mk(proc="later", t=86_400)).disposition == "future"
    assert engine.stats().events_ignored_future == 2 and engine.arrival_count == 3
    assert engine.state_sizes()["seen_events"] == 3                                            # ignored events leave no state
    assert len([r for r in caplog.records if "future" in r.getMessage()]) == 1
    assert engine.endpoint_id == "linux-vm-01"


def test_the_skew_limit_and_the_clock_are_honoured(shipped):
    moving = [NOW]
    engine = RuleEngine(shipped, limits=EngineLimits(max_future_skew_seconds=0), clock=lambda: moving[0])
    graph, ahead = ProcessGraph(), mk(proc="p2", t=0.001)
    assert feed(engine, graph, mk(t=0)).disposition == "evaluated"
    assert feed(engine, graph, ahead).disposition == "future"
    moving[0] = NOW + timedelta(seconds=10)                                                    # the clock moves on:
    assert engine.evaluate(graph, ahead).disposition == "evaluated"                            # the event is no longer ahead of it


def test_a_naive_clock_is_a_programming_error(shipped):
    engine, graph = RuleEngine(shipped, clock=lambda: datetime(2026, 11, 15, 10, 0, 0)), ProcessGraph()
    with pytest.raises(ValueError, match="timezone-aware"):
        feed(engine, graph, mk())


def test_without_a_clock_future_timestamps_are_trusted_and_no_wall_time_is_read(shipped, monkeypatch):
    import time
    monkeypatch.setattr(time, "time", lambda: (_ for _ in ()).throw(AssertionError("wall clock read")))
    monkeypatch.setattr(time, "monotonic", lambda: (_ for _ in ()).throw(AssertionError("monotonic clock read")))
    engine, graph = RuleEngine(shipped), ProcessGraph()
    assert feed(engine, graph, mk(t=10_000_000)).disposition == "evaluated"
    assert engine.stats().events_ignored_future == 0


def replay_stream() -> list[HostEvent]:
    events = fixture_events("linux_l1_events.jsonl") + fixture_events("rules/NX-LIN-001.benign.events.jsonl")
    dup = events[0]
    return events + [dup, mk(endpoint="other-vm", proc="z"), mk(etype="dns_query", proc="d"), dup]


def run(stream: list[HostEvent]) -> tuple[list[str], EngineStats, int]:
    engine, graph = RuleEngine(RuleSet(load_rules(RULES).rules, ())), ProcessGraph()
    seen = [feed(engine, graph, event).disposition for event in stream]
    return seen, engine.stats(), engine.arrival_count


def test_replay_is_deterministic_without_a_clock():
    first, second = run(replay_stream()), run(replay_stream())
    assert first == second
    dispositions, stats, arrivals = first
    assert dispositions.count("duplicate") == 2 and dispositions.count("foreign") == 1 and dispositions.count("no_rules") >= 1
    assert arrivals == stats.events_evaluated == dispositions.count("evaluated")
    assert stats.events_received == len(dispositions)
    assert sum(getattr(stats, f) for f in ("events_evaluated", "events_ignored_duplicate", "events_ignored_future",
                                           "events_ignored_not_in_graph", "events_ignored_no_rules", "events_rejected_foreign",
                                           "events_rejected_bad_identity")) == stats.events_received       # every event is accounted for


def test_equal_timestamps_are_ordered_by_arrival_not_by_event_id(shipped):
    engine, graph = RuleEngine(shipped), ProcessGraph()
    ids = ["linux-vm-01:evt-00000000ffff", "linux-vm-01:evt-000000000001", "linux-vm-01:evt-00000000aaaa"]
    ranks = []
    for index, event_id in enumerate(ids):
        feed(engine, graph, mk(proc=f"p{index}", t=0, event_id=event_id))
        ranks.append(engine.arrival_count)
    assert ranks == [1, 2, 3]                                                                  # arrival order, whatever the ids say


def test_evaluate_reads_but_never_mutates_the_graph_or_the_event(shipped):
    engine, graph = RuleEngine(shipped), ProcessGraph()
    events = fixture_events("linux_l1_events.jsonl")
    for event in events:
        graph.apply(event)
    snapshot = (sorted(graph.nodes), list(graph.events), dict(graph.live_by_pid), [e.model_dump() for e in events])
    for event in events:
        engine.evaluate(graph, event)
    assert (sorted(graph.nodes), list(graph.events), dict(graph.live_by_pid), [e.model_dump() for e in events]) == snapshot


def test_no_regex_predicate_is_ever_evaluated(shipped, tmp_path, monkeypatch):
    real = engine_module.evaluate_where
    seen_ops: list[str] = []

    def guarded(predicates, event, **kwargs):
        seen_ops.extend(p.op for p in predicates)
        assert not predicates_module.has_regex(predicates), "a regex predicate reached the evaluator"
        return real(predicates, event, **kwargs)
    monkeypatch.setattr(engine_module, "evaluate_where", guarded)
    rules = [regex_sequence_rule(tmp_path) if r.id == "NX-WIN-001" else r for r in shipped]
    engine = RuleEngine(rules)
    assert [d.rule_id for d in engine.disabled_rules] == ["NX-WIN-001"]
    graph = ProcessGraph()
    for event in fixture_events("windows_w1_events.jsonl") + fixture_events("linux_l1_events.jsonl"):
        feed(engine, graph, event)
    assert seen_ops and "regex" not in seen_ops                                   # single rules did run, and none was a regex
    source = Path(engine_module.__file__).read_text(encoding="utf-8")
    assert "import re" not in source and ".search(" not in source.replace("search(pattern, text)", "")
    assert "re" not in vars(engine_module)


# ------------------------------------------------------------------ data structures
def l1_match_inputs(shipped):
    expected = json.loads((FIX / "incident_linux_l1.json").read_text(encoding="utf-8"))["rule_matches"][0]
    events = {e.event_id: e for e in fixture_events("linux_l1_events.jsonl")}
    return expected, {step: events[eid] for step, eid in expected["bindings"].items()}


def test_an_engine_match_converts_to_the_existing_contract_rule_match(shipped):
    expected, bound = l1_match_inputs(shipped)
    match = EngineMatch(rule=shipped.get("NX-LIN-001"), bindings=expected["bindings"], events=bound,
                        root_process_instance_id="linux-vm-01:exec-py01", matched_at=parse_utc(expected["matched_at_utc"]),
                        trigger_event_id=expected["bindings"]["net"],
                        process_by_step={"interp": "linux-vm-01:exec-py01"}, placeholder_process_ids=["x"],
                        response_target_process_id=None)
    contract = match.to_contract()
    assert contract.model_dump(exclude_none=True) == expected                                  # exactly the fixture's rule match
    assert set(contract.model_dump()) == {"rule_id", "rule_version", "matched_at_utc", "bindings"}      # no invented fields
    assert match.placeholder_process_ids == ("x",) and match.root_parent_is_placeholder is False and match.distinct_count is None


def test_engine_matches_are_immutable_and_validated(shipped):
    expected, bound = l1_match_inputs(shipped)
    args = dict(rule=shipped.get("NX-LIN-001"), bindings=expected["bindings"], events=bound, root_process_instance_id="r",
                matched_at=NOW, trigger_event_id=expected["bindings"]["net"])
    match = EngineMatch(**args)
    with pytest.raises(AttributeError):
        match.trigger_event_id = "x"
    with pytest.raises(TypeError):
        match.bindings["extra"] = "e"
    with pytest.raises(TypeError):
        match.events["extra"] = bound["net"]
    source = dict(expected["bindings"])
    EngineMatch(**{**args, "bindings": source}).bindings                                       # a caller's dict is copied, not shared
    source["net"] = "changed"
    assert match.bindings["net"] == expected["bindings"]["net"]
    for change, message in (({"bindings": {}}, "at least one binding"), ({"trigger_event_id": "nope"}, "one of the bound events"),
                            ({"matched_at": datetime(2026, 11, 15)}, "timezone-aware"), ({"root_process_instance_id": ""}, "root"),
                            ({"bindings": {"net": 5}}, "both strings"),
                            ({"events": {"net": bound["read"]}}, "does not match bindings"),
                            ({"events": {"ghost": bound["net"]}}, "does not match bindings")):
        with pytest.raises(ValueError, match=message):
            EngineMatch(**{**args, **change})
    assert EngineMatch(**{**args, "events": {}}).events == {}                                  # events may be omitted


def test_a_suppressed_match_carries_evidence_but_is_not_a_rule_match(shipped):
    expected, bound = l1_match_inputs(shipped)
    suppressed = SuppressedMatch(rule=shipped.get("NX-LIN-001"), root_process_instance_id="linux-vm-01:exec-py01", matched_at=NOW,
                                 trigger_event_id=expected["bindings"]["net"], bindings=expected["bindings"], events=bound)
    assert not hasattr(suppressed, "to_contract") and suppressed.bindings["net"] == expected["bindings"]["net"]
    with pytest.raises(TypeError):
        suppressed.events["net"] = bound["net"]
    with pytest.raises(ValueError, match="one of the bound events"):
        SuppressedMatch(rule=shipped.get("NX-LIN-001"), root_process_instance_id="r", matched_at=NOW, trigger_event_id="x",
                        bindings=expected["bindings"], events={})


def test_results_and_stats_are_immutable_snapshots(shipped):
    assert EngineResult() == EngineResult(matches=(), suppressed=(), disposition="evaluated")
    with pytest.raises(AttributeError):
        EngineResult().disposition = "duplicate"
    engine, graph = RuleEngine(shipped), ProcessGraph()
    before = engine.stats()
    feed(engine, graph, mk())
    after = engine.stats()
    assert before.events_received == 0 and after.events_received == 1                          # a snapshot does not follow the engine
    with pytest.raises(AttributeError):
        after.events_received = 99
    assert all(isinstance(getattr(after, f), int) for f in EngineStats.__dataclass_fields__)


def test_reports_and_errors_survive_copy_and_pickle(shipped, tmp_path):
    disabled = DisabledRule("NX-WIN-001", "regex_backend_unavailable", "uses regex")
    load_error = RuleError(tmp_path / "NX-WIN-009.yaml", ["severity: bad"])
    error = RuleEngineError("strict startup refused: x", [disabled], [load_error])
    for clone in (copy.deepcopy(error), copy.copy(error), pickle.loads(pickle.dumps(error)), pickle.loads(pickle.dumps(error, protocol=2))):
        assert type(clone) is RuleEngineError and str(clone) == str(error)
        assert clone.disabled == (disabled,) and [(e.source, e.problems) for e in clone.load_errors] == [(load_error.source, load_error.problems)]
    for value in (disabled, EngineLimits(max_seen_events=7), EngineStats(events_received=3, rules_enabled=2),
                  IndexEntry("NX-A-001", "single", 0, "bin")):
        assert pickle.loads(pickle.dumps(value)) == value and copy.deepcopy(value) == value
    with pytest.raises(RuleEngineError) as live:
        RuleEngine([], strict=True)
    assert pickle.loads(pickle.dumps(live.value)).args == live.value.args


def test_the_package_surface_is_unchanged_by_this_step():
    import nexus_endpoint_core as package
    assert not hasattr(package, "RuleEngine")            # exports come with the engine itself, in a later step
    assert set(engine_module.__all__) >= {"RuleEngine", "EngineLimits", "EngineResult", "EngineMatch", "RuleEngineError"}
