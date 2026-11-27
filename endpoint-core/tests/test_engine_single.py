"""Single-rule evaluation and root selection (task A3a step 3). Sequence and threshold rules are not evaluated yet."""
from __future__ import annotations

import itertools
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
import yaml
from nexus_contracts import HostEvent
from nexus_endpoint_core import ProcessGraph, load_rule, load_rules, parse_utc
from nexus_endpoint_core import engine as engine_module
from nexus_endpoint_core.engine import EngineMatch, EngineResult, RuleEngine
from nexus_endpoint_core.rules import Rule, RuleSet

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "contracts" / "rules"
WIN, LIN = "windows-vm-01", "linux-vm-01"
NOW = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
LAB_BIN = "C:\\Lab\\bin\\lab-test.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
_ids = itertools.count(1)


# ------------------------------------------------------------------ builders
@pytest.fixture(scope="module")
def shipped() -> RuleSet:
    return load_rules(RULES, strict=True)


def stamp(offset: float = 0.0) -> str:
    moment = NOW + timedelta(seconds=offset)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def mk(endpoint: str = WIN, os_: str = "windows", etype: str = "process_start", proc: str = "p1", parent: str | None = None,
       t: float = 0.0, binary: str = LAB_BIN, **extra: Any) -> HostEvent:
    body: dict[str, Any] = {
        "event_id": f"{endpoint}:evt-{next(_ids):012x}", "endpoint_id": endpoint, "os": os_, "timestamp_utc": stamp(t),
        "event_type": etype, "process_instance_id": f"{endpoint}:{proc}", "pid": 10, "binary": binary}
    if parent is not None:
        body["parent_process_instance_id"] = f"{endpoint}:{parent}"
    if etype == "file_access":
        body["file"] = {"path": "C:\\Lab\\staging\\report.zip", "operation": "create"}
    if etype == "network_connect":
        body["network"] = {"protocol": "TCP", "src_ip": "10.0.0.1", "src_port": 5, "dst_ip": "10.0.0.2", "dst_port": 80,
                           "direction": "outbound"}
    body.update(extra)
    return HostEvent.model_validate(body)


def feed(engine: RuleEngine, graph: ProcessGraph, event: HostEvent) -> EngineResult:
    """The documented calling contract: graph.apply, then evaluate immediately."""
    graph.apply(event)
    return engine.evaluate(graph, event)


def windows(shipped: RuleSet, **kw: Any) -> tuple[RuleEngine, ProcessGraph]:
    return RuleEngine(shipped, endpoint_id=WIN, **kw), ProcessGraph()


def linux(shipped: RuleSet, **kw: Any) -> tuple[RuleEngine, ProcessGraph]:
    return RuleEngine(shipped, endpoint_id=LIN, **kw), ProcessGraph()


def variant(base: str, mutate, tmp_path: Path) -> Rule:
    data = yaml.safe_load((RULES / f"{base}.yaml").read_text(encoding="utf-8"))
    mutate(data)
    path = tmp_path / f"{base}.yaml"
    path.write_text(yaml.safe_dump(json.loads(json.dumps(data)), sort_keys=False), encoding="utf-8")
    return load_rule(path)


def file_rule(tmp_path: Path, **context: int) -> Rule:
    """NX-WIN-002 turned into a single rule on a file event (so the matching process can be a placeholder)."""
    def mutate(d: dict) -> None:
        d["steps"][0]["event_type"] = "file_access"
        d["steps"][0]["where"] = {"file.path": {"prefix_any": ["C:\\Lab\\staging\\"]}}
        d["context"].update(context)
    return variant("NX-WIN-002", mutate, tmp_path)


class Declared:
    """A test-only backend that declares it bounds matching time (the engine's condition for regex rules)."""

    enforces_time_limit = True

    def __init__(self, result: bool = True, raises: BaseException | None = None) -> None:
        self.result, self.raises, self.calls = result, raises, []

    def search(self, pattern: str, text: str) -> bool:
        self.calls.append((pattern, text))
        if self.raises is not None:
            raise self.raises
        return self.result


class Tripwire:
    def __getattr__(self, name: str):
        raise AssertionError(f"a compiled pattern was used: {name}")


# ------------------------------------------------------------------ NX-WIN-002 and NX-ANY-001
def test_nx_win_002_detects_a_process_started_from_lab_bin(shipped):
    engine, graph = windows(shipped)
    event = mk(proc="lab", binary=LAB_BIN)
    result = feed(engine, graph, event)
    assert result.disposition == "evaluated" and result.suppressed == () and len(result.matches) == 1
    match = result.matches[0]
    assert isinstance(match, EngineMatch) and match.rule.id == "NX-WIN-002"
    assert dict(match.bindings) == {"bin": event.event_id} and match.events["bin"] is event
    assert match.trigger_event_id == event.event_id and match.matched_at == parse_utc(event.timestamp_utc)
    assert dict(match.process_by_step) == {"bin": f"{WIN}:lab"} and match.root_process_instance_id == f"{WIN}:lab"
    assert match.response_target_process_id == f"{WIN}:lab"                       # rule.response.target_step is "bin"
    assert match.placeholder_process_ids == () and match.identity_inferred_event_ids == ()
    assert (match.root_parent_is_placeholder, match.root_parent_missing) == (False, False)
    assert match.counted_process_id is None and match.distinct_count is None
    assert engine.stats().matches_emitted == 1 and engine.arrival_count == 1


def test_a_match_converts_to_the_contract_rule_match(shipped):
    engine, graph = windows(shipped)
    event = mk(proc="lab", t=12.345)
    contract = feed(engine, graph, event).matches[0].to_contract()
    assert contract.model_dump(exclude_none=True) == {
        "rule_id": "NX-WIN-002", "rule_version": "1.0", "matched_at_utc": "2026-11-15T10:00:12.345Z",
        "bindings": {"bin": event.event_id}}


def test_a_detection_is_immutable_and_independent_of_the_callers_objects(shipped):
    engine, graph = windows(shipped)
    event = mk(proc="lab")
    result = feed(engine, graph, event)
    match = result.matches[0]
    with pytest.raises(AttributeError):
        match.root_process_instance_id = "x"
    with pytest.raises(TypeError):
        match.bindings["x"] = "y"
    with pytest.raises(TypeError):
        match.events["x"] = event
    with pytest.raises(AttributeError):
        result.matches = ()
    assert isinstance(result.matches, tuple) and isinstance(result.suppressed, tuple)


@pytest.mark.parametrize("binary", [
    "C:\\Lab\\bin\\lab-test.exe", "c:\\lab\\BIN\\Lab-Test.EXE", "C:/Lab/bin/x.exe", "C:\\LAB\\Bin\\sub\\deep\\x.exe",
])
def test_windows_paths_match_case_insensitively_with_either_slash(shipped, binary):
    engine, graph = windows(shipped)
    assert [m.rule.id for m in feed(engine, graph, mk(binary=binary)).matches] == ["NX-WIN-002"]


@pytest.mark.parametrize("binary", [
    "C:\\Lab\\binary\\x.exe", "C:\\Lab\\scenarios\\bin\\x.exe", "D:\\Lab\\bin\\x.exe", "C:\\Windows\\System32\\cmd.exe",
    "C:\\Lab\\bi\\x.exe", "C:\\Lab\\bin",
])
def test_events_outside_lab_bin_do_not_match(shipped, binary):
    engine, graph = windows(shipped)
    result = feed(engine, graph, mk(binary=binary))
    assert result.matches == () and result.suppressed == () and result.disposition == "evaluated"
    assert engine.stats().matches_emitted == 0 and dict(engine.state_sizes())["suppression_entries"] == 0


def test_other_event_types_and_the_wrong_os_do_not_match(shipped):
    engine, graph = windows(shipped)
    assert feed(engine, graph, mk(proc="a", etype="file_access")).matches == ()
    assert feed(engine, graph, mk(proc="b", etype="network_connect")).matches == ()
    lin, lin_graph = linux(shipped)
    assert feed(lin, lin_graph, mk(endpoint=LIN, os_="linux", binary=LAB_BIN)).matches == ()       # NX-WIN-002 is Windows only
    assert feed(lin, lin_graph, mk(endpoint=LIN, os_="linux", proc="q", binary="/lab/bin/beacon-sim")).matches == ()


@pytest.mark.parametrize("os_, endpoint, binary", [("linux", LIN, "/usr/bin/python3"), ("windows", WIN, CMD)])
def test_nx_any_001_detects_a_threat_intelligence_hash_hit_on_both_systems(shipped, os_, endpoint, binary):
    engine = RuleEngine(shipped, endpoint_id=endpoint)
    graph = ProcessGraph()
    event = mk(endpoint=endpoint, os_=os_, binary=binary, attributes={"ti_hash_hit": True})
    (match,) = feed(engine, graph, event).matches
    assert match.rule.id == "NX-ANY-001" and match.response_target_process_id is None
    assert dict(match.bindings) == {"bin": event.event_id} and match.rule.severity == "critical"
    assert match.to_contract().rule_id == "NX-ANY-001"


@pytest.mark.parametrize("flag", [False, 1, 0, "true", "True", None, [True]])
def test_nx_any_001_needs_the_boolean_true(shipped, flag):
    engine, graph = windows(shipped)
    attributes = {} if flag is None else {"ti_hash_hit": flag}
    assert feed(engine, graph, mk(binary=CMD, attributes=attributes)).matches == ()
    assert feed(engine, graph, mk(binary=CMD, proc="p2")).matches == ()                         # absent


def test_two_rules_can_match_one_event_and_come_out_in_rule_id_order(shipped):
    engine, graph = windows(shipped)
    event = mk(proc="both", binary=LAB_BIN, attributes={"ti_hash_hit": True})
    result = feed(engine, graph, event)
    assert [m.rule.id for m in result.matches] == ["NX-ANY-001", "NX-WIN-002"]
    assert all(m.root_process_instance_id == f"{WIN}:both" for m in result.matches)
    assert [m.response_target_process_id for m in result.matches] == [None, f"{WIN}:both"]
    assert engine.stats().matches_emitted == 2


# ------------------------------------------------------------------ seeded placeholders are not observed starts
@pytest.mark.parametrize("attributes", [{"placeholder": True}, {"identity_resolution": "placeholder"},
                                        {"placeholder": True, "identity_resolution": "placeholder"}])
def test_a_seeded_placeholder_start_never_matches(shipped, attributes):
    engine, graph = windows(shipped)
    seeded = mk(proc="seed", binary=LAB_BIN, attributes={**attributes, "ti_hash_hit": True})      # would satisfy both rules
    result = feed(engine, graph, seeded)
    assert result.matches == () and result.suppressed == () and result.disposition == "evaluated"
    stats = engine.stats()
    assert stats.placeholder_starts_skipped == 2 and stats.matches_emitted == 0
    assert dict(engine.state_sizes())["suppression_entries"] == 0                          # a refused start leaves no suppression state
    real = mk(proc="seed", t=1, binary=LAB_BIN)                                            # the real start of that process arrives later
    assert [m.rule.id for m in feed(engine, graph, real).matches] == ["NX-WIN-002"]


def test_a_seeded_start_that_satisfies_nothing_is_not_counted(shipped):
    engine, graph = windows(shipped)
    feed(engine, graph, mk(proc="seed", binary=CMD, attributes={"placeholder": True}))
    assert engine.stats().placeholder_starts_skipped == 0


def test_a_placeholder_process_may_still_produce_an_observed_non_start_event(shipped, tmp_path):
    engine, graph = RuleEngine([file_rule(tmp_path)], endpoint_id=WIN), ProcessGraph()
    event = mk(proc="filtered", etype="file_access", binary="C:\\Tools\\x.exe")                # its process_start was never logged
    (match,) = feed(engine, graph, event).matches
    assert graph.get(f"{WIN}:filtered").placeholder and match.placeholder_process_ids == (f"{WIN}:filtered",)
    assert match.root_process_instance_id == f"{WIN}:filtered" and match.response_target_process_id == f"{WIN}:filtered"
    assert engine.stats().placeholder_starts_skipped == 0


@pytest.mark.parametrize("resolution, inferred", [("native", False), ("pid_start_time", True), ("unknown", True), (None, False)])
def test_inferred_identity_is_reported_for_the_bound_event(shipped, resolution, inferred):
    engine, graph = windows(shipped)
    attributes = {} if resolution is None else {"identity_resolution": resolution}
    event = mk(proc=f"p-{resolution}", attributes=attributes)
    (match,) = feed(engine, graph, event).matches
    assert match.identity_inferred_event_ids == ((event.event_id,) if inferred else ())


# ------------------------------------------------------------------ root selection
def chain(engine: RuleEngine, graph: ProcessGraph, names: list[str], binaries: dict[str, str] | None = None,
          last_binary: str = LAB_BIN) -> EngineResult:
    """Start names[0], names[1] (child of names[0]), ...; the last one is the lab binary that triggers the rule."""
    result = EngineResult()
    for index, name in enumerate(names):
        binary = last_binary if index == len(names) - 1 else (binaries or {}).get(name, CMD)
        result = feed(engine, graph, mk(proc=name, parent=names[index - 1] if index else None, t=index, binary=binary))
    return result


def test_the_root_is_the_highest_observed_ancestor_within_max_ancestors(shipped):
    engine, graph = windows(shipped)                                              # NX-WIN-002: max_ancestors = 2
    (match,) = chain(engine, graph, ["gg", "g", "p", "child"]).matches
    assert match.root_process_instance_id == f"{WIN}:g"                           # child -> p -> g, then the cap
    assert match.root_parent_is_placeholder is False and match.root_parent_missing is False   # gg is observed: not a gap


def test_the_climb_for_nx_any_001_stops_after_three_generations(shipped):
    engine, graph = windows(shipped)
    for index, name in enumerate(["a", "b", "c", "d", "e"]):
        feed(engine, graph, mk(proc=name, parent=["a", "b", "c", "d", "e"][index - 1] if index else None, t=index, binary=CMD))
    (match,) = feed(engine, graph, mk(proc="f", parent="e", t=9, binary=CMD, attributes={"ti_hash_hit": True})).matches
    assert match.root_process_instance_id == f"{WIN}:c"                           # f -> e -> d -> c: exactly three generations


def test_the_climb_never_crosses_a_system_process(shipped):
    engine, graph = windows(shipped)
    (match,) = chain(engine, graph, ["desktop", "shell", "child"], {"desktop": "C:\\Windows\\EXPLORER.EXE"}).matches
    assert match.root_process_instance_id == f"{WIN}:shell"                       # explorer.exe is a boundary, whatever its case
    assert (match.root_parent_is_placeholder, match.root_parent_missing) == (False, False)      # a boundary is not a gap


@pytest.mark.parametrize("stop_binary", ["C:\\Windows\\System32\\svchost.exe", "C:/Windows/System32/SERVICES.exe",
                                         "C:\\Windows\\System32\\winlogon.exe"])
def test_every_default_windows_boundary_stops_the_climb(shipped, stop_binary):
    engine, graph = windows(shipped)
    (match,) = chain(engine, graph, ["sys", "child"], {"sys": stop_binary}).matches
    assert match.root_process_instance_id == f"{WIN}:child"


def test_the_stop_list_uses_the_file_name_on_linux_too(shipped):
    engine, graph = linux(shipped)
    feed(engine, graph, mk(endpoint=LIN, os_="linux", proc="init", binary="/usr/lib/systemd/systemd", t=0))
    feed(engine, graph, mk(endpoint=LIN, os_="linux", proc="bash", parent="init", binary="/usr/bin/bash", t=1))
    (match,) = feed(engine, graph, mk(endpoint=LIN, os_="linux", proc="job", parent="bash", t=2, binary="/usr/bin/python3",
                                     attributes={"ti_hash_hit": True})).matches
    assert match.root_process_instance_id == f"{LIN}:bash"
    exact = RuleEngine(shipped, endpoint_id=LIN)                                  # a path component is not the file name
    g2 = ProcessGraph()
    feed(exact, g2, mk(endpoint=LIN, os_="linux", proc="init", binary="/opt/systemd/tool", t=0))
    (other,) = feed(exact, g2, mk(endpoint=LIN, os_="linux", proc="job", parent="init", t=1, binary="/usr/bin/python3",
                                  attributes={"ti_hash_hit": True})).matches
    assert other.root_process_instance_id == f"{LIN}:init"


def test_the_stop_list_is_configurable(shipped):
    names = ["desktop", "shell", "child"]
    crossing = RuleEngine(shipped, endpoint_id=WIN, root_stop_binaries=())
    graph = ProcessGraph()
    (match,) = chain(crossing, graph, names, {"desktop": "C:\\Windows\\explorer.exe"}).matches
    assert match.root_process_instance_id == f"{WIN}:desktop"                     # an empty list crosses explorer.exe
    custom = RuleEngine(shipped, endpoint_id=WIN, root_stop_binaries=["cmd.exe"])
    g2 = ProcessGraph()
    (stopped,) = chain(custom, g2, ["top", "mid", "child"]).matches
    assert stopped.root_process_instance_id == f"{WIN}:child"                     # every cmd.exe is now a boundary


def test_a_placeholder_parent_is_not_crossed_and_is_reported(shipped):
    engine, graph = windows(shipped)
    (match,) = feed(engine, graph, mk(proc="child", parent="never-observed", binary=LAB_BIN)).matches
    assert graph.get(f"{WIN}:never-observed").placeholder
    assert match.root_process_instance_id == f"{WIN}:child"
    assert match.root_parent_is_placeholder is True and match.root_parent_missing is False


def test_the_climb_stops_below_a_placeholder_in_the_middle_of_the_chain(shipped):
    engine, graph = windows(shipped)
    feed(engine, graph, mk(proc="mid", parent="unseen", binary=CMD))              # mid is observed, its parent is a placeholder
    (match,) = feed(engine, graph, mk(proc="child", parent="mid", t=1)).matches
    assert match.root_process_instance_id == f"{WIN}:mid" and match.root_parent_is_placeholder is True


def test_a_missing_parent_is_not_crossed_and_is_reported(shipped, tmp_path):
    rule = file_rule(tmp_path, max_ancestors=3)
    engine = RuleEngine([rule], endpoint_id=WIN)
    graph = ProcessGraph(max_nodes=2, auto_gc_interval=0, retention_seconds=10_000)
    feed(engine, graph, mk(proc="parent", binary=CMD, t=0, pid=101))              # distinct PIDs: no process supersedes another
    feed(engine, graph, mk(proc="child", parent="parent", binary=CMD, t=1, pid=102))
    feed(engine, graph, mk(proc="filler", binary=CMD, t=2, pid=103))
    assert graph.gc() == 1 and f"{WIN}:parent" not in graph                      # the parent is evicted; the child keeps its id
    (match,) = feed(engine, graph, mk(proc="child", etype="file_access", t=3, pid=102)).matches
    assert match.root_process_instance_id == f"{WIN}:child"
    assert match.root_parent_missing is True and match.root_parent_is_placeholder is False


def test_an_observed_root_without_a_parent_reports_no_gap(shipped):
    engine, graph = windows(shipped)
    (match,) = feed(engine, graph, mk(proc="alone")).matches
    assert (match.root_parent_is_placeholder, match.root_parent_missing) == (False, False)


def test_a_zero_ancestor_budget_roots_at_the_matching_process(shipped, tmp_path):
    engine, graph = RuleEngine([file_rule(tmp_path, max_ancestors=0)], endpoint_id=WIN), ProcessGraph()
    feed(engine, graph, mk(proc="parent", binary=CMD))
    (match,) = feed(engine, graph, mk(proc="child", parent="parent", etype="file_access", t=1)).matches
    assert match.root_process_instance_id == f"{WIN}:child" and match.root_parent_missing is False


def test_identity_is_the_process_instance_never_the_pid(shipped):
    engine, graph = windows(shipped)
    first = mk(proc="first", pid=4242)
    second = mk(proc="second", pid=4242, t=1)                                     # the same PID reused by another instance
    r1, r2 = feed(engine, graph, first), feed(engine, graph, second)
    assert r1.matches[0].root_process_instance_id == f"{WIN}:first" and r2.matches[0].root_process_instance_id == f"{WIN}:second"
    assert r2.suppressed == ()                                                    # two roots: no suppression across instances


def test_root_selection_never_decides_whether_a_rule_matches(shipped, tmp_path):
    # the same event matches whether its ancestry is complete, placeholder, missing, or a system process
    for parent, binary in (("none", None), ("unseen", None), ("sys", "C:\\Windows\\System32\\svchost.exe"), ("ok", CMD)):
        engine, graph = windows(shipped)
        if binary is not None:
            feed(engine, graph, mk(proc=parent, binary=binary))
        event = mk(proc="child", parent=None if parent == "none" else parent, t=1)
        assert [m.rule.id for m in feed(engine, graph, event).matches] == ["NX-WIN-002"], parent


# ------------------------------------------------------------------ A1 eviction cannot reject an applied event
def test_a1_event_cache_eviction_cannot_make_an_applied_event_not_in_graph(shipped):
    engine = RuleEngine(shipped, endpoint_id=WIN)
    graph = ProcessGraph(max_events=1, max_events_per_node=1)                     # the smallest possible event cache
    dispositions = []
    for index in range(60):
        event = mk(proc=f"p{index % 7}", etype="file_access" if index % 3 else "process_start", t=index, binary=CMD)
        dispositions.append(feed(engine, graph, event).disposition)
    assert "not_in_graph" not in dispositions and len(graph.events) <= 1
    assert engine.stats().events_ignored_not_in_graph == 0


def test_the_engine_never_reads_the_graph_event_cache(shipped):
    engine, graph = windows(shipped)
    event = mk(proc="lab")
    graph.apply(event)
    graph.events.clear()                                                          # everything evicted right after apply
    (match,) = engine.evaluate(graph, event).matches
    assert match.events["bin"] is event and engine.stats().events_ignored_not_in_graph == 0


def test_automatic_graph_gc_runs_before_the_event_so_the_node_survives(shipped):
    engine = RuleEngine(shipped, endpoint_id=WIN)
    graph = ProcessGraph(max_nodes=1, auto_gc_interval=1, retention_seconds=1)    # gc on every apply
    for index in range(80):
        result = feed(engine, graph, mk(proc=f"p{index}", t=index * 10, binary=CMD))
        assert result.disposition == "evaluated", index
    assert engine.stats().events_ignored_not_in_graph == 0


def test_evaluating_late_after_a_gc_is_a_calling_contract_violation_and_is_reported(shipped):
    engine = RuleEngine(shipped, endpoint_id=WIN)
    graph = ProcessGraph(max_nodes=1, auto_gc_interval=0)
    old = mk(proc="old", binary=CMD, t=0)
    graph.apply(old)
    graph.apply(mk(proc="newer", binary=CMD, t=1))
    graph.gc()                                                                    # the caller removed the old node first
    assert engine.evaluate(graph, old).disposition == "not_in_graph"
    assert engine.stats().events_ignored_not_in_graph == 1


# ------------------------------------------------------------------ isolation, determinism, regex
def test_other_endpoints_never_produce_detections_or_state(shipped):
    engine, graph = windows(shipped)
    foreign = feed(engine, graph, mk(endpoint="other-vm", proc="lab"))
    assert foreign.disposition == "foreign" and foreign.matches == () and dict(engine.state_sizes()) == {
        "seen_events": 0, "suppression_entries": 0}
    assert feed(engine, graph, mk(proc="lab")).matches[0].root_process_instance_id == f"{WIN}:lab"


def test_replaying_a_stream_twice_gives_identical_detections(shipped):
    def run() -> tuple[list, Any]:
        engine, graph = windows(shipped)
        out = []
        for index, (proc, parent, flag) in enumerate([("a", None, False), ("b", "a", True), ("c", "a", False), ("d", None, True),
                                                      ("b", "a", True), ("e", "d", False)]):
            event = HostEvent.model_validate({**mk(proc=proc, parent=parent, t=index * 20,
                                                   attributes={"ti_hash_hit": flag}).model_dump(exclude_none=True),
                                              "event_id": f"{WIN}:evt-{index:012x}"})
            result = feed(engine, graph, event)
            out.append((result.disposition, [m.to_contract().model_dump() for m in result.matches],
                        [(s.rule.id, s.root_process_instance_id, dict(s.bindings)) for s in result.suppressed]))
        return out, engine.stats()
    assert run() == run()


def test_regex_rules_stay_disabled_without_an_approved_backend(shipped, tmp_path):
    rule = variant("NX-WIN-002", lambda d: d["steps"][0]["where"].__setitem__("binary", {"regex": r"^C:\\Lab\\bin\\"}), tmp_path)
    engine, graph = RuleEngine([rule], endpoint_id=WIN), ProcessGraph()
    assert [d.rule_id for d in engine.disabled_rules] == ["NX-WIN-002"]
    assert feed(engine, graph, mk()).matches == () and engine.stats().matches_emitted == 0


def test_an_approved_backend_gets_the_raw_text_and_the_compiled_pattern_is_never_touched(shipped, tmp_path):
    rule = variant("NX-WIN-002", lambda d: d["steps"][0]["where"].__setitem__("binary", {"regex": r"^C:\\Lab\\bin\\"}), tmp_path)
    step = rule.steps[0]
    armed = step.where[0].model_copy(update={"compiled": Tripwire()})
    rule = rule.model_copy(update={"steps": (step.model_copy(update={"where": (armed,)}),)})
    yes, no = Declared(True), Declared(False)
    event = mk(proc="lab", binary="C:\\LAB\\Bin\\X.exe")
    (match,) = feed(RuleEngine([rule], endpoint_id=WIN, regex_backend=yes), ProcessGraph(), event).matches
    assert match.rule.id == "NX-WIN-002" and yes.calls == [(r"^C:\\Lab\\bin\\", "C:\\LAB\\Bin\\X.exe")]     # raw text, no folding
    assert feed(RuleEngine([rule], endpoint_id=WIN, regex_backend=no), ProcessGraph(), mk(proc="lab2")).matches == ()


def test_a_backend_defect_propagates_and_the_event_is_not_recorded_as_seen(shipped, tmp_path):
    rule = variant("NX-WIN-002", lambda d: d["steps"][0]["where"].__setitem__("binary", {"regex": r"^C:\\Lab\\bin\\"}), tmp_path)
    broken = Declared(raises=RuntimeError("backend bug"))
    engine, graph = RuleEngine([rule], endpoint_id=WIN, regex_backend=broken), ProcessGraph()
    event = mk(proc="lab")
    graph.apply(event)
    with pytest.raises(RuntimeError, match="backend bug"):
        engine.evaluate(graph, event)
    assert engine.state_sizes()["seen_events"] == 0 and engine.arrival_count == 0
    broken.raises = None                                                          # the defect is fixed: the same event can be retried
    assert len(engine.evaluate(graph, event).matches) == 1


def test_the_engine_module_still_never_runs_the_standard_regex_engine():
    source = Path(engine_module.__file__).read_text(encoding="utf-8")
    assert "import re" not in source and "re.search" not in source and "re" not in vars(engine_module)


def test_sequence_and_threshold_rules_are_not_evaluated_in_this_step(shipped):
    engine, graph = windows(shipped)
    stream = [mk(proc="ps", binary="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", t=0,
                 command_line="powershell.exe -ExecutionPolicy Bypass -File x.ps1"),
              mk(proc="ps", etype="file_access", t=1), mk(proc="ps", etype="network_connect", t=2)]
    assert [feed(engine, graph, e).matches for e in stream] == [(), (), ()]       # NX-WIN-001 / NX-WIN-003 arrive with A3b
    assert engine.stats().events_evaluated == 3


def test_log_output_for_detections_is_quiet(shipped, caplog):
    engine, graph = windows(shipped)
    with caplog.at_level(logging.WARNING, logger="nexus_endpoint_core.engine"):
        feed(engine, graph, mk(proc="lab"))
        feed(engine, graph, mk(proc="lab2", t=1))
    assert not caplog.records                                                     # matches and suppressions are not warnings
