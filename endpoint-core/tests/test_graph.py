"""ProcessGraph tests. Fixtures come from contracts/fixtures; synthetic events are validated as HostEvent."""
from __future__ import annotations

import dataclasses
import itertools
import json
import logging
import re
import tracemalloc
from datetime import datetime, timedelta, timezone
from pathlib import Path

import nexus_contracts
import pytest
from nexus_contracts import HostEvent
from nexus_contracts.models import NetworkInfo

from nexus_endpoint_core import ProcessGraph, ProcessNode, format_utc, parse_utc
from nexus_endpoint_core import graph as graph_module

FIX = Path(__file__).resolve().parents[2] / "contracts" / "fixtures"
EP = "ep-01"
_counter = itertools.count(1)
BASE = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
_NET = NetworkInfo(protocol="TCP", src_ip="10.0.0.2", src_port=50000, dst_ip="10.0.0.3", dst_port=8080, direction="outbound")


def at(seconds: float = 0) -> datetime:
    return BASE + timedelta(seconds=seconds)


def iso(seconds: float = 0) -> str:
    return format_utc(at(seconds))


def pid_of(name: str) -> str:
    return f"{EP}:{name}"


def ev(kind: str, proc: str, t: float = 0, parent: str | None = None, pid: int = 100, ppid: int | None = None,
       binary: str = "C:\\Windows\\System32\\x.exe", event_id: str | None = None, **extra) -> HostEvent:
    body = {
        "event_id": event_id or f"{EP}:evt-{next(_counter):012x}", "endpoint_id": EP, "os": "windows",
        "timestamp_utc": iso(t), "event_type": kind, "process_instance_id": pid_of(proc),
        "parent_process_instance_id": pid_of(parent) if parent else None,
        "pid": pid, "ppid": ppid, "binary": binary,
    }
    if kind == "file_access":
        body["file"] = {"path": "C:\\Lab\\staging\\a.zip", "operation": "create"}
    if kind == "network_connect":
        body["network"] = {"protocol": "TCP", "src_ip": "10.0.0.2", "src_port": 50000, "dst_ip": "10.0.0.3",
                           "dst_port": 8080, "direction": "outbound"}
    if kind == "dns_query":
        body["dns"] = {"query": "a.nexus.test"}
    body.update(extra)
    return HostEvent.model_validate({k: v for k, v in body.items() if v is not None})


def fast_ev(kind: str, proc: str, t: float, pid: int, parent: str | None = None) -> HostEvent:
    """Cheap event for volume tests: skips field validation (the graph never reads the sub-objects)."""
    return HostEvent.model_construct(
        event_id=f"{EP}:evt-{next(_counter):012x}", endpoint_id=EP, os="windows", timestamp_utc=iso(t),
        event_type=kind, process_instance_id=pid_of(proc), pid=pid, binary="C:\\x.exe",
        parent_process_instance_id=pid_of(parent) if parent else None,
        network=_NET if kind == "network_connect" else None)


def load(path: Path) -> list[HostEvent]:
    return [HostEvent.model_validate(json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def assert_consistent(g: ProcessGraph) -> None:
    """Invariants: references and the event cache agree; parent/child links agree; the PID index is live."""
    referenced: set[str] = set()
    for node in g.nodes.values():
        for ref in (node.start_event_id, node.exit_event_id, *node.file_events, *node.network_events, *node.dns_events):
            if ref:
                assert ref in g.events, f"dangling reference {ref}"
                referenced.add(ref)
        for child in node.children:
            assert g.nodes[child].parent_process_instance_id == node.process_instance_id
        parent_id = node.parent_process_instance_id
        if parent_id in g.nodes:                      # the reverse edge must exist whenever the parent is present
            assert node.process_instance_id in g.nodes[parent_id].children, f"{node.process_instance_id} missing from its parent's children"
    assert set(g.events) == referenced, "cached event not referenced by any node"
    assert set(g._order) == set(g.events), "arrival ranks and the event cache disagree"
    for parent_id, kids in g._orphans.items():       # the orphan index lists exactly the dangling parent ids
        assert parent_id not in g.nodes and kids
        for kid in kids:
            assert kid in g.nodes and g.nodes[kid].parent_process_instance_id == parent_id
    for node in g.nodes.values():
        parent_id = node.parent_process_instance_id
        if parent_id is not None and parent_id not in g.nodes:
            assert node.process_instance_id in g._orphans.get(parent_id, ()), "dangling parent not indexed"
    for pid, nid in g.live_by_pid.items():
        assert nid in g.nodes and g.nodes[nid].pid == pid and g.nodes[nid].is_live


# ------------------------------------------------------------------ contract separation, node semantics
def test_runtime_node_is_not_the_contract_node():
    assert ProcessNode is not nexus_contracts.ProcessNode
    assert graph_module.ProcessNode.__module__ == "nexus_endpoint_core.graph"
    assert not hasattr(nexus_contracts.ProcessNode, "children")


def test_runtime_node_is_hashable_and_compares_by_identity():
    g = ProcessGraph()
    a = g.apply(ev("process_start", "a", pid=1))
    b = g.apply(ev("process_start", "b", pid=2))
    assert len({a, b, a}) == 2 and {a: 1}[a] == 1
    twin1 = ProcessNode("x", None, 1, "b", at())
    twin2 = ProcessNode("x", None, 1, "b", at())
    assert twin1 != twin2 and twin1 == twin1
    assert "file_events" not in repr(a) and "children" not in repr(a)


def test_constructor_rejects_nonsense_limits():
    for kw in ({"max_nodes": 0}, {"max_events": 0}, {"max_events_per_node": 0}, {"retention_seconds": 0}, {"auto_gc_interval": -1}):
        with pytest.raises(ValueError):
            ProcessGraph(**kw)


# ------------------------------------------------------------------ format_utc / parse_utc
def test_format_utc_is_contract_shaped_and_round_trips():
    pattern = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
    for text in ("2026-11-15T10:30:01.120Z", "2026-11-15T00:00:00.000Z", "2026-12-31T23:59:59.999Z"):
        assert format_utc(parse_utc(text)) == text and pattern.match(text)
    assert format_utc(parse_utc("2026-11-15T12:30:01.120+02:00")) == "2026-11-15T10:30:01.120Z"
    assert format_utc(datetime(2026, 11, 15, 10, 0, 0, 999999, tzinfo=timezone.utc)) == "2026-11-15T10:00:00.999Z"   # truncates
    assert format_utc(datetime(2026, 11, 15, 10, 0, 0)) == "2026-11-15T10:00:00.000Z"                                 # naive = UTC
    assert format_utc(datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone(timedelta(hours=-5)))) == "2026-11-15T15:00:00.000Z"
    assert parse_utc("2026-11-15T10:00:00") == datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)


def test_apply_rejects_a_malformed_timestamp_without_changing_state():
    g = ProcessGraph()
    with pytest.raises(ValueError):
        g.apply(ev("process_start", "z", pid=3, timestamp_utc="not-a-time"))
    assert len(g) == 0 and not g.events and g.latest_event_time is None


# ------------------------------------------------------------------ real fixtures
def test_linux_l1_fixture():
    g = ProcessGraph()
    for e in load(FIX / "linux_l1_events.jsonl"):
        g.apply(e)
    py, bash, cat, curl = (g.nodes[f"linux-vm-01:exec-{n}"] for n in ("py01", "bash01", "cat01", "curl01"))
    systemd = g.nodes["linux-vm-01:exec-systemd-user"]
    assert systemd.placeholder and systemd.binary == "<unknown>" and systemd.identity_resolution == "placeholder"
    assert systemd.start_time_utc is None                       # never invent a start time
    assert not any(n.placeholder for n in (py, bash, cat, curl))
    assert [n.process_instance_id for n in g.ancestors(curl.process_instance_id)] == [
        bash.process_instance_id, py.process_instance_id, systemd.process_instance_id]
    assert {n.process_instance_id for n in g.descendants(py.process_instance_id)} == {
        bash.process_instance_id, cat.process_instance_id, curl.process_instance_id}
    assert cat.end_time_utc == parse_utc("2026-11-15T10:30:02.060Z") and g.live_by_pid.get(4212) is None
    assert g.live_by_pid[4215] == curl.process_instance_id
    assert len(cat.file_events) == 1 and len(curl.network_events) == 1
    assert g.lineage_contains(curl.process_instance_id, py.process_instance_id, max_depth=2)
    assert not g.lineage_contains(curl.process_instance_id, py.process_instance_id, max_depth=1)
    assert_consistent(g)


def test_windows_w1_fixture():
    g = ProcessGraph()
    for e in load(FIX / "windows_w1_events.jsonl"):
        g.apply(e)
    cmd = g.nodes["windows-vm-01:{8f3c1a2e-1111-6a3f-0000-000000000100}"]
    ps = g.nodes["windows-vm-01:{8f3c1a2e-2222-6a3f-0000-000000000101}"]
    parent = g.nodes[cmd.parent_process_instance_id]
    assert parent.placeholder and parent.process_instance_id == "windows-vm-01:{explorer-placeholder}"
    assert parent.pid == 3344                                   # from cmd's ppid; nothing else is known
    assert ps.parent_process_instance_id == cmd.process_instance_id and ps.process_instance_id in cmd.children
    assert len(ps.file_events) == 1 and len(ps.network_events) == 1
    assert g.lineage_contains(ps.process_instance_id, cmd.process_instance_id, 2)
    assert_consistent(g)


@pytest.mark.parametrize("path", sorted((FIX / "rules").glob("*.events.jsonl")), ids=lambda p: p.name)
def test_every_rule_fixture_builds_a_consistent_graph(path):
    """Graph-only checks; no rule is evaluated here."""
    events = load(path)
    g = ProcessGraph()
    for e in events:
        node = g.apply(e)
        assert node is None or node.process_instance_id == e.process_instance_id
    for e in events:
        if e.event_type != "process_exit":
            assert e.process_instance_id in g
    assert_consistent(g)
    expect_files = list(path.parent.glob(path.name.replace(".events.jsonl", ".expect.json")))
    if expect_files:   # reading expected ids only; nothing is executed
        for pid in json.loads(expect_files[0].read_text()).get("expected_process_instance_ids", []):
            assert pid in g


# ------------------------------------------------------------------ placeholders
def test_unknown_parent_becomes_placeholder_with_gap_material():
    g = ProcessGraph()
    child = g.apply(ev("process_start", "c", parent="ghost", pid=200, ppid=7, command_line="c.exe"))
    ghost = g.nodes[pid_of("ghost")]
    assert ghost.placeholder and ghost.binary == "<unknown>" and ghost.pid == 7 and ghost.start_time_utc is None
    assert ghost.children == {pid_of("c")} and child.parent_process_instance_id == pid_of("ghost")
    assert not child.placeholder and child.start_time_utc == parse_utc(iso(0))


def test_placeholder_parent_with_unknown_pid_is_not_indexed():
    g = ProcessGraph()
    g.apply(ev("process_start", "c", parent="ghost", pid=2))          # no ppid supplied
    assert g.nodes[pid_of("ghost")].pid == 0 and 0 not in g.live_by_pid


def test_placeholder_is_upgraded_in_place_when_real_start_arrives():
    g = ProcessGraph()
    g.apply(ev("process_start", "c", parent="p", pid=200, ppid=7))
    g.apply(ev("file_access", "p", t=1, pid=7, binary="C:\\real\\p.exe"))   # event attaches to the placeholder
    assert g.nodes[pid_of("p")].binary == "C:\\real\\p.exe" and g.nodes[pid_of("p")].placeholder
    real = g.apply(ev("process_start", "p", t=2, pid=7, binary="C:\\real\\p.exe", command_line="p.exe",
                      user="LAB\\u", parent="gp", ppid=1, sha256="a" * 64,
                      attributes={"identity_resolution": "native"}))
    assert real is g.nodes[pid_of("p")] and not real.placeholder and real.identity_resolution == "native"
    assert real.command_line == "p.exe" and real.sha256 == "a" * 64
    assert real.children == {pid_of("c")} and len(real.file_events) == 1       # children and events preserved
    assert real.parent_process_instance_id == pid_of("gp") and g.nodes[pid_of("gp")].placeholder
    assert g.lineage_contains(pid_of("c"), pid_of("gp"), 2)
    assert_consistent(g)


def test_upgrade_keeps_known_fields_the_start_event_lacks():
    g = ProcessGraph()
    g.apply(ev("file_access", "p", pid=7, ppid=3, user="LAB-u", binary="C:\\known.exe",
               process_start_time_utc=iso(-5)))
    real = g.apply(ev("process_start", "p", t=1, pid=7, binary="<unknown>"))     # sparse start: no user, ppid, cmdline
    assert not real.placeholder
    assert real.user == "LAB-u" and real.ppid == 3 and real.binary == "C:\\known.exe"
    assert real.start_time_utc == parse_utc(iso(1))                              # the start event's own time wins


def test_event_from_unknown_process_creates_placeholder_not_a_drop():
    g = ProcessGraph()
    node = g.apply(ev("network_connect", "filtered", pid=900, binary="C:\\Windows\\System32\\curl.exe"))
    assert node is not None and node.placeholder and node.identity_resolution == "placeholder"
    assert node.binary == "C:\\Windows\\System32\\curl.exe" and node.parent_process_instance_id is None
    assert node.start_time_utc is None and len(node.network_events) == 1
    assert g.live_by_pid[900] == pid_of("filtered")


def test_two_events_from_one_unknown_process_share_one_placeholder():
    g = ProcessGraph()
    g.apply(ev("network_connect", "filtered", pid=900))
    g.apply(ev("file_access", "filtered", t=1, pid=900))
    node = g.nodes[pid_of("filtered")]
    assert len(g) == 1 and len(node.network_events) == 1 and len(node.file_events) == 1


def test_placeholder_seed_via_attributes_is_not_marked_real():
    g = ProcessGraph()
    seeded = g.apply(ev("process_start", "seed", pid=50, binary="C:\\a.exe", attributes={"identity_resolution": "placeholder"}))
    assert seeded.placeholder and seeded.identity_resolution == "placeholder"
    again = g.apply(ev("process_start", "seed", t=1, pid=50, binary="C:\\a.exe", attributes={"placeholder": True}))
    assert again.placeholder


def test_real_node_is_never_downgraded_by_a_placeholder_event():
    g = ProcessGraph()
    g.apply(ev("process_start", "r", pid=60))
    g.apply(ev("process_start", "r", t=1, pid=60, attributes={"identity_resolution": "placeholder"}))
    assert not g.nodes[pid_of("r")].placeholder


def test_identity_resolution_values_from_sensors_are_opaque():
    g = ProcessGraph()
    unseen = g.apply(ev("file_access", "u", pid=70, attributes={"identity_resolution": "unknown"}))   # Linux adapter value
    assert unseen.placeholder and unseen.identity_resolution == "placeholder"
    g.apply(ev("process_start", "k", pid=71, attributes={"identity_resolution": "native"}))
    known = g.apply(ev("file_access", "k", t=1, pid=71, attributes={"identity_resolution": "pid_start_time"}))
    assert not known.placeholder and known.identity_resolution == "native"     # an event never rewrites the node


# ------------------------------------------------------------------ exits and duplicates
def test_exit_closes_node_and_late_events_still_attach():
    g = ProcessGraph()
    g.apply(ev("process_start", "a", pid=10))
    g.apply(ev("process_exit", "a", t=5, pid=10))
    node = g.apply(ev("network_connect", "a", t=6, pid=10))      # late flow/connect after exit
    assert node.end_time_utc == parse_utc(iso(5)) and 10 not in g.live_by_pid and len(node.network_events) == 1
    assert not node.is_live and node.dead_since == parse_utc(iso(5))


def test_exit_of_unknown_process_is_ignored():
    g = ProcessGraph()
    assert g.apply(ev("process_exit", "never-seen", pid=1)) is None
    assert len(g) == 0 and not g.events


def test_exit_before_start_is_ignored_and_start_leaves_the_node_open():
    """Documented limitation: sensor order is assumed."""
    g = ProcessGraph()
    assert g.apply(ev("process_exit", "a", t=1, pid=1)) is None
    g.apply(ev("process_start", "a", t=2, pid=1))
    assert g.nodes[pid_of("a")].end_time_utc is None and g.live_by_pid == {1: pid_of("a")}


def test_duplicate_exit_keeps_first_end_time():
    g = ProcessGraph()
    g.apply(ev("process_start", "a", pid=10))
    g.apply(ev("process_exit", "a", t=5, pid=10))
    g.apply(ev("process_exit", "a", t=9, pid=10))
    assert g.nodes[pid_of("a")].end_time_utc == parse_utc(iso(5))
    assert_consistent(g)


def test_start_for_an_already_exited_instance_does_not_reopen_it():
    g = ProcessGraph()
    g.apply(ev("process_start", "a", pid=1))
    g.apply(ev("process_exit", "a", t=1, pid=1))
    g.apply(ev("process_start", "a", t=2, pid=1))
    assert g.nodes[pid_of("a")].end_time_utc is not None and not g.live_by_pid


def test_duplicate_event_id_is_idempotent():
    g = ProcessGraph()
    e = ev("process_start", "a", pid=10)
    f = ev("file_access", "a", t=1, pid=10)
    g.apply(e), g.apply(f), g.apply(f), g.apply(e)
    node = g.nodes[pid_of("a")]
    assert len(node.file_events) == 1 and len(g.events) == 2 and node.start_event_id == e.event_id


def test_repeated_start_of_a_known_instance_changes_nothing():
    g = ProcessGraph()
    first = ev("process_start", "a", pid=10, parent="p", ppid=1)
    g.apply(first)
    g.apply(ev("process_start", "a", t=1, pid=10, parent="p", ppid=1))      # a new event id for the same instance
    node = g.nodes[pid_of("a")]
    assert node.start_event_id == first.event_id and len(g.events) == 1 and g.nodes[pid_of("p")].children == {pid_of("a")}
    assert_consistent(g)


# ------------------------------------------------------------------ identity, PID reuse, superseded
def test_pid_reuse_does_not_mix_processes():
    g = ProcessGraph()
    g.apply(ev("process_start", "old", pid=4242, binary="C:\\old.exe"))
    g.apply(ev("process_start", "old-child", t=1, parent="old", pid=4300, ppid=4242))
    g.apply(ev("process_start", "new", t=2, pid=4242, binary="C:\\new.exe"))        # same PID, exit never seen
    assert g.live_by_pid[4242] == pid_of("new")
    assert g.nodes[pid_of("old")].children == {pid_of("old-child")} and not g.nodes[pid_of("new")].children
    # a late event for the old instance attaches to the old instance, not to whoever holds the PID now
    g.apply(ev("file_access", "old", t=3, pid=4242, binary="C:\\old.exe"))
    assert len(g.nodes[pid_of("old")].file_events) == 1 and not g.nodes[pid_of("new")].file_events
    # the old instance's exit must not release the PID that now belongs to the new one
    g.apply(ev("process_exit", "old", t=4, pid=4242))
    assert g.live_by_pid[4242] == pid_of("new") and g.nodes[pid_of("new")].is_live
    assert g.nodes[pid_of("old")].end_time_utc == parse_utc(iso(4))                  # the observed exit, now recorded
    g.apply(ev("process_start", "new-child", t=5, parent="new", pid=4400, ppid=4242))
    assert g.nodes[pid_of("new")].children == {pid_of("new-child")}
    assert [a.process_instance_id for a in g.ancestors(pid_of("new-child"))] == [pid_of("new")]
    assert_consistent(g)


def test_pid_takeover_marks_the_old_node_superseded_without_inventing_an_exit():
    g = ProcessGraph()
    old = g.apply(ev("process_start", "old", t=0, pid=9))
    new = g.apply(ev("process_start", "new", t=5, pid=9))
    assert old.end_time_utc is None and old.exit_event_id is None            # no exit was observed, none is invented
    assert old.superseded_by == pid_of("new") and old.superseded_at_utc == parse_utc(iso(5))
    assert not old.is_live and old.dead_since == parse_utc(iso(5))
    assert new.is_live and new.dead_since is None and new.superseded_by is None
    assert g.live_node_for_pid(9) is new


def test_superseded_node_cannot_be_returned_as_live_for_its_pid():
    g = ProcessGraph()
    g.apply(ev("process_start", "old", t=0, pid=9))
    g.apply(ev("process_start", "new", t=5, pid=9))
    g.apply(ev("process_exit", "new", t=6, pid=9))
    assert g.live_node_for_pid(9) is None and not g.nodes[pid_of("old")].is_live


def test_older_start_arriving_late_does_not_steal_the_pid_and_is_not_live():
    g = ProcessGraph()
    new = g.apply(ev("process_start", "new", t=100, pid=5))
    old = g.apply(ev("process_start", "old", t=1, pid=5))                    # out of order
    assert g.live_by_pid[5] == pid_of("new") and g.live_node_for_pid(5) is new
    assert old.superseded_by == pid_of("new") and old.superseded_at_utc == parse_utc(iso(100)) and not old.is_live
    assert old.end_time_utc is None and new.is_live


def test_placeholder_does_not_steal_a_live_pid():
    g = ProcessGraph()
    g.apply(ev("process_start", "real", pid=55))
    g.apply(ev("file_access", "ghost", t=1, pid=55))             # unknown instance reporting the same PID
    assert g.live_by_pid[55] == pid_of("real")
    assert g.live_node_for_pid(55).process_instance_id == pid_of("real") and g.nodes[pid_of("real")].is_live


def test_real_start_supersedes_an_older_placeholder_holding_the_pid():
    g = ProcessGraph()
    ghost = g.apply(ev("file_access", "ghost", t=0, pid=55))
    g.apply(ev("process_start", "real", t=3, pid=55))
    assert ghost.superseded_by == pid_of("real") and not ghost.is_live and g.live_by_pid[55] == pid_of("real")


def test_two_instances_with_one_pid_are_two_nodes():
    g = ProcessGraph()
    g.apply(ev("process_start", "x1", pid=77))
    g.apply(ev("process_exit", "x1", t=1, pid=77))
    g.apply(ev("process_start", "x2", t=2, pid=77))
    assert {pid_of("x1"), pid_of("x2")} <= set(g.nodes) and g.live_by_pid[77] == pid_of("x2")


def test_self_parent_and_cycles_are_refused():
    g = ProcessGraph()
    g.apply(ev("process_start", "a", parent="a", pid=1))
    assert g.nodes[pid_of("a")].parent_process_instance_id is None
    g.apply(ev("process_start", "b", t=1, parent="a", pid=2))
    g.apply(ev("process_start", "a", t=2, parent="b", pid=1))    # would make a <-> b
    assert g.nodes[pid_of("a")].parent_process_instance_id is None
    assert [n.process_instance_id for n in g.ancestors(pid_of("b"))] == [pid_of("a")]


def test_first_parent_wins_for_a_real_node():
    g = ProcessGraph()
    g.apply(ev("process_start", "c", parent="p1", pid=3))
    g.apply(ev("process_start", "c", t=1, parent="p2", pid=3))
    assert g.nodes[pid_of("c")].parent_process_instance_id == pid_of("p1") and pid_of("p2") not in g


# ------------------------------------------------------------------ traversal
def _chain(g: ProcessGraph, n: int = 5) -> None:
    for i in range(n):
        g.apply(ev("process_start", f"p{i}", t=i * 10, parent=f"p{i-1}" if i else None, pid=100 + i))


def test_ancestors_and_depth_limit():
    g = ProcessGraph()
    _chain(g)
    assert [a.process_instance_id for a in g.ancestors(pid_of("p4"))] == [pid_of(f"p{i}") for i in (3, 2, 1, 0)]
    assert [a.process_instance_id for a in g.ancestors(pid_of("p4"), max_depth=2)] == [pid_of("p3"), pid_of("p2")]
    assert g.ancestors(pid_of("p4"), max_depth=0) == [] and g.ancestors(pid_of("missing")) == []


def test_descendants_depth_and_since():
    g = ProcessGraph()
    _chain(g)
    assert [d.process_instance_id for d in g.descendants(pid_of("p0"))] == [pid_of(f"p{i}") for i in (1, 2, 3, 4)]
    assert [d.process_instance_id for d in g.descendants(pid_of("p0"), max_depth=2)] == [pid_of("p1"), pid_of("p2")]
    assert [d.process_instance_id for d in g.descendants(pid_of("p0"), since=at(25))] == [pid_of("p3"), pid_of("p4")]


def test_descendants_with_equal_start_times_keep_arrival_order_not_id_order():
    g = ProcessGraph()
    g.apply(ev("process_start", "root", pid=1))
    for name, pid in (("zeta", 2), ("alpha", 3), ("mid", 4)):
        g.apply(ev("process_start", name, t=1, parent="root", pid=pid))      # identical start times
    assert [d.process_instance_id for d in g.descendants(pid_of("root"))] == [pid_of("zeta"), pid_of("alpha"), pid_of("mid")]


def test_lineage_contains_variants():
    g = ProcessGraph()
    _chain(g, 4)
    assert g.lineage_contains(pid_of("p3"), pid_of("p0"), 3)
    assert not g.lineage_contains(pid_of("p3"), pid_of("p0"), 2)
    assert not g.lineage_contains(pid_of("p0"), pid_of("p3"), 5)                 # direction matters
    assert not g.lineage_contains(pid_of("p1"), pid_of("p0"), 0)
    assert not g.lineage_contains(pid_of("p1"), pid_of("p1"), 2)
    assert g.lineage_contains(pid_of("p1"), pid_of("p1"), 2, include_self=True)
    assert not g.lineage_contains(pid_of("nope"), pid_of("p0"), 3, include_self=True)


def test_lineage_walks_through_placeholders():
    g = ProcessGraph()
    g.apply(ev("process_start", "leaf", parent="ghost", pid=9, ppid=8))
    assert g.lineage_contains(pid_of("leaf"), pid_of("ghost"), 1)
    assert g.nodes[pid_of("ghost")].placeholder


def test_events_for_filters_types_and_window_and_orders():
    g = ProcessGraph()
    g.apply(ev("process_start", "a", t=0, pid=1))
    g.apply(ev("file_access", "a", t=3, pid=1))
    g.apply(ev("network_connect", "a", t=2, pid=1))
    g.apply(ev("dns_query", "a", t=4, pid=1))
    g.apply(ev("process_start", "b", t=1, pid=2))
    g.apply(ev("process_exit", "b", t=5, pid=2))
    ids = [pid_of("a"), pid_of("b"), pid_of("missing")]
    assert [e.event_type for e in g.events_for(ids, ["network_connect", "file_access"])] == ["network_connect", "file_access"]
    assert [e.timestamp_utc for e in g.events_for(ids, ["process_start", "process_exit", "dns_query"])] == [iso(0), iso(1), iso(4), iso(5)]
    assert [e.event_type for e in g.events_for(ids, ["network_connect", "file_access", "dns_query"], (at(2), at(4)))] == [
        "network_connect", "file_access", "dns_query"]
    assert g.events_for(ids, ["file_access"], (at(3.5), None)) == []
    assert len(g.events_for(ids, ["file_access"], (at(3), at(3)))) == 1               # bounds are inclusive
    assert len(g.events_for([pid_of("a"), pid_of("a")], ["file_access"])) == 1       # no duplicates


# ------------------------------------------------------------------ review of PR 3 (Omar): regression tests
def snapshot(g: ProcessGraph) -> dict:
    return {
        "nodes": {k: dataclasses.asdict(n) for k, n in g.nodes.items()},     # asdict copies sets and lists
        "events": list(g.events),
        "live_by_pid": dict(g.live_by_pid),
        "latest_event_time": g.latest_event_time,
        "since_gc": g._since_gc,
    }


@pytest.mark.parametrize("ghost_t, real_t, ghost_superseded", [(50, 40, False), (50, 50, True), (50, 60, True)])
def test_a_placeholder_never_keeps_the_pid_over_a_real_start(ghost_t, real_t, ghost_superseded):
    g = ProcessGraph()
    ghost = g.apply(ev("file_access", "ghost", t=ghost_t, pid=5))            # placeholder, first seen at ghost_t
    real = g.apply(ev("process_start", "real", t=real_t, pid=5))             # authoritative start, any apparent age
    assert g.live_by_pid[5] == pid_of("real") and g.live_node_for_pid(5) is real and real.is_live
    # only a placeholder that is provably older is declared superseded; an ambiguous one is left alone
    assert (ghost.superseded_by == pid_of("real")) is ghost_superseded
    g.apply(ev("network_connect", "later-ghost", t=real_t + 1, pid=5))       # a new placeholder cannot take it back
    assert g.live_by_pid[5] == pid_of("real")
    assert_consistent(g)


def test_a_parent_hint_placeholder_does_not_keep_a_pid_a_real_start_owns():
    g = ProcessGraph()
    g.apply(ev("process_start", "kid", t=10, parent="hint", pid=2, ppid=7))   # placeholder parent "hint", pid 7, seen at +10
    real = g.apply(ev("process_start", "real7", t=5, pid=7))
    assert g.live_by_pid[7] == pid_of("real7") and g.live_node_for_pid(7) is real


def _bad_start(kind: str = "process_start", **kw):
    return lambda: ev(kind, kw.pop("proc", "p"), t=100, pid=70, process_start_time_utc="garbage", **kw)


_FAILING = [
    ("new real start", lambda g: None, _bad_start(user="u", parent="gp", ppid=3)),
    ("placeholder upgrade", lambda g: g.apply(ev("file_access", "p", t=0, pid=7, binary="C:\\known.exe")),
     _bad_start(user="u", parent="gp", ppid=3, binary="C:\\real.exe")),
    ("seeded placeholder start", lambda g: None, _bad_start(attributes={"placeholder": True})),
    ("event on a known node", lambda g: g.apply(ev("process_start", "p", t=0, pid=7)),
     _bad_start("file_access", user="u", ppid=3)),
    ("event from an unknown process", lambda g: None, _bad_start("network_connect", proc="q", parent="gp", ppid=3)),
]


@pytest.mark.parametrize("name, setup, make_bad", _FAILING, ids=[f[0] for f in _FAILING])
def test_a_malformed_optional_start_time_cannot_leave_partial_state(name, setup, make_bad):
    g = ProcessGraph(auto_gc_interval=1)
    setup(g)
    before = snapshot(g)
    with pytest.raises(ValueError):
        g.apply(make_bad())
    assert snapshot(g) == before                                               # nothing at all changed
    assert g.apply(ev("process_start", "p", t=101, pid=7)) is not None          # and the graph still works
    assert_consistent(g)


def test_a_malformed_primary_timestamp_also_changes_nothing():
    g = ProcessGraph(auto_gc_interval=1)
    g.apply(ev("process_start", "p", t=0, pid=7))
    before = snapshot(g)
    with pytest.raises(ValueError):
        g.apply(ev("file_access", "p", t=5, pid=7, timestamp_utc="garbage"))
    assert snapshot(g) == before


def test_promoting_a_seeded_placeholder_keeps_the_authoritative_start_event():
    g = ProcessGraph()
    seed = ev("process_start", "s", t=0, pid=50, attributes={"identity_resolution": "placeholder"})
    real = ev("process_start", "s", t=5, pid=50, command_line="s.exe", attributes={"identity_resolution": "native"})
    g.apply(seed)
    node = g.apply(real)
    assert not node.placeholder and node.start_event_id == real.event_id
    assert [e.event_id for e in g.events_for([pid_of("s")], ["process_start"])] == [real.event_id]
    assert real.event_id in g.events and seed.event_id not in g.events          # the synthetic seed is replaced, not leaked
    assert g.apply(real) is node and len(g.events) == 1                         # re-delivery is still a no-op
    assert_consistent(g)


def test_promoting_an_event_created_placeholder_keeps_both_start_and_earlier_events():
    g = ProcessGraph()
    early = ev("file_access", "s", t=0, pid=50)
    real = ev("process_start", "s", t=5, pid=50)
    g.apply(early)
    g.apply(real)
    got = g.events_for([pid_of("s")], ["process_start", "file_access"])
    assert [e.event_id for e in got] == [early.event_id, real.event_id]


def test_a_repeated_start_does_not_replace_a_real_start_event():
    g = ProcessGraph()
    first = ev("process_start", "r", t=0, pid=9)
    g.apply(first)
    g.apply(ev("process_start", "r", t=1, pid=9))
    assert [e.event_id for e in g.events_for([pid_of("r")], ["process_start"])] == [first.event_id]


def test_equal_timestamps_keep_arrival_order_not_event_id_order():
    g = ProcessGraph()
    g.apply(ev("process_start", "a", t=0, pid=1))
    ids = [f"{EP}:evt-0000000000f{i}" for i in (3, 2, 1)]                       # arrival order is descending by id
    for event_id in ids:
        g.apply(ev("file_access", "a", t=1, pid=1, event_id=event_id))
    assert [e.event_id for e in g.events_for([pid_of("a")], ["file_access"])] == ids


def test_equal_timestamp_order_holds_across_nodes_and_types_and_timestamp_stays_primary():
    g = ProcessGraph()
    a_start = ev("process_start", "a", t=1, pid=1, event_id=f"{EP}:evt-00000000000f")
    b_start = ev("process_start", "b", t=1, pid=2, event_id=f"{EP}:evt-00000000000e")
    a_file = ev("file_access", "a", t=1, pid=1, event_id=f"{EP}:evt-00000000000d")
    early = ev("network_connect", "a", t=0.5, pid=1, event_id=f"{EP}:evt-00000000000c")   # arrives last, happened first
    for e in (a_start, b_start, a_file, early):
        g.apply(e)
    got = g.events_for([pid_of("b"), pid_of("a")], ["process_start", "file_access", "network_connect"])
    assert [e.event_id for e in got] == [early.event_id, a_start.event_id, b_start.event_id, a_file.event_id]
    again = g.events_for([pid_of("a"), pid_of("b")], ["file_access", "network_connect", "process_start"])
    assert [e.event_id for e in again] == [e.event_id for e in got]            # independent of argument order


def test_arrival_order_survives_eviction():
    g = ProcessGraph(max_events=3)
    ids = [f"{EP}:evt-0000000000a{i}" for i in (9, 8, 7, 6, 5)]                 # descending ids, equal timestamps
    for event_id in ids:
        g.apply(ev("file_access", "a", t=1, pid=1, event_id=event_id))
    assert [e.event_id for e in g.events_for([pid_of("a")], ["file_access"])] == ids[-3:]
    assert_consistent(g)


# ------------------------------------------------------------------ parent restoration after forced eviction (Omar, round 2)
def _evicted_parent_graph(**kw) -> ProcessGraph:
    """p -> c, plus a filler so max_nodes=2 forces gc to evict the oldest live node (p) while c stays."""
    g = ProcessGraph(max_nodes=2, retention_seconds=10_000, auto_gc_interval=0, **kw)
    g.apply(ev("process_start", "p", t=0, pid=1))
    g.apply(ev("process_start", "c", t=1, parent="p", pid=2, ppid=1))
    g.apply(ev("process_start", "filler", t=2, pid=3))
    assert g.gc() == 1 and pid_of("p") not in g                      # real eviction through gc, not a manual delete
    assert g.nodes[pid_of("c")].parent_process_instance_id == pid_of("p") and g.ancestors(pid_of("c")) == []
    return g


def _both_directions(g: ProcessGraph, parent: str, children: list[str]) -> None:
    for child in children:
        assert pid_of(parent) in [a.process_instance_id for a in g.ancestors(pid_of(child))]
    assert [d.process_instance_id for d in g.descendants(pid_of(parent), max_depth=1)] == [pid_of(c) for c in children]
    assert g.nodes[pid_of(parent)].children == {pid_of(c) for c in children}             # a set: no duplicate edges


def test_evicted_parent_restored_by_a_real_start_regains_its_children():
    g = _evicted_parent_graph()
    g.apply(ev("process_start", "p", t=10, pid=1))                   # same process_instance_id comes back
    _both_directions(g, "p", ["c"])
    g.apply(ev("file_access", "c", t=11, parent="p", pid=2))         # more activity on the child changes nothing
    g.apply(ev("process_start", "c", t=12, parent="p", pid=2, ppid=1))   # not even a repeated start
    _both_directions(g, "p", ["c"])
    assert_consistent(g)


def test_evicted_parent_restored_as_a_placeholder_from_its_own_event():
    g = _evicted_parent_graph()
    ghost = g.apply(ev("network_connect", "p", t=10, pid=1))
    assert ghost.placeholder
    _both_directions(g, "p", ["c"])
    assert_consistent(g)


def test_evicted_parent_restored_as_a_placeholder_when_a_new_child_names_it():
    g = _evicted_parent_graph()
    g.apply(ev("process_start", "c2", t=10, parent="p", pid=4, ppid=1))   # creates the placeholder parent "p"
    assert g.nodes[pid_of("p")].placeholder
    assert g.nodes[pid_of("p")].children == {pid_of("c"), pid_of("c2")}   # old child re-adopted, new child added
    assert_consistent(g)


def test_restoring_a_parent_regains_every_child_and_the_nested_tree():
    g = ProcessGraph(max_nodes=5, retention_seconds=10_000, auto_gc_interval=0)
    g.apply(ev("process_start", "p", t=0, pid=1))
    g.apply(ev("process_start", "c1", t=1, parent="p", pid=2, ppid=1))
    g.apply(ev("process_start", "c2", t=2, parent="p", pid=3, ppid=1))
    g.apply(ev("process_start", "g1", t=3, parent="c1", pid=4, ppid=2))
    for i, name in enumerate(("x", "y")):
        g.apply(ev("process_start", name, t=4 + i, pid=10 + i))
    assert g.gc() == 1 and pid_of("p") not in g                       # only p goes; its subtree stays
    g.apply(ev("process_start", "p", t=20, pid=1))
    _both_directions(g, "p", ["c1", "c2"])
    assert [d.process_instance_id for d in g.descendants(pid_of("p"))] == [pid_of("c1"), pid_of("c2"), pid_of("g1")]
    assert [a.process_instance_id for a in g.ancestors(pid_of("g1"))] == [pid_of("c1"), pid_of("p")]
    assert g.lineage_contains(pid_of("g1"), pid_of("p"), 2)
    assert_consistent(g)


def test_repeated_eviction_and_restoration_stays_consistent():
    g = ProcessGraph(max_nodes=3, retention_seconds=10_000, auto_gc_interval=0)
    g.apply(ev("process_start", "p", t=0, pid=1))
    g.apply(ev("process_start", "c", t=1, parent="p", pid=2, ppid=1))
    g.apply(ev("process_start", "f1", t=2, pid=3))
    g.apply(ev("process_start", "f2", t=3, pid=4))
    for cycle in range(5):
        assert g.gc() == 1 and pid_of("p") not in g                    # p is always the oldest live node
        assert g._orphans == {pid_of("p"): {pid_of("c")}}
        assert g.ancestors(pid_of("c")) == []
        g.apply(ev("process_start", "p", t=10 + cycle, pid=1, process_start_time_utc=iso(0)))   # real start time: oldest again
        _both_directions(g, "p", ["c"])
        assert g._orphans == {}
        assert_consistent(g)


def test_an_orphaned_child_that_is_itself_removed_leaves_no_trace():
    g = _evicted_parent_graph()
    assert g._orphans == {pid_of("p"): {pid_of("c")}}
    g.apply(ev("process_exit", "c", t=3, pid=2))
    g.gc(now=at(100_000))                                              # retention removes the exited orphan
    assert pid_of("c") not in g and g._orphans == {}
    g.apply(ev("process_start", "p", t=200_000, pid=1))
    assert g.nodes[pid_of("p")].children == set()
    assert_consistent(g)


def test_restoring_a_parent_never_creates_a_cycle():
    g = _evicted_parent_graph()
    g.apply(ev("process_start", "p", t=10, pid=1, parent="c", ppid=2))   # restored p claims its own child as parent
    assert g.nodes[pid_of("p")].parent_process_instance_id is None
    assert [a.process_instance_id for a in g.ancestors(pid_of("c"))] == [pid_of("p")]
    assert [a.process_instance_id for a in g.ancestors(pid_of("p"))] == []
    assert_consistent(g)


def test_restoring_a_parent_does_not_disturb_pid_ownership():
    g = _evicted_parent_graph()
    g.apply(ev("process_start", "q", t=5, pid=1))                      # another process now owns PID 1
    ghost = g.apply(ev("file_access", "p", t=10, pid=1))               # p reappears only as a placeholder
    assert ghost.placeholder and g.live_by_pid[1] == pid_of("q")
    _both_directions(g, "p", ["c"])
    assert_consistent(g)


# ------------------------------------------------------------------ retention and gc
def test_gc_drops_exited_nodes_after_retention_using_event_time():
    g = ProcessGraph(retention_seconds=600)
    g.apply(ev("process_start", "short", t=0, pid=1))
    g.apply(ev("file_access", "short", t=1, pid=1))
    g.apply(ev("process_exit", "short", t=2, pid=1))
    g.apply(ev("process_start", "alive", t=3, pid=2))
    g.apply(ev("process_start", "recent", t=590, pid=3))
    g.apply(ev("process_exit", "recent", t=595, pid=3))
    g.apply(ev("process_start", "tick", t=700, pid=4))              # advances event time to +700 s
    assert g.gc() == 1                                              # only "short" (exited at +2, cutoff +100)
    assert pid_of("short") not in g and pid_of("alive") in g and pid_of("recent") in g
    assert not any(e.process_instance_id == pid_of("short") for e in g.events.values())
    assert g.gc(now=at(2000)) == 1 and pid_of("recent") not in g
    assert_consistent(g)


def test_gc_with_explicit_now_ignores_event_time():
    g = ProcessGraph(retention_seconds=600)
    g.apply(ev("process_start", "a", t=0, pid=1))
    g.apply(ev("process_exit", "a", t=1, pid=1))
    g.apply(ev("process_start", "far", t=5000, pid=2))               # event time is far ahead
    assert g.gc(now=at(100)) == 0 and pid_of("a") in g


def test_clock_overrides_event_time_so_a_future_dated_event_cannot_expire_everything():
    wall = [at(100)]
    g = ProcessGraph(retention_seconds=600, clock=lambda: wall[0])
    g.apply(ev("process_start", "a", t=0, pid=1))
    g.apply(ev("process_exit", "a", t=1, pid=1))
    g.apply(ev("process_start", "future", t=99_999, pid=2))           # bogus timestamp
    assert g.gc() == 0 and pid_of("a") in g
    wall[0] = at(1000)
    assert g.gc() == 1 and pid_of("a") not in g


def test_gc_keeps_exited_parent_while_a_child_is_retained():
    g = ProcessGraph(retention_seconds=60)
    g.apply(ev("process_start", "parent", t=0, pid=1))
    g.apply(ev("process_start", "child", t=1, parent="parent", pid=2, ppid=1))
    g.apply(ev("process_exit", "parent", t=2, pid=1))
    assert g.gc(now=at(1000)) == 0
    assert [a.process_instance_id for a in g.ancestors(pid_of("child"))] == [pid_of("parent")]
    g.apply(ev("process_exit", "child", t=3, pid=2))
    assert g.gc(now=at(1000)) == 2 and len(g) == 0   # child first, then its parent
    assert not g.live_by_pid and not g.events


def test_superseded_node_expires_after_retention_but_not_while_it_has_children():
    g = ProcessGraph(retention_seconds=60)
    g.apply(ev("process_start", "old", t=0, pid=9))
    g.apply(ev("process_start", "kid", t=1, parent="old", pid=20, ppid=9))
    g.apply(ev("process_start", "new", t=5, pid=9))                  # supersedes old at +5
    assert g.gc(now=at(5 + 59)) == 0                                  # inside retention
    assert g.gc(now=at(5 + 61)) == 0 and pid_of("old") in g           # past retention, but kid still hangs below it
    g.apply(ev("process_exit", "kid", t=70, pid=20))
    assert g.gc(now=at(70 + 61)) == 2 and pid_of("old") not in g and pid_of("kid") not in g
    assert pid_of("new") in g and g.live_by_pid[9] == pid_of("new")
    assert_consistent(g)


def test_pid_reuse_cycles_do_not_accumulate():
    g = ProcessGraph(retention_seconds=60)
    for i in range(500):
        g.apply(ev("process_start", f"x{i}", t=i * 10, pid=42))     # same PID reused, no exits ever seen
    assert len(g) == 500 and g.gc(now=at(500 * 10 + 1000)) == 499    # all but the live holder expire
    assert list(g.nodes) == [pid_of("x499")] and g.live_by_pid == {42: pid_of("x499")}
    assert_consistent(g)


def test_max_nodes_evicts_dead_nodes_before_live_ones():
    g = ProcessGraph(max_nodes=3, retention_seconds=10_000)
    g.apply(ev("process_start", "root_service", t=0, pid=1))          # long-lived, live
    g.apply(ev("process_start", "child", t=1, parent="root_service", pid=2, ppid=1))
    for i in range(3):
        g.apply(ev("process_start", f"leak{i}", t=10 + i, pid=99))   # same PID; leak0 and leak1 are superseded
    assert g.gc() == 2
    assert set(g.nodes) == {pid_of("root_service"), pid_of("child"), pid_of("leak2")}
    assert_consistent(g)


def test_max_nodes_evicts_dead_leaves_before_dead_parents_then_live():
    g = ProcessGraph(max_nodes=2, retention_seconds=10_000)
    g.apply(ev("process_start", "p", t=0, pid=1))
    g.apply(ev("process_start", "c", t=1, parent="p", pid=2, ppid=1))
    g.apply(ev("process_exit", "p", t=2, pid=1))                      # dead parent, live child
    g.apply(ev("process_start", "z", t=4, pid=3))
    g.apply(ev("process_exit", "z", t=9, pid=3))                      # dead leaf, died later than p
    assert g.gc() == 1 and set(g.nodes) == {pid_of("p"), pid_of("c")}


def test_gc_enforces_max_nodes_oldest_exited_first_then_oldest_live():
    g = ProcessGraph(retention_seconds=10_000, max_nodes=3)
    for i in range(6):
        g.apply(ev("process_start", f"n{i}", t=i, pid=10 + i))
    g.apply(ev("process_exit", "n4", t=10, pid=14))
    g.apply(ev("process_exit", "n1", t=11, pid=11))
    assert g.gc() == 3 and len(g) == 3
    assert pid_of("n4") not in g and pid_of("n1") not in g and pid_of("n0") not in g
    assert set(g.live_by_pid.values()) <= set(g.nodes)
    assert_consistent(g)


def test_forced_eviction_leaves_children_safe():
    g = ProcessGraph(max_nodes=1)
    g.apply(ev("process_start", "p", t=0, pid=1))
    g.apply(ev("process_start", "c", t=1, parent="p", pid=2, ppid=1))
    g.gc()
    assert len(g) == 1 and pid_of("c") in g
    assert g.ancestors(pid_of("c")) == [] and g.nodes[pid_of("c")].parent_process_instance_id == pid_of("p")


def test_gc_on_empty_graph_is_a_noop():
    assert ProcessGraph().gc() == 0


# ------------------------------------------------------------------ how gc is triggered
def test_gc_runs_automatically_so_max_nodes_cannot_be_exceeded_indefinitely():
    interval, cap = 10, 5
    g = ProcessGraph(max_nodes=cap, auto_gc_interval=interval, retention_seconds=10_000)
    worst = 0
    for i in range(300):
        g.apply(ev("process_start", f"n{i}", t=i, parent=f"n{i-1}" if i % 2 else None, pid=1000 + i))
        worst = max(worst, len(g))
    assert worst <= cap + 2 * interval, worst                          # documented bound
    assert len(g) < 300 and g.nodes                                    # gc really ran
    assert_consistent(g)


def test_returned_node_survives_automatic_gc():
    g = ProcessGraph(max_nodes=1, auto_gc_interval=1, retention_seconds=10_000)
    for i in range(20):
        node = g.apply(ev("process_start", f"n{i}", t=i, pid=10 + i))
        assert g.nodes[node.process_instance_id] is node


def test_disabled_auto_gc_leaves_gc_to_the_caller_and_warns_once(caplog):
    g = ProcessGraph(max_nodes=5, auto_gc_interval=0, retention_seconds=10_000)
    with caplog.at_level(logging.WARNING, logger="nexus_endpoint_core.graph"):
        for i in range(30):
            g.apply(ev("process_start", f"n{i}", t=i, pid=10 + i))
    assert len(g) == 30                                                # nothing trimmed on its own
    assert len([r for r in caplog.records if "call gc()" in r.getMessage()]) == 1
    assert g.gc() == 25 and len(g) == 5


def test_manual_gc_resets_the_automatic_counter():
    g = ProcessGraph(max_nodes=1000, auto_gc_interval=5)
    for i in range(4):
        g.apply(ev("process_start", f"n{i}", t=i, pid=10 + i))
    g.gc()
    assert g._since_gc == 0


# ------------------------------------------------------------------ bounded memory
def test_event_cache_and_node_references_stay_consistent_under_eviction():
    g = ProcessGraph(max_events=5)
    for i in range(12):
        g.apply(ev("file_access", "a", t=i, pid=1))
    node = g.nodes[pid_of("a")]
    assert len(g.events) == 5 and len(node.file_events) == 5                   # references follow evictions
    assert [g.events[i].timestamp_utc for i in node.file_events] == [iso(t) for t in range(7, 12)]
    assert_consistent(g)


def test_evicted_start_and_exit_references_are_cleared():
    g = ProcessGraph(max_events=4)
    g.apply(ev("process_start", "a", t=0, pid=1))
    for i in range(1, 6):
        g.apply(ev("file_access", "a", t=i, pid=1))
    node = g.nodes[pid_of("a")]
    assert node.start_event_id is None and len(node.file_events) == 4
    g.apply(ev("process_exit", "a", t=9, pid=1))
    for i in range(10, 16):
        g.apply(ev("file_access", "a", t=i, pid=1))
    assert node.exit_event_id is None and node.end_time_utc == parse_utc(iso(9))      # the fact survives, the event does not
    assert_consistent(g)


def test_per_node_references_are_capped_and_consistent_with_the_cache():
    g = ProcessGraph(max_events_per_node=5, max_events=1000)
    for i in range(12):
        g.apply(ev("network_connect", "n", t=i, pid=1))
    node = g.nodes[pid_of("n")]
    assert len(node.network_events) == 5 and len(g.events) == 5
    assert [g.events[i].timestamp_utc for i in node.network_events] == [iso(t) for t in range(7, 12)]   # newest kept
    assert_consistent(g)


def test_sustained_ingestion_respects_every_limit():
    interval = 50
    g = ProcessGraph(max_nodes=200, max_events=500, max_events_per_node=20, auto_gc_interval=interval, retention_seconds=30)
    worst_nodes = worst_events = worst_refs = 0
    for i in range(30_000):
        proc = f"p{i % 700}"                                           # PIDs and names recur: reuse without exits
        g.apply(fast_ev("process_start", f"q{i}", i * 0.01, pid=1 + i % 400))
        g.apply(fast_ev("network_connect", proc, i * 0.01, pid=2000 + i % 700, parent="p-root"))
        g.apply(fast_ev("network_connect", "noisy", i * 0.01, pid=7))
        if i % 3 == 0:
            g.apply(fast_ev("process_exit", f"q{i}", i * 0.01 + 0.001, pid=1 + i % 400))
        worst_nodes = max(worst_nodes, len(g))
        worst_events = max(worst_events, len(g.events))
        if i % 500 == 0:
            worst_refs = max(worst_refs, max(len(n.network_events) for n in g.nodes.values()))
    assert worst_events <= 500 and worst_refs <= 20
    assert worst_nodes <= 200 + 2 * interval, worst_nodes
    assert_consistent(g)


def test_memory_does_not_grow_with_sustained_ingestion():
    g = ProcessGraph(max_nodes=300, max_events=1000, max_events_per_node=20, auto_gc_interval=100, retention_seconds=30)

    def feed(start: int, count: int) -> None:
        for i in range(start, start + count):
            g.apply(fast_ev("process_start", f"q{i}", i * 0.01, pid=1 + i % 500, parent=f"q{i-1}" if i % 3 else None))
            g.apply(fast_ev("network_connect", f"q{i}", i * 0.01 + 0.001, pid=1 + i % 500))

    feed(0, 5_000)                                                      # warm-up: caches full
    tracemalloc.start()
    try:
        feed(5_000, 2_000)
        baseline, _ = tracemalloc.get_traced_memory()
        feed(7_000, 20_000)
        after, _ = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert after < baseline * 1.5 + 1_000_000, (baseline, after)
    assert len(g) <= 300 + 200 and len(g.events) <= 1000
