"""Bounded suppression of repeated single-rule detections (task A3a step 3).

Semantics under test (see the engine module docstring): the key is ``(rule_id, root)``; a repeat while
``event_time < last_hit + incident_window_seconds`` is a SuppressedMatch that refreshes the window from the latest hit;
the window is half-open; state is bounded and a live entry lost at the cap is counted, never silent.
"""
from __future__ import annotations

import itertools
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from nexus_contracts import HostEvent
from nexus_endpoint_core import ProcessGraph, load_rules
from nexus_endpoint_core.engine import EngineLimits, EngineResult, RuleEngine
from nexus_endpoint_core.rules import RuleSet

ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]
WIN = "windows-vm-01"
NOW = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
LAB_BIN = "C:\\Lab\\bin\\lab-test.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
LOG = "nexus_endpoint_core.engine"
_ids = itertools.count(1)
_pids = itertools.count(100)


@pytest.fixture(scope="module")
def shipped() -> RuleSet:
    return load_rules(ROOT_DIR / "contracts" / "rules", strict=True)


def stamp(offset: float = 0.0) -> str:
    moment = NOW + timedelta(seconds=offset)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def mk(proc: str, t: float = 0.0, parent: str | None = None, binary: str = LAB_BIN, endpoint: str = WIN,
       event_id: str | None = None, **extra: Any) -> HostEvent:
    body: dict[str, Any] = {
        "event_id": event_id or f"{endpoint}:evt-{next(_ids):012x}", "endpoint_id": endpoint, "os": "windows",
        "timestamp_utc": stamp(t), "event_type": "process_start", "process_instance_id": f"{endpoint}:{proc}",
        "pid": next(_pids), "binary": binary}
    if parent is not None:
        body["parent_process_instance_id"] = f"{endpoint}:{parent}"
    body.update(extra)
    return HostEvent.model_validate(body)


def feed(engine: RuleEngine, graph: ProcessGraph, event: HostEvent) -> EngineResult:
    graph.apply(event)
    return engine.evaluate(graph, event)


def setup(shipped: RuleSet, **kw: Any) -> tuple[RuleEngine, ProcessGraph]:
    engine, graph = RuleEngine(shipped, endpoint_id=WIN, **kw), ProcessGraph()
    feed(engine, graph, mk("par", binary=CMD))                         # a shared parent, so siblings share one root
    return engine, graph


def outcome(result: EngineResult) -> str:
    return "match" if result.matches and not result.suppressed else "suppressed" if result.suppressed and not result.matches else \
        "both" if result.matches and result.suppressed else "none"


# ------------------------------------------------------------------ new match versus suppressed detection
def test_the_first_detection_is_a_match_and_a_repeat_is_a_suppressed_match_with_its_evidence(shipped):
    engine, graph = setup(shipped)
    first_event, second_event = mk("c1", 1, "par"), mk("c2", 2, "par")
    first, second = feed(engine, graph, first_event), feed(engine, graph, second_event)
    assert outcome(first) == "match" and outcome(second) == "suppressed"
    (match,), (repeat,) = first.matches, second.suppressed
    assert match.root_process_instance_id == repeat.root_process_instance_id == f"{WIN}:par"
    assert repeat.rule.id == match.rule.id == "NX-WIN-002" and second.matches == ()
    assert dict(repeat.bindings) == {"bin": second_event.event_id} and repeat.events["bin"] is second_event     # the new evidence, for A4
    assert repeat.trigger_event_id == second_event.event_id and repeat.matched_at == datetime.fromisoformat("2026-11-15T10:00:02+00:00")
    assert not hasattr(repeat, "to_contract")                                  # a repeat is evidence, not a second rule match
    stats = engine.stats()
    assert (stats.matches_emitted, stats.matches_suppressed) == (1, 1) and dict(engine.state_sizes())["suppression_entries"] == 1


def test_repeated_events_of_the_same_process_are_suppressed_too(shipped):
    engine, graph = setup(shipped)
    assert outcome(feed(engine, graph, mk("c1", 1, "par"))) == "match"
    for offset in (2, 3, 4):
        assert outcome(feed(engine, graph, mk("c1", offset, "par"))) == "suppressed"
    assert engine.stats().matches_suppressed == 3


def test_a_suppressed_detection_does_not_create_a_second_rule_match(shipped):
    engine, graph = setup(shipped)
    results = [feed(engine, graph, mk(f"c{i}", i, "par")) for i in range(1, 6)]
    assert sum(len(r.matches) for r in results) == 1 and sum(len(r.suppressed) for r in results) == 4


def test_a_different_rule_on_the_same_root_still_fires(shipped):
    engine, graph = setup(shipped)
    hit = feed(engine, graph, mk("c1", 1, "par", binary=CMD, attributes={"ti_hash_hit": True}))   # NX-ANY-001 only
    assert [m.rule.id for m in hit.matches] == ["NX-ANY-001"]
    lab = feed(engine, graph, mk("c2", 2, "par"))                                                  # NX-WIN-002 only, same root
    assert [m.rule.id for m in lab.matches] == ["NX-WIN-002"] and lab.suppressed == ()
    assert lab.matches[0].root_process_instance_id == hit.matches[0].root_process_instance_id
    again = feed(engine, graph, mk("c3", 3, "par", binary=CMD, attributes={"ti_hash_hit": True}))
    assert outcome(again) == "suppressed" and again.suppressed[0].rule.id == "NX-ANY-001"
    assert dict(engine.state_sizes())["suppression_entries"] == 2


def test_the_same_rule_on_a_different_root_still_fires(shipped):
    engine, graph = setup(shipped)
    feed(engine, graph, mk("par2", binary=CMD, t=0))
    assert outcome(feed(engine, graph, mk("a", 1, "par"))) == "match"
    other = feed(engine, graph, mk("b", 2, "par2"))
    assert outcome(other) == "match" and other.matches[0].root_process_instance_id == f"{WIN}:par2"
    assert outcome(feed(engine, graph, mk("c", 3, "par2"))) == "suppressed"
    assert dict(engine.state_sizes())["suppression_entries"] == 2


def test_a_process_whose_ancestry_is_unrelated_is_a_separate_root(shipped):
    engine, graph = setup(shipped)
    assert outcome(feed(engine, graph, mk("a", 1, "par"))) == "match"
    assert outcome(feed(engine, graph, mk("loner", 2))) == "match"             # no parent at all: its own root


# ------------------------------------------------------------------ the sliding, half-open window
@pytest.mark.parametrize("offset, expected", [(0.001, "suppressed"), (30.0, "suppressed"), (59.999, "suppressed"),
                                              (60.0, "match"), (60.001, "match"), (3600.0, "match")])
def test_the_window_is_half_open_at_incident_window_seconds(shipped, offset, expected):
    engine, graph = setup(shipped)                                             # NX-WIN-002: incident_window_seconds = 60
    assert outcome(feed(engine, graph, mk("c1", 0, "par"))) == "match"
    assert outcome(feed(engine, graph, mk("c2", offset, "par"))) == expected


def test_the_window_slides_from_the_latest_hit(shipped):
    engine, graph = setup(shipped)
    seen = [outcome(feed(engine, graph, mk(f"c{i}", i * 50, "par"))) for i in range(5)]     # hits every 50 s, window 60 s
    assert seen == ["match", "suppressed", "suppressed", "suppressed", "suppressed"]
    assert outcome(feed(engine, graph, mk("x", 200 + 59.999, "par"))) == "suppressed"
    engine2, graph2 = setup(shipped)
    for i in range(4):
        feed(engine2, graph2, mk(f"c{i}", i * 50, "par"))                      # last hit at 150: the window ends at 210
    assert outcome(feed(engine2, graph2, mk("y", 209.999, "par"))) == "suppressed"
    engine3, graph3 = setup(shipped)
    for i in range(4):
        feed(engine3, graph3, mk(f"c{i}", i * 50, "par"))
    assert outcome(feed(engine3, graph3, mk("z", 210.0, "par"))) == "match"


def test_a_late_event_never_moves_the_window_backwards(shipped):
    engine, graph = setup(shipped)
    assert outcome(feed(engine, graph, mk("c1", 100, "par"))) == "match"       # window ends at 160
    assert outcome(feed(engine, graph, mk("late", 90, "par"))) == "suppressed"      # older than the last hit: still inside
    assert outcome(feed(engine, graph, mk("c2", 159.999, "par"))) == "suppressed"   # would be a match had the late event moved it to 150
    engine2, graph2 = setup(shipped)
    feed(engine2, graph2, mk("c1", 100, "par"))
    feed(engine2, graph2, mk("late", 90, "par"))
    assert outcome(feed(engine2, graph2, mk("c2", 160.0, "par"))) == "match"


def test_each_rule_uses_its_own_incident_window(shipped):
    engine, graph = setup(shipped)                                             # NX-WIN-002: 60 s, NX-ANY-001: 120 s
    both = dict(binary=LAB_BIN, attributes={"ti_hash_hit": True})
    assert [m.rule.id for m in feed(engine, graph, mk("c1", 0, "par", **both)).matches] == ["NX-ANY-001", "NX-WIN-002"]
    later = feed(engine, graph, mk("c2", 90, "par", **both))
    assert [m.rule.id for m in later.matches] == ["NX-WIN-002"] and [s.rule.id for s in later.suppressed] == ["NX-ANY-001"]
    edge = feed(engine, graph, mk("c3", 209.999, "par", **both))               # NX-WIN-002 was refreshed at 90 (ends 150); ANY-001 ends 210
    assert [m.rule.id for m in edge.matches] == ["NX-WIN-002"] and [s.rule.id for s in edge.suppressed] == ["NX-ANY-001"]
    engine2, graph2 = setup(shipped)
    feed(engine2, graph2, mk("c1", 0, "par", **both))
    feed(engine2, graph2, mk("c2", 90, "par", **both))
    last = feed(engine2, graph2, mk("c3", 210.0, "par", **both))               # exactly at ANY-001's end: both windows are over
    assert [m.rule.id for m in last.matches] == ["NX-ANY-001", "NX-WIN-002"] and last.suppressed == ()


def test_a_refire_after_expiry_replaces_the_entry_and_is_counted(shipped):
    engine, graph = setup(shipped)
    feed(engine, graph, mk("c1", 0, "par"))
    assert outcome(feed(engine, graph, mk("c2", 100, "par"))) == "match"
    stats = engine.stats()
    assert stats.suppression_expired == 1 and stats.suppression_evicted == 0 and stats.matches_emitted == 2
    assert dict(engine.state_sizes())["suppression_entries"] == 1               # replaced, not duplicated


def test_a_suppressed_hit_is_reported_at_its_own_time_and_root(shipped):
    engine, graph = setup(shipped)
    feed(engine, graph, mk("c1", 0, "par"))
    (repeat,) = feed(engine, graph, mk("c2", 7.5, "par")).suppressed
    assert repeat.matched_at.isoformat() == "2026-11-15T10:00:07.500000+00:00" and repeat.root_process_instance_id == f"{WIN}:par"


# ------------------------------------------------------------------ bounded state, eviction, counters
def roots(shipped: RuleSet, cap: int, **kw: Any) -> tuple[RuleEngine, ProcessGraph]:
    return RuleEngine(shipped, endpoint_id=WIN, limits=EngineLimits(max_suppression_entries=cap), **kw), ProcessGraph()


def solo(engine: RuleEngine, graph: ProcessGraph, name: str, t: float) -> str:
    return outcome(feed(engine, graph, mk(name, t)))                            # no parent: every name is its own root


def test_suppression_state_never_exceeds_its_limit_and_evictions_are_counted(shipped):
    engine, graph = roots(shipped, 3)
    outcomes = [solo(engine, graph, f"r{i}", i) for i in range(1, 6)]
    assert outcomes == ["match"] * 5
    stats = engine.stats()
    assert dict(engine.state_sizes())["suppression_entries"] == 3 and stats.suppression_evicted == 2 and stats.suppression_expired == 0


def test_an_evicted_entry_means_a_repeat_may_fire_again_not_a_lifetime_guarantee(shipped):
    engine, graph = roots(shipped, 3)
    for i in range(1, 6):
        solo(engine, graph, f"r{i}", i)                                         # r1 and r2 were evicted
    assert solo(engine, graph, "r4", 6) == "suppressed"                          # still retained
    assert solo(engine, graph, "r1", 7) == "match"                               # forgotten: detected again (A4 merges by root)
    assert engine.stats().suppression_evicted == 3


def test_eviction_takes_the_least_recently_updated_entry(shipped):
    engine, graph = roots(shipped, 3)
    for i in (1, 2, 3):
        solo(engine, graph, f"r{i}", i)
    assert solo(engine, graph, "r1", 4) == "suppressed"                          # refreshed: now the most recently updated
    assert solo(engine, graph, "r4", 5) == "match"                               # evicts r2, the least recently updated
    assert solo(engine, graph, "r1", 6) == "suppressed" and solo(engine, graph, "r3", 7) == "suppressed"
    assert solo(engine, graph, "r2", 8) == "match"


def test_an_expired_entry_is_dropped_before_a_live_one_at_the_cap(shipped, caplog):
    engine, graph = roots(shipped, 2)
    solo(engine, graph, "r1", 0)
    solo(engine, graph, "r2", 1)
    with caplog.at_level(logging.WARNING, logger=LOG):
        assert solo(engine, graph, "r3", 100) == "match"                         # r1 and r2 have expired: r1 goes, not a live entry
        assert solo(engine, graph, "r4", 101) == "match"                         # r2 is the next expired one
    stats = engine.stats()
    assert stats.suppression_expired == 2 and stats.suppression_evicted == 0
    assert solo(engine, graph, "r3", 102) == "suppressed" and solo(engine, graph, "r4", 102.5) == "suppressed"
    assert not [r for r in caplog.records if "suppression" in r.getMessage()]    # dropping expired entries is not a warning


@pytest.mark.parametrize("third_at, expired, evicted", [(59.999, 0, 1), (60.0, 1, 0), (60.001, 1, 0)])
def test_an_entry_expiring_exactly_at_the_event_time_is_expired_not_a_live_eviction(shipped, caplog, third_at, expired, evicted):
    """NX-WIN-002 incident window is 60 s: r1 (hit at 0) expires at exactly 60.000. With the table full, a new key at
    t == expiry must drop r1 as EXPIRED (``expires <= t``, no warning); one millisecond earlier r1 is still live, so its
    removal is a live eviction (counted and logged)."""
    engine, graph = roots(shipped, 2)
    solo(engine, graph, "r1", 0)                                                # window ends at 60.000
    solo(engine, graph, "r2", 30)                                               # window ends at 90.000
    before = engine.stats()
    with caplog.at_level(logging.WARNING, logger=LOG):
        assert solo(engine, graph, "r3", third_at) == "match"
    stats = engine.stats()
    assert (stats.suppression_expired - before.suppression_expired, stats.suppression_evicted - before.suppression_evicted) == (expired, evicted)
    assert dict(engine.state_sizes())["suppression_entries"] == 2
    assert bool([r for r in caplog.records if "suppression state is full" in r.getMessage()]) is bool(evicted)
    assert solo(engine, graph, "r2", third_at + 1) == "suppressed"             # the genuinely live entry is never the victim
    assert solo(engine, graph, "r3", third_at + 2) == "suppressed"
    assert solo(engine, graph, "r1", third_at + 3) == "match"                  # r1 is gone either way


def test_losing_a_live_entry_is_logged_once_and_then_rate_limited(shipped, caplog):
    engine, graph = roots(shipped, 2)
    with caplog.at_level(logging.WARNING, logger=LOG):
        for i in range(10):
            solo(engine, graph, f"r{i}", i * 0.01)
    warnings = [r for r in caplog.records if "suppression state is full" in r.getMessage()]
    assert len(warnings) == 1 and "may fire again" in warnings[0].getMessage()
    assert engine.stats().suppression_evicted == 8


def test_the_bound_holds_under_many_roots_and_the_counters_account_for_every_removal(shipped):
    engine, graph = roots(shipped, 5)
    for i in range(300):
        assert solo(engine, graph, f"r{i}", i * 0.001) == "match"
        assert dict(engine.state_sizes())["suppression_entries"] <= 5
    stats = engine.stats()
    assert stats.matches_emitted == 300
    assert stats.suppression_evicted + stats.suppression_expired == 300 - dict(engine.state_sizes())["suppression_entries"]


def test_state_bounds_report_the_suppression_limit(shipped):
    assert RuleEngine(shipped, limits=EngineLimits(max_suppression_entries=7)).state_bounds()["suppression_entries"] == 7


# ------------------------------------------------------------------ expiry is lazy: no entry is removed because ANOTHER key's event is later
# An entry that looks expired to the newest event can still be needed by an event that arrives late. These tests fail if
# entries are swept by the time of whatever event is being processed.
def suppression_counters(engine: RuleEngine) -> tuple[int, int, int, int]:
    """(emitted, suppressed, expired, evicted)"""
    s = engine.stats()
    return s.matches_emitted, s.matches_suppressed, s.suppression_expired, s.suppression_evicted


@pytest.mark.parametrize("other", ["other_root", "other_rule"])
@pytest.mark.parametrize("late_at, expected, counters", [(50.0, "suppressed", (2, 1, 0, 0)), (59.999, "suppressed", (2, 1, 0, 0)),
                                                         (60.0, "match", (3, 0, 1, 0))])
def test_a_late_repeat_is_still_suppressed_after_a_later_event_of_another_key(shipped, other, late_at, expected, counters):
    """A fires at 0 (NX-WIN-002, window ends at 60). Another key fires at 70. A's repeat arrives last but is stamped inside
    A's window: it is judged by its own time. The half-open end (60.000) is not moved by the event at 70 either."""
    engine, graph = setup(shipped)
    feed(engine, graph, mk("par2", binary=CMD))
    assert outcome(feed(engine, graph, mk("a1", 0, "par"))) == "match"
    if other == "other_root":                                                  # the same rule on an unrelated root
        later = feed(engine, graph, mk("b1", 70, "par2"))
    else:                                                                      # another rule (NX-ANY-001) on the same root
        later = feed(engine, graph, mk("b1", 70, "par", binary=CMD, attributes={"ti_hash_hit": True}))
    assert outcome(later) == "match"
    assert later.matches[0].rule.id == ("NX-WIN-002" if other == "other_root" else "NX-ANY-001")
    assert suppression_counters(engine) == (2, 0, 0, 0) and dict(engine.state_sizes())["suppression_entries"] == 2

    late = feed(engine, graph, mk("a2", late_at, "par"))                       # a distinct event and process, same (rule, root)
    assert late.disposition == "evaluated" and outcome(late) == expected
    (hit,) = late.matches + late.suppressed
    assert (hit.rule.id, hit.root_process_instance_id) == ("NX-WIN-002", f"{WIN}:par")
    assert suppression_counters(engine) == counters and dict(engine.state_sizes())["suppression_entries"] == 2


@pytest.mark.parametrize("live", [True, False], ids=["live_clock", "replay_without_clock"])
def test_a_future_dated_event_does_not_erase_entries_still_needed_by_in_time_events(shipped, live):
    """Live mode accepts events up to 300 s ahead of the clock; replay trusts any timestamp. One such event is later than
    every window here (60 s), yet the in-time repeats that follow must all still be suppressed."""
    clock_at = 20.0
    engine, graph = RuleEngine(shipped, endpoint_id=WIN, clock=(lambda: NOW + timedelta(seconds=clock_at)) if live else None), ProcessGraph()
    names = [f"r{i}" for i in range(12)]
    assert [solo(engine, graph, name, i * 0.5) for i, name in enumerate(names)] == ["match"] * 12     # hits at 0 .. 5.5
    future_at = clock_at + 300 if live else 10 * 86_400.0
    if live:                                                                    # one millisecond beyond the allowed skew: rejected
        rejected = feed(engine, graph, mk("too-far", future_at + 0.001))
        assert rejected.disposition == "future" and outcome(rejected) == "none"
    ahead = feed(engine, graph, mk("ahead", future_at))
    assert ahead.disposition == "evaluated" and outcome(ahead) == "match"
    assert suppression_counters(engine) == (13, 0, 0, 0) and dict(engine.state_sizes())["suppression_entries"] == 13

    assert [solo(engine, graph, name, 10 + i * 0.5) for i, name in enumerate(names)] == ["suppressed"] * 12
    assert suppression_counters(engine) == (13, 12, 0, 0) and dict(engine.state_sizes())["suppression_entries"] == 13
    assert engine.stats().events_ignored_future == (1 if live else 0)


@pytest.mark.parametrize("late_at", [109.999, 100.0, 0.0], ids=["just_over_20s_earlier", "at_first_hit", "before_first_hit"])
@pytest.mark.parametrize("probe_at, expected, counters", [(189.999, "suppressed", (1, 3, 0, 0)), (190.0, "match", (2, 2, 1, 0))])
def test_a_repeat_far_earlier_than_the_last_hit_is_suppressed_and_does_not_move_the_expiry(shipped, late_at, probe_at, expected, counters):
    """NX-WIN-002 (60 s): A fires at 100 and is refreshed at 130, so its window ends at 190. A distinct repeat stamped more
    than 20 s before that last hit (even before the first hit) is still a repeat: there is no lower time limit. It leaves
    the stored window exactly as it was."""
    engine, graph = setup(shipped)
    assert outcome(feed(engine, graph, mk("a1", 100, "par"))) == "match"
    assert outcome(feed(engine, graph, mk("a2", 130, "par"))) == "suppressed"
    stored = dict(engine._suppression)
    assert list(stored) == [("NX-WIN-002", f"{WIN}:par")]

    late_event = mk("late", late_at, "par")
    late = feed(engine, graph, late_event)
    assert late.disposition == "evaluated" and outcome(late) == "suppressed"
    (repeat,) = late.suppressed
    assert repeat.rule.id == "NX-WIN-002" and repeat.root_process_instance_id == f"{WIN}:par"
    assert dict(repeat.bindings) == {"bin": late_event.event_id}
    assert dict(engine._suppression) == stored                                  # neither the last hit nor the expiry moved back
    assert suppression_counters(engine) == (1, 2, 0, 0) and dict(engine.state_sizes())["suppression_entries"] == 1

    assert outcome(feed(engine, graph, mk("probe", probe_at, "par"))) == expected    # the window still ends at exactly 190
    assert suppression_counters(engine) == counters and dict(engine.state_sizes())["suppression_entries"] == 1


@pytest.mark.parametrize("refresh", ["in_order", "late"])
@pytest.mark.parametrize("last_at, expected, counters", [(109.999, "suppressed", (13, 2, 0, 0)), (110.0, "match", (14, 1, 1, 0))])
def test_a_refreshed_entry_outlives_its_first_window_while_other_keys_arrive(shipped, refresh, last_at, expected, counters):
    """A fires at 0 (first window ends at 60) and is refreshed at 50 (now ends at 110), either before or after twelve other
    keys fire at 70 .. 81. The refreshed end is what counts, to the millisecond."""
    engine, graph = setup(shipped)
    assert outcome(feed(engine, graph, mk("a1", 0, "par"))) == "match"
    if refresh == "in_order":
        assert outcome(feed(engine, graph, mk("a2", 50, "par"))) == "suppressed"
    assert [solo(engine, graph, f"r{i}", 70 + i) for i in range(12)] == ["match"] * 12
    if refresh == "late":
        assert outcome(feed(engine, graph, mk("a2", 50, "par"))) == "suppressed"
    assert suppression_counters(engine) == (13, 1, 0, 0) and dict(engine.state_sizes())["suppression_entries"] == 13

    assert outcome(feed(engine, graph, mk("a3", last_at, "par"))) == expected
    assert suppression_counters(engine) == counters and dict(engine.state_sizes())["suppression_entries"] == 13


def test_state_sizes_reports_retained_entries_including_expired_ones(shipped):
    engine, graph = RuleEngine(shipped, endpoint_id=WIN), ProcessGraph()         # default limits: no capacity pressure
    for i in range(5):
        assert solo(engine, graph, f"r{i}", i) == "match"                        # windows end at 60 .. 64
    assert solo(engine, graph, "new", 1000) == "match"                           # a later processed event: r0 .. r4 have expired
    assert dict(engine.state_sizes())["suppression_entries"] == 6                # retained, not "currently live" (that would be 1)
    assert solo(engine, graph, "again", 5000) == "match"
    assert outcome(feed(engine, graph, mk("benign", 9000, binary=CMD))) == "none"
    assert dict(engine.state_sizes())["suppression_entries"] == 7 and suppression_counters(engine) == (7, 0, 0, 0)

    assert solo(engine, graph, "r0", 9001) == "match"                            # retained does not mean suppressing: r0's window is over
    assert dict(engine.state_sizes())["suppression_entries"] == 7                # its entry is replaced, and only now counted as expired
    assert suppression_counters(engine) == (8, 0, 1, 0)
    assert engine.state_bounds()["suppression_entries"] == EngineLimits().max_suppression_entries


@pytest.mark.parametrize("late_at, expired, evicted", [(50.0, 0, 1), (59.999, 0, 1), (60.0, 1, 0)])
def test_at_the_cap_a_late_event_judges_expiry_by_its_own_time(shipped, caplog, late_at, expired, evicted):
    """Table full: r1 (ends at 60) and r2 (hit at 100). A new key then arrives late. r1 is over by the newest time seen (100),
    but still live at the late event's own time, so its removal is counted as a live eviction and logged; from 60.000 on
    it is counted as expired and is not logged."""
    engine, graph = roots(shipped, 2)
    assert solo(engine, graph, "r1", 0) == "match"
    with caplog.at_level(logging.WARNING, logger=LOG):
        assert solo(engine, graph, "r2", 100) == "match"                         # fits: below the cap nothing is removed
        assert suppression_counters(engine) == (2, 0, 0, 0) and not caplog.records
        assert solo(engine, graph, "r3", late_at) == "match"
    assert suppression_counters(engine) == (3, 0, expired, evicted) and dict(engine.state_sizes())["suppression_entries"] == 2
    assert len([r for r in caplog.records if "suppression state is full" in r.getMessage()]) == evicted

    assert solo(engine, graph, "r2", 101) == "suppressed"                        # the newer entry survived ...
    assert solo(engine, graph, "r3", late_at + 59.999) == "suppressed"           # ... and the late key owns a full window from its own time
    assert solo(engine, graph, "r1", 55) == "match"                              # r1 was the one removed, so a late repeat fires again
    assert suppression_counters(engine) == (4, 2, expired, evicted + 1)          # r1's return removes a live entry


def test_at_the_cap_a_future_dated_event_counts_the_removed_entry_as_expired(shipped, caplog):
    """The mirror image: judged by a future-dated event, entries that in-time events still need look expired. Exactly one is
    removed (only what the cap requires), it is counted as ``suppression_expired``, and nothing is logged."""
    engine, graph = roots(shipped, 3, clock=lambda: NOW + timedelta(seconds=20))
    for i in (1, 2, 3):
        assert solo(engine, graph, f"r{i}", i) == "match"
    with caplog.at_level(logging.WARNING, logger=LOG):
        assert solo(engine, graph, "ahead", 320) == "match"                      # the inclusive skew limit: accepted
    assert suppression_counters(engine) == (4, 0, 1, 0) and not caplog.records
    assert dict(engine.state_sizes())["suppression_entries"] == 3
    assert solo(engine, graph, "r2", 10) == "suppressed" and solo(engine, graph, "r3", 11) == "suppressed"
    assert solo(engine, graph, "r1", 12) == "match"                              # r1 (least recently updated) was removed


# ------------------------------------------------------------------ duplicates and the deduplication horizon
def test_a_duplicate_event_id_produces_neither_a_match_nor_a_suppressed_match(shipped):
    engine, graph = setup(shipped)
    event = mk("c1", 1, "par")
    assert outcome(feed(engine, graph, event)) == "match"
    again = engine.evaluate(graph, event)
    assert again.disposition == "duplicate" and again.matches == () and again.suppressed == ()
    stats = engine.stats()
    assert (stats.matches_emitted, stats.matches_suppressed, stats.events_ignored_duplicate) == (1, 0, 1)


def test_deduplication_is_best_effort_within_a_horizon_not_lifetime_idempotency(shipped):
    limits = EngineLimits(max_seen_events=2, max_suppression_entries=1)
    engine, graph = RuleEngine(shipped, endpoint_id=WIN, limits=limits), ProcessGraph()
    first = mk("a", 0)
    assert outcome(feed(engine, graph, first)) == "match"
    assert engine.evaluate(graph, first).disposition == "duplicate"              # inside the horizon: recognized
    assert outcome(feed(engine, graph, mk("b", 1))) == "match"                   # another root evicts a's live suppression entry
    feed(engine, graph, mk("c", 2, binary=CMD))                                  # an accepted event: pushes `first` out of the horizon
    stats = engine.stats()
    assert stats.seen_evicted >= 1 and stats.suppression_evicted == 1
    replay = engine.evaluate(graph, first)                                       # no source of truth remains: it is processed again
    assert replay.disposition == "evaluated" and outcome(replay) == "match"       # a duplicate detection, merged by A4 through the root


def test_a_forgotten_event_is_only_suppressed_while_its_suppression_entry_lives(shipped):
    engine, graph = RuleEngine(shipped, endpoint_id=WIN, limits=EngineLimits(max_seen_events=1)), ProcessGraph()
    first = mk("a", 0)
    feed(engine, graph, first)
    feed(engine, graph, mk("b", 1, binary=CMD, attributes={"ti_hash_hit": True}))      # pushes `first` out of the horizon
    replay = engine.evaluate(graph, first)
    assert replay.disposition == "evaluated" and outcome(replay) == "suppressed"      # the entry for (rule, root a) is still there


# ------------------------------------------------------------------ isolation, determinism, safety
def test_foreign_events_leave_the_suppression_state_untouched(shipped):
    engine, graph = setup(shipped)
    feed(engine, graph, mk("c1", 1, "par"))
    before = dict(engine.state_sizes())
    foreign = feed(engine, graph, mk("c2", 2, "par", endpoint="other-vm"))
    assert foreign.disposition == "foreign" and foreign.matches == () and foreign.suppressed == ()
    assert dict(engine.state_sizes()) == before and engine.stats().matches_suppressed == 0


def test_suppression_keys_carry_the_endpoint_through_the_root_id(shipped):
    first, graph1 = RuleEngine(shipped, endpoint_id=WIN), ProcessGraph()
    second, graph2 = RuleEngine(shipped, endpoint_id="windows-vm-02"), ProcessGraph()
    a = feed(first, graph1, mk("same-name", 1))
    b = feed(second, graph2, mk("same-name", 1, endpoint="windows-vm-02"))
    assert a.matches[0].root_process_instance_id == f"{WIN}:same-name" and b.matches[0].root_process_instance_id == "windows-vm-02:same-name"
    assert all(key[1].startswith(f"{WIN}:") for key in first._suppression) and all(
        key[1].startswith("windows-vm-02:") for key in second._suppression)


def test_replay_with_eviction_is_deterministic(shipped):
    def run() -> tuple[list[Any], Any, dict[str, int]]:
        engine, graph = roots(shipped, 4)
        out = []
        for i in range(120):
            name = f"r{(i * 7) % 11}"
            result = feed(engine, graph, mk(name, i * 3.5, event_id=f"{WIN}:evt-{i:012x}"))
            out.append((result.disposition, [m.to_contract().model_dump() for m in result.matches],
                        [(s.rule.id, s.root_process_instance_id, dict(s.bindings)) for s in result.suppressed]))
        return out, engine.stats(), dict(engine.state_sizes())
    assert run() == run()


def test_the_counters_account_for_every_detection(shipped):
    engine, graph = setup(shipped)
    qualifying = 0
    for i in range(30):                                                         # ten bursts of three hits, 25 s apart, 200 s between bursts
        result = feed(engine, graph, mk(f"c{i}", (i // 3) * 200 + (i % 3) * 25, "par"))
        qualifying += len(result.matches) + len(result.suppressed)
    stats = engine.stats()
    assert qualifying == 30 == stats.matches_emitted + stats.matches_suppressed
    assert (stats.matches_emitted, stats.matches_suppressed, stats.suppression_expired) == (10, 20, 9)


def test_no_suppression_state_is_created_for_events_that_do_not_match(shipped):
    engine, graph = setup(shipped)
    for i in range(20):
        feed(engine, graph, mk(f"x{i}", i, "par", binary=CMD))
    assert dict(engine.state_sizes())["suppression_entries"] == 0


def test_a_disabled_regex_rule_never_creates_suppression_state(shipped, tmp_path):
    import json

    import yaml
    from nexus_endpoint_core import load_rule
    data = yaml.safe_load((ROOT_DIR / "contracts" / "rules" / "NX-WIN-002.yaml").read_text(encoding="utf-8"))
    data["steps"][0]["where"]["binary"] = {"regex": r"^C:\\Lab\\bin\\"}
    path = tmp_path / "NX-WIN-002.yaml"
    path.write_text(yaml.safe_dump(json.loads(json.dumps(data)), sort_keys=False), encoding="utf-8")
    engine, graph = RuleEngine([load_rule(path)], endpoint_id=WIN), ProcessGraph()
    assert [d.rule_id for d in engine.disabled_rules] == ["NX-WIN-002"]
    for i in range(5):
        assert outcome(feed(engine, graph, mk(f"c{i}", i))) == "none"
    assert dict(engine.state_sizes())["suppression_entries"] == 0 and engine.stats().matches_emitted == 0
