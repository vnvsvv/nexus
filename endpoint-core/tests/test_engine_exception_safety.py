"""Exception safety of single-rule evaluation (task A3a): a failure while evaluating one rule must not leave
suppression state, counters or the seen-event record changed, so that a retry of the same event behaves as if the
failed call never happened (in particular: the earlier rule's detection is still delivered as a new EngineMatch).
"""
from __future__ import annotations

import itertools
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from nexus_contracts import HostEvent
from nexus_endpoint_core import ProcessGraph, load_rules
from nexus_endpoint_core import engine as engine_module
from nexus_endpoint_core.engine import EngineLimits, EngineResult, RuleEngine
from nexus_endpoint_core.rules import RuleSet

ROOT_DIR = __import__("pathlib").Path(__file__).resolve().parents[2]
WIN = "windows-vm-01"
NOW = datetime(2026, 11, 15, 10, 0, 0, tzinfo=timezone.utc)
LAB_BIN = "C:\\Lab\\bin\\lab-test.exe"
CMD = "C:\\Windows\\System32\\cmd.exe"
_ids = itertools.count(1)
_pids = itertools.count(100)

RULE_A, RULE_B = "NX-ANY-001", "NX-WIN-002"            # both fire on a lab binary carrying ti_hash_hit; A sorts first


class BackendDefect(RuntimeError):
    """The kind of unexpected failure a defective regex backend or a bug would raise."""


@pytest.fixture(scope="module")
def shipped() -> RuleSet:
    return load_rules(ROOT_DIR / "contracts" / "rules", strict=True)


def stamp(offset: float = 0.0) -> str:
    moment = NOW + timedelta(seconds=offset)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def mk(proc: str, t: float = 0.0, parent: str | None = None, binary: str = LAB_BIN, **extra: Any) -> HostEvent:
    body: dict[str, Any] = {
        "event_id": f"{WIN}:evt-{next(_ids):012x}", "endpoint_id": WIN, "os": "windows", "timestamp_utc": stamp(t),
        "event_type": "process_start", "process_instance_id": f"{WIN}:{proc}", "pid": next(_pids), "binary": binary}
    if parent is not None:
        body["parent_process_instance_id"] = f"{WIN}:{parent}"
    body.update(extra)
    return HostEvent.model_validate(body)


def both(proc: str, t: float = 0.0, parent: str = "par") -> HostEvent:
    return mk(proc, t, parent, attributes={"ti_hash_hit": True})


def setup(shipped: RuleSet, **kw: Any) -> tuple[RuleEngine, ProcessGraph]:
    engine, graph = RuleEngine(shipped, endpoint_id=WIN, **kw), ProcessGraph()
    root = mk("par", binary=CMD)
    graph.apply(root)
    engine.evaluate(graph, root)
    return engine, graph


def snapshot(engine: RuleEngine) -> tuple:
    """Everything a failed call must leave alone. ``events_received`` is excluded: it counts calls, including failed ones."""
    counters = {k: v for k, v in engine._counters.items() if k != "events_received"}
    return (engine._suppression.copy(), engine._seen.copy(), counters, dict(engine.state_sizes()))


@pytest.fixture
def fail_rule_b(monkeypatch):
    """Make predicate evaluation raise for rule B's step only, until ``armed['on']`` is switched off."""
    armed = {"on": False, "calls": 0}
    real = engine_module.evaluate_where

    def evaluate_where(preds, event, **kw):
        if armed["on"] and preds is _step_where(RULE_B):
            armed["calls"] += 1
            raise BackendDefect("boom")
        return real(preds, event, **kw)

    monkeypatch.setattr(engine_module, "evaluate_where", evaluate_where)
    return armed


_WHERE: dict[str, Any] = {}


def _step_where(rule_id: str):
    return _WHERE[rule_id]


@pytest.fixture(autouse=True)
def _register_where(shipped):
    for rule in shipped.rules:
        if rule.id in (RULE_A, RULE_B):
            _WHERE[rule.id] = rule.steps[0].where


def test_a_later_rule_failure_does_not_change_state_and_the_retry_returns_the_original_match(shipped, fail_rule_b):
    engine, graph = setup(shipped)
    event = both("c1", 1)
    graph.apply(event)
    before = snapshot(engine)
    fail_rule_b["on"] = True
    with pytest.raises(BackendDefect):
        engine.evaluate(graph, event)
    assert fail_rule_b["calls"] == 1
    assert snapshot(engine) == before                                       # suppression, seen, counters, sizes
    assert event.event_id not in engine._seen

    fail_rule_b["on"] = False
    retry = engine.evaluate(graph, event)                                   # the same event again
    assert retry.disposition == "evaluated" and retry.suppressed == ()
    assert sorted(m.rule.id for m in retry.matches) == [RULE_A, RULE_B]     # A is a NEW match, not a suppressed repeat
    assert engine.stats().matches_emitted == 2 and engine.stats().matches_suppressed == 0


def test_existing_suppression_entries_survive_a_failed_evaluation(shipped, fail_rule_b):
    engine, graph = setup(shipped)
    first = both("c1", 1)
    graph.apply(first)
    engine.evaluate(graph, first)
    entries = engine._suppression.copy()
    fail_rule_b["on"] = True
    second = both("c2", 2)
    graph.apply(second)
    with pytest.raises(BackendDefect):
        engine.evaluate(graph, second)
    assert engine._suppression == entries                                   # not refreshed by the failed call
    fail_rule_b["on"] = False
    retry = engine.evaluate(graph, second)
    assert len(retry.suppressed) == 2 and retry.matches == ()               # genuine repeats of the earlier detections


def test_no_eviction_happens_during_a_failed_evaluation(shipped, fail_rule_b):
    engine, graph = setup(shipped, limits=EngineLimits(max_suppression_entries=2))
    for name, t in (("a", 1), ("b", 2)):                                    # two live entries fill the table
        event = mk(name, t, "par", binary=CMD, attributes={"ti_hash_hit": True})
        graph.apply(event)
        engine.evaluate(graph, event)
    other = mk("o", 3)                                                      # a new root: would need a third entry
    graph.apply(other)
    other_hit = mk("o2", 3, "o", attributes={"ti_hash_hit": True})
    graph.apply(other_hit)
    before = snapshot(engine)
    fail_rule_b["on"] = True
    with pytest.raises(BackendDefect):
        engine.evaluate(graph, other_hit)
    assert snapshot(engine) == before and engine.stats().suppression_evicted == 0


def test_failure_in_the_first_rule_also_leaves_nothing_behind(shipped, monkeypatch):
    engine, graph = setup(shipped)
    real = engine_module.evaluate_where

    def evaluate_where(preds, event, **kw):
        if preds is _step_where(RULE_A):
            raise BackendDefect("boom")
        return real(preds, event, **kw)

    event = both("c1", 1)
    graph.apply(event)
    before = snapshot(engine)
    monkeypatch.setattr(engine_module, "evaluate_where", evaluate_where)
    with pytest.raises(BackendDefect):
        engine.evaluate(graph, event)
    assert snapshot(engine) == before


def test_a_failure_while_building_a_match_leaves_state_unchanged(shipped, monkeypatch):
    """Not only predicates: any exception before the commit point must leave the engine as it was."""
    engine, graph = setup(shipped)
    event = both("c1", 1)
    graph.apply(event)
    before = snapshot(engine)
    real = engine_module.EngineMatch
    seen = {"n": 0}

    def flaky(*args, **kwargs):
        seen["n"] += 1
        if seen["n"] == 2:                                                  # the second match fails to build
            raise BackendDefect("construction failed")
        return real(*args, **kwargs)

    monkeypatch.setattr(engine_module, "EngineMatch", flaky)
    with pytest.raises(BackendDefect):
        engine.evaluate(graph, event)
    assert snapshot(engine) == before
    monkeypatch.setattr(engine_module, "EngineMatch", real)
    retry = engine.evaluate(graph, event)
    assert sorted(m.rule.id for m in retry.matches) == [RULE_A, RULE_B] and retry.suppressed == ()


def test_successful_multi_rule_evaluation_and_independent_suppression(shipped):
    engine, graph = setup(shipped)
    first = both("c1", 1)
    graph.apply(first)
    result = engine.evaluate(graph, first)
    assert [m.rule.id for m in result.matches] == [RULE_A, RULE_B] and result.suppressed == ()   # rule-id order
    second = both("c2", 2)
    graph.apply(second)
    repeat = engine.evaluate(graph, second)
    assert repeat.matches == () and [s.rule.id for s in repeat.suppressed] == [RULE_A, RULE_B]
    only_a = mk("c3", 3, "par", binary=CMD, attributes={"ti_hash_hit": True})      # rule A again, B does not apply
    graph.apply(only_a)
    assert [s.rule.id for s in engine.evaluate(graph, only_a).suppressed] == [RULE_A]
    other_root = mk("p2", 4)
    graph.apply(other_root)
    fresh = mk("c4", 5, "p2", attributes={"ti_hash_hit": True})
    graph.apply(fresh)
    fired = engine.evaluate(graph, fresh)
    assert [m.rule.id for m in fired.matches] == [RULE_A, RULE_B] and fired.suppressed == ()
    stats = engine.stats()
    assert (stats.matches_emitted, stats.matches_suppressed) == (4, 3)


def _replay(shipped, fail_first: bool, monkeypatch) -> list:
    engine, graph = setup(shipped)
    out = []
    events = [both("c1", 1), both("c2", 2), mk("c3", 3, "par"), both("c4", 70)]
    for index, event in enumerate(events):
        graph.apply(event)
        if fail_first and index == 1:
            real = engine_module.evaluate_where
            monkeypatch.setattr(engine_module, "evaluate_where",
                                lambda p, e, **kw: (_ for _ in ()).throw(BackendDefect("x")) if p is _step_where(RULE_B) else real(p, e, **kw))
            with pytest.raises(BackendDefect):
                engine.evaluate(graph, event)
            monkeypatch.setattr(engine_module, "evaluate_where", real)
        result = engine.evaluate(graph, event)
        out.append(([m.rule.id for m in result.matches], [s.rule.id for s in result.suppressed], result.disposition))
    return out + [dict(engine.stats().__dict__)]


def test_replay_with_a_transient_failure_equals_replay_without_it(shipped, monkeypatch):
    clean = _replay(shipped, False, monkeypatch)
    failed = _replay(shipped, True, monkeypatch)
    assert failed[:-1] == clean[:-1]
    assert failed[-1]["matches_emitted"] == clean[-1]["matches_emitted"]
    assert failed[-1]["matches_suppressed"] == clean[-1]["matches_suppressed"]
    assert failed[-1]["events_evaluated"] == clean[-1]["events_evaluated"]
    assert clean == _replay(shipped, False, monkeypatch)                            # deterministic


# ------------------------------------------------------------------ counters and identity are part of "state"
def test_the_placeholder_counter_is_unchanged_by_a_failed_evaluation_and_correct_after_the_retry(shipped, fail_rule_b):
    """A seeded placeholder start matches both rules (A first, then B raises). Rule A's skip must not be counted by the
    failed call: counting happens only in the commit phase, so the retry counts each skipped rule exactly once."""
    engine, graph = setup(shipped)
    seeded = mk("c1", 1, "par", attributes={"ti_hash_hit": True, "placeholder": True})
    graph.apply(seeded)
    before = snapshot(engine)
    assert engine.stats().placeholder_starts_skipped == 0
    fail_rule_b["on"] = True
    with pytest.raises(BackendDefect):
        engine.evaluate(graph, seeded)
    assert fail_rule_b["calls"] == 1                                        # rule A was evaluated first, then rule B raised
    assert engine.stats().placeholder_starts_skipped == 0                   # A's skip was not counted by the failed call
    assert snapshot(engine) == before and seeded.event_id not in engine._seen

    fail_rule_b["on"] = False
    retry = engine.evaluate(graph, seeded)
    assert retry.disposition == "evaluated" and retry.matches == () and retry.suppressed == ()
    stats = engine.stats()
    assert stats.placeholder_starts_skipped == 2                            # one per matching rule (A and B), not 3 (no double count)
    assert stats.matches_emitted == 0 and stats.matches_suppressed == 0
    assert dict(engine.state_sizes())["suppression_entries"] == 0           # a seeded start never registers a detection


def test_the_endpoint_identity_stays_unset_after_a_failed_first_event(shipped, fail_rule_b):
    """Only an ACCEPTED event may fix the engine's endpoint and OS. A first event that raises must not claim them."""
    engine, graph = RuleEngine(shipped), ProcessGraph()                     # no endpoint_id: learned from the first accepted event
    failing = mk("c1", 1, "par")                                            # a lab binary: rule B's predicates are evaluated and raise
    graph.apply(failing)
    fail_rule_b["on"] = True
    with pytest.raises(BackendDefect):
        engine.evaluate(graph, failing)
    assert engine.endpoint_id is None and engine.arrival_count == 0
    assert engine.stats().events_rejected_foreign == 0

    fail_rule_b["on"] = False
    other = mk("o1", 2, "opar", binary="/usr/bin/x", endpoint_id="other-vm-01", os="linux",
               event_id="other-vm-01:evt-0000000000a1", process_instance_id="other-vm-01:o1",
               parent_process_instance_id="other-vm-01:opar")
    graph.apply(other)
    result = engine.evaluate(graph, other)                                  # a different endpoint AND OS: must not be "foreign"
    assert result.disposition == "evaluated"
    assert engine.endpoint_id == "other-vm-01" and engine.stats().events_rejected_foreign == 0

    # Control: a first event that SUCCEEDS does fix the identity, so the same kind of event is then foreign.
    control, graph2 = RuleEngine(shipped), ProcessGraph()
    ok = mk("c1", 1, "par")
    graph2.apply(ok)
    assert control.evaluate(graph2, ok).disposition == "evaluated" and control.endpoint_id == WIN
    graph2.apply(other)
    assert control.evaluate(graph2, other).disposition == "foreign"


# ------------------------------------------------------------------ a failing log sink must not break evaluation
LOG = "nexus_endpoint_core.engine"


class _RaisingHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        raise OSError("log sink is broken")


def _raise_in_filter(record: logging.LogRecord) -> bool:
    raise OSError("log filter is broken")


@pytest.fixture(params=["handler", "filter"])
def broken_sink(request):
    """A handler (or a filter) on the engine's logger that raises for every record, as a full disk or a bad formatter would."""
    logger = logging.getLogger(LOG)
    sink = _RaisingHandler() if request.param == "handler" else _raise_in_filter
    (logger.addHandler if request.param == "handler" else logger.addFilter)(sink)
    yield request.param
    (logger.removeHandler if request.param == "handler" else logger.removeFilter)(sink)


def _two_rule_eviction(shipped: RuleSet):
    """Cap 1: one event matches rules A and B, so B's new entry evicts A's live one, which is the logged event."""
    engine, graph = setup(shipped, limits=EngineLimits(max_suppression_entries=1))
    event = both("c1", 1)
    graph.apply(event)
    return engine, graph, event


def _reference_state(shipped: RuleSet):
    engine, graph, event = _two_rule_eviction(shipped)
    result = engine.evaluate(graph, event)
    return snapshot(engine), [m.rule.id for m in result.matches]


def test_a_failing_log_sink_does_not_break_a_two_rule_eviction(shipped, broken_sink):
    expected_state, expected_rules = _reference_state(shipped)
    engine, graph, event = _two_rule_eviction(shipped)
    result = engine.evaluate(graph, event)                                  # must not raise
    assert result.disposition == "evaluated" and result.suppressed == ()
    assert [m.rule.id for m in result.matches] == expected_rules == [RULE_A, RULE_B]
    stats = engine.stats()
    assert (stats.matches_emitted, stats.matches_suppressed, stats.suppression_evicted) == (2, 0, 1)
    assert dict(engine.state_sizes())["suppression_entries"] == 1
    assert event.event_id in engine._seen and stats.events_evaluated == 2    # the event was fully accepted, nothing to retry
    got = snapshot(engine)                                                  # identical to a run with a healthy sink (ids differ per run)
    assert (list(got[0].values()), got[2], got[3]) == (list(expected_state[0].values()), expected_state[2], expected_state[3])
    assert [k for k, _ in got[0].items()] == [k for k, _ in expected_state[0].items()]


def test_a_failing_log_sink_does_not_turn_a_redelivery_into_a_wrong_result(shipped, broken_sink):
    engine, graph, event = _two_rule_eviction(shipped)
    engine.evaluate(graph, event)
    assert engine.evaluate(graph, event).disposition == "duplicate"         # accepted once: no second match, no downgrade
    assert engine.stats().matches_emitted == 2 and engine.stats().matches_suppressed == 0


def test_a_failing_log_sink_does_not_break_skip_diagnostics(shipped, broken_sink):
    engine, graph = setup(shipped)
    stranger = mk("x1", 2, "xpar", endpoint_id="other-vm-01", process_instance_id="other-vm-01:x1",
                  parent_process_instance_id="other-vm-01:xpar", event_id="other-vm-01:evt-0000000000b1")
    result = engine.evaluate(graph, stranger)                               # the first skip is logged, and the sink raises
    assert result.disposition == "foreign" and engine.stats().events_rejected_foreign == 1


def test_the_eviction_warning_is_emitted_after_the_event_is_fully_recorded(shipped):
    engine, graph, event = _two_rule_eviction(shipped)
    seen_at_emit: list[tuple[bool, int, int]] = []

    class Spy(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen_at_emit.append((event.event_id in engine._seen, engine.stats().events_evaluated, engine.stats().matches_emitted))

    logger, spy = logging.getLogger(LOG), Spy(level=logging.WARNING)
    logger.addHandler(spy)
    try:
        engine.evaluate(graph, event)
    finally:
        logger.removeHandler(spy)
    assert seen_at_emit == [(True, 2, 2)]                                   # logged once, after the commit and the bookkeeping


def test_a_failing_sink_does_not_hide_a_real_defect_and_the_failed_call_still_leaves_no_trace(shipped, fail_rule_b, broken_sink):
    engine, graph = setup(shipped)
    event = both("c1", 1)
    graph.apply(event)
    before = snapshot(engine)
    fail_rule_b["on"] = True
    with pytest.raises(BackendDefect):                                      # the defect propagates, not the sink's error
        engine.evaluate(graph, event)
    assert snapshot(engine) == before and event.event_id not in engine._seen


# ------------------------------------------------------------------ fatal conditions are never swallowed by the log guard
class _FatalHandler(logging.Handler):
    def __init__(self, exc: BaseException) -> None:
        super().__init__()
        self.exc = exc

    def emit(self, record: logging.LogRecord) -> None:
        raise self.exc


@pytest.mark.parametrize("exc", [MemoryError("out of memory"), KeyboardInterrupt(), SystemExit(3)], ids=["MemoryError", "KeyboardInterrupt", "SystemExit"])
def test_a_fatal_exception_from_a_log_handler_is_not_suppressed(shipped, exc):
    engine, graph, event = _two_rule_eviction(shipped)
    logger, handler = logging.getLogger(LOG), _FatalHandler(exc)
    logger.addHandler(handler)
    try:
        with pytest.raises(type(exc)):
            engine.evaluate(graph, event)                                   # propagates; no atomicity is claimed for this case
    finally:
        logger.removeHandler(handler)


def test_a_memory_error_from_a_log_filter_is_not_suppressed(shipped):
    engine, graph, event = _two_rule_eviction(shipped)
    logger = logging.getLogger(LOG)

    def boom(record: logging.LogRecord) -> bool:
        raise MemoryError("out of memory")

    logger.addFilter(boom)
    try:
        with pytest.raises(MemoryError):
            engine.evaluate(graph, event)
    finally:
        logger.removeFilter(boom)


def test_a_memory_error_from_a_skip_diagnostic_is_not_suppressed(shipped):
    engine, graph = setup(shipped)
    stranger = mk("x1", 2, "xpar", endpoint_id="other-vm-01", process_instance_id="other-vm-01:x1",
                  parent_process_instance_id="other-vm-01:xpar", event_id="other-vm-01:evt-0000000000b2")
    logger, handler = logging.getLogger(LOG), _FatalHandler(MemoryError("out of memory"))
    logger.addHandler(handler)
    try:
        with pytest.raises(MemoryError):
            engine.evaluate(graph, stranger)
    finally:
        logger.removeHandler(handler)
