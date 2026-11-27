"""Rule engine (task A3a, and A3b phase 1: sequence rules).

Implemented: construction, startup policy, deterministic indexes, validated limits, the safeguards every event passes
through, evaluation of ``kind: single`` and ``kind: sequence`` rules, root selection and bounded suppression. NOT
implemented yet (A3b phase 2): threshold rules. An event that only threshold steps listen to is accepted and counted
but produces no detection.

Calling contract (one engine per endpoint, single-threaded)
    for event in adapter:
        graph.apply(event)                  # A1: may raise ValueError on a malformed timestamp; then skip evaluate
        result = engine.evaluate(graph, event)

    * ``evaluate`` is called exactly once per event, IMMEDIATELY AFTER ``graph.apply(event)``, in the same order.
      Arrival order is the order of accepted ``evaluate`` calls, so equal timestamps are ordered by arrival, never by
      event id. The engine looks the event's process up in the graph (not the graph's event cache, whose eviction
      cannot affect it), so a call made after a later ``apply`` or ``gc`` may find the process gone: ``not_in_graph``.
    * Enrichment such as ``attributes.ti_hash_hit`` must be set on the event BEFORE ``graph.apply`` (A8).
    * The engine only reads the graph and the event; it mutates neither.

Startup policy (``strict``)
    A rule is *disabled* when it cannot be evaluated safely: it contains a ``regex`` predicate and no
    approved ``RegexBackend`` was given (Python's ``re`` has no timeout and is never run on event data), or its
    ``min_distinct`` exceeds ``limits.max_values_per_key``. No production backend exists yet, and an arbitrary
    callback is not one: ``regex_backend=`` is refused unless the object declares ``enforces_time_limit = True``
    (a declaration, not proof; the backend's own review is the safeguard). Non-strict (tests, tooling): disabled rules are listed in
    ``engine.disabled_rules``, logged at ERROR and counted. Strict (the live agent, A8): any disabled rule, any rule
    the loader rejected (``RuleSet.errors``) or an empty rule set raises ``RuleEngineError``. Coverage is never
    reduced silently. A rule set whose sequence steps need more candidate slots than
    ``limits.max_total_candidate_events`` is a configuration error and raises in both modes.

Endpoint isolation
    An engine serves one endpoint and one OS. A8 MUST pass ``endpoint_id=`` in a live deployment; only tests and
    replay tools may let the first accepted event fix it. An event of another endpoint or OS, or whose
    ``process_instance_id`` does not start with ``<endpoint_id>:``, is rejected before it can touch any state, so ids
    of different endpoints never share a key.

Deduplication is best effort, within a horizon
    The engine remembers the ids of the last ``max_seen_events`` successfully evaluated events: those that passed every
    safeguard (disposition ``evaluated``, called "accepted" elsewhere in this module) and whose evaluation got as far
    as recording the id, whether or not they matched, including events that only sequence or threshold steps listen to.
    Events rejected or ignored before evaluation (every other disposition) are not recorded, and neither is an event
    whose call fails before that point. Only the id is compared, so the first successfully evaluated arrival wins: while
    its id is remembered, a later delivery never reaches the rules, even with different content, and does not renew the
    id's place in the first-in, first-out order. The other safeguards, the graph lookup among them, run before the
    duplicate check, so a redelivery is not always reported as ``duplicate`` (it is ``not_in_graph`` if its process has
    left the graph).

    This is not durable exactly-once processing. The memory lasts only as long as the engine, and an id that left the
    horizon (counted in ``seen_evicted``) is processed again if redelivered. For an unchanged event that a single rule
    had detected, the result is a ``SuppressedMatch`` if it selects the same root and the cap has not removed that
    ``(rule, root)`` entry, even when later events have outlived the entry. After a removal, or under another root (the
    graph may have changed), it is judged like any other detection and may be a new ``EngineMatch``. Merging such a
    repeat by root is planned for the incident builder (A4), and lifetime idempotency for the store (A5); neither is
    implemented yet, and this engine provides neither.

Single rules
    A rule with ``kind: single`` is evaluated for events of its OS and event type with ``predicates.evaluate_where``;
    no regex runs unless an approved backend is installed. A ``process_start`` that is a seeded placeholder
    (``attributes.placeholder`` is True or ``identity_resolution == "placeholder"``) was not observed and never matches.
    ``placeholder_starts_skipped`` counts the refused (rule, event) pairs, one for each rule whose predicates the event
    satisfied; it does not count distinct process starts. Another event for the same placeholder process counts again.
    A redelivery inside the dedup horizon does not, but one processed again after it does. A detection carries the
    event as evidence, the root process, the placeholder and inferred-identity facts for A4, and the response target,
    and converts to the contract ``RuleMatch`` with ``to_contract()``.

Sequence rules (bounded candidates, bounded search)
    Candidates. For every enabled sequence rule and step, an accepted event that satisfies the step's ``where`` (and
    is not a seeded placeholder start) is kept as a candidate, with its timestamp in milliseconds and its arrival rank.
    The store deduplicates event ids itself (first arrival wins), so a redelivery after the ``_seen`` horizon adds
    nothing. Nothing is removed by time, so a late, out-of-order event can still pair with older ones. Above
    ``max_candidates_per_step`` the OLDEST candidate by (timestamp, arrival) is removed, possibly the new one itself:
    ``sequence_candidates_expired`` if it was already outside the rule window at the new event's time, else
    ``sequence_candidates_evicted`` (rate-limited warning: a detection that needed it may be missed). Both labels are
    relative to that one event's time, like the suppression counters. "Expired" does not mean the candidate could never
    have mattered: under out-of-order delivery a later event stamped near it could still have needed it, so both
    counters are coverage-loss signals, the second one the stronger. The startup capacity check guarantees that the
    per-step limits never add up to more than ``max_total_candidate_events``.

    Search. Every event that satisfies at least one step is also an ANCHOR at that step (any step, not only the last,
    so a sequence completed by a late event is still found). The other steps are bound from their candidate stores by a
    depth-first search in rule-step order; the first complete binding wins, at most one per rule and event (the anchor's
    step positions are tried in step order). PHASE 1 LIMITATION: when several bindings are valid and would select
    different roots, only the preferred one is reported; the others are neither reported nor counted, so an
    independently valid detection under another root can be lost (test_engine_sequence.py shows a case). Reporting
    one detection per distinct root would need the search to continue past the first binding, within the same
    budgets. A binding must satisfy:
    * one event per step: a single event never fills two steps;
    * the window: the span between the earliest and latest bound timestamps is at most ``window_seconds`` (inclusive);
    * order (``ordered: true``): steps follow the listed order by (timestamp, arrival rank), so equal timestamps are
      ordered by acceptance and never by event id; ``ordered: false`` has no order constraint;
    * lineage, on the graph at the time of the anchor: ``same`` is the same ``process_instance_id``; ``child_of`` is one
      observed parent link; ``descendant_of`` follows up to ``max_depth`` observed parent links (``include_self`` also
      accepts the same process). Links are followed through placeholders, never across a missing node, and nothing is
      inferred from PIDs;
    * every bound process is still in the graph. A candidate whose process left it is skipped; if the search then
      fails, ``sequence_candidates_unavailable`` counts it.
    Per step, candidates are tried nearest to the anchor's time first, then latest arrival; at most
    ``max_search_candidates`` are tried (a failed search that skipped some counts ``sequence_searches_truncated``),
    and at most ``max_search_nodes`` candidates are examined per anchor and step (``sequence_searches_exhausted``,
    with a rate-limited warning). A search that fails only because a step has no candidate is not a loss.

    Result. ``matched_at`` is the latest bound event's time (the trigger's when events arrive in order); suppression
    is keyed and timed by it. The root is selected from the process of the EARLIEST bound event (docs/02 section 4:
    ``max_ancestors`` counts from the earliest bound process). ``placeholder_process_ids`` lists placeholder bound
    processes, then placeholders on the lineage paths between bound processes. ``identity_inferred_event_ids`` lists
    bound events whose ``identity_resolution`` is not "native". ``response_target_process_id`` is the process of
    ``response.target_step``. Candidates are not consumed by a match: a later completion for the same root is a
    ``SuppressedMatch`` carrying its full binding as evidence.

Root selection (never decides whether a rule matches)
    From the process of the matching event (for a sequence, of its earliest bound event), follow the OBSERVED
    parent links up to ``context.max_ancestors`` generations, by ``process_instance_id`` only. The climb stops before
    a parent that is missing from the graph (never observed, or evicted), a placeholder, or a process on the system
    stop list (``root_stop_binaries``, compared by case-folded file name). Nothing is invented: ``root_parent_missing`` and ``root_parent_is_placeholder`` report a
    gap for A4 instead of filling it, and a stop-list boundary or the generation cap is not a gap.

Suppression (sliding window, bounded)
    State is keyed by ``(rule_id, root_process_instance_id)`` and judged by event timestamps, in whole milliseconds. A
    detection with no entry for its key returns an ``EngineMatch`` and creates one that expires
    ``incident_window_seconds`` later. While the entry is retained, a detection with ``event_time < expires_at`` returns
    a ``SuppressedMatch`` carrying the new evidence; at ``expires_at`` or later it is a new match with a new window. A
    repeat moves the expiry to the latest hit plus the window, never backwards: an event older than the latest hit is
    still suppressed, however old, and leaves the window as it was. Another rule on the same root, or the same rule on
    another root, is independent.

    Expiry is lazy. Nothing sweeps by time, because an entry that has expired for one event may still be needed by a
    late one. An entry stays until a detection for its own key finds it expired and replaces it, or the cap
    (``max_suppression_entries``) removes it, so ``state_sizes()`` counts retained entries, expired ones included. If
    adding a new key exceeds the cap, one other entry is removed. The first one, in least-recently-updated order (that of
    processing, not of timestamps), that has expired AT THE NEW EVENT'S TIME is chosen (``suppression_expired``, which
    also counts a same-key replacement). If none has, the least recently updated one goes (``suppression_evicted``, with
    a rate-limited warning: its detection may fire again). Both labels are relative to that one event's time, not to
    the whole stream: a future-dated event can remove as "expired" an entry that events arriving afterwards still
    needed, and a late event can count as evicted an entry that newer events have already outlived. Suppression is
    therefore guaranteed only while its entry is retained, never for a lifetime.

Memory (counts, not bytes)
    Every runtime structure is bounded by an ``EngineLimits`` field, per key and globally, and starts empty:
    nothing is preallocated. ``EngineLimits`` and ``RuleEngine.state_bounds()`` state *item counts* that the
    implementation must enforce. They are not byte guarantees; byte costs will be measured before being quoted.

Time
    No wall clock is read unless a ``clock`` is supplied (live mode), so replay is deterministic. With a clock, an
    event more than ``max_future_skew_seconds`` ahead of it is ignored and counted.

Rules the later steps must keep (approved A3 decisions)
    * Threshold evidence is always a valid witness inside the active sliding window: each live value is represented
      by its LATEST in-window event, never by an earlier occurrence that has expired because the value reappeared.
    * A new detection (``EngineMatch``), a repeat of an active ``(rule, root)`` (``SuppressedMatch``) and any other
      event of an open incident are three different things: A4 extends incident evidence from the second without
      creating a second rule match.
    * Every loss of detection coverage (search limits, evicted state, unsupported regex) must be countable in
      ``EngineStats`` or listed in ``disabled_rules``; counters are added together with the code that can lose.
    * State is never shared across endpoints, and no ancestry or relationship is invented for a missing or
      disconnected root: a gap is reported, not filled.
"""
from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from typing import Any, Final, Literal

from nexus_contracts import HostEvent
from nexus_contracts import RuleMatch as ContractRuleMatch

from .graph import ProcessGraph, format_utc, parse_utc
from .predicates import RegexBackend, evaluate_where, has_regex
from .rules import Lineage, Rule, RuleError, RuleSet, Step

log = logging.getLogger(__name__)

__all__ = ["DEFAULT_ROOT_STOP_BINARIES", "DisabledRule", "Disposition", "EngineLimits", "EngineMatch", "EngineResult",
           "EngineStats", "IndexEntry", "RuleEngine", "RuleEngineError", "SuppressedMatch"]

Disposition = Literal["evaluated", "duplicate", "future", "foreign", "bad_identity", "not_in_graph", "no_rules"]

DEFAULT_ROOT_STOP_BINARIES: Final = frozenset({
    "systemd", "init", "sshd", "login",
    "explorer.exe", "services.exe", "svchost.exe", "winlogon.exe", "wininit.exe", "userinit.exe",
})

_EPOCH: Final = datetime(1970, 1, 1, tzinfo=timezone.utc)
_MS: Final = timedelta(milliseconds=1)
_ENDPOINT_CHARS: Final = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")     # the contract's endpoint_id alphabet
_WARN_EVERY: Final = 1000


def _log_safely(level: int, message: str, *args: object) -> None:
    """Log a diagnostic without letting a broken log sink break detection.

    A handler or filter that raises ``Exception`` (full disk, bad formatter, ...) would otherwise propagate out of
    ``evaluate``. The error is dropped on purpose: reporting it through another logger call could fail the same way, and
    the diagnostic is only advisory (the counters in ``EngineStats`` stay the source of truth). Ordinary exceptions are
    dropped. ``MemoryError`` is a subclass of ``Exception``, so it is re-raised explicitly; ``KeyboardInterrupt`` and
    ``SystemExit`` derive from ``BaseException`` and are never caught. None of these is suppressed, and no atomicity is
    claimed when one of them interrupts evaluation.
    """
    try:
        log.log(level, message, *args)
    except MemoryError:
        raise
    except Exception:  # noqa: BLE001
        pass


def _to_ms(moment: datetime) -> int:
    """Exact integer milliseconds since the epoch (no float rounding)."""
    return (moment - _EPOCH) // _MS


# ---------------------------------------------------------------------------------------------- limits
# name: (default, minimum, ceiling). Ceilings only guard against absurd configurations.
_LIMITS: Final = {
    "max_candidates_per_step": (128, 1, 10_000),          # sequence state: events kept per rule step
    "max_search_candidates": (64, 1, 10_000),             # sequence search: candidates tried per step and anchor
    "max_search_nodes": (2_000, 1, 1_000_000),            # sequence search: nodes explored per anchor
    "max_total_candidate_events": (50_000, 1, 5_000_000),  # sequence state: all steps of all rules together
    "max_threshold_keys": (1_024, 1, 1_000_000),          # threshold state: (rule, counting root, group) keys
    "max_values_per_key": (128, 1, 100_000),              # threshold state: distinct values kept per key
    "max_threshold_bindings": (200, 1, 200),              # evidence references per match (Incident.evidence is capped at 200)
    "max_suppression_entries": (4_096, 1, 1_000_000),     # suppression state: (rule, root) entries
    "max_seen_events": (50_000, 1, 10_000_000),           # duplicate tracking horizon (best effort, not lifetime)
    "max_future_skew_seconds": (300, 0, 86_400),          # live mode: how far ahead of the clock an event may be
}
_MAX_THRESHOLD_RECORDS: Final = 5_000_000                 # max_threshold_keys * max_values_per_key


@dataclass(frozen=True)
class EngineLimits:
    """Validated, immutable bounds for the engine's runtime state. Invalid values raise ``ValueError``."""

    max_candidates_per_step: int = 128
    max_search_candidates: int = 64
    max_search_nodes: int = 2_000
    max_total_candidate_events: int = 50_000
    max_threshold_keys: int = 1_024
    max_values_per_key: int = 128
    max_threshold_bindings: int = 200
    max_suppression_entries: int = 4_096
    max_seen_events: int = 50_000
    max_future_skew_seconds: int = 300

    def __post_init__(self) -> None:
        problems: list[str] = []
        for name, (_, low, high) in _LIMITS.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                problems.append(f"{name}: must be an integer, got {value!r}")
            elif not low <= value <= high:
                problems.append(f"{name}: must be between {low} and {high}, got {value}")
        if not problems:
            if self.max_search_candidates > self.max_candidates_per_step:
                problems.append("max_search_candidates: cannot exceed max_candidates_per_step")
            if self.max_candidates_per_step > self.max_total_candidate_events:
                problems.append("max_candidates_per_step: cannot exceed max_total_candidate_events")
            if self.max_threshold_keys * self.max_values_per_key > _MAX_THRESHOLD_RECORDS:
                problems.append(f"max_threshold_keys * max_values_per_key: cannot exceed {_MAX_THRESHOLD_RECORDS}")
        if problems:
            raise ValueError("invalid EngineLimits: " + "; ".join(problems))


# ---------------------------------------------------------------------------------------------- errors, reports
@dataclass(frozen=True)
class DisabledRule:
    """A rule the engine refused to enable. ``code`` is the first reason, ``reason`` lists all of them."""

    rule_id: str
    code: Literal["regex_backend_unavailable", "min_distinct_exceeds_limit"]
    reason: str


class RuleEngineError(ValueError):
    """Strict startup found rules that cannot be enabled safely, or the configuration cannot be honoured."""

    def __init__(self, message: str, disabled: Iterable[DisabledRule] = (), load_errors: Iterable[RuleError] = ()) -> None:
        self.disabled = tuple(disabled)
        self.load_errors = tuple(load_errors)
        super().__init__(message)

    def __reduce__(self):
        return (self.__class__, (self.args[0], self.disabled, self.load_errors))


@dataclass(frozen=True)
class IndexEntry:
    """One place a rule listens: a sequence/single step, or the event type of a threshold rule."""

    rule_id: str
    kind: Literal["single", "sequence", "threshold"]
    step_index: int | None            # None for a threshold rule
    step_name: str | None


@dataclass(frozen=True)
class EngineStats:
    """A point-in-time copy of the engine's counters. Skips are categorized; none is silent."""

    events_received: int = 0
    events_evaluated: int = 0                 # accepted: passed every safeguard (the arrival count)
    events_ignored_duplicate: int = 0
    events_ignored_future: int = 0
    events_ignored_not_in_graph: int = 0
    events_ignored_no_rules: int = 0          # no enabled rule listens to this (os, event type): normal, not a loss
    events_rejected_foreign: int = 0          # another endpoint or OS than the one this engine serves
    events_rejected_bad_identity: int = 0     # process_instance_id not prefixed with the event's endpoint_id
    seen_evicted: int = 0                     # tracked event ids dropped to honour max_seen_events (the horizon moved)
    matches_emitted: int = 0                  # new EngineMatch results
    matches_suppressed: int = 0               # SuppressedMatch results (a repeat before expiry, late ones included)
    placeholder_starts_skipped: int = 0       # (rule, event) pairs refused: a seeded placeholder start satisfied the rule
    # The next two are judged at the triggering event's time only (module docstring, "Suppression"):
    suppression_expired: int = 0              # entries expired then: replaced by their key, or removed at the cap
    suppression_evicted: int = 0              # entries live then but removed at the cap: a possible duplicate match
    # Sequence coverage (module docstring, "Sequence rules"). The first two are judged at the triggering event's time.
    sequence_candidates_expired: int = 0      # dropped at max_candidates_per_step, outside the window of the event that
    #                                           caused the drop (a later, out-of-order event might still have needed it)
    sequence_candidates_evicted: int = 0      # dropped at max_candidates_per_step while inside that window: likely loss
    sequence_searches_truncated: int = 0      # (rule, event) searches that failed after skipping candidates past
    #                                           max_search_candidates: a binding among those may have been missed
    sequence_searches_exhausted: int = 0      # (rule, event) searches that stopped at max_search_nodes without a binding
    sequence_candidates_unavailable: int = 0  # (rule, event) searches that failed after skipping in-window candidates
    #                                           whose process has left the graph (evicted or removed by gc)
    rules_enabled: int = 0
    rules_disabled: int = 0
    rules_rejected_at_load: int = 0


_COUNTERS: Final = tuple(f.name for f in fields(EngineStats) if not f.name.startswith("rules_"))


# ---------------------------------------------------------------------------------------------- matches
def _freeze(mapping: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(mapping))


@dataclass(frozen=True, eq=False)
class EngineMatch:
    """A new rule detection: the ``RuleMatch{rule, bindings, root}`` of docs/02 section 4, plus the facts A4 needs.

    ``to_contract()`` produces the contract ``nexus_contracts.RuleMatch`` (rule_id, rule_version, matched_at_utc,
    bindings) and nothing else; ``root`` and the rest stay internal.
    """

    rule: Rule
    bindings: Mapping[str, str]                    # step -> event_id (a threshold uses hit_001, hit_002, ...)
    events: Mapping[str, HostEvent]                # step -> the bound event (same keys as bindings, or a subset)
    root_process_instance_id: str
    matched_at: datetime                           # time of the latest bound event (a single rule: the triggering one)
    trigger_event_id: str
    process_by_step: Mapping[str, str] = field(default_factory=dict)
    placeholder_process_ids: tuple[str, ...] = ()       # placeholder bound processes, then placeholders on lineage paths
    identity_inferred_event_ids: tuple[str, ...] = ()   # bound events whose identity_resolution is not "native"
    root_parent_is_placeholder: bool = False
    root_parent_missing: bool = False
    response_target_process_id: str | None = None
    counted_process_id: str | None = None          # threshold only
    distinct_count: int | None = None              # threshold only

    def __post_init__(self) -> None:
        _check_detection(self.bindings, self.events, self.trigger_event_id, self.matched_at, self.root_process_instance_id)
        object.__setattr__(self, "bindings", _freeze(self.bindings))
        object.__setattr__(self, "events", _freeze(self.events))
        object.__setattr__(self, "process_by_step", _freeze(self.process_by_step))
        object.__setattr__(self, "placeholder_process_ids", tuple(self.placeholder_process_ids))
        object.__setattr__(self, "identity_inferred_event_ids", tuple(self.identity_inferred_event_ids))
        if not set(self.identity_inferred_event_ids) <= set(self.bindings.values()):
            raise ValueError("identity_inferred_event_ids must be bound events")

    def to_contract(self) -> ContractRuleMatch:
        return ContractRuleMatch(rule_id=self.rule.id, rule_version=self.rule.version,
                                 matched_at_utc=format_utc(self.matched_at), bindings=dict(self.bindings))


# TODO(A4): when building incidents, handle a repeat that is older than its incident or arrives after it closed, and
# deduplicate evidence by event id (past the dedup horizon the same event can be reported again).
@dataclass(frozen=True, eq=False)
class SuppressedMatch:
    """The same rule detected again for a ``(rule, root)`` whose suppression entry has not expired at this event's
    time. It is not a new rule match; the planned incident builder (A4) is to add its evidence to that detection's
    incident."""

    rule: Rule
    root_process_instance_id: str
    matched_at: datetime
    trigger_event_id: str
    bindings: Mapping[str, str]
    events: Mapping[str, HostEvent]

    def __post_init__(self) -> None:
        _check_detection(self.bindings, self.events, self.trigger_event_id, self.matched_at, self.root_process_instance_id)
        object.__setattr__(self, "bindings", _freeze(self.bindings))
        object.__setattr__(self, "events", _freeze(self.events))


def _check_detection(bindings: Mapping[str, str], events: Mapping[str, HostEvent], trigger: str, matched_at: datetime,
                     root: str) -> None:
    if not bindings:
        raise ValueError("a detection needs at least one binding")
    for step, event_id in bindings.items():
        if not isinstance(step, str) or not isinstance(event_id, str):
            raise ValueError("bindings map step names to event ids (both strings)")
    if trigger not in bindings.values():
        raise ValueError("trigger_event_id must be one of the bound events")
    for step, bound in events.items():
        if step not in bindings or bound.event_id != bindings[step]:
            raise ValueError(f"events[{step!r}] does not match bindings[{step!r}]")
    if matched_at.tzinfo is None:
        raise ValueError("matched_at must be timezone-aware")
    if not root:
        raise ValueError("a detection needs a root process")


@dataclass(frozen=True)
class EngineResult:
    """What one ``evaluate`` call produced. ``disposition`` says what happened to the event, so a skip is never silent."""

    matches: tuple[EngineMatch, ...] = ()
    suppressed: tuple[SuppressedMatch, ...] = ()
    disposition: Disposition = "evaluated"


# ---------------------------------------------------------------------------------------------- engine
def _normalize_stop_list(names: Collection[str]) -> frozenset[str]:
    out = set()
    for name in names:
        if not isinstance(name, str) or not name.strip() or "/" in name or "\\" in name:
            raise ValueError(f"root_stop_binaries entries must be bare, non-empty file names, got {name!r}")
        out.add(name.strip().casefold())
    return frozenset(out)


def _regex_locations(rule: Rule) -> list[str]:
    """Where a rule needs a regex backend (empty when it does not), using the predicate layer's own test."""
    where: list[str] = []
    for index, step in enumerate(rule.steps):
        where += [f"steps[{index}].where[{p.field!r}]" for p in step.where if has_regex((p,))]
    if rule.threshold is not None:
        where += [f"threshold.where[{p.field!r}]" for p in rule.threshold.where if has_regex((p,))]
    return where


def _is_seeded_placeholder_start(event: HostEvent) -> bool:
    """A ``process_start`` that stands in for a process whose start was never observed (for example the psutil seed)."""
    attributes = event.attributes
    return attributes.get("placeholder") is True or attributes.get("identity_resolution") == "placeholder"


def _is_inferred(event: HostEvent) -> bool:
    """The sensor reported a process identity other than its native id (``identity_resolution`` is not "native")."""
    resolution = event.attributes.get("identity_resolution")
    return isinstance(resolution, str) and resolution != "native"


def _file_name(path: str) -> str:
    return path.replace("\\", "/").rsplit("/", 1)[-1].casefold()


@dataclass(frozen=True)
class _Root:
    process_id: str
    parent_is_placeholder: bool      # the root's parent is a placeholder: its real parent was never observed
    parent_missing: bool             # the root's parent id is known but the node is gone (never seen, or evicted)


def _select_root(graph: ProcessGraph, node: Any, max_ancestors: int, stop_binaries: frozenset[str]) -> _Root:
    """Climb the OBSERVED parent links of ``node`` by ``process_instance_id``, at most ``max_ancestors`` generations.

    The climb stops before a parent that is missing, a placeholder, already visited, or a stop-list system process.
    Nothing is invented. Only the facts about the root's own parent are reported; a stop-list boundary or the
    generation cap is a deliberate limit, not a gap.
    """
    current, visited = node, {node.process_instance_id}
    for _ in range(max_ancestors):
        parent_id = current.parent_process_instance_id
        parent = graph.get(parent_id) if parent_id is not None else None
        if (parent is None or parent.placeholder or parent.process_instance_id in visited
                or _file_name(parent.binary) in stop_binaries):
            break
        visited.add(parent.process_instance_id)
        current = parent
    parent_id = current.parent_process_instance_id
    parent = graph.get(parent_id) if parent_id is not None else None
    return _Root(current.process_instance_id, parent is not None and parent.placeholder,
                 parent_id is not None and parent is None)


# ---------------------------------------------------------------------------------------------- sequence helpers
@dataclass(frozen=True, eq=False)
class _Candidate:
    """An accepted event that satisfied one sequence step's ``where``. ``rank`` is its arrival rank (``arrival_count``
    when it was accepted); ``(t_ms, rank)`` orders events: by timestamp, equal timestamps by arrival, never by id."""

    event: HostEvent
    t_ms: int
    rank: int

    @property
    def key(self) -> tuple[int, int]:
        return self.t_ms, self.rank


class _SearchExhausted(Exception):
    """Internal: the search reached ``max_search_nodes``."""


def _lineage_path(graph: ProcessGraph, child: str, of: str, lineage: Lineage) -> list[Any] | None:
    """The intermediate nodes between ``child`` and ``of`` if ``child`` satisfies ``lineage`` relative to ``of``,
    else None. Follows OBSERVED parent links by ``process_instance_id`` (through placeholders, as ``RULE-FORMAT.md``
    says); stops at a missing node or a cycle, so no relationship is ever invented."""
    if lineage.relation == "same":
        return [] if child == of else None
    depth = 1 if lineage.relation == "child_of" else lineage.max_depth
    if child == of:
        return [] if lineage.relation == "descendant_of" and lineage.include_self else None
    path: list[Any] = []
    seen = {child}
    current = graph.get(child)
    for _ in range(depth or 0):
        if current is None:
            return None
        parent_id = current.parent_process_instance_id
        if parent_id is None or parent_id in seen:
            return None
        if parent_id == of:
            return path
        seen.add(parent_id)
        current = graph.get(parent_id)
        if current is None:
            return None
        path.append(current)
    return None


class RuleEngine:
    """Deterministic rule engine. See the module docstring for the calling contract and policies."""

    def __init__(self, rules: RuleSet | Iterable[Rule], *, limits: EngineLimits | None = None,
                 regex_backend: RegexBackend | None = None, strict: bool = False,
                 clock: Callable[[], datetime] | None = None, endpoint_id: str | None = None,
                 root_stop_binaries: Collection[str] = DEFAULT_ROOT_STOP_BINARIES) -> None:
        if limits is not None and not isinstance(limits, EngineLimits):
            raise TypeError("limits must be an EngineLimits")
        if regex_backend is not None:
            if not callable(getattr(regex_backend, "search", None)):
                raise TypeError("regex_backend must provide search(pattern, text)")
            if getattr(regex_backend, "enforces_time_limit", False) is not True:
                raise TypeError("regex_backend must declare enforces_time_limit = True: no approved production backend "
                                "exists yet and an arbitrary callable is never trusted with attacker-controlled text")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be a callable returning a timezone-aware datetime")
        if endpoint_id is not None and (not isinstance(endpoint_id, str) or not endpoint_id
                                        or not set(endpoint_id) <= _ENDPOINT_CHARS):
            raise ValueError(f"endpoint_id must be a lowercase slug (a-z, 0-9, -), got {endpoint_id!r}")
        self.limits: Final = limits or EngineLimits()
        self.strict: Final = strict
        self.root_stop_binaries: Final = _normalize_stop_list(root_stop_binaries)
        self._regex_backend = regex_backend
        self._clock = clock
        self._endpoint_id = endpoint_id
        self._os: str | None = None

        if isinstance(rules, RuleSet):
            candidates, self.load_errors = list(rules.rules), tuple(rules.errors)
        else:
            candidates, self.load_errors = list(rules), ()
        for rule in candidates:
            if not isinstance(rule, Rule):
                raise TypeError(f"rules must be validated Rule objects, got {type(rule).__name__}")
        ids = [rule.id for rule in candidates]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate rule ids: " + ", ".join(sorted({i for i in ids if ids.count(i) > 1})))

        enabled: list[Rule] = []
        disabled: list[DisabledRule] = []
        for rule in sorted(candidates, key=lambda r: r.id):
            reasons = self._disable_reasons(rule)
            if reasons:
                disabled.append(DisabledRule(rule.id, reasons[0][0], "; ".join(text for _, text in reasons)))
            else:
                enabled.append(rule)
        self.enabled_rules: Final = tuple(enabled)
        self.disabled_rules: Final = tuple(disabled)

        self._check_candidate_capacity()
        self._index = self._build_index()
        self._singles = self._build_singles()
        self._sequences = self._build_sequences()
        self._window_ms = {rule.id: round(rule.context.incident_window_seconds * 1000) for rule in self.enabled_rules}
        self._sequence_window_ms = {rule.id: round(rule.window_seconds * 1000)
                                    for rule in self.enabled_rules if rule.kind == "sequence"}
        self._step_index = {rule.id: {step.name: i for i, step in enumerate(rule.steps)}
                            for rule in self.enabled_rules if rule.kind == "sequence"}
        # Runtime state starts empty and only ever grows to its limit:
        self._seen: OrderedDict[str, None] = OrderedDict()                    # duplicate horizon (max_seen_events)
        # (rule, root) -> (last_ms, expires_ms), least recently updated first; expired entries stay until replaced/removed
        self._suppression: OrderedDict[tuple[str, str], tuple[int, int]] = OrderedDict()
        # (rule id, step index) -> event id -> candidate, in insertion order; at most max_candidates_per_step each. The
        # store deduplicates event ids itself (first arrival wins), so it stays correct after an id leaves _seen.
        self._candidates: dict[tuple[str, int], OrderedDict[str, _Candidate]] = {}
        self._counters = dict.fromkeys(_COUNTERS, 0)
        self._report_startup()

    # -- startup -----------------------------------------------------------------------------------
    def _disable_reasons(self, rule: Rule) -> list[tuple[str, str]]:
        reasons: list[tuple[str, str]] = []
        if self._regex_backend is None:
            where = _regex_locations(rule)
            if where:
                reasons.append(("regex_backend_unavailable",
                                f"uses regex at {', '.join(where)} and no safe RegexBackend is available (fail closed)"))
        if rule.threshold is not None and rule.threshold.min_distinct > self.limits.max_values_per_key:
            reasons.append(("min_distinct_exceeds_limit",
                            f"min_distinct {rule.threshold.min_distinct} exceeds max_values_per_key "
                            f"{self.limits.max_values_per_key}, so it could never fire"))
        return reasons

    def _check_candidate_capacity(self) -> None:
        slots = sum(len(rule.steps) for rule in self.enabled_rules if rule.kind == "sequence") * self.limits.max_candidates_per_step
        if slots > self.limits.max_total_candidate_events:
            raise RuleEngineError(f"the enabled sequence rules need {slots} candidate slots but max_total_candidate_events "
                                  f"is {self.limits.max_total_candidate_events}; raise the limit or reduce the rules",
                                  self.disabled_rules, self.load_errors)

    def _build_index(self) -> Mapping[tuple[str, str], tuple[IndexEntry, ...]]:
        index: dict[tuple[str, str], list[IndexEntry]] = {}
        for rule in self.enabled_rules:                              # rule ids ascending, steps in rule order
            if rule.kind == "threshold":
                listens = [(None, None, rule.threshold.event_type)]
            else:
                listens = [(i, step.name, step.event_type) for i, step in enumerate(rule.steps)]
            for os_name in sorted(rule.os):
                for step_index, step_name, event_type in listens:
                    index.setdefault((os_name, event_type), []).append(IndexEntry(rule.id, rule.kind, step_index, step_name))
        return MappingProxyType({key: tuple(index[key]) for key in sorted(index)})

    def _build_singles(self) -> Mapping[tuple[str, str], tuple[tuple[Rule, Step], ...]]:
        singles: dict[tuple[str, str], list[tuple[Rule, Step]]] = {}
        for rule in self.enabled_rules:
            if rule.kind == "single":
                step = rule.steps[0]
                for os_name in sorted(rule.os):
                    singles.setdefault((os_name, step.event_type), []).append((rule, step))
        return MappingProxyType({key: tuple(singles[key]) for key in sorted(singles)})

    def _build_sequences(self) -> Mapping[tuple[str, str], tuple[tuple[Rule, tuple[int, ...]], ...]]:
        """(os, event type) -> the sequence rules with steps of that type, in rule-id order, and those step indexes."""
        sequences: dict[tuple[str, str], list[tuple[Rule, tuple[int, ...]]]] = {}
        for rule in self.enabled_rules:                              # rule ids ascending
            if rule.kind != "sequence":
                continue
            for os_name in sorted(rule.os):
                for event_type in sorted({step.event_type for step in rule.steps}):
                    indexes = tuple(i for i, step in enumerate(rule.steps) if step.event_type == event_type)
                    sequences.setdefault((os_name, event_type), []).append((rule, indexes))
        return MappingProxyType({key: tuple(sequences[key]) for key in sorted(sequences)})

    def _report_startup(self) -> None:
        for item in self.disabled_rules:
            log.error("rule disabled at startup: %s: %s", item.rule_id, item.reason)
        for error in self.load_errors:
            log.error("rule rejected at load and not enabled: %s", error)
        if not self.enabled_rules:
            log.warning("the rule engine has no enabled rules: nothing will be detected")
        log.info("rule engine ready: %d enabled, %d disabled, %d rejected at load", len(self.enabled_rules),
                 len(self.disabled_rules), len(self.load_errors))
        if self.strict and (self.disabled_rules or self.load_errors or not self.enabled_rules):
            parts = [f"{d.rule_id} disabled: {d.reason}" for d in self.disabled_rules]
            parts += [f"rejected at load: {e}" for e in self.load_errors]
            if not self.enabled_rules and not parts:
                parts.append("no rules were given")
            message = "strict startup refused: " + " | ".join(parts)
            log.error(message)
            raise RuleEngineError(message, self.disabled_rules, self.load_errors)

    # -- introspection -----------------------------------------------------------------------------
    @property
    def endpoint_id(self) -> str | None:
        return self._endpoint_id

    def index_for(self, os_name: str, event_type: str) -> tuple[IndexEntry, ...]:
        """The enabled rule steps that listen to ``event_type`` on ``os_name``, in a deterministic order."""
        return self._index.get((os_name, event_type), ())

    def state_bounds(self) -> Mapping[str, int]:
        """Upper bounds, in ITEM COUNTS, that the implementation enforces for this rule set. Not byte estimates."""
        limits = self.limits
        sequence_steps = sum(len(rule.steps) for rule in self.enabled_rules if rule.kind == "sequence")
        has_threshold = any(rule.kind == "threshold" for rule in self.enabled_rules)
        return MappingProxyType({
            "candidate_events": sequence_steps * limits.max_candidates_per_step,
            "threshold_keys": limits.max_threshold_keys if has_threshold else 0,
            "threshold_value_records": limits.max_threshold_keys * limits.max_values_per_key if has_threshold else 0,
            "suppression_entries": limits.max_suppression_entries if self.enabled_rules else 0,
            "seen_event_ids": limits.max_seen_events if self.enabled_rules else 0,
        })

    def state_sizes(self) -> Mapping[str, int]:
        """How many items each runtime structure retains now. Structures a later step adds start at zero.

        These are retained items, not live ones: ``suppression_entries`` includes entries that have expired relative to a
        later event and have not been replaced or removed, and ``candidate_events`` counts sequence candidates in all
        step stores (one event counts once per step it satisfies), whatever their age.
        """
        return MappingProxyType({"seen_events": len(self._seen), "suppression_entries": len(self._suppression),
                                 "candidate_events": sum(len(store) for store in self._candidates.values())})

    def stats(self) -> EngineStats:
        return EngineStats(**self._counters, rules_enabled=len(self.enabled_rules),
                           rules_disabled=len(self.disabled_rules), rules_rejected_at_load=len(self.load_errors))

    @property
    def arrival_count(self) -> int:
        """Number of accepted events so far: the arrival rank that orders equal timestamps."""
        return self._counters["events_evaluated"]

    # -- evaluation --------------------------------------------------------------------------------
    def _skip(self, disposition: Disposition, counter: str, why: str, warn: bool = True) -> EngineResult:
        self._counters[counter] += 1
        if warn and (self._counters[counter] == 1 or self._counters[counter] % _WARN_EVERY == 0):
            _log_safely(logging.WARNING, "event skipped (%s, %d so far): %s", disposition, self._counters[counter], why)
        return EngineResult(disposition=disposition)

    def evaluate(self, graph: ProcessGraph, event: HostEvent) -> EngineResult:
        """Run one event, already applied to ``graph``, through the safeguards and then the single and sequence rules.

        ``disposition`` reports what happened to the event. Checks, in order: identity and endpoint isolation, future
        timestamp (live mode), presence of its process in the graph, whether any enabled rule listens to it,
        duplicate id (best effort, see the module docstring). An accepted event is evaluated against every enabled
        ``single`` and ``sequence`` rule of its OS and event type; results are in rule-id order. Each qualifying
        detection is either a new ``EngineMatch`` or, while its suppression entry has not expired at the detection's
        time, a ``SuppressedMatch``. Threshold rules are not evaluated yet. An exception from a regex backend propagates
        (a defect is not hidden).

        Exception safety: evaluation is prepared first and committed afterwards. An exception raised before the commit
        leaves suppression state, sequence candidates, detection counters, the seen record and the engine's identity untouched (only
        ``events_received`` counts the call), so the same event can be retried. A skipped event differs: its skip counter
        advances before its diagnostic is logged. Diagnostics are logged only after the state is recorded, and a logging
        handler or filter that raises ``Exception`` is ignored (see ``_log_safely``).

        The commit and the bookkeeping after it are not a transaction. ``MemoryError``, ``KeyboardInterrupt`` and
        ``SystemExit`` are not suppressed; one raised during those updates may leave them partly applied, and one raised
        at any point after the commit began loses this call's results. A retry cannot be relied on to recover them: it
        reports ``duplicate`` if the id was recorded, and otherwise a detection whose suppression entry was already
        written (and is still retained) comes back as a ``SuppressedMatch``. No atomicity is claimed from the commit
        onwards, nor against process termination.
        """
        self._counters["events_received"] += 1
        if not event.process_instance_id.startswith(f"{event.endpoint_id}:"):
            return self._skip("bad_identity", "events_rejected_bad_identity",
                              f"process_instance_id {event.process_instance_id!r} is not prefixed with {event.endpoint_id!r}")
        if self._endpoint_id is not None and event.endpoint_id != self._endpoint_id:
            return self._skip("foreign", "events_rejected_foreign",
                              f"endpoint {event.endpoint_id!r}, this engine serves {self._endpoint_id!r}")
        if self._os is not None and event.os != self._os:
            return self._skip("foreign", "events_rejected_foreign", f"os {event.os!r}, this engine serves {self._os!r}")
        if self._clock is not None:
            now = self._clock()
            if now.tzinfo is None:
                raise ValueError("clock must return a timezone-aware datetime")
            if _to_ms(parse_utc(event.timestamp_utc)) > _to_ms(now) + self.limits.max_future_skew_seconds * 1000:
                return self._skip("future", "events_ignored_future",
                                  f"{event.event_id} is stamped {event.timestamp_utc}, beyond the allowed clock skew")
        if graph.get(event.process_instance_id) is None:
            return self._skip("not_in_graph", "events_ignored_not_in_graph",
                              f"{event.event_id}: its process is not in the graph (was graph.apply called first?)",
                              warn=event.event_type != "process_exit")
        if not self.index_for(event.os, event.event_type):
            return self._skip("no_rules", "events_ignored_no_rules", "", warn=False)
        if event.event_id in self._seen:
            return self._skip("duplicate", "events_ignored_duplicate", "", warn=False)

        matches, suppressed, warnings = self._evaluate_rules(graph, event)

        # TODO(A8): recover from a fatal error after the commit: the results are lost and a retry may not restore them.
        if self._endpoint_id is None:                                   # only an accepted event may fix the identity
            self._endpoint_id = event.endpoint_id
        self._os = event.os
        self._seen[event.event_id] = None
        if len(self._seen) > self.limits.max_seen_events:
            self._seen.popitem(last=False)
            self._counters["seen_evicted"] += 1
        self._counters["events_evaluated"] += 1
        for message, args in warnings:                                  # state is final: only now may logging run
            _log_safely(logging.WARNING, message, *args)
        return EngineResult(tuple(matches), tuple(suppressed))

    # -- single and sequence rules -----------------------------------------------------------------
    def _evaluate_rules(self, graph: ProcessGraph, event: HostEvent
                        ) -> tuple[list[EngineMatch], list[SuppressedMatch], list[tuple[str, tuple[object, ...]]]]:
        """Returns the matches, the suppressed repeats, and the warnings (message, args) the caller logs afterwards."""
        matches: list[EngineMatch] = []
        suppressed: list[SuppressedMatch] = []
        warnings: list[tuple[str, tuple[object, ...]]] = []
        singles = self._singles.get((event.os, event.event_type), ())
        sequences = self._sequences.get((event.os, event.event_type), ())
        if not singles and not sequences:
            return matches, suppressed, warnings
        seeded = event.event_type == "process_start" and _is_seeded_placeholder_start(event)
        node = graph.get(event.process_instance_id)                     # present: evaluate() checked
        moment = parse_utc(event.timestamp_utc)
        t_ms = _to_ms(moment)
        inferred = (event.event_id,) if _is_inferred(event) else ()

        # Phase 1 - prepare. The work a defect could break (predicates, which may run a regex backend; the sequence
        # search; root selection; building the result objects) happens here, and nothing in the engine is mutated: an
        # exception leaves no trace beyond events_received, so a retry of the same event behaves as if the failed call
        # never happened. Both possible results are built because whether a hit is new or a repeat is only known when it
        # is committed. The search only reads the candidate stores; the event joins them in phase 2.
        prepared: list[tuple[str, tuple[str, str], int, int, EngineMatch, SuppressedMatch]] = []
        skipped_placeholders = 0
        inserts: list[tuple[tuple[str, int], _Candidate, int]] = []    # (store key, candidate, rule window in ms)
        losses: list[str] = []                                          # counter names, one per failed (rule, event)
        for rule, step in singles:                                      # rule ids ascending
            if not evaluate_where(step.where, event, regex_backend=self._regex_backend):
                continue
            if seeded:                                                  # a synthetic start was never observed
                skipped_placeholders += 1
                continue
            root = _select_root(graph, node, rule.context.max_ancestors, self.root_stop_binaries)
            bindings, bound = {step.name: event.event_id}, {step.name: event}
            fresh = EngineMatch(
                rule=rule, bindings=bindings, events=bound, root_process_instance_id=root.process_id, matched_at=moment,
                trigger_event_id=event.event_id, process_by_step={step.name: node.process_instance_id},
                placeholder_process_ids=(node.process_instance_id,) if node.placeholder else (),
                identity_inferred_event_ids=inferred,
                root_parent_is_placeholder=root.parent_is_placeholder, root_parent_missing=root.parent_missing,
                response_target_process_id=node.process_instance_id if rule.response is not None else None)
            repeat = SuppressedMatch(rule=rule, root_process_instance_id=root.process_id, matched_at=moment,
                                     trigger_event_id=event.event_id, bindings=bindings, events=bound)
            prepared.append((rule.id, (rule.id, root.process_id), t_ms, self._window_ms[rule.id], fresh, repeat))

        rank = self._counters["events_evaluated"]                       # this event's arrival rank once accepted
        anchor = _Candidate(event, t_ms, rank)
        for rule, step_indexes in sequences:                            # rule ids ascending
            satisfied = [i for i in step_indexes
                         if evaluate_where(rule.steps[i].where, event, regex_backend=self._regex_backend)]
            if not satisfied:
                continue
            if seeded:                                                  # never a candidate, never an anchor
                skipped_placeholders += 1
                continue
            window_ms = self._sequence_window_ms[rule.id]
            inserts += [((rule.id, i), anchor, window_ms) for i in satisfied]
            found, missed = None, set()
            for i in satisfied:                                         # first step position that completes, in order
                found, why = self._search_sequence(graph, rule, i, anchor)
                missed |= why
                if found is not None:
                    break
            if found is None:
                losses += sorted(missed)
                continue
            fresh, repeat, latest_ms = self._sequence_results(graph, rule, found, event.event_id)
            prepared.append((rule.id, (rule.id, fresh.root_process_instance_id), latest_ms, self._window_ms[rule.id],
                             fresh, repeat))
        prepared.sort(key=lambda item: item[0])                         # results in rule-id order (stable)

        # Phase 2 - commit. Only dictionary and counter bookkeeping on values prepared above; no predicate, graph,
        # object construction or logging runs here (warnings are returned and logged after the event is recorded). It is
        # not atomic: a fatal exception such as MemoryError can still interrupt it part way (see evaluate).
        self._counters["placeholder_starts_skipped"] += skipped_placeholders
        for name in losses:
            self._counters[name] += 1
            if name == "sequence_searches_exhausted" and (self._counters[name] == 1 or self._counters[name] % _WARN_EVERY == 0):
                warnings.append(("sequence search stopped at max_search_nodes (%d) without a binding (%d so far); a "
                                 "detection may have been missed", (self.limits.max_search_nodes, self._counters[name])))
        for store_key, candidate, window_ms in inserts:
            evicted_so_far = self._store_candidate(store_key, candidate, window_ms)
            if evicted_so_far is not None:
                warnings.append(("sequence candidate store %s step %d is full (%d events): an in-window candidate was "
                                 "evicted (%d so far); a detection may be missed",
                                 (store_key[0], store_key[1], self.limits.max_candidates_per_step, evicted_so_far)))
        for _, key, hit_ms, window_ms, fresh, repeat in prepared:
            repeat_hit, evicted_so_far = self._register_hit(key, hit_ms, window_ms)
            if evicted_so_far is not None:
                warnings.append(("suppression state is full (%d entries): a live entry was evicted (%d so far); "
                                 "repeats of that detection may fire again",
                                 (self.limits.max_suppression_entries, evicted_so_far)))
            if repeat_hit:
                self._counters["matches_suppressed"] += 1
                suppressed.append(repeat)
            else:
                self._counters["matches_emitted"] += 1
                matches.append(fresh)
        return matches, suppressed, warnings

    # -- sequence rules ----------------------------------------------------------------------------
    def _search_sequence(self, graph: ProcessGraph, rule: Rule, anchor_index: int, anchor: _Candidate
                         ) -> tuple[dict[int, _Candidate] | None, set[str]]:
        """Bind every step of ``rule`` with ``anchor`` fixed at ``anchor_index``; never mutates the engine.

        Returns ``(binding, missed)``: the binding (step index -> candidate) or None, and the coverage-loss counter
        names that apply when no binding was found. Only reads the candidate stores and the graph.
        """
        window = self._sequence_window_ms[rule.id]
        ordered = bool(rule.ordered)
        limit = self.limits.max_search_candidates
        truncated = unavailable = False
        pools: dict[int, list[_Candidate]] = {}
        for i in range(len(rule.steps)):
            if i == anchor_index:
                continue
            pool, skipped = [], False
            for candidate in self._candidates.get((rule.id, i), {}).values():
                if candidate.event.event_id == anchor.event.event_id or abs(candidate.t_ms - anchor.t_ms) > window:
                    continue
                if ordered and (candidate.key < anchor.key) != (i < anchor_index):
                    continue
                if graph.get(candidate.event.process_instance_id) is None:     # its process left the graph
                    skipped = True
                    continue
                pool.append(candidate)
            if not pool:                         # this step cannot be bound: other steps' limits did not matter
                return None, {"sequence_candidates_unavailable"} if skipped else set()
            unavailable |= skipped
            pool.sort(key=lambda c: (abs(c.t_ms - anchor.t_ms), -c.rank))     # nearest in time, then latest arrival
            if len(pool) > limit:
                truncated = True
                del pool[limit:]
            pools[i] = pool

        order = [i for i in range(len(rule.steps)) if i != anchor_index]
        assigned: dict[int, _Candidate] = {anchor_index: anchor}
        budget = [self.limits.max_search_nodes]

        def fits(i: int, candidate: _Candidate) -> bool:
            if any(other.event.event_id == candidate.event.event_id for other in assigned.values()):
                return False                     # one event binds one step
            times = [other.t_ms for other in assigned.values()]
            if max(*times, candidate.t_ms) - min(*times, candidate.t_ms) > window:
                return False
            if ordered and any((j < i) != (other.key < candidate.key) for j, other in assigned.items()):
                return False
            trial = {**assigned, i: candidate}
            for s, step in enumerate(rule.steps):
                if step.lineage is None:
                    continue
                t = self._step_index[rule.id][step.lineage.of]
                if i not in (s, t) or s not in trial or t not in trial:
                    continue
                if _lineage_path(graph, trial[s].event.process_instance_id, trial[t].event.process_instance_id,
                                 step.lineage) is None:
                    return False
            return True

        def bind(position: int) -> bool:
            if position == len(order):
                return True
            i = order[position]
            for candidate in pools[i]:
                if budget[0] <= 0:
                    raise _SearchExhausted
                budget[0] -= 1
                if fits(i, candidate):
                    assigned[i] = candidate
                    if bind(position + 1):
                        return True
                    del assigned[i]
            return False

        try:                                     # each lineage edge is checked when its second end is bound
            if bind(0):
                return dict(assigned), set()
            missed: set[str] = set()
        except _SearchExhausted:
            missed = {"sequence_searches_exhausted"}
        if truncated:
            missed.add("sequence_searches_truncated")
        if unavailable:
            missed.add("sequence_candidates_unavailable")
        return None, missed

    def _sequence_results(self, graph: ProcessGraph, rule: Rule, found: Mapping[int, _Candidate], trigger_id: str
                          ) -> tuple[EngineMatch, SuppressedMatch, int]:
        """Build both possible results of a complete binding, and return the latest bound event time in ms."""
        steps = rule.steps
        bound = {steps[i].name: found[i].event for i in range(len(steps))}
        bindings = {name: event.event_id for name, event in bound.items()}
        process_by_step = {name: event.process_instance_id for name, event in bound.items()}
        earliest = min(found.values(), key=lambda c: c.key)
        latest = max(found.values(), key=lambda c: c.key)
        root = _select_root(graph, graph.get(earliest.event.process_instance_id), rule.context.max_ancestors,
                            self.root_stop_binaries)
        placeholders: list[str] = []
        for i in range(len(steps)):                                     # placeholder bound processes, in step order
            pid = found[i].event.process_instance_id
            if graph.get(pid).placeholder and pid not in placeholders:
                placeholders.append(pid)
        for i, step in enumerate(steps):                                # then placeholders on lineage paths
            if step.lineage is None:
                continue
            t = self._step_index[rule.id][step.lineage.of]
            path = _lineage_path(graph, found[i].event.process_instance_id, found[t].event.process_instance_id,
                                 step.lineage) or []
            placeholders += [n.process_instance_id for n in path if n.placeholder and n.process_instance_id not in placeholders]
        matched_at = parse_utc(latest.event.timestamp_utc)
        target = process_by_step[rule.response.target_step] if rule.response is not None else None
        fresh = EngineMatch(
            rule=rule, bindings=bindings, events=bound, root_process_instance_id=root.process_id, matched_at=matched_at,
            trigger_event_id=trigger_id, process_by_step=process_by_step, placeholder_process_ids=tuple(placeholders),
            identity_inferred_event_ids=tuple(e.event_id for e in bound.values() if _is_inferred(e)),
            root_parent_is_placeholder=root.parent_is_placeholder, root_parent_missing=root.parent_missing,
            response_target_process_id=target)
        repeat = SuppressedMatch(rule=rule, root_process_instance_id=root.process_id, matched_at=matched_at,
                                 trigger_event_id=trigger_id, bindings=bindings, events=bound)
        return fresh, repeat, latest.t_ms

    def _store_candidate(self, key: tuple[str, int], candidate: _Candidate, window_ms: int) -> int | None:
        """Add an accepted event to one step's store; never logs. Returns the live-eviction count when a warning is due.

        The first arrival of an event id wins. Above ``max_candidates_per_step`` the OLDEST candidate by (timestamp,
        arrival) is removed, the new one included: it is ``expired`` if it was already outside the rule window at the
        new event's time, else ``evicted`` (a detection that needed it may be missed). Nothing is removed by time alone.
        """
        store = self._candidates.setdefault(key, OrderedDict())
        if candidate.event.event_id in store:
            return None
        store[candidate.event.event_id] = candidate
        if len(store) <= self.limits.max_candidates_per_step:
            return None
        victim_id, victim = min(store.items(), key=lambda item: item[1].key)
        del store[victim_id]
        if victim.t_ms < candidate.t_ms - window_ms:
            self._counters["sequence_candidates_expired"] += 1
            return None
        self._counters["sequence_candidates_evicted"] += 1
        count = self._counters["sequence_candidates_evicted"]
        return count if count == 1 or count % _WARN_EVERY == 0 else None

    def _register_hit(self, key: tuple[str, str], t_ms: int, window_ms: int) -> tuple[bool, int | None]:
        """Record a detection for ``key`` at event time ``t_ms``; never logs.

        Returns ``(repeat, evicted_so_far)``: ``repeat`` is True if the key's entry has not expired at ``t_ms``
        (suppressed); ``evicted_so_far`` is the live-eviction count when this call should be reported (first, then every
        ``_WARN_EVERY``-th), else None. "Expired" and "live" below always mean at ``t_ms``.
        """
        entry = self._suppression.get(key)
        if entry is not None and t_ms < entry[1]:                        # not expired: the window is half-open
            last = max(entry[0], t_ms)                                    # a late event never moves the window backwards
            self._suppression[key] = (last, last + window_ms)
            self._suppression.move_to_end(key)
            return True, None
        if entry is not None:                                             # expired at t_ms: a new window starts
            self._counters["suppression_expired"] += 1
            del self._suppression[key]
        self._suppression[key] = (t_ms, t_ms + window_ms)
        if len(self._suppression) > self.limits.max_suppression_entries:
            victim = next((k for k, (_, expires) in self._suppression.items() if expires <= t_ms and k != key), None)
            if victim is not None:                                        # prefer an entry that is expired at t_ms
                del self._suppression[victim]
                self._counters["suppression_expired"] += 1
            else:                                                         # live at t_ms, lost: a repeat may fire again
                self._suppression.popitem(last=False)
                self._counters["suppression_evicted"] += 1
                if self._counters["suppression_evicted"] == 1 or self._counters["suppression_evicted"] % _WARN_EVERY == 0:
                    return False, self._counters["suppression_evicted"]
        return False, None
