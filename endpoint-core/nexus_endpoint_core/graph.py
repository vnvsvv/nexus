"""Process graph (docs/02-CORRELATION.md sections 1-2).

Identity
    Nodes are keyed by ``process_instance_id`` only. A PID is stored for display and indexed in
    ``live_by_pid`` as a fallback, but it never decides which node an event belongs to, so PID reuse
    cannot attach events or children to the wrong process.

    ``ProcessNode`` here is the *runtime* node (children, per-process event references). It is not the
    ``nexus_contracts.ProcessNode`` that appears inside an incident; the incident builder converts.

Liveness (never invents an exit)
    ``end_time_utc`` is set only from an observed ``process_exit``. When a newer process takes over a PID
    whose previous holder never reported an exit, the old node gets ``superseded_by`` and
    ``superseded_at_utc`` (the new holder's start time) and ``end_time_utc`` stays ``None``.
    ``is_live`` is False for both exited and superseded nodes; it is a *necessary* condition for acting on
    a process (use it, not ``end_time_utc``), but never a *sufficient* one. The graph only knows what the
    sensor reported: a placeholder's PID is a guess, an ambiguous placeholder is merely un-indexed and stays
    ``is_live``, and an exit may simply not have been observed yet. The response gate (A6) must therefore
    also verify, against the operating system at action time, that the PID is still owned by the same
    process (executable path, and start time where available) before it terminates anything.
    ``dead_since`` is the time retention counts from.

Bounds and garbage collection (nothing grows without limit)
    * ``max_events``: strict cap on the event cache (FIFO eviction). Evicting an event also removes the
      reference to it from its node, so node references and the cache never disagree.
    * ``max_events_per_node``: strict cap on each per-node reference list; the oldest reference and its
      cached event are dropped first.
    * ``max_nodes`` / ``retention_seconds``: enforced by ``gc()``. ``gc()`` runs automatically at the start
      of ``apply`` every ``auto_gc_interval`` applied events (default 1000), so between runs the graph can
      exceed ``max_nodes`` by at most ``2 * auto_gc_interval`` nodes (an event creates at most one node
      plus one placeholder parent). The agent may also call ``gc()`` on a timer.
    * ``auto_gc_interval=0`` disables the automatic run: the caller then owns ``gc()``, and ``apply``
      logs one warning if the graph passes twice ``max_nodes``.
    * Retention removes dead nodes older than ``retention_seconds``, but keeps a dead node while it still
      has retained children so lineage stays intact. When ``max_nodes`` forces eviction the order is: dead
      nodes without children (oldest ``dead_since`` first), dead nodes with children, then live nodes
      (oldest first). A removed parent leaves its children's ``parent_process_instance_id`` dangling;
      ``ancestors`` simply stops there. If a node with that same ``process_instance_id`` is created again
      (a later event, or a new child naming it), it regains those surviving children: they are remembered
      in an orphan index, so no scan of the graph is needed and the index never outgrows the node count.
    * "Now" for ``gc`` is ``clock()`` when a clock is supplied (use wall-clock UTC in the live agent, so one
      future-dated event cannot expire everything), else the newest event time (deterministic for replay).

Ordering and atomicity
    * Equal timestamps keep meaningful order: ``events_for`` sorts by (timestamp, arrival order) and
      ``descendants`` by (start time, order in which the graph first saw the process). Event and process IDs
      are never used as tie-breakers: they can be random (Tetragon exec ids, ``new_event_id``).
    * ``apply`` is atomic with respect to bad input: every timestamp it needs (``timestamp_utc`` and the
      optional ``process_start_time_utc``) is parsed before anything is changed, so a ``ValueError`` leaves
      the graph exactly as it was (including the event clock and the gc counter).

Known limitations (see also endpoint-core/README.md)
    * Single-threaded; callers must not share a graph across threads.
    * ``apply`` returns the affected node, but a later ``apply`` (automatic gc) or ``gc`` may remove it.
    * Events are assumed to arrive in sensor order. An exit that arrives before its start is ignored
      and the start then leaves the node open. Clock skew can yield ``end_time_utc < start_time_utc``.
    * The event cache is FIFO, not true LRU: reads do not refresh an entry.
    * A placeholder's ``pid`` is 0 when unknown; 0 is never indexed. Placeholders have no start time.
    * ``apply`` raises ``ValueError`` for a malformed ``timestamp_utc``; callers handle it per event.
      A timestamp without an offset is read as UTC.
    * All datetimes passed in (``since``, ``window``, ``now``) must be timezone-aware.
"""
from __future__ import annotations

import itertools
import logging
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable

from nexus_contracts import HostEvent

log = logging.getLogger(__name__)

UNKNOWN_BINARY = "<unknown>"
PLACEHOLDER = "placeholder"

_REF_LIST = {"file_access": "file_events", "network_connect": "network_events", "dns_query": "dns_events"}


def parse_utc(value: str) -> datetime:
    """ISO-8601 (trailing ``Z`` or an offset) to a timezone-aware UTC datetime. No offset means UTC."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_utc(dt: datetime) -> str:
    """Datetime to the contract timestamp form ``YYYY-MM-DDTHH:MM:SS.mmmZ`` (UTC, milliseconds, ``Z``).

    A naive datetime is read as UTC; sub-millisecond precision is truncated, like
    ``nexus_contracts.utc_now_iso``. Inverse of ``parse_utc`` at millisecond precision.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return f"{dt:%Y-%m-%dT%H:%M:%S}.{dt.microsecond // 1000:03d}Z"


@dataclass(eq=False)   # identity semantics: hashable, usable in sets/dicts, never compared by value
class ProcessNode:
    process_instance_id: str
    parent_process_instance_id: str | None
    pid: int                                  # 0 = unknown (placeholder parent without a known ppid)
    binary: str                               # "<unknown>" for a placeholder we know nothing about
    first_seen_utc: datetime                  # time of the first event that mentioned this process
    command_line: str | None = None
    user: str | None = None
    ppid: int | None = None
    start_time_utc: datetime | None = None    # None when never observed (placeholders); not invented
    end_time_utc: datetime | None = None      # only ever set from an observed process_exit
    sha256: str | None = None
    placeholder: bool = False
    identity_resolution: str | None = None    # opaque sensor string: "native" | "pid_start_time" | "placeholder" | ...
    superseded_by: str | None = None          # instance id that took over this PID without an exit being seen
    superseded_at_utc: datetime | None = None
    start_event_id: str | None = None
    exit_event_id: str | None = None
    children: set[str] = field(default_factory=set, repr=False)
    file_events: list[str] = field(default_factory=list, repr=False)       # ids of cached events, oldest first
    network_events: list[str] = field(default_factory=list, repr=False)
    dns_events: list[str] = field(default_factory=list, repr=False)
    rule_hits: list[str] = field(default_factory=list, repr=False)
    order: int = field(default=0, repr=False)   # runtime-only arrival rank (never part of HostEvent/Incident); tie-breaker

    @property
    def sort_time(self) -> datetime:
        return self.start_time_utc or self.first_seen_utc

    @property
    def dead_since(self) -> datetime | None:
        """When this process is known to be gone: the observed exit, else when its PID was taken over."""
        return self.end_time_utc or self.superseded_at_utc

    @property
    def is_live(self) -> bool:
        """False once exited or superseded. Required before any action, never enough on its own: the response
        gate must also re-verify PID ownership and process identity against the OS (see module docstring)."""
        return self.end_time_utc is None and self.superseded_by is None


def _wants_placeholder(ev: HostEvent) -> bool:
    a = ev.attributes
    return a.get("placeholder") is True or a.get("identity_resolution") == PLACEHOLDER


def _keep(new, old):
    """A later event may add information but must not erase what is already known."""
    return new if new is not None else old


class ProcessGraph:
    def __init__(self, retention_seconds: int = 600, max_nodes: int = 50_000, max_events: int = 100_000,
                 max_events_per_node: int = 2_000, auto_gc_interval: int = 1_000,
                 clock: Callable[[], datetime] | None = None) -> None:
        if min(retention_seconds, max_nodes, max_events, max_events_per_node) < 1 or auto_gc_interval < 0:
            raise ValueError("limits must be >= 1 (auto_gc_interval >= 0)")
        self.retention_seconds = retention_seconds
        self.max_nodes = max_nodes
        self.max_events = max_events
        self.max_events_per_node = max_events_per_node
        self.auto_gc_interval = auto_gc_interval
        self._clock = clock
        self.nodes: dict[str, ProcessNode] = {}
        self.events: OrderedDict[str, HostEvent] = OrderedDict()   # bounded FIFO; full copies live in the store
        self.live_by_pid: dict[int, str] = {}
        self.latest_event_time: datetime | None = None
        # Children whose parent was force-evicted (parent id -> child ids). Lets a restored parent regain its
        # children in O(its orphans) without scanning the graph. Never larger than the number of nodes.
        self._orphans: dict[str, set[str]] = {}
        self._order: dict[str, int] = {}          # event_id -> arrival rank; same keys as ``events``
        self._event_seq = itertools.count()
        self._node_seq = itertools.count()
        self._since_gc = 0
        self._warned_over_capacity = False

    # ------------------------------------------------------------------ queries
    def __len__(self) -> int:
        return len(self.nodes)

    def __contains__(self, process_instance_id: object) -> bool:
        return process_instance_id in self.nodes

    def get(self, process_instance_id: str) -> ProcessNode | None:
        return self.nodes.get(process_instance_id)

    def live_node_for_pid(self, pid: int) -> ProcessNode | None:
        """Current live node for a PID. Display/fallback only; never use it to key an event."""
        node = self.nodes.get(self.live_by_pid.get(pid, ""))
        return node if node is not None and node.is_live else None

    def ancestors(self, process_instance_id: str, max_depth: int = 5) -> list[ProcessNode]:
        """Parents, nearest first, up to max_depth. Placeholders are included; stops at a missing node."""
        out: list[ProcessNode] = []
        seen = {process_instance_id}
        cur = self.nodes.get(process_instance_id)
        while cur is not None and len(out) < max_depth:
            parent_id = cur.parent_process_instance_id
            if parent_id is None or parent_id in seen:
                break
            seen.add(parent_id)
            cur = self.nodes.get(parent_id)
            if cur is not None:
                out.append(cur)
        return out

    def descendants(self, process_instance_id: str, max_depth: int = 5, since: datetime | None = None) -> list[ProcessNode]:
        """Breadth-first; siblings by (start time, arrival order of first sight). ``since`` (aware) keeps only nodes that started
        (or were first seen) at or after it; the walk still passes through older nodes because a late
        child can hang below an early one."""
        out: list[ProcessNode] = []
        seen = {process_instance_id}
        frontier = deque([(process_instance_id, 0)])
        while frontier:
            cur_id, depth = frontier.popleft()
            cur = self.nodes.get(cur_id)
            if cur is None or depth >= max_depth:
                continue
            kids = sorted((self.nodes[c] for c in cur.children if c in self.nodes and c not in seen),
                          key=lambda n: (n.sort_time, n.order))
            for kid in kids:
                seen.add(kid.process_instance_id)
                if since is None or kid.sort_time >= since:
                    out.append(kid)
                frontier.append((kid.process_instance_id, depth + 1))
        return out

    def lineage_contains(self, candidate: str, root: str, max_depth: int, include_self: bool = False) -> bool:
        """True if ``candidate`` is a descendant of ``root`` within max_depth generations (or is ``root``
        itself when include_self). Follows parent links by instance id, through placeholders.
        ``child_of`` is ``max_depth=1``; ``same`` is ``candidate == root`` with ``include_self``."""
        cur = self.nodes.get(candidate)
        if cur is None:
            return False
        if candidate == root:
            return include_self
        seen = {candidate}
        for _ in range(max_depth):
            parent_id = cur.parent_process_instance_id
            if parent_id is None or parent_id in seen:
                return False
            if parent_id == root:
                return True
            seen.add(parent_id)
            cur = self.nodes.get(parent_id)
            if cur is None:
                return False
        return False

    def events_for(self, node_ids: Iterable[str], types: Iterable[str],
                   window: tuple[datetime | None, datetime | None] | None = None) -> list[HostEvent]:
        """Cached events of the given nodes and event types, optionally inside an inclusive (aware) time
        window, ordered by (timestamp, arrival order), without duplicates: events with equal timestamps come
        back in the order they were applied, never in event-id order. Evicted events are not returned."""
        wanted = set(types)
        lo, hi = window if window else (None, None)
        found: dict[str, tuple[datetime, HostEvent]] = {}
        for node_id in node_ids:
            node = self.nodes.get(node_id)
            if node is None:
                continue
            ids: list[str] = []
            if "process_start" in wanted and node.start_event_id:
                ids.append(node.start_event_id)
            if "process_exit" in wanted and node.exit_event_id:
                ids.append(node.exit_event_id)
            if "file_access" in wanted:
                ids += node.file_events
            if "network_connect" in wanted:
                ids += node.network_events
            if "dns_query" in wanted:
                ids += node.dns_events
            for event_id in ids:
                ev = self.events.get(event_id)
                if ev is None or event_id in found:
                    continue
                t = parse_utc(ev.timestamp_utc)
                if (lo is not None and t < lo) or (hi is not None and t > hi):
                    continue
                found[event_id] = (t, ev)
        return [ev for _, ev in sorted(found.values(), key=lambda p: (p[0], self._order.get(p[1].event_id, 0)))]

    # ------------------------------------------------------------------ apply
    def apply(self, ev: HostEvent) -> ProcessNode | None:
        """Apply one event and return the affected node.

        Returns None only for a ``process_exit`` of a process the graph has never seen (ignored, per
        docs/02 section 1). A duplicate ``event_id`` still in the cache is a no-op returning the node.
        Raises ``ValueError`` for a malformed ``timestamp_utc`` or ``process_start_time_utc``; both are
        parsed first, so a rejected event changes nothing. Automatic gc, when due, runs next, so the
        returned node is in the graph until the next call.
        """
        ts = parse_utc(ev.timestamp_utc)
        started = parse_utc(ev.process_start_time_utc) if ev.process_start_time_utc else None
        self._auto_gc()
        if self.latest_event_time is None or ts > self.latest_event_time:
            self.latest_event_time = ts
        if ev.event_id in self.events:
            return self.nodes.get(ev.process_instance_id)

        if ev.event_type == "process_exit":
            node = self.nodes.get(ev.process_instance_id)
            if node is None:
                log.debug("ignoring process_exit for unknown process %s", ev.process_instance_id)
                return None
            if node.end_time_utc is None:            # a duplicate exit keeps the first observation
                node.end_time_utc = ts
                node.exit_event_id = ev.event_id
                self._store_event(ev)
            self._unindex(node)
            return node

        if ev.event_type == "process_start":
            return self._apply_start(ev, ts, started)

        node = self.nodes.get(ev.process_instance_id)
        if node is None:
            node = self._create_from_event(ev, ts, started, placeholder=True)
        else:
            self._fill_missing(node, ev, started)
        if ev.parent_process_instance_id and node.parent_process_instance_id is None:
            self._link_parent(node, ev.parent_process_instance_id, ev.ppid, ts, replace=False)
        refs: list[str] = getattr(node, _REF_LIST[ev.event_type])
        refs.append(ev.event_id)
        self._store_event(ev)
        if len(refs) > self.max_events_per_node:      # strict per-node cap: drop the oldest reference and its event
            self._pop_event(refs.pop(0))
        return node

    def _apply_start(self, ev: HostEvent, ts: datetime, started: datetime | None) -> ProcessNode:
        placeholder_ev = _wants_placeholder(ev)
        node = self.nodes.get(ev.process_instance_id)
        replace_parent = False
        if node is None:
            node = self._create_from_event(ev, ts, started, placeholder=placeholder_ev)
            node.command_line = ev.command_line
            node.sha256 = ev.sha256
            node.identity_resolution = PLACEHOLDER if placeholder_ev else ev.attributes.get("identity_resolution")
            replace_parent = True
        elif node.placeholder and not placeholder_ev:
            # The real start arrived after we had to guess: upgrade in place, keep children, events and
            # anything already known that this event does not repeat.
            self._unindex(node)
            node.pid = ev.pid
            node.ppid = _keep(ev.ppid, node.ppid)
            if ev.binary != UNKNOWN_BINARY:
                node.binary = ev.binary
            node.command_line = _keep(ev.command_line, node.command_line)
            node.user = _keep(ev.user, node.user)
            node.sha256 = _keep(ev.sha256, node.sha256)
            node.start_time_utc = started or ts
            node.placeholder = False
            node.identity_resolution = ev.attributes.get("identity_resolution")
            if node.start_event_id is not None:       # a seeded placeholder's synthetic start gives way to the real one
                self._pop_event(node.start_event_id)
                node.start_event_id = None
            replace_parent = True
        else:
            self._fill_missing(node, ev, started)
        if node.start_event_id is None:               # a repeated start of a known instance is not stored again
            node.start_event_id = ev.event_id
            self._store_event(ev)
        if ev.parent_process_instance_id:
            self._link_parent(node, ev.parent_process_instance_id, ev.ppid, ts, replace=replace_parent)
        self._index(node, override=not node.placeholder)   # a real start supersedes an older holder of the PID
        return node

    # ------------------------------------------------------------------ gc
    def gc(self, now: datetime | None = None) -> int:
        """Remove dead nodes older than ``retention_seconds``, then enforce ``max_nodes``. Returns the
        number of nodes removed. See the module docstring for ordering and for when gc runs on its own."""
        self._since_gc = 0
        now = now or self._now()
        removed = 0
        if now is not None:
            cutoff = now - timedelta(seconds=self.retention_seconds)

            def expired(n: ProcessNode) -> bool:
                dead = n.dead_since
                return dead is not None and dead < cutoff and not n.children

            work = [n for n in self.nodes.values() if expired(n)]
            while work:
                node = work.pop()
                if node.process_instance_id not in self.nodes:
                    continue
                parent = self.nodes.get(node.parent_process_instance_id or "")
                self._remove(node)
                removed += 1
                if parent is not None and expired(parent):
                    work.append(parent)

        excess = len(self.nodes) - self.max_nodes
        if excess > 0:
            for node in sorted(self.nodes.values(), key=self._eviction_key)[:excess]:
                self._remove(node)
                removed += 1
        return removed

    @staticmethod
    def _eviction_key(n: ProcessNode) -> tuple:
        dead = n.dead_since
        if dead is not None:
            return (1 if n.children else 0, dead, n.order)    # dead leaves, then dead parents
        return (2, n.sort_time, n.order)                      # live nodes, oldest first

    def _now(self) -> datetime | None:
        return self._clock() if self._clock is not None else self.latest_event_time

    def _auto_gc(self) -> None:
        if self.auto_gc_interval:
            self._since_gc += 1
            if self._since_gc >= self.auto_gc_interval:
                self.gc()
        elif len(self.nodes) > 2 * self.max_nodes and not self._warned_over_capacity:
            self._warned_over_capacity = True
            log.warning("process graph holds %d nodes (max_nodes=%d) and auto_gc_interval=0: call gc()",
                        len(self.nodes), self.max_nodes)

    # ------------------------------------------------------------------ internals
    def _store_event(self, ev: HostEvent) -> None:
        if ev.event_id not in self.events:
            self._order[ev.event_id] = next(self._event_seq)       # arrival rank: the tie-breaker for equal timestamps
        self.events[ev.event_id] = ev
        while len(self.events) > self.max_events:
            _, old = self.events.popitem(last=False)
            self._order.pop(old.event_id, None)
            self._forget(old)

    def _pop_event(self, event_id: str) -> None:
        self.events.pop(event_id, None)
        self._order.pop(event_id, None)

    def _forget(self, ev: HostEvent) -> None:
        """An event left the cache: drop the node's reference so references never outlive the event."""
        node = self.nodes.get(ev.process_instance_id)
        if node is None:
            return
        if ev.event_type == "process_start":
            if node.start_event_id == ev.event_id:
                node.start_event_id = None
        elif ev.event_type == "process_exit":
            if node.exit_event_id == ev.event_id:
                node.exit_event_id = None
        else:
            refs: list[str] = getattr(node, _REF_LIST[ev.event_type])
            try:
                refs.remove(ev.event_id)
            except ValueError:
                pass

    def _create_from_event(self, ev: HostEvent, ts: datetime, started: datetime | None, placeholder: bool) -> ProcessNode:
        node = ProcessNode(
            process_instance_id=ev.process_instance_id,
            parent_process_instance_id=None,
            pid=ev.pid,
            ppid=ev.ppid,
            binary=ev.binary,
            user=ev.user,
            first_seen_utc=ts,
            start_time_utc=started or (ts if ev.event_type == "process_start" and not placeholder else None),
            placeholder=placeholder,
            identity_resolution=PLACEHOLDER if placeholder else None,
            order=next(self._node_seq),
        )
        self._register(node)
        if placeholder:
            self._index(node, override=False)
        return node

    def _register(self, node: ProcessNode) -> None:
        """Add a node to the graph. If children of this same process_instance_id survived an earlier forced
        eviction of the node, re-attach them, so the reverse edge matches the children's ``parent`` ids."""
        self.nodes[node.process_instance_id] = node
        for child_id in self._orphans.pop(node.process_instance_id, ()):
            child = self.nodes.get(child_id)
            if child is not None and child.parent_process_instance_id == node.process_instance_id:
                node.children.add(child_id)

    def _unorphan(self, child_id: str, parent_id: str | None) -> None:
        kids = self._orphans.get(parent_id) if parent_id is not None else None
        if kids is not None:
            kids.discard(child_id)
            if not kids:
                del self._orphans[parent_id]

    @staticmethod
    def _fill_missing(node: ProcessNode, ev: HostEvent, started: datetime | None) -> None:
        """Add facts an event carries that the node lacks. Never overwrites an existing value."""
        if node.binary == UNKNOWN_BINARY and ev.binary != UNKNOWN_BINARY:
            node.binary = ev.binary
        node.user = _keep(node.user, ev.user)
        node.ppid = _keep(node.ppid, ev.ppid)
        node.command_line = _keep(node.command_line, ev.command_line)
        node.sha256 = _keep(node.sha256, ev.sha256)
        if node.start_time_utc is None and started is not None:
            node.start_time_utc = started

    def _link_parent(self, child: ProcessNode, parent_id: str, ppid: int | None, ts: datetime, replace: bool) -> None:
        if parent_id == child.process_instance_id:
            return
        current = child.parent_process_instance_id
        if current == parent_id:
            if current in self.nodes:
                self.nodes[current].children.add(child.process_instance_id)
            return
        if current is not None and not replace:
            log.debug("keeping first parent %s of %s; ignoring %s", current, child.process_instance_id, parent_id)
            return
        if self._is_lineage_of(parent_id, child.process_instance_id):
            log.warning("refusing parent link %s -> %s: it would create a cycle", parent_id, child.process_instance_id)
            return
        if current is not None:
            if current in self.nodes:
                self.nodes[current].children.discard(child.process_instance_id)
            else:
                self._unorphan(child.process_instance_id, current)
        parent = self.nodes.get(parent_id)
        if parent is None:
            # Honest placeholder: we know the parent existed, nothing else about it.
            parent = ProcessNode(
                process_instance_id=parent_id, parent_process_instance_id=None, pid=ppid or 0, ppid=None,
                binary=UNKNOWN_BINARY, first_seen_utc=ts, placeholder=True, identity_resolution=PLACEHOLDER,
                order=next(self._node_seq))
            self._register(parent)
            self._index(parent, override=False)
        parent.children.add(child.process_instance_id)
        child.parent_process_instance_id = parent_id

    def _is_lineage_of(self, candidate_ancestor: str, node_id: str) -> bool:
        """True if node_id is candidate_ancestor itself or one of its ancestors (linking would loop)."""
        seen: set[str] = set()
        cur: str | None = candidate_ancestor
        while cur is not None and cur not in seen:
            if cur == node_id:
                return True
            seen.add(cur)
            n = self.nodes.get(cur)
            cur = n.parent_process_instance_id if n else None
        return False

    def _index(self, node: ProcessNode, override: bool) -> None:
        """Maintain ``live_by_pid``. ``override`` is True only for a real process_start.

        A newer real start takes over the PID and marks the old holder superseded. An older start that
        arrives late never steals the PID; it is the one marked superseded (when the holder is real).
        Placeholders (override False) only ever claim a free PID.
        """
        if node.pid <= 0 or not node.is_live:
            return
        holder_id = self.live_by_pid.get(node.pid)
        if holder_id is None or holder_id == node.process_instance_id:
            self.live_by_pid[node.pid] = node.process_instance_id
            return
        if not override:
            return
        holder = self.nodes.get(holder_id)
        if holder is not None and not holder.placeholder and holder.sort_time > node.sort_time:
            if node.superseded_by is None:
                node.superseded_by = holder.process_instance_id        # a real holder started later: we are the older one
                node.superseded_at_utc = holder.sort_time
            return
        # A placeholder only guesses at its PID (a parent hint, or a process whose start we missed), so a real
        # start always takes the PID from it. The placeholder is declared superseded only when it is provably
        # older; when its apparent age is ambiguous it is merely un-indexed (is_live stays as it was).
        if holder is not None and holder.is_live and holder.sort_time <= node.sort_time:
            holder.superseded_by = node.process_instance_id            # no exit was seen; do not invent one
            holder.superseded_at_utc = node.sort_time
        self.live_by_pid[node.pid] = node.process_instance_id

    def _unindex(self, node: ProcessNode) -> None:
        if self.live_by_pid.get(node.pid) == node.process_instance_id:   # a reused PID may belong to a newer node
            del self.live_by_pid[node.pid]

    def _remove(self, node: ProcessNode) -> None:
        self.nodes.pop(node.process_instance_id, None)
        self._unindex(node)
        parent = self.nodes.get(node.parent_process_instance_id or "")
        if parent is not None:
            parent.children.discard(node.process_instance_id)
        else:
            self._unorphan(node.process_instance_id, node.parent_process_instance_id)
        if node.children:                              # forced eviction: remember who lost their parent
            survivors = {c for c in node.children if c in self.nodes}
            if survivors:
                self._orphans.setdefault(node.process_instance_id, set()).update(survivors)
        for event_id in (node.start_event_id, node.exit_event_id, *node.file_events, *node.network_events, *node.dns_events):
            if event_id:
                self._pop_event(event_id)
