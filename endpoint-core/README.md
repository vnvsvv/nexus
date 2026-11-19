# endpoint-core (`nexus_endpoint_core`)

OS-agnostic core shared by the Linux and Windows agents (`docs/01-ARCHITECTURE.md` section 2.2). Input: `HostEvent`
objects from an adapter. Output (later tasks): `Incident` and `ResponseResult` objects.
Contracts are imported from `nexus_contracts`, never re-defined here.

**Status: task A1 only.** Implemented: `graph.py` (process graph). Not yet: rules, incident builder, store,
transport, response gate, agent loop, replay, config (tasks A2 to A9, see `docs/06-SIX-WEEK-PLAN.md`).

## Install (Python 3.11+, from the repository root)
```powershell
python -m venv .venv ; .venv\Scripts\activate          # Linux: . .venv/bin/activate
pip install -e .                                       # nexus_contracts first: it is not on PyPI
pip install -e "./endpoint-core[dev]"
```

## Run the tests
```powershell
pytest endpoint-core            # needs the editable install above; no path tricks
pytest -q tests/                # contracts/tools tests (what a bare `pytest` at the root runs)
python tools/validate_fixtures.py
```
The rule-engine fixtures (`contracts/fixtures/rules/*`) are executed by `validate_fixtures.py` only after
`replay.py` exists (task A9). Until then the graph tests only build graphs from those event files.

Test with fixtures, run against the mock server, run in the lab: not applicable until the agent loop (A8) and the
adapters exist; this README is extended then. Configuration (`.env.example`) arrives with `config.py` (A8).

## Process graph (`nexus_endpoint_core.graph`)
```python
from nexus_endpoint_core import ProcessGraph, format_utc, parse_utc
g = ProcessGraph(retention_seconds=600, max_nodes=50_000, max_events=100_000,
                 max_events_per_node=2_000, auto_gc_interval=1_000, clock=None)
node = g.apply(host_event)        # -> ProcessNode, or None for the exit of a process never seen
g.ancestors(id, max_depth=5); g.descendants(id, max_depth=5, since=None)
g.lineage_contains(candidate, root, max_depth, include_self=False)
g.events_for(node_ids, event_types, window=(lo, hi)); g.gc(now=None)
```
`graph.ProcessNode` is the runtime node (children, event references). It is not the contract
`nexus_contracts.ProcessNode`; the incident builder (A4) converts. Nodes compare by identity and are hashable.

* **Identity.** Keyed by `process_instance_id` only. PID is display/fallback (`live_by_pid`, `live_node_for_pid`).
* **Placeholders.** An unknown parent, or an event from a process whose start was never seen, creates a node with
  `placeholder=True`, `binary="<unknown>"` (or the event's binary), no start time, no invented parent. A real start
  later upgrades it in place and keeps children, events and every field the start does not repeat. An adapter can
  seed a placeholder with `attributes.placeholder=true` or `identity_resolution="placeholder"` on a `process_start`.
* **Exits and PID reuse.** `end_time_utc` comes only from an observed exit. If a newer start takes over a PID whose
  holder never exited, the old node gets `superseded_by` / `superseded_at_utc` and stays `end_time_utc=None`;
  an older start arriving late never takes the PID. `node.is_live` (false for exited and superseded) is required
  before acting on a process, and `node.dead_since` drives retention.
* **`is_live` is necessary, not sufficient (decision for the response gate, task A6, not implemented yet).** The
  graph only knows what the sensor reported: a placeholder's PID is a guess, an ambiguous placeholder is just
  un-indexed and keeps `is_live`, and an exit may not have been observed yet. Before terminating anything the
  gate must also verify against the OS, at action time, that the PID is still owned by the same process
  (executable path, plus start time where available). `ProcessNode.order` is a runtime-only arrival rank; it is
  never part of `HostEvent`, `Incident` or any schema.
* **Bounds.** Event cache `max_events` and per-node references `max_events_per_node` are strict and always agree
  (evicting an event removes the reference). Nodes: `gc()` removes dead nodes older than `retention_seconds` (kept
  while they still have retained children), then enforces `max_nodes` (dead leaves, dead parents, then oldest live).
  `gc()` runs by itself every `auto_gc_interval` applied events, so the graph exceeds `max_nodes` by at most
  `2 * auto_gc_interval` between runs. `auto_gc_interval=0` leaves gc to the caller (one warning if it is neglected).
  In the live agent pass `clock=lambda: datetime.now(timezone.utc)`; replay omits it and uses the newest event time.
* **Ordering.** `events_for` returns events by (timestamp, arrival order) and `descendants` orders siblings by
  (start time, order first seen). IDs are never tie-breakers: Tetragon exec ids and `new_event_id()` are random, so an
  ID sort would scramble events that share a millisecond.
* **Atomic rejection.** `apply` parses `timestamp_utc` and `process_start_time_utc` before touching anything; a
  malformed value raises `ValueError` and leaves the graph (nodes, cache, PID index, clocks) exactly as it was.
* **PID ownership.** A real start always takes a PID from a placeholder, whatever the placeholder's apparent age; a
  placeholder never takes a PID a real process holds. A seeded placeholder's synthetic start event is replaced by the
  authoritative one, so `events_for(..., ["process_start"])` returns the real start (subject to cache retention).
* **Time.** `parse_utc` / `format_utc` convert to and from `YYYY-MM-DDTHH:MM:SS.mmmZ`.

### Known limitations
Single-threaded; sensor event order is assumed (an exit before its start is ignored); the event cache is FIFO, not
LRU, and may evict an old start event of a long-lived process (the SQLite store keeps full copies, task A5); a
forced eviction can leave a child pointing at a removed parent (`ancestors` stops there; the incident builder must
report `PARENT_NOT_OBSERVED`); `apply` raises `ValueError` on a malformed timestamp, so the agent loop wraps it per
event; datetimes passed in must be timezone-aware.
