# endpoint-core (`nexus_endpoint_core`)

OS-agnostic core shared by the Linux and Windows agents (`docs/01-ARCHITECTURE.md` section 2.2). Input: `HostEvent`
objects from an adapter. Output (later tasks): `Incident` and `ResponseResult` objects.
Contracts are imported from `nexus_contracts`, never re-defined here.

**Status: tasks A1 and A2.** Implemented: `graph.py` (process graph) and `rules.py` (rule loading, validation and
pre-compilation). Not yet: rule evaluation (A3), incident builder, store, transport, response gate, agent loop, replay,
config (tasks A3 to A9, see `docs/06-SIX-WEEK-PLAN.md`).

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
`replay.py` exists (task A9). Until then the graph tests only build graphs from those event files, and the rules
tests load and validate the seven shipped rules without evaluating them.

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

### Known limitations of the graph
Single-threaded; sensor event order is assumed (an exit before its start is ignored); the event cache is FIFO, not
LRU, and may evict an old start event of a long-lived process (the SQLite store keeps full copies, task A5); a
forced eviction can leave a child pointing at a removed parent (`ancestors` stops there; the incident builder must
report `PARENT_NOT_OBSERVED`; if the same `process_instance_id` comes back, the parent regains its surviving children); `apply` raises `ValueError` on a malformed timestamp, so the agent loop wraps it per
event; datetimes passed in must be timezone-aware.

## Rules loader (`nexus_endpoint_core.rules`, task A2)
Turns `contracts/rules/*.yaml` (format: `contracts/rules/RULE-FORMAT.md`) into immutable, validated rule objects with
regexes and CIDR networks compiled once. It does **not** evaluate rules; matching is task A3.
```python
from nexus_endpoint_core import load_rules, load_rule, load_attack_mapping
rules = load_rules("contracts/rules")                   # RuleSet: .rules (sorted by id), .errors, .get(id), .for_os("linux")
rules = load_rules(path, strict=True)                   # raises RuleLoadError if any rule is rejected or none were found
rules = load_rules(path, attack_mapping="contracts/attack-mapping.yaml")   # explicit mapping: required
rule = load_rule("contracts/rules/NX-WIN-001.yaml")     # one file; raises RuleError listing every problem
rule = load_rule(path, attack_mapping=mapping_or_path)  # a path or an already loaded AttackMapping, as in load_rules
```
`Rule` fields mirror the YAML: `id, version, title, kind, os, severity, technique_ids, references, window_seconds,
ordered, context, steps, threshold, response, source`. A `Step` has `name, event_type, where, lineage`; `where` is a tuple
of `Predicate(field, op, operand, compiled)` (several operators on one field are separate predicates, all ANDed);
`Lineage(relation, of, max_depth, include_self)`; `ThresholdSpec(event_type, where, scope, distinct_field, group_by,
min_distinct, window_seconds)` with `scope = Scope(kind, depth)`; `ResponseSpec(action, target_step)`. All models are
frozen and every collection is a tuple. `ordered` is always a bool on a sequence (omitted means `True`) and `None` on
single and threshold rules, so an evaluator can never read an omitted value as "unordered". `RuleError`,
`RuleLoadError` and `AttackMappingError` can be copied and pickled.

**Policy.** A rejected rule is logged at ERROR (file name plus the path of every problem), listed in `RuleSet.errors`,
and the other rules still load; `strict=True` raises one `RuleLoadError` instead. A missing rules directory, and a
required-but-missing or malformed ATT&CK mapping, raise immediately in both modes (`FileNotFoundError`,
`AttackMappingError`). A file must be named `<id>.yaml`, so duplicate ids cannot load: a stray copy is rejected naming
the file it should be, and the correctly named original stays authoritative. Within one rule, field-level problems are
reported first and cross-field problems (lineage targets, kind consistency, response) once those are fixed.

**Resilience.** One file can never abort a load. Files are limited to 64 KiB, YAML nesting to 20 levels (checked on the
parser's non-recursive event stream before the recursive constructor runs), no anchors or aliases, one document;
regex compilation failures (`re.error`, `OverflowError`, `RecursionError`) reject the rule. As a last line of defence
`load_rules` turns any other `Exception` from one file into a `RuleError` with `unexpected=True` (the original is its
`__cause__`), logs it with its traceback and continues; `strict=True` raises `RuleLoadError`. `KeyboardInterrupt` and
`SystemExit` are never caught, and `load_rule` itself does not hide a defect.

**ATT&CK mapping.** An explicit `attack_mapping=` is always required. Otherwise `<rules dir>/../attack-mapping.yaml` is
used when it exists. When it does not exist the check is skipped for an independent directory, but never for the
repository layout `contracts/rules`, where a missing mapping raises `AttackMappingError`. With a mapping, each rule's
`technique_ids` must exist in it and equal its list for that rule id.

**What is validated** (decisions where `RULE-FORMAT.md` is silent; none changes a contract): unknown keys are errors; `context`
requires `max_descendant_depth` and `incident_window_seconds` (`max_ancestors` defaults to 3); `window_seconds` is required
for single/sequence and forbidden for threshold; `ordered` only on sequences (default true); a single rule has one step and
a sequence 2 to 5; every step needs a non-empty `where`; field paths are the `RULE-FORMAT.md` list plus `attributes.<key>`
and must suit the step's `event_type`; operators must suit the field (text operators on free text, CIDR on `network.dst_ip`,
`gte`/`lte` on ports; the text operators also work on `network.dst_ip`) and closed-set values (`file.operation`, `network.direction`, `network.protocol`) are checked against
the contract (a Windows-only rule may spell them in any case, since `equals` is case-insensitive there, and the stored value is
the canonical spelling; a rule that covers Linux must match exactly); CIDRs must have no host bits set; regexes are at most 500
characters and pass the screen below; lineage targets must be existing,
other steps (earlier ones in an ordered rule, no cycles otherwise) and `descendant_of` needs `max_depth` 1 to 10;
`response.target_step` must be a step, the rule's severity at least `high`, and thresholds cannot respond. YAML is read
with a safe loader that rejects duplicate keys, anchors/aliases, extra documents, deep nesting, files over 64 KiB and
non-UTF-8 text.

### Regex safety (read before implementing A3)
The `regex` operator is kept, but Python's `re` backtracks and has **no timeout**: `(a+)+$` needs seconds on 26 characters of
attacker-controlled text and doubles with each one. Loading applies a conservative lexical screen. It is a **heuristic, not a
guarantee** (it uses no private `re` internals): it refuses nested unbounded repetition (`(a+)+`, `(.*a)*`, `(\d+\.)+`),
repeated groups whose alternatives may overlap (`(a|ab)*`, `(a|b+)+`; `(foo|bar)+` is fine), repeat counts above 1000 or
nested counts multiplying above 10,000, verbose `(?x)` patterns and syntax it cannot analyse. Atomic groups `(?>...)` and
possessive quantifiers (Python 3.11+) are the escape hatch. It does **not** catch polynomial blow-ups such as `.*.*x`, it
refuses some harmless patterns, and it proves nothing about an accepted one. No shipped rule uses `regex`.

**Mandatory for A3** (the loader cannot provide these): never run a rule regex on event text in the evaluation path without
a hard time bound; **input truncation alone is not sufficient**, since an exponential pattern is already slow at about 30
characters. A real timeout is an architectural decision that is deliberately not taken here:
* **(a) the third-party `regex` package** with `search(..., timeout=...)`: one new binary dependency, nearly source compatible;
* **(b) RE2** (`google-re2`): linear time by construction, new dependency, but no back-references or look-around, so some
  accepted patterns would have to be refused;
* **(c) a worker process** killed at a deadline: no dependency, but more machinery and latency; the only way to bound stdlib `re`;
* **(d) refuse to evaluate `regex` predicates** until one of the above is chosen.

### Known limitations and open questions (A2)
* **`scope: lineage(N)`** is parsed and its depth kept, but `RULE-FORMAT.md` does not define what it traverses
  (descendants only, or ancestors and descendants). Nothing here interprets it, and **its exact evaluation semantics must
  be confirmed before A3 evaluates threshold rules with that scope**. No shipped rule uses it.
* Windows string normalization (case, slashes) is applied at match time in A3, not here, because `NX-ANY-001` covers both
  OSes; operands are kept as authored (enum values canonicalized as described). Regexes carry no flags and run with
  `re.search`; see **Regex safety** above for what A3 must add.
* Five of the seven shipped rules have no sibling fixtures yet (`RULE-FORMAT.md` asks for them); they are an A3 deliverable.
* The ATT&CK check mirrors `tools/validate_fixtures.py` (exact ordered list equality).
