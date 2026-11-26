# endpoint-core (`nexus_endpoint_core`)

OS-agnostic core shared by the Linux and Windows agents (`docs/01-ARCHITECTURE.md` section 2.2). Input: `HostEvent`
objects from an adapter. Intended output: `Incident` and `ResponseResult` objects, **neither of which is produced
yet**. Contracts are imported from `nexus_contracts`, never re-defined here.

## Status
Tasks A1, A2 and A3a are in the package. It is a set of library building blocks, **not a working agent or a complete
detection pipeline**.

**Implemented and tested**
* A1, `graph.py`: the process graph.
* A2, `rules.py`: rule loading, validation and pre-compilation.
* A3a, `engine.py` and `predicates.py`: the rule engine's startup policy and per-event safeguards, evaluation of
  `kind: single` rules, root selection, event-id deduplication and suppression.

**Implemented, with limitations that matter**
* Only single-event rules detect: see [Detection coverage](#detection-coverage-today).
* `regex` predicates fail closed because no approved regex backend exists.
* Known limits of the [graph](#known-limitations-of-the-graph), the
  [rule loader](#known-limitations-and-open-questions-a2) and the [engine](#known-limitations-of-the-engine-a3a).

**Not implemented**
* A3b: sequence and threshold detection.
* Incident builder (A4), SQLite store (A5), transport, response gate (A6), agent loop and configuration (A8) and
  replay (A9). See `docs/01-ARCHITECTURE.md` section 2.2 and `docs/06-SIX-WEEK-PLAN.md`.

## Detection coverage today
> **Only `kind: single` rules detect anything.** Sequence and threshold rules load, are enabled and are indexed, but
> they are **not evaluated**: their events are accepted and counted, and produce no match. `strict=True` does not
> change this. It checks that startup is safe and that no rule was disabled or rejected, not that every enabled rule
> can detect.

| Shipped rule | OS | Kind | Evaluated now |
|---|---|---|---|
| `NX-ANY-001` | linux, windows | single | yes, see below |
| `NX-LIN-001` | linux | sequence | **no** |
| `NX-LIN-002` | linux | threshold | **no** |
| `NX-LIN-003` | linux | sequence | **no** |
| `NX-WIN-001` | windows | sequence | **no** |
| `NX-WIN-002` | windows | single | yes |
| `NX-WIN-003` | windows | threshold | **no** |

* Of the shipped rules that apply to each OS, **Linux evaluates 1 of 4** and **Windows 2 of 4**.
* `NX-ANY-001` needs the boolean `attributes.ti_hash_hit: true` on a `process_start`, set before `graph.apply`.
* **Linux:** the engine can evaluate `NX-ANY-001` and matches a Linux event that carries that attribute. Nothing in this
  repository populates it yet (the agent, A8, is meant to), and the other three shipped Linux rules need A3b. So
  **automated Linux detection is not yet operational end to end**: on unenriched events no shipped Linux rule matches,
  and nothing connects the Linux adapter to the engine.
* A rule that uses `regex` is disabled (and `strict=True` refuses to start) unless an approved, time-bounded backend
  is passed. `RegexBackend` is only the interface: **no implementation exists**. No shipped rule uses `regex`.

## Install (Python 3.11+, from the repository root)
```powershell
python -m venv .venv ; .venv\Scripts\activate          # Linux: . .venv/bin/activate
pip install -e .                                       # nexus_contracts first: it is not on PyPI
pip install -e "./endpoint-core[dev]"
```

## Run
There is nothing to start: this is a library with no executable (see the engine's [usage example](#usage-example)).
Configuration (`.env.example`) arrives with `config.py` (A8).

## Test with fixtures
```powershell
pytest endpoint-core            # needs the editable install above; no path tricks
pytest -q tests/                # contracts/tools tests (what a bare `pytest` at the root runs)
python tools/validate_fixtures.py
```
**A successful `validate_fixtures.py` does not mean the rule fixtures were executed.** It runs them only if
`nexus_endpoint_core.replay` can be imported, and that module does not exist yet (A9). Until then it prints
`nexus_endpoint_core not installed; rule fixtures schema-checked only`, even with the package installed, and still
exits successfully: the events in `contracts/fixtures/rules/` are checked against the schema and the models, and the
expected rule matches are not run. Its ML feature-parity check is likewise skipped when `nexus_ml` is not installed.

What the package's own tests do with the rule fixtures:
* only `NX-LIN-001` and `NX-WIN-001` have them, and both are sequence rules, which are not evaluated yet;
* the graph tests build graphs from the events, the predicate tests check that each step is satisfied by exactly its
  expected event (and that the benign set satisfies only the first step), and an engine test replays the benign set to
  check dispositions;
* **no test runs a fixture as a detection**. The single rules are tested with events built inside the tests.

CI (`.github/workflows/ci.yml`) uses Ubuntu and Python 3.11 and also runs the Linux endpoint tests, which need Linux.

**Recorded CI result.** GitHub Actions passed on commit `0a5f4d9`, both on the branch and merged with `main`
(2026-11-26, Ubuntu, Python 3.11): 792 `endpoint-core` tests, 27 repository tests and 103 Linux endpoint tests. These
counts are a snapshot of that run; for later commits, see the checks on the commit or pull request.

* The Linux endpoint tests use recorded Tetragon samples and synthetic data. Passing them is **not** a test against a
  live Tetragon sensor or a real endpoint, and none of them feeds the adapter's output to the rule engine.
* Rule fixture replay and the ML feature-parity check were **skipped** in those runs, as described above.

## Run against the mock server, run in the lab
Not applicable yet: nothing in this package talks to a server, and there is no agent loop (A8) to connect an adapter
to it. The adapter in `endpoint-linux/` runs on its own and does not call the rule engine.

## Process graph (`nexus_endpoint_core.graph`)
```python
from nexus_endpoint_core import ProcessGraph, format_utc, parse_utc
g = ProcessGraph(retention_seconds=600, max_nodes=50_000, max_events=100_000,
                 max_events_per_node=2_000, auto_gc_interval=1_000, clock=None)
node = g.apply(host_event)        # -> ProcessNode, or None for the exit of a process never seen
g.ancestors(id, max_depth=5); g.descendants(id, max_depth=5, since=None)
g.lineage_contains(candidate, root, max_depth, include_self=False)
g.events_for(node_ids, types, window=(lo, hi)); g.gc(now=None)
```
`graph.ProcessNode` is the runtime node (children, event references). It is not the contract
`nexus_contracts.ProcessNode`; the planned incident builder (A4) will convert. Nodes compare by identity and are
hashable.

* **Identity.** Keyed by `process_instance_id` only. PID is display/fallback (`live_by_pid`, `live_node_for_pid`).
* **Placeholders.** An unknown parent, or an event from a process whose start was never seen, creates a node with
  `placeholder=True`, `binary="<unknown>"` (or the event's binary), no invented parent, and no start time unless an
  event reports `process_start_time_utc`. A real start later upgrades it in place and keeps children, events and every
  field the start does not repeat. An adapter can seed a placeholder with `attributes.placeholder=true` or
  `attributes.identity_resolution="placeholder"` on a `process_start`.
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
LRU, and may evict an old start event of a long-lived process (the planned SQLite store, A5, is to keep full copies); a
forced eviction can leave a child pointing at a removed parent (`ancestors` stops there; the planned incident builder
must report `PARENT_NOT_OBSERVED`; if the same `process_instance_id` comes back, the parent regains its surviving
children); `apply` raises `ValueError` on a malformed timestamp, so the caller (the agent loop, A8) must handle it per
event; datetimes passed in must be timezone-aware.

## Rules loader (`nexus_endpoint_core.rules`, task A2)
Turns `contracts/rules/*.yaml` (format: `contracts/rules/RULE-FORMAT.md`) into immutable, validated rule objects with
regexes and CIDR networks compiled once. The loader never looks at events: evaluation is done by the
[rule engine](#rule-engine-a3a), so far for `single` rules only.
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

**ATT&CK mapping.** An explicit `attack_mapping=` must exist and be well formed. Without one,
`<rules dir>/../attack-mapping.yaml` is used when it exists. When it does not exist the check is skipped for an
independent directory, but never for the repository layout `contracts/rules`, where a missing mapping raises
`AttackMappingError`. With a mapping, each rule's `technique_ids` must exist in it and equal its list for that rule id.

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

### Regex safety (read before adding a regex backend)
The `regex` operator is kept, but Python's `re` backtracks and has **no timeout**: `(a+)+$` needs seconds on 26 characters of
attacker-controlled text and doubles with each one. Loading applies a conservative lexical screen. It is a **heuristic, not a
guarantee** (it uses no private `re` internals): it refuses nested unbounded repetition (`(a+)+`, `(.*a)*`, `(\d+\.)+`),
repeated groups whose alternatives may overlap (`(a|ab)*`, `(a|b+)+`; `(foo|bar)+` is fine), repeat counts above 1000 or
nested counts multiplying above 10,000, verbose `(?x)` patterns and syntax it cannot analyse. Atomic groups `(?>...)` and
possessive quantifiers (Python 3.11+) are the escape hatch. It does **not** catch polynomial blow-ups such as `.*.*x`, it
refuses some harmless patterns, and it proves nothing about an accepted one. No shipped rule uses `regex`.

**Mandatory at evaluation time** (the loader cannot provide this): never run a rule regex on event text in the evaluation
path without a hard time bound; **input truncation alone is not sufficient**, since an exponential pattern is already slow
at about 30 characters. How to provide a real timeout is an architectural decision that has **not** been taken. Until it
is, the engine behaves as option (d) below.
* **(a) the third-party `regex` package** with `search(..., timeout=...)`: one new binary dependency, nearly source compatible;
* **(b) RE2** (`google-re2`): linear time by construction, new dependency, but no back-references or look-around, so some
  accepted patterns would have to be refused;
* **(c) a worker process** killed at a deadline: no dependency, but more machinery and latency; the only way to bound stdlib `re`;
* **(d) refuse to evaluate `regex` predicates** until one of the above is chosen.

### Known limitations and open questions (A2)
* **`scope: lineage(N)`** is parsed and its depth kept, but `RULE-FORMAT.md` does not define what it traverses
  (descendants only, or ancestors and descendants). Nothing interprets it, and **its exact evaluation semantics must
  be confirmed before A3b evaluates threshold rules with that scope**. No shipped rule uses it.
* Windows string normalization (case, slashes) is applied at match time (`predicates.py`), not here, because
  `NX-ANY-001` covers both OSes; operands are kept as authored (enum values canonicalized as described). Regexes are
  compiled without flags, but the engine never runs the compiled pattern: an approved backend would receive the pattern
  text and the raw event text (`RULE-FORMAT.md` defines `regex` as Python `re.search`).
* Five of the seven shipped rules have no sibling fixtures yet (`RULE-FORMAT.md` asks for them); they are still owed
  from task A3. Neither single rule has one.
* The ATT&CK check mirrors `tools/validate_fixtures.py` (exact ordered list equality).

## Rule engine (A3a)
`engine.py` evaluates one `HostEvent` at a time against the loaded rules, using the process graph; `predicates.py` tests
a step's `where` against an event. (`docs/01-ARCHITECTURE.md` section 2.2 places evaluation in `rules.py`; it is
implemented in these two modules.) The engine returns **results**, not incidents: it builds no `Incident`, stores and
sends nothing, and performs **no response**. The docstring of `engine.py` is the detailed reference.

These names are importable from `nexus_endpoint_core`: `RuleEngine`, `EngineLimits`, `EngineStats`, `EngineResult`,
`EngineMatch`, `SuppressedMatch`, `DisabledRule`, `RuleEngineError`, `DEFAULT_ROOT_STOP_BINARIES`, `RegexBackend` and
`RegexTimeout`. The annotation types `Disposition` and `IndexEntry` come from `nexus_endpoint_core.engine`; the
predicate helpers stay in `nexus_endpoint_core.predicates`.

### Usage example
Run from the repository root. It builds events by hand; in an agent they would come from an adapter.
```python
from nexus_contracts import HostEvent
from nexus_endpoint_core import ProcessGraph, RuleEngine, load_rules

ENDPOINT = "windows-vm-01"


def start(number: int, name: str, binary: str, parent: str | None = None) -> HostEvent:
    return HostEvent(
        event_id=f"{ENDPOINT}:evt-{number:012x}", endpoint_id=ENDPOINT, os="windows", event_type="process_start",
        timestamp_utc=f"2026-11-15T10:00:{number:02d}.000Z", process_instance_id=f"{ENDPOINT}:{name}",
        parent_process_instance_id=f"{ENDPOINT}:{parent}" if parent else None, pid=1000 + number, binary=binary)


rules = load_rules("contracts/rules", strict=True)
graph = ProcessGraph()
engine = RuleEngine(rules, endpoint_id=ENDPOINT, strict=True)

events = [start(1, "shell", "C:\\Windows\\System32\\cmd.exe"),
          start(2, "first", "C:\\Lab\\bin\\lab-test.exe", parent="shell"),
          start(3, "second", "C:\\Lab\\bin\\lab-test.exe", parent="shell")]

for event in events:
    try:
        graph.apply(event)                      # 1. always first
    except ValueError:                          #    malformed timestamp: the graph is unchanged, so do not evaluate
        continue
    result = engine.evaluate(graph, event)      # 2. immediately afterwards, once per event
    print(result.disposition, len(result.matches), len(result.suppressed))
    for match in result.matches:
        print("  new:", match.rule.id, match.root_process_instance_id, match.to_contract().bindings)
    for repeat in result.suppressed:
        print("  repeat:", repeat.rule.id, repeat.trigger_event_id)
```
Output:
```text
evaluated 0 0
evaluated 1 0
  new: NX-WIN-002 windows-vm-01:shell {'bin': 'windows-vm-01:evt-000000000002'}
evaluated 0 1
  repeat: NX-WIN-002 windows-vm-01:evt-000000000003
```

### Construction
```python
RuleEngine(rules, *, limits=None, regex_backend=None, strict=False, clock=None, endpoint_id=None,
           root_stop_binaries=DEFAULT_ROOT_STOP_BINARIES)
```
| Argument | Meaning |
|---|---|
| `rules` | A `RuleSet`, or an iterable of validated `Rule` objects. Only a `RuleSet` carries the loader's rejected rules. |
| `limits` | An `EngineLimits`; the defaults when omitted. |
| `regex_backend` | An object with `search(pattern, text) -> bool` that declares `enforces_time_limit = True`. None exists today; the declaration is not proof, so a backend needs its own review. |
| `strict` | Refuse to start instead of running with reduced coverage (below). |
| `clock` | Live mode: returns a timezone-aware `datetime`. Omit for deterministic replay. |
| `endpoint_id` | The endpoint served (lowercase letters, digits, `-`). **A live deployment must pass it.** |
| `root_stop_binaries` | Bare file names that root selection never climbs into. Replaces the default list; `()` disables it. |

A wrong argument type raises `TypeError`; a bad `endpoint_id` or stop-list entry, or duplicate rule ids, raise
`ValueError`. `RuleEngineError` (a `ValueError`) covers the startup refusals below and carries `.disabled` and
`.load_errors`.

### Startup: `strict` and disabled rules
A rule is **disabled** when it cannot be evaluated safely: it uses `regex` and there is no approved backend
(`regex_backend_unavailable`), or its `min_distinct` exceeds `max_values_per_key` (`min_distinct_exceeds_limit`).

| Situation | `strict=False` | `strict=True` (intended for the live agent) |
|---|---|---|
| A disabled rule | listed in `engine.disabled_rules`, logged, not indexed | `RuleEngineError` |
| A rule the loader rejected (`RuleSet.errors`) | listed in `engine.load_errors`, logged | `RuleEngineError` |
| No enabled rule | warning; the engine detects nothing | `RuleEngineError` |
| Sequence rules need more candidate slots than `max_total_candidate_events` | `RuleEngineError` | `RuleEngineError` |

This is separate from `load_rules(..., strict=True)`, which refuses at load time.

### Calling contract
* **One engine and one graph per endpoint, used from a single thread.**
* Call `graph.apply(event)`, then `engine.evaluate(graph, event)` immediately, once per event and in the same order.
  If a later `apply` or `gc` removes the process first, the result is `not_in_graph`.
* Set enrichment such as `attributes.ti_hash_hit` on the event **before** `graph.apply`.
* The engine only reads the graph and the event.
* In live use pass `clock=lambda: datetime.now(timezone.utc)` to the engine and to the graph. The engine then ignores
  events more than `max_future_skew_seconds` ahead of the clock. Without a clock it reads no wall time.
* An engine serves one endpoint and one OS. Without `endpoint_id`, the first accepted event fixes the endpoint (tests
  and replay only); the first accepted event always fixes the OS. Every other endpoint or OS is rejected.

### How predicates match
A missing value never matches, for any operator (including `not_in_cidr`), and the binary `<unknown>` counts as
missing. Comparisons are typed (`True` is not `1`, `"80"` is not `80`). Windows string comparisons ignore case and treat
`\` as `/`; Linux comparisons are exact. `network.dst_ip` is compared as an address by `equals`, `in` and the CIDR
operators. `regex` goes only to the backend, on raw text: text over 4096 characters is not sent and a `RegexTimeout` is
no match, while any other backend exception propagates.

### Results
`evaluate` returns an `EngineResult(matches, suppressed, disposition)`. The checks run in the order below, and the first
one that applies decides the disposition. Each has its own `EngineStats` counter.

| `disposition` | Meaning | Counter |
|---|---|---|
| `bad_identity` | `process_instance_id` is not prefixed with the event's `endpoint_id` | `events_rejected_bad_identity` |
| `foreign` | another endpoint or OS | `events_rejected_foreign` |
| `future` | live mode only: too far ahead of the clock | `events_ignored_future` |
| `not_in_graph` | its process is not in the graph (`apply` skipped, node removed, or the exit of a process never seen) | `events_ignored_not_in_graph` |
| `no_rules` | no enabled rule listens to this OS and event type | `events_ignored_no_rules` |
| `duplicate` | the event id is already remembered | `events_ignored_duplicate` |
| `evaluated` | passed every check ("accepted"), with or without a match | `events_evaluated` |

`evaluated` does not mean a rule ran: an event that only sequence or threshold steps listen to is `evaluated` and
detects nothing. Matches and suppressed repeats are tuples in rule-id order. Results are immutable.

**`EngineMatch`** is a new detection:
* what matched: `rule`, `bindings` (step name to event id), `events` (step name to `HostEvent`), `trigger_event_id`,
  `matched_at`, `process_by_step`;
* the root and the facts an incident builder needs: `root_process_instance_id`, `root_parent_is_placeholder`,
  `root_parent_missing`, `placeholder_process_ids`, `identity_inferred_event_ids`;
* `response_target_process_id`, set when the rule declares a response. It is **only a request: nothing is terminated**;
* `counted_process_id` and `distinct_count` belong to threshold rules and are always `None` today.

`to_contract()` returns a `nexus_contracts.RuleMatch` (`rule_id`, `rule_version`, `matched_at_utc`, `bindings`).

**`SuppressedMatch`** is a repeat of a detection: `rule`, `root_process_instance_id`, `matched_at`, `trigger_event_id`,
`bindings`, `events`. It is not a new rule match and has no `to_contract()`; the planned incident builder is to add it
to the incident as evidence.

A seeded placeholder `process_start` (see [Placeholders](#process-graph-nexus_endpoint_coregraph)) was not observed and
never matches. `placeholder_starts_skipped` counts the refused (rule, event) pairs, not processes.

### Root selection
From the matching process, the engine follows observed parent links up to the rule's `context.max_ancestors`
generations. It stops before a parent that is missing, a placeholder, already visited, or named in the stop list
(`DEFAULT_ROOT_STOP_BINARIES`, for example `systemd`, `sshd`, `explorer.exe`, `svchost.exe`; compared by file name,
ignoring case). Nothing is invented: a missing or placeholder parent of the root is reported in the match. Root
selection never decides whether a rule matches.

### Deduplication (best effort, bounded)
* The engine remembers the ids of the last `max_seen_events` evaluated events, matching or not. Skipped events are not
  remembered.
* Only the id is compared: the first evaluated arrival wins, and a redelivery does not renew its place (first in, first
  out). Earlier checks still apply, so a redelivery can also be reported as, for example, `not_in_graph`.
* It is **not exactly-once processing**. After an id leaves the horizon (`seen_evicted`) or the engine restarts, a
  redelivery is evaluated again and, depending on suppression state and the root, may be reported again.

### Suppression (bounded, in memory)
* Keyed by `(rule_id, root_process_instance_id)`, judged by **event timestamps** in whole milliseconds, using the
  rule's `context.incident_window_seconds`.
* While the key's entry is retained, a repeat stamped before its expiry is a `SuppressedMatch`; one at or after it is a
  new `EngineMatch`.
* The window **slides**: a repeat inside it moves the expiry to the latest hit plus the window. While the entry is
  retained, matching activity that continues without a gap of a whole window therefore keeps it active, with no new
  `EngineMatch` for that key. An older, late event is suppressed too and never moves the window back.
* This is suppression state only. A3a has **no incident lifecycle** (A4): the window does not open, extend or close an
  incident. (`docs/02-CORRELATION.md` section 3 words this as firing once per `incident_window_seconds`; the engine does
  not fire again merely because that long has passed since the first hit.)
* Expired entries are not swept. They stay until the same key replaces them or the `max_suppression_entries` cap removes
  one: an entry expired at the new event's time if there is one (`suppression_expired`, also counted on replacement),
  otherwise the least recently updated (`suppression_evicted`: that detection may fire again). Both counters are
  relative to the triggering event's time, so out-of-order or future-dated events can make either label misleading.
* The state is **not durable**: after a restart, a repeat that would have been suppressed is reported as new.

### Limits (`EngineLimits`)
Counts of items, not bytes. Invalid or mutually inconsistent values raise `ValueError`.

| Field | Default | Effect in A3a |
|---|---|---|
| `max_seen_events` | 50000 | deduplication horizon |
| `max_suppression_entries` | 4096 | suppression cap |
| `max_future_skew_seconds` | 300 | live mode future check |
| `max_candidates_per_step` | 128 | startup capacity check only |
| `max_total_candidate_events` | 50000 | startup capacity check only |
| `max_values_per_key` | 128 | disables threshold rules whose `min_distinct` is larger |
| `max_search_candidates` | 64 | reserved for A3b (validated) |
| `max_search_nodes` | 2000 | reserved for A3b (validated) |
| `max_threshold_keys` | 1024 | reserved for A3b (validated, shown by `state_bounds()`) |
| `max_threshold_bindings` | 200 | reserved for A3b (validated) |

### Statistics and state
* `engine.stats()` returns an `EngineStats` snapshot: the counters above plus `events_received`, `seen_evicted`,
  `matches_emitted`, `matches_suppressed`, `placeholder_starts_skipped`, `suppression_expired`,
  `suppression_evicted`, `rules_enabled`, `rules_disabled` and `rules_rejected_at_load`.
* `engine.state_bounds()` gives upper bounds in item counts (`seen_event_ids`, `suppression_entries`,
  `candidate_events`, `threshold_keys`, `threshold_value_records`; the last three describe A3b structures that do not
  exist yet).
* `engine.state_sizes()` gives what is retained now (`seen_events`, `suppression_entries`), including expired entries.
* Also: `enabled_rules`, `disabled_rules`, `load_errors`, `endpoint_id`, `arrival_count` and
  `index_for(os_name, event_type)`, which lists listening steps, including ones that are not evaluated yet.

### Errors
An exception raised while an event is being prepared (for example by a regex backend) propagates and leaves suppression
state, detection counters and the seen record unchanged (`events_received` still counts the call), so the event can be
retried. A logging handler or filter that raises an ordinary exception during `evaluate` is ignored. `MemoryError`,
`KeyboardInterrupt` and `SystemExit` are not suppressed and updates are not transactional: one raised after the commit
began loses that call's results, and a retry may not recover them. Recovery is left to the agent loop (A8).

### Known limitations of the engine (A3a)
* No sequence or threshold detection ([Detection coverage](#detection-coverage-today)), and no regex backend.
* Single-threaded.
* Deduplication and suppression are bounded, in-memory and best effort; neither survives a restart.
* No incident builder, persistence, transport or response, and no agent loop that connects it to an adapter.
* A tiny `incident_window_seconds` is accepted but rounded to whole milliseconds: 0.0005 s or less becomes 0 ms, and
  repeats stamped at or after the latest hit are then reported as new matches. The shipped rules use 60 and 120 s.
