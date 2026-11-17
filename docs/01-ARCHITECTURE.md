# NEXUS — Final Architecture (v1.0, frozen for the six-week build)

Everything in this document is a decision. Where a decision rests on an assumption that must be verified in the lab, it is marked **[verify W1]** (verify in Week 1).

---

## 1. System overview

```text
   LINUX ENDPOINT VM (192.168.10.10)                  WINDOWS ENDPOINT VM (192.168.20.10)
   ┌──────────────────────────────────┐               ┌──────────────────────────────────┐
   │ Tetragon (eBPF)                  │               │ Sysmon (ETW-backed)              │
   │   exec/exit, file (kprobe),      │               │   EID 1,5 process; 3 network;    │
   │   tcp_connect (kprobe)           │               │   11/23 file; 22 DNS             │
   │        │ JSON (unix socket/file) │               │        │ EvtSubscribe (XML)      │
   │   linux_adapter.py ──► HostEvent │               │   windows_adapter.py ──► HostEvent│
   │        │                         │               │        │                         │
   │   nexus_endpoint_core            │               │   nexus_endpoint_core            │
   │    ProcessGraph  RuleEngine      │               │    (same package, same rules fmt)│
   │    IncidentBuilder  Outbox       │               │                                  │
   │    ResponseExecutor(linux)       │               │    ResponseExecutor(windows)     │
   │        │ SQLite (events, outbox) │               │        │ SQLite                  │
   └────────┼─────────────────────────┘               └────────┼─────────────────────────┘
            │ HTTPS: POST /incidents, /heartbeat, GET /commands │
            ▼                                                   ▼
   ┌────────────────────────── NEXUS GATEWAY VM (Linux) ──────────────────────────────┐
   │ ens-lin 192.168.10.1 ◄── routes ──► ens-win 192.168.20.1     ens-ext (NAT, inet) │
   │ ens-mgmt 192.168.56.x (host-only: SSH + dashboard access from the laptop)        │
   │                                                                                  │
   │  conntrack -E ──► connection_registry  (every routed connection, real time)      │
   │  NFStream (ens-lin, ens-win) ──► flow_service ──► features(nf-lite-1) ──► ML     │
   │                                                     │                             │
   │  FastAPI api_service ◄── incidents ──► correlator ◄─┘ (5-tuple + time + identity) │
   │        │                   │                                                      │
   │  PostgreSQL 16   ti_service (offline feeds + VirusTotal cache)                    │
   │        │                                                                          │
   │  response_controller (endpoint command queue; nftables set for gateway blocks)    │
   │        │                                                                          │
   │  dashboard (React, served statically by api_service at /ui, SSE for live updates) │
   └──────────────────────────────────────────────────────────────────────────────────┘
```

**One sentence:** endpoints reconstruct and ship *incidents*; the gateway records *every connection it routes*, scores flows with a team-trained model, deterministically joins incident connections to gateway records, enriches with TI, and shows one evidence-graded story.

---

## 2. Components and responsibilities

### 2.1 `contracts/` + `nexus_contracts` (owner: Anas; frozen after Day 2, changes by PR + version bump)
JSON Schemas, Pydantic models, OpenAPI spec, rule format, flow-feature contract, ATT&CK mapping, fixtures. Every other package imports `nexus_contracts` and validates against the schemas in tests. **No component may define its own copy of these structures.**

### 2.2 `endpoint-core/` → `nexus_endpoint_core` (owner: Anas)
OS-agnostic. Input: `HostEvent` objects. Output: `Incident` objects, `ResponseResult` objects.

| Module | Responsibility |
|---|---|
| `graph.py` | `ProcessGraph`: nodes keyed by `process_instance_id`; parent links; per-process lists of file/network/dns events; bounded retention (default: keep exited processes 10 min, max 50k nodes); `pid → live process` index. |
| `rules.py` | Loads `contracts/rules/*.yaml`; evaluates `single`, `sequence`, `threshold` rules over the graph with lineage constraints and time windows. Emits `RuleMatch` with step→event bindings. |
| `incident.py` | `IncidentBuilder`: from a `RuleMatch`, selects evidence (matched events + ancestry up to `max_ancestors`, descendants within window), builds `process_nodes`, `relationships` (with `basis`), `connections`, `technique_ids`, `gaps`. Dedupes into an open incident if the same root process already has one within `incident_window_seconds`; bumps `incident_version`. |
| `store.py` | SQLite: normalized events (bounded, for debugging and replay), incidents, outbox. |
| `transport.py` | HTTPS client with bearer token, retry/backoff, idempotent re-send from outbox; heartbeat with measured clock offset; command polling. |
| `response.py` | `ResponseExecutor` interface + policy gate (allowlist, protected PIDs, dry-run) — OS implementations live in the adapters. |
| `agent.py` | Event loop wiring: adapter → graph → rules → incident → outbox; command poll → response. |
| `replay.py` | `nexus-replay events.jsonl --rules dir --expect manifest.json` (used by Omar's harness). |

### 2.3 `endpoint-linux/` (owner: Omar)
- Tetragon installed as a systemd service with TracingPolicies in `lab/tetragon-policies/` (exec/exit base, `tcp_connect` kprobe, `security_file_permission` kprobe limited to `/lab/protected/` and `/etc/` paths).
- `linux_adapter.py`: reads Tetragon JSON export (`/var/log/tetragon/tetragon.log` tail, or gRPC `GetEvents` **[verify W1 which is simpler on your distro]**), normalizes to `HostEvent`, computes SHA-256 for `process_start`, maintains the `pid→exec_id` fallback table, reads `/proc/<pid>/net` if source port missing **[verify W1: tcp_connect sock arg includes sport]**.
- `linux_response.py`: `terminate_process` via `SIGKILL` guarded by policy; stretch: Tetragon `Sigkill` enforcement policy for protected-file reads by non-allowlisted binaries.
- Lab host (VirtualBox), scenario scripts, ground-truth manifests, replay/evaluation harness, benign noise generator.

### 2.4 `endpoint-windows/` (owner: Anas)
- Sysmon installed with `lab/sysmon/nexus-sysmon.xml` (EID 1, 3, 5, 11, 22, 23 on; hashes SHA256; noise filtered).
- `windows_adapter.py`: `win32evtlog.EvtSubscribe` on `Microsoft-Windows-Sysmon/Operational` (push), XML → `HostEvent`; `ProcessGuid` → `process_instance_id`; EID 3 `Initiated` → direction.
- `windows_response.py`: `terminate_process` via `TerminateProcess`/`taskkill /PID /F`, same policy gate.
- Runs as an elevated console process in the MVP; a Windows service wrapper (NSSM) is a stretch.

### 2.5 `server/` (owner: Rakan)

| Service (one process each, systemd units) | Responsibility |
|---|---|
| `api_service` (FastAPI + uvicorn, HTTPS 8443) | Implements `contracts/openapi.yaml`: incident upsert, heartbeat, command polling, results, dashboard read APIs, SSE stream, static `/ui`. Bearer auth per endpoint and for the dashboard. |
| `connection_registry` | Runs `conntrack -E -e NEW,DESTROY -o timestamp,extended`, parses lines, writes `gateway_connections` (NEW → first_seen; DESTROY → last_seen, byte/packet counters). Resolves `src_endpoint_id` / `dst_endpoint_id` by IP map. |
| `flow_service` | One `NFStreamer` per internal interface (`idle_timeout=15`, `active_timeout=60`, `statistical_analysis=True`, `n_dissections=20`, custom `NFPlugin` for packet-size bins). Computes `nf-lite-1` features, calls `nexus_ml.FlowClassifier`, writes `gateway_flows`, links each flow to its `gateway_connections` row (5-tuple, time overlap, dedupe across interfaces), emits `network_alert` when label = suspicious and no incident references the tuple. |
| `correlator` | On incident upsert and on new registry rows: match algorithm in `02-CORRELATION.md`; writes `incident_correlations`; adds `NETWORK_FLOW` relationships into the server-side incident view; maintains `pending` retries. |
| `ti_service` | Loads offline feeds (abuse.ch MalwareBazaar hashes, Feodo IPs, URLhaus) into `ti_indicators`; async enrichment of incident hashes/IPs/domains; VirusTotal v3 file lookup with persistent cache and rate limiter. |
| `response_controller` | Creates `ResponseCommand`s for endpoints (queued, polled); executes gateway `block_connection`/`unblock` via an nftables set with timeout; records `response_history`. |

Storage: **PostgreSQL 16** (native package on the gateway VM). Tables listed in `02-CORRELATION.md §6`.

### 2.6 `ml/` → `nexus_ml` (owner: Bashar)
- `features.py`: the **single implementation** of `nf-lite-1` from (a) an NFStream `NFlow` object and (b) a UQ NetFlow v2 dataset row. Both paths produce the same ordered vector; a fixture test asserts equality.
- `train.py`: dataset download/clean, column mapping, stratified split, RandomForest baseline + XGBoost, threshold selection at target FPR, metrics report (JSON + markdown), model bundle export.
- `FlowClassifier`: `load(bundle_dir)`, `predict(features: dict) -> MLPrediction`. Pure sklearn/xgboost, no network.
- Model bundle layout: `model.joblib`, `features.json` (ordered names + `feature_version`), `metadata.json` (dataset, split, metrics, threshold, `model_version`), `CHANGELOG.md`.
- Lab evaluation: scripts to capture benign lab traffic and scripted attack traffic into pcaps, score them, and produce the generalization report.

### 2.7 `dashboard/` (owner: Bashar)
React 18 + Vite + TypeScript. Pages: Incidents list (live via SSE) → Incident detail (React Flow graph of `process_nodes` + `relationships`, edge style by `basis`, timeline of evidence, connections panel with correlation state and ML verdict, TI panel, gaps panel, response panel with confirm dialogs) ; Network alerts ; Endpoints health ; Response history. Types generated from `contracts/openapi.yaml` (`openapi-typescript`). Built bundle is served by `api_service` at `/ui`.

---

## 3. Network and lab design

| Item | Decision |
|---|---|
| Hypervisor | VirtualBox 7.x (free, scripted via `VBoxManage`, "Internal Network" = fully isolated). VMware Workstation Pro (free for personal use) is acceptable if a member prefers it; keep the same addressing. |
| Lab host | Omar's and Rakan's laptops (16 GB). Three VMs: gateway (2 vCPU, 3 GB), Linux endpoint (2 vCPU, 2 GB, Ubuntu 24.04 LTS), Windows endpoint (2 vCPU, 4 GB, Windows 11 Enterprise Evaluation). Export OVAs after Week 1 so both laptops hold identical labs. |
| Gateway NICs | `ens-lin` internal net `nexus-lin` 192.168.10.1/24; `ens-win` internal net `nexus-win` 192.168.20.1/24; `ens-ext` NAT (internet for apt/pip/TI only); `ens-mgmt` host-only 192.168.56.10/24 (SSH, dashboard from the laptop). |
| Endpoints | Static IPs `.10`, default gateway `.1`, DNS = gateway (dnsmasq, forwards to upstream via NAT; can be disabled for fully isolated runs). Hosts entry `nexus-server` → the gateway IP on their own subnet. |
| Routing | `net.ipv4.ip_forward=1`; nftables: forward between internal nets allowed and logged by conntrack; masquerade **only** on `ens-ext`; management interface never forwarded. |
| Time | chrony on gateway as server; endpoints sync to it (`makestep` enabled). Windows: `w32tm /config /manualpeerlist:192.168.20.1 /syncfromflags:manual`. |
| Capture | NFStream on `ens-lin` and `ens-win` only. conntrack covers everything routed. |
| Access | Team members reach dashboard at `https://192.168.56.10:8443/ui` from the lab laptop. |

Each endpoint subnet contains exactly one host, so all its non-loopback traffic passes the gateway. This is the property that makes "the gateway sees everything" true; document it in the report as a lab constraint, not a general property.

---

## 4. Data flow, end to end (normal case)

1. Process activity on an endpoint → sensor event → adapter → `HostEvent` → `ProcessGraph`.
2. `RuleEngine` evaluates affected process lineage after each event; a `RuleMatch` triggers `IncidentBuilder`.
3. `Incident v1` → SQLite outbox → `POST /api/v1/incidents` (bearer token). New evidence within `incident_window_seconds` → `Incident v2` (same id) → re-POST.
4. Meanwhile the connection the process opened crossed the gateway: `conntrack` NEW wrote a `gateway_connections` row within milliseconds; NFStream will emit the flow ≤15 s after the connection goes idle and the flow gets `nf-lite-1` features + `MLPrediction`.
5. `correlator` matches each `incident.connections[i]` to `gateway_connections` (see `02-CORRELATION.md`), state ∈ {matched, ambiguous, pending, unmatched}; attaches flows/ML verdicts as they arrive.
6. `ti_service` enriches hashes/IPs asynchronously.
7. Dashboard receives SSE `incident.updated` and renders the graph: observed edges solid, inferred dashed, NETWORK_FLOW edges in a distinct colour with the ML verdict badge, gaps listed.
8. Response: rule-declared automatic endpoint action (allowlisted, audited) or manual from the dashboard → `ResponseCommand` → endpoint poll → `ResponseResult` → response history.

**Network-only case:** ML flags a flow, no incident references the tuple → `network_alert` shown on its own page; if a later incident references the tuple, the alert is linked to it.

---

## 5. Technology choices (final)

| Concern | Choice | Why (one line) |
|---|---|---|
| Agent/server language | Python 3.11+ | Fastest for AI-assisted development; all libs available (pywin32, nfstream, sklearn, FastAPI). |
| Schemas | JSON Schema 2020-12 + Pydantic v2 | Validation in tests on every side; TS types generated for dashboard. |
| Transport | HTTPS REST (self-signed CA in repo for the lab) + SSE | No message broker to operate; polling commands avoids inbound connections to endpoints. |
| Endpoint storage | SQLite (WAL) | Zero-ops, bounded. |
| Server storage | PostgreSQL 16 | Indexed 5-tuple/time queries; JSONB for incident documents. |
| Linux sensor | Tetragon ≥ 1.3 (systemd, TracingPolicies) | Stable exec IDs, kprobe file/network events, JSON export. |
| Windows sensor | Sysmon (latest) via Event Log push subscription | ProcessGuid, network 5-tuple, hashes; no driver work. |
| Flow extraction | NFStream 6.6 (+ one NFPlugin) | Maintained, nDPI, statistical features, Python-native. |
| Connection registry | conntrack-tools | Real-time, deduplicated, free with the router. |
| ML | scikit-learn RandomForest (baseline), XGBoost (candidate) | Tabular, interpretable, CPU-only inference. |
| Dashboard | React + Vite + TS + React Flow + Tailwind | Graph rendering is the hard part; React Flow solves it. |
| Rules | NEXUS YAML v1 | Fits a streaming graph; Sigma hand-ported. |
| TI | abuse.ch feeds (offline) + VirusTotal v3 (cached) | Works in an isolated lab; EICAR for the demo. |
| Gateway response | nftables named set with timeout | Reversible, auditable, one command. |

---

## 6. Must-have vs. stretch

**Must-have (the demo is judged on these):**
1. Both endpoints produce correct process ancestry for scripted scenarios.
2. Both endpoints emit versioned incidents with evidence, `basis`-tagged edges, connections, ATT&CK labels, gaps.
3. Gateway connection registry + flows with `nf-lite-1` features + ML verdict.
4. Deterministic correlation with the four states, including matching to *normal* flows.
5. Dashboard: incident list, incident graph/timeline/connections/TI/gaps, network alerts, response history.
6. TI enrichment by hash (offline feed + VT) and by lab indicator.
7. Response: allowlisted automatic terminate on one Linux and one Windows scenario; manual terminate; manual gateway block/unblock.
8. Evaluation report with the metrics in `07-DEMO-AND-EVALUATION.md`.

**Stretch (only after Gate G2 is green):** Tetragon enforcement policy; Windows SACL file-read auditing; raw ETW provider for process events; DNS correlation; XGBoost vs RF comparison with calibration; incident "what-if" replay; Windows service wrapper; mTLS.

**Out of scope (say so in the report):** antivirus, ransomware prevention, automatic ML-driven blocking, LLM narratives, VLANs, eBPF for Windows.
