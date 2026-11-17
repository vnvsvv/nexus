# Coding prompt — Anas: `endpoint-core/` (shared library) and `endpoint-windows/`

Paste this whole file as the first message to your coding agent, with the repository open at its root.

---

You are the implementing engineer for two packages of the NEXUS project (see `docs/01-ARCHITECTURE.md`): the shared, OS-agnostic endpoint library `nexus_endpoint_core` in `endpoint-core/`, and the Windows endpoint agent in `endpoint-windows/`. Read `AGENTS.md`, `docs/01-ARCHITECTURE.md`, `docs/02-CORRELATION.md` §1–4, `docs/04-DETECTION-TI-RESPONSE.md`, `contracts/README.md`, `contracts/rules/RULE-FORMAT.md`, `lab/sysmon/README.md`, and every file in `contracts/fixtures/` before writing code. Work in this order and stop for review after each part.

## Part A — `endpoint-core/` (package `nexus_endpoint_core`, pure Python 3.11, no OS-specific imports)

Dependencies: `nexus_contracts` (repo root `pip install -e .`), `pyyaml`, `httpx`, `pydantic`. SQLite via stdlib.

Deliver these modules exactly as described in `docs/01-ARCHITECTURE.md` §2.2 and `docs/02-CORRELATION.md` §2–4:

1. `graph.py` — `ProcessNode`, `ProcessGraph.apply(HostEvent) -> ProcessNode` (creates placeholder parents with `placeholder=True`; closes nodes on `process_exit`; keeps `live_by_pid`), `ancestors`, `descendants`, `lineage_contains`, `events_for`, `gc` with `retention_seconds=600`, `max_nodes=50000`. Events are stored in an LRU dict (max 100k) and also written to the SQLite store.
2. `rules.py` — loader for `contracts/rules/*.yaml` with validation of kinds/operators/field paths (reject bad rules with a logged error); evaluator per `RULE-FORMAT.md` and `02-CORRELATION.md` §3: `evaluate(graph, new_event) -> list[RuleMatch]`, predicates (closed set), lineage relations, ordered/unordered sequences, threshold rules with sliding windows, suppression per `(rule_id, root)` within `incident_window_seconds`. Windows string comparisons case-insensitive with backslash normalization; Linux case-sensitive.
3. `incident.py` — `IncidentBuilder.build(match) -> Incident` and `IncidentBuilder.extend(open_incident, new_event) -> Incident | None` implementing §4 exactly (root selection, process set, evidence roles, relationships with `basis`, connections, technique_ids from the rule only, severity/confidence, gaps, caps with truncation gaps, versioning, status close after window). Output must validate against `incident.schema.json` (assert in tests).
4. `store.py` — SQLite WAL: tables `events(event_id PK, ts, json)`, `incidents(incident_id, version, json, sent INTEGER)`, `outbox(seq PK, kind, payload, attempts, next_attempt)`. Bounded: delete events older than `retention_seconds` × 10.
5. `transport.py` — `ServerClient(base_url, token, verify_tls)`: `post_incident`, `heartbeat` (measures `clock_offset_ms` = local_send_time + rtt/2 − server_time_utc), `poll_commands`, `post_result`, `fetch_ti_hashes(etag)`. Retries with exponential backoff; resends from the outbox in order; idempotent on server side so duplicates are safe.
6. `response.py` — `ResponsePolicy` (allowlist globs, protected pids/binaries, dry_run) with `allowed(node) -> (bool, reason)` exactly as in `04-DETECTION-TI-RESPONSE.md` §3.2; `ResponseExecutor` protocol with `terminate(pid, binary) -> ResponseResult`; `execute(command, graph, policy, executor)` that always records a `ResponseResult`.
7. `agent.py` — `Agent(adapter, config)` event loop: adapter yields `HostEvent`s → graph → rules → incident build/extend → store/outbox → transport flush every 1 s; heartbeat every 30 s; poll commands every 5 s; TI hash list refresh every 10 min (sets `attributes.ti_hash_hit=True` on `process_start` events whose `sha256` is in the list, *before* rule evaluation). `Adapter` protocol: `events() -> Iterator[HostEvent]`, `name`.
8. `replay.py` — CLI `nexus-replay EVENTS.jsonl --rules contracts/rules [--expect EXPECT.json] [--out incidents.json]` and the function `run_rule_fixture(events_path, expect, rules_dir) -> (ok, msg)` used by `tools/validate_fixtures.py`.
9. `config.py` — settings from env/`.env` (`NEXUS_ENDPOINT_ID`, `NEXUS_SERVER_URL`, `NEXUS_TOKEN`, `NEXUS_TLS_VERIFY`, `NEXUS_DRY_RUN=true`, `NEXUS_ALLOWLIST`, `NEXUS_RULES_DIR`, `NEXUS_DB_PATH`).

Tests (`pytest`): all `contracts/fixtures/rules/*.events.jsonl` produce the expected `fires`/bindings/root; the built incident for `NX-LIN-001` deep-equals the structure of `contracts/fixtures/incident_linux_l1.json` ignoring ids/timestamps; placeholder parent → `PARENT_NOT_OBSERVED` gap and `confidence=medium`; threshold rule fires at 15 distinct ports and not at 14; suppression merges a second match into version 2; outbox resend after simulated network failure; policy gate denies protected/non-allowlisted; dry-run result recorded. Run `python tools/validate_fixtures.py` — it must now say "rule-engine fixtures executed".

## Part B — `endpoint-windows/` (runs on Windows 10/11, elevated)

Dependencies: `nexus_endpoint_core`, `pywin32`, `psutil`.

1. `windows_adapter.py` — `SysmonAdapter` implementing the `Adapter` protocol: push subscription to `Microsoft-Windows-Sysmon/Operational` via `win32evtlog.EvtSubscribe` (callback puts rendered XML into a `queue.Queue`; generator drains it). Parse XML (`xml.etree`) into `HostEvent` for EID 1, 3, 5, 11, 22, 23 using the field mapping in `lab/sysmon/README.md`. `process_instance_id = f"{endpoint_id}:{ProcessGuid}"`. Convert `UtcTime` to ISO `Z` with milliseconds. SHA256 from `Hashes`. On start, seed placeholder nodes for running processes from `psutil` (binary, pid, ppid, create_time) with `attributes.identity_resolution="placeholder"`. Keep an internal `pid -> process_instance_id` map from EID 1/5 for events that only carry a PID. Each event `attributes` includes `sensor:"sysmon"`, `sensor_event_id`, and for EID 3 `initiated`.
2. `windows_response.py` — `WindowsExecutor.terminate(pid, binary)` using `psutil.Process(pid).kill()` after re-checking that the process's current exe path equals `binary` (guards PID reuse); returns `ResponseResult`.
3. `main.py` — builds `Agent(SysmonAdapter(...), config)`; console logging; `--replay-xml DIR` option to feed saved EVTX-exported XML files for offline testing.
4. Tests: XML samples for each EID (save real ones from your laptop, redact nothing sensitive beyond the username) → expected `HostEvent` JSON; run `contracts/fixtures/windows_w1_events.jsonl` through the core and confirm NX-WIN-001 fires; integration test against `tools/mock_server.py` (heartbeat, incident upsert, command poll → dry-run result).
5. `README.md` — install Sysmon with `lab/sysmon/nexus-sysmon.xml`, run elevated, `.env.example`, how to test against the mock server, how to point at the real server (`https://nexus-server:8443/api/v1`, lab CA bundle in `lab/pki/` if present, else `NEXUS_TLS_VERIFY=false` in the lab only).

Scenario acceptance: on the lab VM, `cmd /c powershell -ExecutionPolicy Bypass -File C:\Lab\scenarios\w1_stage.ps1` produces one incident with rule `NX-WIN-001`, process nodes cmd → powershell, an `ACCESSED_FILE` edge to `C:\Lab\staging\report.zip`, a `CONNECTED_TO` edge to the Linux VM, the gap `FILE_READ_NOT_OBSERVABLE_ON_WINDOWS` **only when file evidence exists**, and it is stored by the server with `status: stored`.

Constraints: do not implement raw ETW providers, services, or anything in `stretch` lists; mark them `TODO(stretch)`.
