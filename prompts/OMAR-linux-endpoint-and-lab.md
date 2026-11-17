# Coding prompt — Omar: `endpoint-linux/`, `lab/`, and the replay/evaluation harness

Paste this whole file as the first message to your coding agent, with the repository open at its root.

---

You are the implementing engineer for the Linux endpoint of NEXUS and for the lab tooling. Read `AGENTS.md`, `docs/01-ARCHITECTURE.md`, `docs/02-CORRELATION.md` §1–2, `docs/04-DETECTION-TI-RESPONSE.md` §1.4, `docs/07-DEMO-AND-EVALUATION.md`, `docs/08-LAB-SETUP.md`, `contracts/README.md`, `lab/tetragon-policies/README.md`, `lab/scenarios/README.md`, and every file in `contracts/fixtures/`. The shared library `nexus_endpoint_core` (owned by Anas) will land around Day 10; until then your adapter must work standalone (JSONL output + a hand-built incident POST to the mock server). Work in this order.

## Part A — `endpoint-linux/` (Ubuntu 24.04, runs as root or with CAP_* for the kill action)

Dependencies: `nexus_contracts`, later `nexus_endpoint_core`; stdlib otherwise (`hashlib`, `json`, `subprocess`, `os`).

1. `tetragon_adapter.py` — `TetragonAdapter` implementing the core `Adapter` protocol (`events() -> Iterator[HostEvent]`). Input: tail of the Tetragon JSON export file (`/var/log/tetragon/tetragon.log`, rotation-safe) — gRPC is `TODO(stretch)`. Normalize:
   - `process_exec` → `process_start`: `process_instance_id = f"{endpoint_id}:{process.exec_id}"`, parent from `process.parent_exec_id` (or `parent.exec_id`), `pid`, `ppid` from `parent.pid`, `binary`, `command_line = binary + " " + arguments`, `user` from `process.uid` (resolve via `pwd`), `process_start_time_utc` from `process.start_time`, `sha256` computed with a cache keyed by `(path, mtime, size)` (skip if file > 64 MB or unreadable; record `attributes.hash_skipped`). Events with `flags` containing `procFS` (pre-existing at startup) get `attributes.identity_resolution="placeholder"` semantics only if their parent is unknown; otherwise `native`.
   - `process_exit` → `process_exit` with `exit.exit_code`/`signal`.
   - `process_kprobe` with `function_name == "tcp_connect"` → `network_connect` (`protocol=TCP`, `src_ip/src_port/dst_ip/dst_port` from the `sock_arg`, `direction=outbound`). If `sport` is 0, record `attributes.sport_missing=true` and attempt one lookup in `/proc/<pid>/net/tcp` for the tuple; document the outcome in `docs/08-LAB-SETUP.md` §5.
   - `process_kprobe` with `function_name == "security_file_permission"` → `file_access` with `file.path` from the file arg and `operation = read` if int arg has bit 0x4, `write` if 0x2.
   - **Identity fallback**: maintain `pid -> (exec_id, start_time)` from exec/exit; if a kprobe event's `process.exec_id` was never seen, resolve by `pid` + `start_time` within 10 ms and set `attributes.identity_resolution="pid_start_time"`; otherwise emit with the raw exec_id and `attributes.identity_resolution="unknown"`.
   - Every event gets `attributes.sensor="tetragon"`, `attributes.sensor_event_id` (function name or event kind), and `attributes.raw_ref` (line offset).
2. `linux_response.py` — `LinuxExecutor.terminate(pid, binary)`: re-check `/proc/<pid>/exe` resolves to `binary`, then `os.kill(pid, SIGKILL)`; return `ResponseResult`.
3. `main.py` — standalone mode (`--jsonl-out events.jsonl`) and agent mode (wires `Agent(TetragonAdapter, config)` once the core exists). `.env.example` with `NEXUS_ENDPOINT_ID=linux-vm-01`, `NEXUS_ALLOWLIST=/lab/bin/*`, `NEXUS_DRY_RUN=true`.
4. Until the core lands: `tools/post_manual_incident.py` that takes your JSONL from a real L1 run, builds the incident **by hand** following `contracts/fixtures/incident_linux_l1.json` as the template (same shape, real ids/timestamps), validates it with `nexus_contracts.validate_against_schema`, and POSTs it to the server. This is what Gate G1 on Day 10 uses if the core is late.
5. Tests: saved real Tetragon JSON lines for each event kind → expected `HostEvent`; fallback identity test; hash cache test; rotation test; run the resulting JSONL through `nexus-replay` (when available) and confirm NX-LIN-001 fires on L1.

## Part B — `lab/` ownership

1. Build the VirtualBox lab per `docs/08-LAB-SETUP.md`; keep `lab/README.md` updated with the exact commands you ran and the snapshot names; export OVAs for Rakan.
2. Install Tetragon with `lab/tetragon-policies/*.yaml`; complete the "Verified" table in `docs/08-LAB-SETUP.md` §5 (items 1–3, 6–7).
3. Finish the scenario scripts in `lab/scenarios/` (L1, L2 `beacon_sim.py` installed as `/lab/bin/beacon-sim`, L3, `noise.sh`) and make each write a manifest as in `l1_stage_and_send.py`. Windows scripts stay with Anas except that you review their manifests for the same format.
4. Run the Week-1 timing experiment (`08-LAB-SETUP.md` §4) together with Rakan and record `T`.

## Part C — replay and evaluation harness (`endpoint-linux/nexus_eval/` or `tools/eval/`)

1. `nexus-eval compare --incidents incidents.json --manifests /lab/manifests --out report.md`: computes **process-node recall, edge precision, root correctness** per scenario as defined in `docs/07-DEMO-AND-EVALUATION.md` §2.1, by matching manifest PIDs/binaries/parents to incident `process_nodes`/`relationships`, and manifest connections to `incident.connections` (dst ip/port + source-port range + time ± 5 s).
2. `nexus-eval correlation --server-export export.json --manifests ...`: match coverage/precision/ambiguity using the server's correlation export (Rakan provides `GET /stats` and an export endpoint; agree on the JSON with him — the fields of `server_incident_view.schema.json` are enough).
3. `nexus-eval noise --incidents incidents.json --window START END`: counts incidents during noise-only windows (false positives per hour).
4. `nexus-eval latency`: from incident `detected_at_utc`, server `received_at_utc`, correlation `updated_utc`, and manifest connection times.
5. Output: Markdown tables matching `07-DEMO-AND-EVALUATION.md` §3 plus a JSON file. Tests with synthetic manifests/incidents.

Acceptance for Gate G1 (Day 10): on the lab, `python3 /lab/scenarios/l1_stage_and_send.py` → your adapter produces validating events for python3/bash/cat/curl, the file read, and the tcp_connect; an incident (core-built or hand-built) reaches the real server; Rakan's dashboard/API shows the connection `matched`.

Constraints: no gRPC client, no Tetragon enforcement, no eBPF of your own in v1 — mark `TODO(stretch)`.
