# NEXUS — Demonstration and Evaluation Plan

## 1. Demo script (≈ 15 minutes)

| # | Minutes | What the audience sees | Capability proven |
|---|---|---|---|
| 0 | 1 | Dashboard overview: two endpoints healthy, clock offsets, model version, empty incident list | monitoring, health |
| 1 | 4 | **L1** runs on the Linux VM. Within ~2 s an incident appears: graph python3 → bash → cat → curl; file edge; connection edge; ATT&CK T1059.004/T1005/T1041; connection state **matched** with the gateway record; ~15 s later the flow's ML verdict (probably benign) and features attach; TI panel shows the lab-test indicator and hash lookups; "Terminate curl" is clicked → **denied** by the allowlist gate (shown in response history) | reconstruction, host↔network correlation incl. normal flows, evidence-vs-inference legend, TI, response safety |
| 2 | 3 | **W1** on the Windows VM: cmd → powershell → file create → connection; gap panel reads "file reads not observable on Windows (Sysmon)"; matched flow | cross-OS parity, honest gaps |
| 3 | 2 | **L2**: `/lab/bin/beacon-sim` starts → NX-LIN-003 → **automatic terminate** (dry_run=false on the lab VM) → process gone, audit entry, incident shows `local_response: executed` | semi-automated response, allowlist |
| 4 | 3 | **N1**: Windows script generates many connections to closed Linux ports with the host rule disabled → network alerts page fills from ML alone → analyst blocks the source at the gateway (confirm dialog) → next connections fail → unblock | ML IDS standalone, gateway response |
| 5 | 2 | **L3** (or the evaluation slide): threshold rule, 30 matched connections, several ML-flagged, one incident | scale of matching, threshold rules, metrics |

Backups: recordings of every scenario; `nexus-replay` of recorded sensor logs if a VM misbehaves.

## 2. Evaluation methodology

Principle: every number comes from a script and a manifest, never from eyeballing a screenshot. Each measurement is repeated **3 times**; report mean and range.

### 2.1 Endpoint reconstruction correctness
- Ground truth: scenario manifests (PIDs, binaries, parent PIDs, files, connections).
- Metric: for each scenario, **process-node recall** (expected processes present in the incident / expected), **edge precision** (incident PARENT_OF/ACCESSED_FILE/CONNECTED_TO edges that are correct / all edges), **root correctness** (root equals the manifest root).
- Tool: `nexus-replay --server-export incidents.json --manifest-dir /lab/manifests` (Omar).

### 2.2 Host detection quality
- Runs: each scenario ×3 (positives) + benign noise generator for 60 min on each OS ×2 (negatives) + a mixed run (noise + scenarios).
- Metrics: detection rate per rule; **false positives per hour** on noise-only runs; time from last matched event to incident emission (local latency).

### 2.3 Network-to-host correlation
- Ground truth: manifest connections (dst ip/port + source-port range + time) joined to the server's `gateway_connections`.
- Metrics: **match coverage** (expected connections with state `matched` / expected), **match precision** (matched pairs whose gateway record agrees with the manifest / matched), ambiguity rate, pending-time distribution, and **end-to-end latency** (connection start → `matched` visible; connection end → ML verdict attached).
- Stress: L3 (30 connections in 6 s) ×3; deliberate port-reuse test (same source port twice within `T`) to show `ambiguous`.

### 2.4 ML IDS
- Dataset: precision/recall/F1/ROC-AUC/PR-AUC on the held-out test split; per-family recall.
- Lab: alerts/hour on 60 min of benign lab traffic (×2); fraction of scenario flows flagged (L1, L2, L3/N1); ablation without `l4_dst_port`.
- Parity: fixture test + 50-flow pcap-vs-live feature comparison (max abs difference per feature).

### 2.5 Threat intelligence
- Hit rate on known indicators (EICAR hash, lab-test IP:port); VT lookup latency and cache hit ratio; feed load time.

### 2.6 Response
- Automatic: L2 ×5 — time from incident to process termination; success rate; zero collateral (no other process killed, verified by manifest PIDs).
- Gate: 10 attempts to terminate non-allowlisted processes → 10 `denied`.
- Gateway: block applied → connection failure confirmed; unblock → success; audit completeness (every action has a result row).

### 2.7 Reliability and performance
- Endpoint: events/minute under noise; CPU/RAM of the agent (psutil sampling); dropped events reported by sensors (Tetragon export stats; Sysmon has no drop counter → note).
- Gateway: flows/minute, conntrack table size, correlator queue depth, API p95 latency under L3.
- Recovery: kill the agent during L1 → restart → outbox resends → incident appears once (idempotency check); kill the server → agents buffer → recovery.

### 2.8 Evidence integrity (the originality claim, measured)
- 100 % of relationship edges carry ≥ 1 evidence_event_id that exists in `evidence[]` (automated check).
- Every incident with a placeholder or fallback identity carries `IDENTITY_INFERRED`/`PARENT_NOT_OBSERVED` and `confidence ≤ medium` (automated check).
- Every Windows incident with file evidence carries `FILE_READ_NOT_OBSERVABLE_ON_WINDOWS`.

## 3. Report table templates

| Scenario | Runs | Node recall | Edge precision | Root ok | Detected | Local latency (s) | Match coverage | Match precision | E2E latency (s) | ML flagged flows |
|---|---|---|---|---|---|---|---|---|---|---|
| L1 | 3 | | | | | | | | | |
| L2 | 3 | | | | | | | | | |
| L3 | 3 | | | | | | | | | |
| W1 | 3 | | | | | | | | | |
| W2 | 3 | | | | | | | | | |
| N1 | 3 | n/a | n/a | n/a | n/a | n/a | n/a | n/a | | |

| Benign run | Duration | Events/min | Incidents (FP) | Network alerts (FP) | Agent CPU % | Agent RAM MB |
|---|---|---|---|---|---|---|
| Linux noise | 60 min | | | | | |
| Windows noise | 60 min | | | | | |

## 4. Limitations to state up front (judges respect this)
Lab with one host per subnet; Sysmon file-read blind spot; conntrack/flow timing tolerance; ML domain shift; no encrypted-traffic inspection; response limited to allowlisted lab binaries and manual gateway blocks; no evaluation against real malware by design.
