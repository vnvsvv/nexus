# NEXUS — Critical Technical Assessment

**Scope:** the latest agreed architecture in the SENTINEL conversation record (15 Nov 2026), reviewed against a six-week, four-person deadline and the team's actual hardware.
**Stance:** the core idea is sound and worth keeping. Several of the agreed details would have made the demo fail or look broken. Each is listed with the fix that is now baked into the rest of this package.

---

## 1. Verdict

| Question | Answer |
|---|---|
| Is the concept viable in six weeks? | **Yes, if** the scope in `01-ARCHITECTURE.md` is treated as a ceiling, not a floor. The MVP is: two endpoint agents with a *shared* correlation core, a gateway that records every connection it routes, a deterministic host↔network matcher, an ML flow classifier used as an *annotation*, and a dashboard that tells one evidence-backed story. |
| Is it original? | **Moderately.** Commercial EDR/XDR products already link process trees to network flows. What is defensible for a graduation project is (a) an explicit *observed-vs-inferred* evidence model carried in the data itself, (b) matching host incidents to **all** gateway connections, including ones the IDS calls normal, with explicit `matched / ambiguous / pending / unmatched` states instead of silent guesses, and (c) a *measured* evaluation. Say this honestly in the report; do not claim a new security category. |
| Technical complexity? | High enough. Stable process identity across two OSes, time-tolerant flow matching, live ML feature parity, and safe response are each non-trivial. |
| Biggest risks (ordered) | 1. Nobody owned the server/correlator/dashboard. 2. Windows telemetry path was undecided ("ETW"). 3. Flow-emission latency would have made correlation look broken live. 4. Dataset features that cannot be reproduced on live traffic. 5. Two independently generated endpoint pipelines diverging. |

---

## 2. Critical findings and the decisions taken

Severity: **S1** = would have caused failure or a broken demo; **S2** = would have cost a week or produced a weak result; **S3** = quality/credibility.

### F1 (S1) — The crown jewel had no owner
The team split (Anas=Windows, Omar=Linux, Rakan=IDS+TI, Bashar=ML) leaves the central server — API, database, gateway capture, the host↔network correlator, response controller, and the dashboard — unassigned. That is exactly the integration point the project is judged on.

**Decision:** Rakan owns the **gateway server** (networking, connection registry, flow service, correlator, API, DB, TI, gateway response). Bashar owns **ML *and* the dashboard**: model training is 1–2 weeks of real work and then becomes evaluation; the dashboard is the other half of his contribution and is what makes his model visible. See `05-TEAM-AND-INTEGRATION.md`.

### F2 (S1) — "Windows ETW" was never pinned down
Consuming raw kernel ETW providers (Kernel-Process, Kernel-Network, Kernel-File) from Python/C# with stable process identity, in six weeks, by one person who is also writing the shared core, is a bad bet. Sysmon is itself ETW-based (it logs to the `Microsoft-Windows-Sysmon/Operational` channel), gives a stable `ProcessGuid`, parent GUID, hashes, and in Event ID 3 the full 5-tuple with `Initiated` (direction). 

**Decision:** Windows telemetry = **Sysmon, consumed through the Windows Event Log/ETW channel** via a push subscription. Raw ETW providers are a documented stretch goal. Report wording: "Windows telemetry via Sysmon (ETW-backed)". 

**Consequence you must accept:** Sysmon does **not** log file *reads*. It logs creates (11), deletes (23/26), stream creation (15), executable detection (29). So the Windows demo scenario is "stage a file *into* a protected folder" (create/modify), not "read a secret". If a *read* is required on Windows, enable object-access auditing (SACL on `C:\Lab\protected`, Security Event 4663) — it gives PID but not ProcessGuid, so the agent must join by PID+time. Marked as stretch.

### F3 (S1) — Flow-based correlation would have looked broken on stage
NFStream (and every flow exporter) emits a flow record only when it **expires**: default `idle_timeout=120 s`, `active_timeout=1800 s`. A 2-second demo connection would show up on the dashboard two minutes after the host incident. Judges would conclude correlation does not work.

**Decision:** The gateway keeps a **real-time connection registry from `conntrack`** (the Linux router already tracks every routed connection; `conntrack -E` streams `NEW`/`DESTROY` events with the exact 5-tuple at SYN time). The correlator matches against that registry immediately. NFStream flows (with ML verdicts) are attached to the same connection record when they expire, with timeouts lowered (`idle_timeout=15`, `active_timeout=60`). Fallback if conntrack misbehaves: NFStream-only with `idle_timeout=5`.

### F4 (S1) — Features the model is trained on must be computable live
CIC-IDS2017/2018 CSVs are CICFlowMeter features; CICFlowMeter is a Java tool with known flag-handling bugs and you will not run it live. Training on them and running NFStream live gives a model whose inputs mean something different at inference time.

**Decision:** Train on the **University of Queensland NetFlow v2 datasets** (NF-UNSW-NB15-v2 for speed, NF-CSE-CIC-IDS2018-v2/NF-UQ-NIDS-v2 subsample for breadth). Their 43 features are NetFlow/nProbe-style counters that NFStream (also nDPI-based) can reproduce for a defined subset. The exact subset and formulas are frozen in `contracts/flow-features.md` (`feature_version: nf-lite-1`). Bashar trains **only** on those columns; Rakan's flow service computes **only** those columns. Both are tested against the same fixture. Expect a performance drop from dataset test split to lab traffic — measure it, report it, and position ML as an annotation, never as the trigger for automatic blocking.

### F5 (S1) — Two AI agents, two correlation engines
If Anas's agent and Omar's agent each implement "graph + rules + incident builder" separately, their incidents will differ in subtle ways and the server will need two code paths.

**Decision:** One shared, OS-agnostic Python library **`nexus-endpoint-core`** (process graph, rule engine, incident builder, outbox/transport, response executor interface), owned by Anas, developed against JSONL fixtures from day one. Each OS has only a thin **sensor adapter** (Tetragon JSON → `HostEvent`; Sysmon XML → `HostEvent`) and a thin **response adapter**. Omar is not blocked: his adapter emits contract events to JSONL and to the mock server before the core exists, and he builds the replay/evaluation harness in the meantime.

### F6 (S2) — Process identity on Linux is not as clean as assumed
Tetragon's `exec_id` is the right identity, but there is an open upstream report (cilium/tetragon #4349) of `exec_id` differing between a `process_exec` event and a later `tcp_connect` kprobe event for the same PID. Do not assume equality.

**Decision:** The Linux adapter keeps a `pid → (exec_id, start_time)` live table from exec/exit events and, for kprobe events whose `exec_id` is unknown, resolves identity by `pid` + `start_time` within 10 ms. Every resolved-by-fallback event is marked `attributes.identity_resolution: "pid_start_time"` so the dashboard can show it as inferred.

### F7 (S2) — Gateway capture details were unspecified
Three things that break matching silently: (a) a cross-subnet flow is seen on **both** internal interfaces → duplicate flows; (b) NAT on the external interface rewrites addresses; (c) the agents' own HTTPS traffic to the server (port 8443) is itself routed and captured.

**Decision:** Capture only on the two internal interfaces; dedupe flows by 5-tuple+time to the single conntrack connection; NAT only on the external interface and never for inter-subnet traffic; exclude gateway-terminated traffic (`dst = gateway IPs`, ports 8443/123/53) from ML scoring but keep it in the registry.

### F8 (S2) — Hardware does not fit the earlier plan
Bashar's laptop (6 GB RAM) cannot load NF-UQ-NIDS-v2 (~75 M rows) and cannot run a VM lab. Anas's (8 GB) cannot host a Windows VM plus a gateway VM comfortably.

**Decision:** The lab (3 VMs ≈ 9 GB) runs on Omar's and Rakan's 16 GB laptops (export as OVA; both keep an identical copy). Anas develops the Windows agent **on his physical Windows laptop with Sysmon installed**, against the mock server; he only needs the lab for integration days. Bashar trains on **Google Colab/Kaggle** (free CPU/GPU, >12 GB RAM) and develops the dashboard locally against fixtures and the mock server. Model bundles are small files committed via Git LFS or released as artifacts.

### F9 (S2) — Sigma was treated as a rule source without an engine
Sigma is a query-oriented format; pySigma backends translate to SIEM queries, not to a streaming graph matcher. Building a Sigma evaluator is a week you do not have.

**Decision:** A small, explicit **NEXUS rule format** (YAML, three kinds: `single`, `sequence`, `threshold`) with lineage constraints. Hand-port 4–6 Sigma/Elastic rules into it and cite them. The format is in `contracts/rules/RULE-FORMAT.md`.

### F10 (S2) — Response was described, not constrained
"Terminate a process" on a real OS from an automatic rule is where graduation demos go wrong (killing the agent, a shell, or explorer.exe).

**Decision:** Endpoint automatic response only for **rules that declare it**, only against binaries matching an agent-local **allowlist** (`/lab/bin/*`, `C:\Lab\bin\*`), never against protected PIDs, and only when `dry_run=false` is explicitly set. All other response is **manual from the dashboard** with confirmation, and gateway blocks are nftables set entries with a timeout. Every action produces an audited `ResponseResult`.

### F11 (S2) — Time was not engineered
Matching requires synchronized clocks and a tolerance you measured, not guessed.

**Decision:** Gateway runs chrony as the lab NTP server; both endpoints sync to it; heartbeat carries a measured clock offset; Week 1 includes a 50-connection experiment that sets `MATCH_TOLERANCE_SECONDS` from data (default 5 s until measured).

### F12 (S2) — Incidents are not static
After a detection fires, the same processes keep acting. The old design had one POST per incident.

**Decision:** Incidents carry `incident_version`; the endpoint re-sends an updated incident (same `incident_id`) when new evidence attaches within the incident window (default 120 s after last evidence). The server upserts and re-runs correlation. Idempotent by `(endpoint_id, incident_id, incident_version)`.

### F13 (S3) — "Evidence vs inference" must live in the data
The originality claim depends on it, so it cannot be a UI label.

**Decision:** Every relationship edge has `basis: observed | inferred`, `evidence_event_ids[]`, and optional `note`. Server-added edges (NETWORK_FLOW) carry `basis: observed` with gateway record IDs; identity resolved via fallback is `inferred`. Missing telemetry is recorded as `gaps[]` on the incident (e.g., "file reads not observable on Windows").

### F14 (S3) — Evaluation needs ground truth, not screenshots
**Decision:** Scenario scripts emit a **ground-truth manifest** (expected process chain, expected connection tuples) while they run. The replay harness compares generated incidents to the manifest. A benign noise generator runs alongside to measure false positives per hour. Full plan in `07-DEMO-AND-EVALUATION.md`.

### F15 (S3) — Linux binaries have no hashes for TI
Tetragon does not hash binaries. **Decision:** the Linux adapter computes SHA-256 of the executable at `process_start` (cached by path+mtime+size). Sysmon provides hashes natively when configured.

### F16 (S3) — Threat intel will be empty in an isolated lab
Private IPs have no reputation and there is no DNS. **Decision:** TI is demonstrated with **file hashes** (the EICAR test file is known to every vendor), with **offline feeds** (abuse.ch MalwareBazaar/Feodo/URLhaus CSVs loaded into the DB), and one clearly labelled **lab test indicator** (`192.168.20.10:8443` tagged `lab-test`) so the enrichment path is exercised end-to-end. VirusTotal lookups are cached and rate-limited (free tier: 4/min, 500/day).

### F17 (S3) — Things that will bite on Windows
Defender/SmartScreen will quarantine or block "suspicious-looking" PowerShell scenarios. Add a Defender exclusion for `C:\Lab` on the lab VM only. Use the Windows 11 Enterprise 90-day evaluation ISO. Sysmon Event 3 is disabled by default — the provided config enables it.

### F18 (S3) — Out of scope, explicitly
Signature antivirus, general ransomware prevention, automatic ML-driven blocking, LLM explanations, VLANs, Microsoft eBPF-for-Windows, multi-tenant anything. Each is listed as "future work" in the report with one sentence on why.

---

## 3. What stays exactly as agreed
- Hybrid correlation: local process/file/network correlation on endpoints; central host↔network correlation on the gateway.
- Endpoints send **only** reconstructed incidents with evidence and process-linked connection metadata — never all kernel telemetry.
- The gateway stores **all** routed connections, normal and suspicious, and matches incidents against all of them.
- Two isolated virtual subnets (`192.168.10.0/24` Linux, `192.168.20.0/24` Windows) routed only by the NEXUS gateway. With exactly one endpoint per subnet, every off-host packet traverses the gateway — there is no bypass path to worry about.
- Deterministic host correlation; rule-based host detection; team-trained binary ML flow classifier; evidence-based ATT&CK labels; limited, audited response.

## 4. What changed, in one table

| Area | Before | Now |
|---|---|---|
| Ownership | Server/correlator/dashboard unowned | Rakan = server; Bashar = ML + dashboard; Anas = Windows + shared endpoint core + contracts; Omar = Linux + lab + replay/eval harness |
| Windows sensor | "ETW" | Sysmon via ETW channel; raw ETW = stretch |
| Gateway connection source | NFStream flows only | conntrack registry (real-time) + NFStream flows (features/ML) |
| Dataset | CIC-IDS2017 / ToN-IoT undecided | UQ NetFlow v2 family with frozen `nf-lite-1` feature subset |
| Endpoint pipeline | Per-OS implementations | Shared `nexus-endpoint-core` + thin adapters |
| Rules | "Sigma" | NEXUS YAML rule format; Sigma hand-ported |
| Identity (Linux) | exec_id only | exec_id with pid+start_time fallback, marked |
| Incidents | One-shot POST | Versioned upserts |
| Response | Described | Allowlisted, dry-run default, audited; gateway manual |
| Time | Not addressed | chrony + measured tolerance |
| Evaluation | Listed targets | Ground-truth manifests + replay harness + noise generator |
