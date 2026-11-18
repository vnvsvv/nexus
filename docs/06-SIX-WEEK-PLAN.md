# NEXUS — Six-Week Development Plan

Working assumption: five working days per week, AI-assisted coding, everyone starts the same day. Day numbers are working days (D1–D30). **Bold** items are gates.

## 1. Week-by-week, per member

| Week | Anas (Windows + core + contracts) | Omar (Linux + lab + harness) | Rakan (server + gateway) | Bashar (ML + dashboard) |
|---|---|---|---|---|
| **1** (D1–5) | D1–2: review/adjust contracts with the team, **freeze (I0)**. D3–5: Sysmon dev profile installed on the laptop after the verification matrix in `lab/sysmon/README.md` passes, adapter v0 (EID 1/3/5/11 → HostEvent JSONL that validates); heartbeat to mock server. | D1–3: VM lab built (`08-LAB-SETUP.md`), OVAs exported; Tetragon installed with the two policies; raw events captured for a manual L1 run. D4–5: adapter v0 (exec/exit/tcp_connect/file → HostEvent JSONL). | D1–2: gateway bootstrapped (routing, nftables, chrony, dnsmasq, PostgreSQL). D3: `connection_registry` from conntrack writing rows. D4–5: `api_service` skeleton implementing `openapi.yaml` with schema validation + DB upsert of incidents; **50-connection timing experiment → `MATCH_TOLERANCE_SECONDS`**. | D1–2: download NF-UNSW-NB15-v2; column study; direction/rate caveats resolved and written up. D3: `nexus_ml.features` (both paths) passes the parity fixture; `DummyClassifier` published. D4–5: dashboard scaffold (Vite+TS, routing, API client from OpenAPI, incident list + detail rendering the fixture view). |
| **2** (D6–10) | D6–9: `nexus_endpoint_core`: graph, rule engine (single/sequence/threshold), incident builder, SQLite store, outbox/transport, dry-run response gate; rule fixtures pass. D10: Windows adapter wired to the core; W1 incident reaches the mock server. | D6–7: Linux adapter hardened (pid+start_time fallback, SHA-256, exit handling); scenario scripts L1/L2/L3 + manifests. D8–9: `nexus-replay` harness (events.jsonl + manifest → report). D10: **Gate G1 (I2):** L1 on the real lab → core (or hand-built incident if the core slips a day) → real server → `matched`. | D6–7: `flow_service` with NFStream + plugin + feature computation + DummyClassifier; flow↔connection linking + interface dedupe. D8–9: `correlator` (4 states, pending retry, reverse direction, network_alerts). D10: Gate G1 support; correlation metrics logging. | D6–8: RF baseline trained on NF-UNSW-NB15-v2; threshold at FPR ≤ 1 %; report v1; bundle `ids-rf-001`. D9–10: dashboard incident graph (React Flow, basis styling), timeline, connections panel with correlation states, SSE live list. |
| **3** (D11–15) | D11–12: Windows response adapter (terminate) + command polling; EID 22/26 mapping; placeholder seeding from `psutil`. D13–14: incident versioning/updates; `gaps` population; Windows evaluation run with noise.ps1. D15: **I3**: W1 live → `matched` on the real server. | D11–12: Linux response adapter (SIGKILL, allowlist); NX-LIN-003 automatic path in dry-run. D13–14: benign noise generator; first FP measurement on Linux; event-loss check under noise. D15: I3 support; replay reports for L1/L2/L3. | D11–12: `ti_service` offline feeds + lab indicators + agent hash list endpoint; VT lookup with cache/limits. D13–14: `response_controller` (endpoint command queue, nftables block/unblock), audit tables. D15: real model bundle loaded (`ids-rf-001`); SSE events for all update paths. | D11–12: second dataset sample (CSE-CIC-IDS2018-v2), model `ids-rf-002` or XGBoost; generalization test on first lab pcaps from Omar/Rakan. D13–15: dashboard TI panel, gaps panel, network alerts page, endpoints page, response page with confirm dialogs; manual response wired to API. |
| **4** (D16–20) | D16–18: integration fixes on the Windows path; Defender/SmartScreen handling; W2 scenario; NX-ANY-001 with the hash list. D19–20: **Gate G2 (I4)**: L1 + W1 complete stories with ML + TI + dry-run response on the dashboard. | D16–18: integration fixes Linux; L2 with real terminate (`dry_run=false` on the lab VM only); timing/latency instrumentation. D19–20: Gate G2; evaluation harness v2 (matching precision/coverage computed from manifests + server export). | D16–18: pending/ambiguous paths tested with deliberate port reuse; performance under L3 (hundreds of connections); backups of DB. D19–20: Gate G2; `/stats` and evaluation export endpoints. | D16–18: ML lab evaluation report (benign baseline alerts/hour, scenario recall, ablation); threshold revisited with the team. D19–20: dashboard polish for Gate G2; empty/error states; incident export (JSON). |
| **5** (D21–25) | D21–23: hardening (token rotation, outbox durability, agent restart recovery); Windows service wrapper (stretch). D24–25: **I5**; freeze contracts at v1.0 final; write the report sections for Windows + architecture. | D21–23: N1 and L3 end-to-end; stretch: Tetragon enforcement policy for `/lab/protected`. D24–25: I5; full evaluation runs (3 repetitions each) and report tables. | D21–23: N1 manual gateway block/unblock demo path; ambiguity UI backing; log retention; VM snapshot "demo-ready". D24–25: I5; server metrics into the report. | D21–23: final model selection; model card; dashboard "evidence vs inference" legend and walkthrough mode. D24–25: I5; dashboard screenshots for the report. |
| **6** (D26–30) | **D26: code freeze (I6).** Bug fixes only. Three full demo rehearsals (D27, D28, D29) with timing. Report, slides, demo script, backup recordings of every scenario. D30: buffer. | same | same | same |

## 2. Milestones and gates

| Gate | Day | Pass criterion | If failed |
|---|---|---|---|
| I0 | D2 | Contracts frozen; fixtures validate; mock server runs on all four machines | Nobody starts component code until it passes (it is a two-day job at most). |
| I1 | D5 | Cross-subnet `curl` visible in `conntrack -E`; chrony synced; both sensors emit all five event types | Omar + Rakan pair on it; everyone else continues against fixtures. |
| **G1** | **D10** | One real Linux connection from L1 is `matched` on the real server with score ≥ 1.5 | Stop feature work on the server and Linux side; fix matching first. If still failing at D13, activate **Fallback A**. |
| I3 | D15 | Windows path `matched`; dashboard live | If Windows lags, the demo order becomes Linux-first; Anas gets help from Omar on the adapter for two days. |
| **G2** | **D20** | L1 and W1 complete stories on the dashboard with ML verdict, TI, dry-run response, gaps | Cut stretch items; if G2 slips past D22, activate **Fallback B**. |
| I5 | D25 | L2 real response, N1 network alert + gateway block, L3 threshold; evaluation tables filled | Drop N1 or L3 from the demo, keep them in the report as partially evaluated. |
| I6 | D26 | Freeze | — |

## 3. Parallelism summary
Weeks 1–2: four independent tracks against contracts + mock server + fixtures. Week 2 Friday: first real integration (Linux + server only). Week 3: Windows joins; ML and dashboard join through files and APIs, not through the lab. Weeks 4–5: integration-driven with daily lab use. Week 6: no new code.

## 4. Fallbacks (decided in advance so nobody argues under pressure)

- **Fallback A — matching unreliable at D13:** drop conntrack; use NFStream-only with `idle_timeout=5`, match on flows; accept 5–10 s correlation latency and say so.
- **Fallback B — one endpoint OS not ready at D22:** demo with one endpoint OS live and the other OS **replayed** through `nexus-replay` from recorded real sensor logs (clearly labelled "replay" on the dashboard). The architecture is still shown; honesty preserved.
- **Fallback C — ML weak on lab traffic:** keep the model as an annotation, show the dataset metrics and the lab generalization result as a finding ("domain shift measured"), and rely on N1 only if at least the scan-like pattern is flagged; otherwise drop N1.
- **Fallback D — response risky:** demo response in `dry_run` mode and show the audit trail; mention that real termination was tested in the lab (with the recording).
- **Fallback E — time:** cut in this order: Windows SACL reads → DNS events → XGBoost comparison → TI VT live lookups (keep offline) → L3 → N1 → ambiguity UI (keep API) → W2.

## 5. Definition of done (project)
- Must-have list in `01-ARCHITECTURE.md` §6 all green.
- Evaluation tables in `07-DEMO-AND-EVALUATION.md` filled with measured numbers from ≥ 3 runs.
- Recorded video of each scenario as backup.
- Report sections: assessment summary, architecture, correlation, ML, detection/TI/response, evaluation, limitations/future work.
